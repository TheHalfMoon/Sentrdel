//! Cross-platform process-tree containment for the T027 engine boundary.
//!
//! This module is intentionally private. It wraps the single external-engine
//! spawn with a POSIX process group on Unix and a Windows Job Object on Windows.
//! Repository data never chooses the containment mode and no shell is involved.

use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io,
    path::Path,
    process::{ChildStderr, ChildStdout, ExitStatus, Stdio},
};

#[cfg(unix)]
use nix::errno::Errno;
#[cfg(target_os = "macos")]
use nix::{sys::signal::kill, unistd::Pid};
#[cfg(windows)]
use process_wrap::std::JobObject;
#[cfg(unix)]
use process_wrap::std::ProcessGroup;
use process_wrap::std::{ChildWrapper, CommandWrap};

#[derive(Debug)]
pub(crate) struct ContainedChild {
    inner: Box<dyn ChildWrapper>,
    pub(crate) stdout: Option<ChildStdout>,
    pub(crate) stderr: Option<ChildStderr>,
    #[cfg(target_os = "macos")]
    process_group_id: u32,
}

impl ContainedChild {
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        match self.inner.start_kill() {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.process_boundary_is_absent_after_kill_failure(&error) {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        self.inner.wait()
    }

    /// Terminate any remaining members of the admitted process boundary after
    /// the root process has already reported an exit status.
    ///
    /// On non-macOS Unix, `ESRCH` means the process group has already drained.
    /// On macOS, `ESRCH` and `EPERM` both require an exited-root reap followed
    /// by an exact-group signal-zero absence proof. Windows `NotFound` is
    /// likewise treated as quiescent. Every other failure remains fail-closed.
    pub(crate) fn terminate_remaining(&mut self) -> io::Result<()> {
        self.start_kill()
    }

    fn process_boundary_is_absent_after_kill_failure(&mut self, error: &io::Error) -> bool {
        #[cfg(unix)]
        {
            #[cfg(target_os = "macos")]
            {
                let raw_error = error.raw_os_error();
                let needs_post_reap_proof = raw_error == Some(Errno::ESRCH as i32)
                    || raw_error == Some(Errno::EPERM as i32);
                if !needs_post_reap_proof {
                    return false;
                }

                // macOS process-group kill errors can race an exited but not-yet-
                // reaped group leader. Neither ESRCH nor EPERM is accepted by
                // itself: first require the process-group wrapper to reap/report
                // the exited root, then require a signal-zero probe to prove the
                // exact spawn-time process group no longer exists. A running root,
                // failed reap, surviving group member, inaccessible group, or any
                // indeterminate probe preserves the original kill failure.
                matches!(self.inner.try_wait(), Ok(Some(_)))
                    && macos_process_group_is_absent(self.process_group_id)
            }

            #[cfg(not(target_os = "macos"))]
            {
                error.raw_os_error() == Some(Errno::ESRCH as i32)
            }
        }
        #[cfg(windows)]
        {
            error.kind() == io::ErrorKind::NotFound
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = error;
            false
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_process_group_is_absent(process_group_id: u32) -> bool {
    let Ok(process_group_id) = i32::try_from(process_group_id) else {
        return false;
    };

    // `kill` with signal 0 sends no signal. A negative PID probes the exact
    // process group created for this child. ESRCH is the only result that proves
    // the boundary has drained; success and every other errno are live or
    // indeterminate and therefore remain fail-closed.
    matches!(
        kill(
            Pid::from_raw(-process_group_id),
            None::<nix::sys::signal::Signal>,
        ),
        Err(Errno::ESRCH)
    )
}

pub(crate) fn spawn_contained_process(
    executable: &Path,
    arguments: &[OsString],
    working_directory: &Path,
    environment: &BTreeMap<String, OsString>,
) -> io::Result<ContainedChild> {
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (executable, arguments, working_directory, environment);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "T027 process-tree containment is supported only on Unix and Windows",
        ));
    }

    #[cfg(any(unix, windows))]
    {
        let mut command = CommandWrap::with_new(executable, |command| {
            command
                .args(arguments)
                .current_dir(working_directory)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env_clear();
            for (name, value) in environment {
                command.env(OsStr::new(name), value);
            }
        });

        #[cfg(unix)]
        command.wrap(ProcessGroup::leader());
        #[cfg(windows)]
        command.wrap(JobObject);

        let mut child = command.spawn()?;
        #[cfg(target_os = "macos")]
        let process_group_id = child.id();
        let stdout = child.stdout().take();
        let stderr = child.stderr().take();
        Ok(ContainedChild {
            inner: child,
            stdout,
            stderr,
            #[cfg(target_os = "macos")]
            process_group_id,
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn signal_zero_probe_never_masks_a_live_process_group() {
        let process_group_id = nix::unistd::getpgrp();
        assert!(process_group_id.as_raw() > 0);

        assert!(!macos_process_group_is_absent(
            process_group_id.as_raw() as u32
        ));
    }
}
