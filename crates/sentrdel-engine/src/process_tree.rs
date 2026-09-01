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
    #[cfg(unix)]
    process_group_id: u32,
}

impl ContainedChild {
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        match self.inner.start_kill() {
            Ok(()) => Ok(()),
            Err(error) if self.process_boundary_is_absent(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        self.inner.wait()
    }

    /// Terminate any remaining members of the admitted process boundary after
    /// the root process has already reported an exit status.
    ///
    /// An absent Unix process group means the entire group has already drained.
    /// Windows `NotFound` is likewise treated as quiescent. Every other failure
    /// remains fail-closed so permission or containment errors are never hidden.
    pub(crate) fn terminate_remaining(&mut self) -> io::Result<()> {
        self.start_kill()
    }

    fn process_boundary_is_absent(&self, error: &io::Error) -> bool {
        #[cfg(unix)]
        {
            unix_process_boundary_is_absent(error, self.process_group_id)
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

#[cfg(unix)]
fn unix_process_boundary_is_absent(error: &io::Error, _process_group_id: u32) -> bool {
    if error.raw_os_error() == Some(Errno::ESRCH as i32) {
        return true;
    }

    // macOS can report EPERM from killpg when the short-lived group leader has
    // already exited during an output-cap/root-exit race. Never treat EPERM as
    // quiescent by itself: a signal-0 probe must prove that the exact process
    // group no longer exists. A live but unkillable group therefore remains a
    // fail-closed containment error.
    #[cfg(target_os = "macos")]
    if error.raw_os_error() == Some(Errno::EPERM as i32) {
        return macos_process_group_is_absent(_process_group_id);
    }

    false
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
            None::<nix::sys::signal::Signal>
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
        #[cfg(unix)]
        let process_group_id = child.id();
        let stdout = child.stdout().take();
        let stderr = child.stderr().take();
        Ok(ContainedChild {
            inner: child,
            stdout,
            stderr,
            #[cfg(unix)]
            process_group_id,
        })
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_never_masks_a_live_process_group() {
        let process_group_id = nix::unistd::getpgrp();
        assert!(process_group_id.as_raw() > 0);
        let permission_denied = io::Error::from_raw_os_error(Errno::EPERM as i32);

        assert!(!unix_process_boundary_is_absent(
            &permission_denied,
            process_group_id.as_raw() as u32
        ));
    }
}
