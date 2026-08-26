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
}

impl ContainedChild {
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        self.inner.start_kill()
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
        match self.inner.start_kill() {
            Ok(()) => Ok(()),
            Err(error) if process_boundary_is_absent(&error) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(unix)]
fn process_boundary_is_absent(error: &io::Error) -> bool {
    error.raw_os_error() == Some(Errno::ESRCH as i32)
}

#[cfg(windows)]
fn process_boundary_is_absent(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
}

#[cfg(not(any(unix, windows)))]
fn process_boundary_is_absent(_error: &io::Error) -> bool {
    false
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
        let stdout = child.stdout().take();
        let stderr = child.stderr().take();
        Ok(ContainedChild {
            inner: child,
            stdout,
            stderr,
        })
    }
}
