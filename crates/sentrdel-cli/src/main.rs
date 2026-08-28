#![forbid(unsafe_code)]

pub mod bootstrap;
mod guard_git_hooks;

use std::process::ExitCode;

use sentrdel_cli::CliExitCode;

fn main() -> ExitCode {
    println!("Sentrdel bootstrap — implementation in progress");
    CliExitCode::Success.into()
}
