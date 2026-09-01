#![forbid(unsafe_code)]

pub mod bootstrap;
// Command parsing is intentionally deferred in the current R1 CLI skeleton;
// keep feature modules compiled and tested without weakening lints anywhere
// else in the workspace.
#[allow(dead_code)]
mod explain;
#[allow(dead_code)]
mod explain_provider;
#[cfg(test)]
mod explain_t070_contract;
#[allow(dead_code)]
mod guard_git_hooks;
#[allow(dead_code)]
mod provider_registration;
#[allow(dead_code)]
mod review_reasoning;

use std::process::ExitCode;

use sentrdel_cli::CliExitCode;

fn main() -> ExitCode {
    println!("Sentrdel bootstrap — implementation in progress");
    CliExitCode::Success.into()
}
