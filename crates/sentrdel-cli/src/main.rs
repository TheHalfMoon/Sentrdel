#![forbid(unsafe_code)]

use std::process::ExitCode;

use sentrdel_cli::CliExitCode;

fn main() -> ExitCode {
    println!("Sentrdel bootstrap — implementation in progress");
    CliExitCode::Success.into()
}
