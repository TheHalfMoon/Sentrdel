#![forbid(unsafe_code)]
//! Diff-first security review. Target repository code is data, never authority.

pub mod git;
pub mod structural;
pub mod view;

pub const TARGET_BUILD_EXECUTION_ALLOWED: bool = false;
