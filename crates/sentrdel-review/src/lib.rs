#![forbid(unsafe_code)]
//! Diff-first security review. Target repository code is data, never authority.

pub mod coverage;
pub mod dependency;
pub mod git;
pub mod github_actions;
pub mod osv;
pub mod reconcile;
pub mod secrets;
pub mod structural;
pub mod structural_rules;
pub mod view;

pub const TARGET_BUILD_EXECUTION_ALLOWED: bool = false;
