#![forbid(unsafe_code)]
//! Diff-first security review. Target repository code is data, never authority.

pub mod config_detection;
pub mod coverage;
pub mod dependency;
pub mod git;
pub mod github_actions;
pub mod osv;
pub mod pack_registry;
pub mod profile;
pub mod project_detection;
pub mod reasoner;
pub mod reconcile;
pub mod secrets;
pub mod stack_detection;
pub mod structural;
pub mod structural_rules;
pub mod supabase;
pub mod supabase_detection;
#[path = "supabase/integration.rs"]
pub mod supabase_integration;
pub mod view;

pub const TARGET_BUILD_EXECUTION_ALLOWED: bool = false;
