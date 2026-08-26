#![forbid(unsafe_code)]
//! Canonical, versioned security data contracts for Sentrdel.
//!
//! The schema crate owns representation and validation only. It performs no
//! filesystem mutation, subprocess execution, network access, or policy
//! evaluation.

pub mod asel;
pub mod canonical;
pub mod coverage;
pub mod engine;
pub mod evidence;
pub mod finding;
pub mod graph;
pub mod pack;
pub mod policy;
pub mod project;
pub mod reasoner;
pub mod schema_export;
pub mod version;

pub use version::SCHEMA_V1;
