//! Deliberately small Sentrdel-owned structural security rule set.
//!
//! These rules produce structural observations only. They do not create
//! canonical Findings, claim exploitability, or execute target code.

use crate::structural::{StructuralLanguage, StructuralRule};

pub const JS_EVAL_CALL: StructuralRule = StructuralRule::new(
    "js.eval-call",
    StructuralLanguage::JavaScript,
    "eval($ARG)",
);

pub const JS_DYNAMIC_FUNCTION_CONSTRUCTOR: StructuralRule = StructuralRule::new(
    "js.dynamic-function-constructor",
    StructuralLanguage::JavaScript,
    "new Function($$$ARGS)",
);

pub const HIGH_SIGNAL_STRUCTURAL_RULES: &[StructuralRule] =
    &[JS_EVAL_CALL, JS_DYNAMIC_FUNCTION_CONSTRUCTOR];

#[must_use]
pub const fn high_signal_structural_rules() -> &'static [StructuralRule] {
    HIGH_SIGNAL_STRUCTURAL_RULES
}
