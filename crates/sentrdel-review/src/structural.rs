//! Bounded native structural matching for Sentrdel-owned rules.
//!
//! Target repository source is data only. Rules are compiled into Sentrdel and
//! parsing/matching never executes repository commands, package managers, build
//! scripts, dynamic grammars, network operations, or repository-provided rules.

use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;

use ast_grep_core::AstGrep;
use ast_grep_core::language::Language;
use ast_grep_core::matcher::{Pattern, PatternBuilder, PatternError};
use ast_grep_core::tree_sitter::{LanguageExt, StrDoc, TSLanguage};

use crate::view::{DEFAULT_MAX_FILE_BYTES, NormalizedRepoPath};

pub const MAX_STRUCTURAL_RULES: usize = 256;
pub const MAX_STRUCTURAL_RULE_ID_BYTES: usize = 128;
pub const MAX_STRUCTURAL_PATTERN_BYTES: usize = 16 * 1024;
pub const MAX_STRUCTURAL_DOCUMENT_BYTES: usize = DEFAULT_MAX_FILE_BYTES as usize;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StructuralLanguage {
    JavaScript,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructuralRule {
    id: &'static str,
    language: StructuralLanguage,
    pattern: &'static str,
}

impl StructuralRule {
    #[must_use]
    pub const fn new(
        id: &'static str,
        language: StructuralLanguage,
        pattern: &'static str,
    ) -> Self {
        Self {
            id,
            language,
            pattern,
        }
    }

    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }

    #[must_use]
    pub const fn language(&self) -> StructuralLanguage {
        self.language
    }

    #[must_use]
    pub const fn pattern(&self) -> &'static str {
        self.pattern
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StructuralMatch {
    pub rule_id: &'static str,
    pub language: StructuralLanguage,
    pub path: NormalizedRepoPath,
    pub byte_range: Range<usize>,
}

#[derive(Debug)]
pub enum StructuralError {
    TooManyRules {
        count: usize,
        max: usize,
    },
    InvalidRuleId(&'static str),
    DuplicateRuleId(&'static str),
    EmptyPattern(&'static str),
    PatternTooLarge {
        rule_id: &'static str,
        bytes: usize,
        max: usize,
    },
    InvalidPattern {
        rule_id: &'static str,
        source: PatternError,
    },
    DocumentTooLarge {
        bytes: usize,
        max: usize,
    },
    NonUtf8Source,
    ParseFailed(String),
    MalformedSyntax,
}

impl fmt::Display for StructuralError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyRules { count, max } => {
                write!(formatter, "structural rule count {count} exceeds cap {max}")
            }
            Self::InvalidRuleId(id) => {
                write!(formatter, "invalid Sentrdel structural rule id: {id:?}")
            }
            Self::DuplicateRuleId(id) => {
                write!(formatter, "duplicate Sentrdel structural rule id: {id:?}")
            }
            Self::EmptyPattern(rule_id) => {
                write!(
                    formatter,
                    "structural rule {rule_id:?} has an empty pattern"
                )
            }
            Self::PatternTooLarge {
                rule_id,
                bytes,
                max,
            } => write!(
                formatter,
                "structural rule {rule_id:?} pattern size {bytes} exceeds cap {max}"
            ),
            Self::InvalidPattern { rule_id, source } => {
                write!(
                    formatter,
                    "structural rule {rule_id:?} has an invalid pattern: {source}"
                )
            }
            Self::DocumentTooLarge { bytes, max } => {
                write!(
                    formatter,
                    "structural document size {bytes} exceeds cap {max}"
                )
            }
            Self::NonUtf8Source => formatter.write_str("structural source must be valid UTF-8"),
            Self::ParseFailed(error) => write!(formatter, "structural parser failed: {error}"),
            Self::MalformedSyntax => {
                formatter.write_str("structural source contains parser error or missing nodes")
            }
        }
    }
}

impl std::error::Error for StructuralError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPattern { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct JavaScriptLanguage;

impl Language for JavaScriptLanguage {
    fn kind_to_id(&self, kind: &str) -> u16 {
        self.get_ts_language().id_for_node_kind(kind, true)
    }

    fn field_to_id(&self, field: &str) -> Option<u16> {
        self.get_ts_language()
            .field_id_for_name(field)
            .map(|id| id.get())
    }

    fn build_pattern(&self, builder: &PatternBuilder<'_>) -> Result<Pattern, PatternError> {
        builder.build(|source| StrDoc::try_new(source, self.clone()))
    }
}

impl LanguageExt for JavaScriptLanguage {
    fn get_ts_language(&self) -> TSLanguage {
        tree_sitter_javascript::LANGUAGE.into()
    }
}

struct CompiledRule {
    source: StructuralRule,
    pattern: Pattern,
}

pub struct StructuralRegistry {
    rules: Vec<CompiledRule>,
}

impl StructuralRegistry {
    pub fn new(rules: &[StructuralRule]) -> Result<Self, StructuralError> {
        if rules.len() > MAX_STRUCTURAL_RULES {
            return Err(StructuralError::TooManyRules {
                count: rules.len(),
                max: MAX_STRUCTURAL_RULES,
            });
        }

        let mut seen = BTreeSet::new();
        let mut compiled = Vec::with_capacity(rules.len());
        for rule in rules {
            validate_rule_id(rule.id)?;
            if !seen.insert(rule.id) {
                return Err(StructuralError::DuplicateRuleId(rule.id));
            }
            if rule.pattern.trim().is_empty() {
                return Err(StructuralError::EmptyPattern(rule.id));
            }
            if rule.pattern.len() > MAX_STRUCTURAL_PATTERN_BYTES {
                return Err(StructuralError::PatternTooLarge {
                    rule_id: rule.id,
                    bytes: rule.pattern.len(),
                    max: MAX_STRUCTURAL_PATTERN_BYTES,
                });
            }
            let pattern = compile_pattern(*rule)?;
            compiled.push(CompiledRule {
                source: *rule,
                pattern,
            });
        }

        compiled.sort_by_key(|rule| rule.source.id);
        Ok(Self { rules: compiled })
    }

    pub fn scan(
        &self,
        path: &NormalizedRepoPath,
        source: &[u8],
    ) -> Result<Vec<StructuralMatch>, StructuralError> {
        if source.len() > MAX_STRUCTURAL_DOCUMENT_BYTES {
            return Err(StructuralError::DocumentTooLarge {
                bytes: source.len(),
                max: MAX_STRUCTURAL_DOCUMENT_BYTES,
            });
        }
        let source = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;

        let document = AstGrep::<StrDoc<JavaScriptLanguage>>::try_new(source, JavaScriptLanguage)
            .map_err(StructuralError::ParseFailed)?;
        let root = document.root();
        if root.dfs().any(|node| node.is_error() || node.is_missing()) {
            return Err(StructuralError::MalformedSyntax);
        }

        let mut matches = Vec::new();
        for rule in &self.rules {
            if rule.source.language != StructuralLanguage::JavaScript {
                continue;
            }
            matches.extend(
                root.find_all(rule.pattern.clone())
                    .map(|matched| StructuralMatch {
                        rule_id: rule.source.id,
                        language: rule.source.language,
                        path: path.clone(),
                        byte_range: matched.range(),
                    }),
            );
        }
        matches.sort_by(|left, right| {
            left.rule_id
                .cmp(right.rule_id)
                .then_with(|| left.byte_range.start.cmp(&right.byte_range.start))
                .then_with(|| left.byte_range.end.cmp(&right.byte_range.end))
        });
        Ok(matches)
    }
}

fn compile_pattern(rule: StructuralRule) -> Result<Pattern, StructuralError> {
    match rule.language {
        StructuralLanguage::JavaScript => Pattern::try_new(rule.pattern, JavaScriptLanguage),
    }
    .map_err(|source| StructuralError::InvalidPattern {
        rule_id: rule.id,
        source,
    })
}

fn validate_rule_id(id: &'static str) -> Result<(), StructuralError> {
    if id.is_empty()
        || id.len() > MAX_STRUCTURAL_RULE_ID_BYTES
        || !id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(StructuralError::InvalidRuleId(id));
    }
    Ok(())
}
