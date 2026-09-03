//! Final lexical qualification for bounded R3 route extraction.
//!
//! The core T009 extractor recognizes only the frozen adapter syntax. This wrapper adds a
//! conservative binding gate for the Express factory name before downstream tasks may treat a
//! route observation as an adapter-backed semantic fact. Repository source remains data only.

use sentrdel_schema::canonical::content_id;

pub(crate) use super::model;
use super::model::{BusinessLogicLimits, ModelError, RouteObservation, SourceLocation};
use crate::structural::{StructuralError, StructuralLanguage};
use crate::view::NormalizedRepoPath;

#[path = "route.rs"]
mod core;

pub use core::{
    MAX_ROUTE_CALLBACKS, MAX_ROUTE_COVERAGE_GAPS, MAX_ROUTE_OBSERVATIONS, RouteAdapter,
    RouteCoverageGapReason, RouteExtractionError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCoverageGap {
    reason: RouteCoverageGapReason,
    adapter: RouteAdapter,
    provenance: SourceLocation,
}

impl RouteCoverageGap {
    #[must_use]
    pub const fn reason(&self) -> RouteCoverageGapReason {
        self.reason
    }

    #[must_use]
    pub const fn adapter(&self) -> RouteAdapter {
        self.adapter
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteExtraction {
    routes: Vec<RouteObservation>,
    gaps: Vec<RouteCoverageGap>,
}

impl RouteExtraction {
    #[must_use]
    pub fn routes(&self) -> &[RouteObservation] {
        &self.routes
    }

    #[must_use]
    pub fn gaps(&self) -> &[RouteCoverageGap] {
        &self.gaps
    }
}

pub fn extract_routes(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<RouteExtraction, RouteExtractionError> {
    let raw = core::extract_routes(adapter, language, path, source, limits)?;
    let mut routes = raw.routes().to_vec();
    let mut gaps: Vec<RouteCoverageGap> = raw
        .gaps()
        .iter()
        .map(|gap| RouteCoverageGap {
            reason: gap.reason(),
            adapter: gap.adapter(),
            provenance: gap.provenance().clone(),
        })
        .collect();

    if adapter == RouteAdapter::Express && express_factory_binding_is_ambiguous(language, source)? {
        routes.clear();
        let source_text = std::str::from_utf8(source)
            .map_err(|_| RouteExtractionError::Structural(StructuralError::NonUtf8Source))?;
        let digest = content_id("r3-route-source", &(path.as_str(), source_text))
            .map_err(ModelError::from)
            .map_err(RouteExtractionError::Model)?;
        let provenance = SourceLocation::new(path.clone(), 0, source.len(), digest)
            .map_err(RouteExtractionError::Model)?;
        let candidate = RouteCoverageGap {
            reason: RouteCoverageGapReason::AmbiguousReceiverBinding,
            adapter,
            provenance,
        };
        if !gaps.contains(&candidate) {
            if gaps.len() >= MAX_ROUTE_COVERAGE_GAPS {
                return Err(RouteExtractionError::TooManyCoverageGaps {
                    count: gaps.len().saturating_add(1),
                    max: MAX_ROUTE_COVERAGE_GAPS,
                });
            }
            gaps.push(candidate);
        }
    }

    gaps.sort_by(|left, right| {
        left.reason
            .cmp(&right.reason)
            .then_with(|| {
                left.provenance
                    .start_byte()
                    .cmp(&right.provenance.start_byte())
            })
            .then_with(|| left.provenance.end_byte().cmp(&right.provenance.end_byte()))
    });
    gaps.dedup();

    Ok(RouteExtraction { routes, gaps })
}

fn express_factory_binding_is_ambiguous(
    language: StructuralLanguage,
    source: &[u8],
) -> Result<bool, RouteExtractionError> {
    let source = std::str::from_utf8(source)
        .map_err(|_| RouteExtractionError::Structural(StructuralError::NonUtf8Source))?;
    let language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).map_err(|error| {
        RouteExtractionError::Structural(StructuralError::ParseFailed(error.to_string()))
    })?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        RouteExtractionError::Structural(StructuralError::ParseFailed(
            "Express final binding parser returned no syntax tree".to_owned(),
        ))
    })?;

    let mut canonical_imports = 0usize;
    let mut noncanonical_binding = false;
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if matches!(
            node.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && source.get(node.byte_range()) == Some("express")
            && identifier_is_binding(node)
        {
            if express_binding_is_canonical_default_import(node, source) {
                canonical_imports = canonical_imports.saturating_add(1);
            } else {
                noncanonical_binding = true;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    Ok(canonical_imports > 1 || (canonical_imports == 1 && noncanonical_binding))
}

fn express_binding_is_canonical_default_import(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "import_clause" {
        return false;
    }
    let Some(default_name) = parent.named_child(0) else {
        return false;
    };
    if default_name.start_byte() != node.start_byte() || default_name.end_byte() != node.end_byte()
    {
        return false;
    }

    let Some(statement) = parent.parent() else {
        return false;
    };
    if statement.kind() != "import_statement" {
        return false;
    }
    let Some(module) = statement.child_by_field_name("source") else {
        return false;
    };
    matches!(
        source.get(module.byte_range()),
        Some("\"express\"") | Some("'express'")
    )
}

fn identifier_is_binding(node: tree_sitter::Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let same_as_field = |field: &str| {
        parent.child_by_field_name(field).is_some_and(|candidate| {
            candidate.start_byte() == node.start_byte() && candidate.end_byte() == node.end_byte()
        })
    };
    match parent.kind() {
        "variable_declarator" | "function_declaration" | "class_declaration" => {
            same_as_field("name")
        }
        "assignment_expression" | "assignment_pattern" => same_as_field("left"),
        "catch_clause" => same_as_field("parameter"),
        "pair_pattern" => same_as_field("value"),
        "object_pattern" | "array_pattern" => true,
        "formal_parameters"
        | "required_parameter"
        | "optional_parameter"
        | "rest_pattern"
        | "import_specifier"
        | "import_clause"
        | "namespace_import"
        | "shorthand_property_identifier_pattern" => true,
        _ => parent.parent().is_some_and(|grandparent| {
            matches!(
                grandparent.kind(),
                "formal_parameters" | "required_parameter" | "optional_parameter"
            )
        }),
    }
}
