//! Final route and lexical-origin qualification for bounded R3 value derivation.
//!
//! `value_scope` already rejects cross-handler, shadowed request-parameter, and import-shadow
//! ambiguity. This final qualifier closes two narrower seams that require information unavailable
//! to the lower extractor: an Express named handler must be backed by a canonical route
//! observation, and catch-bound authentication receiver names must never impersonate adapter
//! origins. Rejected values degrade to UNKNOWN with fail-visible coverage.

use std::collections::{BTreeMap, BTreeSet};

pub(crate) use super::model;
use super::model::{
    BusinessLogicLimits, SourceLocation, StableSemanticId, ValueOrigin, ValueOriginKind,
};
pub(crate) use super::route;
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage};
use crate::view::NormalizedRepoPath;

#[path = "value_scope.rs"]
mod scoped;

pub use scoped::{
    MAX_VALUE_AST_NODES, MAX_VALUE_COVERAGE_GAPS, MAX_VALUE_ORIGINS,
    STATIC_VALUE_DERIVATION_PROVES_RUNTIME_VALUE, ValueCoverageGapReason, ValueExtractionError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueCoverageGap {
    reason: ValueCoverageGapReason,
    provenance: SourceLocation,
}

impl ValueCoverageGap {
    #[must_use]
    pub const fn reason(&self) -> ValueCoverageGapReason {
        self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueExtraction {
    values: Vec<ValueOrigin>,
    gaps: Vec<ValueCoverageGap>,
}

impl ValueExtraction {
    #[must_use]
    pub fn values(&self) -> &[ValueOrigin] {
        &self.values
    }

    #[must_use]
    pub fn gaps(&self) -> &[ValueCoverageGap] {
        &self.gaps
    }

    #[must_use]
    pub fn value_for_range(&self, start: usize, end: usize) -> Option<&ValueOrigin> {
        self.values.iter().find(|value| {
            value
                .provenance()
                .iter()
                .any(|location| location.start_byte() == start && location.end_byte() == end)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CatchShadow {
    start: usize,
    end: usize,
}

pub fn extract_value_origins(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<ValueExtraction, ValueExtractionError> {
    let limits = limits.validate().map_err(ValueExtractionError::Model)?;
    let extracted = scoped::extract_value_origins(adapter, language, path, source, limits)?;
    let source_text = std::str::from_utf8(source)
        .map_err(|_| ValueExtractionError::Structural(StructuralError::NonUtf8Source))?;
    let tree = parse_tree(language, source_text)?;
    let nodes = collect_nodes(tree.root_node())?;
    let routes =
        route::extract_routes(adapter, language, path, source, limits).map_err(|error| {
            ValueExtractionError::ParseFailed(format!("final route qualification failed: {error}"))
        })?;

    let express_named_route_proven = adapter != RouteAdapter::Express
        || unique_exported_handler(&nodes, source_text)
            && routes
                .routes()
                .iter()
                .any(|route| route.handler_semantic_key() == Some("handler"));
    let catch_shadows = collect_authentication_catch_shadows(&nodes, source_text, adapter);

    let values_by_id: BTreeMap<String, &ValueOrigin> = extracted
        .values()
        .iter()
        .map(|value| (value.value_id().as_str().to_owned(), value))
        .collect();
    let mut unsafe_ids = BTreeSet::new();

    for value in extracted.values() {
        let Some(location) = value.provenance().first() else {
            unsafe_ids.insert(value.value_id().as_str().to_owned());
            continue;
        };
        if extracted
            .value_for_range(location.start_byte(), location.end_byte())
            .is_none()
        {
            unsafe_ids.insert(value.value_id().as_str().to_owned());
            continue;
        }

        if adapter == RouteAdapter::Express
            && is_direct_origin(value.origin_kind())
            && inside_exported_handler(
                &nodes,
                source_text,
                location.start_byte(),
                location.end_byte(),
            )
            && !express_named_route_proven
        {
            unsafe_ids.insert(value.value_id().as_str().to_owned());
            continue;
        }

        if is_authenticated_origin(value.origin_kind())
            && catch_shadows.iter().any(|shadow| {
                shadow.start <= location.start_byte() && location.end_byte() <= shadow.end
            })
        {
            unsafe_ids.insert(value.value_id().as_str().to_owned());
        }
    }
    propagate_unsafe_inputs(&extracted, &values_by_id, &mut unsafe_ids);

    let mut gaps = BTreeMap::new();
    for gap in extracted.gaps() {
        insert_gap(
            &mut gaps,
            ValueCoverageGap {
                reason: gap.reason(),
                provenance: gap.provenance().clone(),
            },
        )?;
    }

    let mut values = BTreeMap::new();
    for value in extracted.values() {
        if !unsafe_ids.contains(value.value_id().as_str()) {
            values.insert(value.value_id().as_str().to_owned(), value.clone());
            continue;
        }
        let Some(location) = value.provenance().first() else {
            continue;
        };
        insert_gap(
            &mut gaps,
            ValueCoverageGap {
                reason: ValueCoverageGapReason::AmbiguousBinding,
                provenance: location.clone(),
            },
        )?;
        let start = location.start_byte().to_string();
        let end = location.end_byte().to_string();
        let unknown_id = StableSemanticId::from_parts(
            "r3.value-final-unknown",
            &[path.as_str(), &start, &end, value.value_id().as_str()],
            limits,
        )
        .map_err(ValueExtractionError::Model)?;
        let unknown = ValueOrigin::new(
            unknown_id.clone(),
            ValueOriginKind::Unknown,
            format!("unknown:final-qualification@{start}:{end}"),
            None,
            Vec::new(),
            0,
            vec![location.clone()],
            limits,
        )
        .map_err(ValueExtractionError::Model)?;
        values.insert(unknown_id.as_str().to_owned(), unknown);
    }

    Ok(ValueExtraction {
        values: values.into_values().collect(),
        gaps: gaps.into_values().collect(),
    })
}

fn propagate_unsafe_inputs(
    extracted: &scoped::ValueExtraction,
    values_by_id: &BTreeMap<String, &ValueOrigin>,
    unsafe_ids: &mut BTreeSet<String>,
) {
    loop {
        let mut changed = false;
        for value in extracted.values() {
            let id = value.value_id().as_str();
            if unsafe_ids.contains(id) {
                continue;
            }
            if value.derivation_inputs().iter().any(|input| {
                unsafe_ids.contains(input.as_str()) || !values_by_id.contains_key(input.as_str())
            }) {
                changed |= unsafe_ids.insert(id.to_owned());
            }
        }
        if !changed {
            break;
        }
    }
}

fn unique_exported_handler(nodes: &[tree_sitter::Node<'_>], source: &str) -> bool {
    nodes
        .iter()
        .copied()
        .filter(|node| is_exported_named_handler(*node, source))
        .count()
        == 1
}

fn inside_exported_handler(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    start: usize,
    end: usize,
) -> bool {
    innermost_function_for_range(nodes, start, end)
        .is_some_and(|function| is_exported_named_handler(function, source))
}

fn is_exported_named_handler(node: tree_sitter::Node<'_>, source: &str) -> bool {
    is_function_boundary(node)
        && node
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source))
            == Some("handler")
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "export_statement")
}

fn collect_authentication_catch_shadows(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    adapter: RouteAdapter,
) -> Vec<CatchShadow> {
    let target = match adapter {
        RouteAdapter::NextApp => "auth",
        RouteAdapter::SupabaseEdge => "supabase",
        RouteAdapter::Express | RouteAdapter::NextPagesApi => return Vec::new(),
    };
    let mut shadows = Vec::new();
    for node in nodes {
        if node.kind() != "catch_clause" {
            continue;
        }
        let Some(parameter) = node.child_by_field_name("parameter") else {
            continue;
        };
        if !pattern_binding_names(parameter, source)
            .iter()
            .any(|binding| binding == target)
        {
            continue;
        }
        let body = node.child_by_field_name("body").unwrap_or(*node);
        shadows.push(CatchShadow {
            start: body.start_byte(),
            end: body.end_byte(),
        });
    }
    shadows.sort_by_key(|shadow| (shadow.start, shadow.end));
    shadows.dedup();
    shadows
}

fn is_direct_origin(kind: ValueOriginKind) -> bool {
    matches!(
        kind,
        ValueOriginKind::RequestPath
            | ValueOriginKind::RequestQuery
            | ValueOriginKind::RequestBody
            | ValueOriginKind::RequestHeader
            | ValueOriginKind::AuthenticatedUserId
            | ValueOriginKind::AuthenticatedTenantId
            | ValueOriginKind::AuthenticatedRole
    )
}

fn is_authenticated_origin(kind: ValueOriginKind) -> bool {
    matches!(
        kind,
        ValueOriginKind::AuthenticatedUserId
            | ValueOriginKind::AuthenticatedTenantId
            | ValueOriginKind::AuthenticatedRole
    )
}

fn insert_gap(
    gaps: &mut BTreeMap<(ValueCoverageGapReason, usize, usize), ValueCoverageGap>,
    gap: ValueCoverageGap,
) -> Result<(), ValueExtractionError> {
    let key = (
        gap.reason,
        gap.provenance.start_byte(),
        gap.provenance.end_byte(),
    );
    if !gaps.contains_key(&key) && gaps.len() >= MAX_VALUE_COVERAGE_GAPS {
        return Err(ValueExtractionError::TooManyCoverageGaps {
            count: gaps.len().saturating_add(1),
            max: MAX_VALUE_COVERAGE_GAPS,
        });
    }
    gaps.insert(key, gap);
    Ok(())
}

fn parse_tree(
    language: StructuralLanguage,
    source: &str,
) -> Result<tree_sitter::Tree, ValueExtractionError> {
    let language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ValueExtractionError::ParseFailed(error.to_string()))?;
    parser.parse(source, None).ok_or_else(|| {
        ValueExtractionError::ParseFailed(
            "final value qualifier returned no syntax tree".to_owned(),
        )
    })
}

fn collect_nodes<'tree>(
    root: tree_sitter::Node<'tree>,
) -> Result<Vec<tree_sitter::Node<'tree>>, ValueExtractionError> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if nodes.len() >= MAX_VALUE_AST_NODES {
            return Err(ValueExtractionError::TooManyAstNodes {
                count: nodes.len().saturating_add(1),
                max: MAX_VALUE_AST_NODES,
            });
        }
        nodes.push(node);
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    Ok(nodes)
}

fn innermost_function_for_range<'tree>(
    nodes: &[tree_sitter::Node<'tree>],
    start: usize,
    end: usize,
) -> Option<tree_sitter::Node<'tree>> {
    nodes
        .iter()
        .copied()
        .filter(|node| {
            is_function_boundary(*node) && node.start_byte() <= start && end <= node.end_byte()
        })
        .min_by_key(|node| node.end_byte().saturating_sub(node.start_byte()))
}

fn pattern_binding_names(node: tree_sitter::Node<'_>, source: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(
            current.kind(),
            "identifier"
                | "shorthand_property_identifier"
                | "shorthand_property_identifier_pattern"
        ) && let Some(value) = node_text(current, source)
            && is_identifier(value)
        {
            values.push(value.to_owned());
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    values.sort();
    values.dedup();
    values
}

fn is_function_boundary(node: tree_sitter::Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_expression"
            | "function_declaration"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
            | "method_definition"
    )
}

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first == b'$' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric())
}
