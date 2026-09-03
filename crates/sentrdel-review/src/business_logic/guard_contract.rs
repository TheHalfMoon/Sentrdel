//! Conservative public contract for bounded R3 typed guard extraction.
//!
//! The underlying recognizer records file-local static guard shapes. This contract layer keeps
//! those typed observations non-authoritative until a later bounded correlation step proves
//! handler containment and prefix dominance. It also supplements fail-visible coverage for
//! request-selected computed authorization callbacks.

use std::collections::{BTreeMap, BTreeSet};

use sentrdel_schema::canonical::content_id;

pub(crate) use super::model;
pub(crate) use super::route;
use super::model::{
    BusinessLogicLimits, ComparisonShape, DominanceScope, GuardKind, GuardObservation, ModelError,
    SourceLocation, StableSemanticId,
};
use super::route::RouteAdapter;
use crate::structural::StructuralLanguage;
use crate::view::NormalizedRepoPath;

#[path = "guard.rs"]
mod recognizer;

pub use recognizer::{
    GuardCoverageGapReason, GuardExtractionError, MAX_GUARD_AST_NODES, MAX_GUARD_COVERAGE_GAPS,
    MAX_GUARD_OBSERVATIONS, STATIC_GUARD_RECOGNITION_PROVES_RUNTIME_AUTHORIZATION,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardCoverageGap {
    reason: GuardCoverageGapReason,
    provenance: SourceLocation,
}

impl GuardCoverageGap {
    #[must_use]
    pub const fn reason(&self) -> GuardCoverageGapReason {
        self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardExtraction {
    guards: Vec<GuardObservation>,
    gaps: Vec<GuardCoverageGap>,
}

impl GuardExtraction {
    #[must_use]
    pub fn guards(&self) -> &[GuardObservation] {
        &self.guards
    }

    #[must_use]
    pub fn gaps(&self) -> &[GuardCoverageGap] {
        &self.gaps
    }
}

pub fn extract_guard_observations(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<GuardExtraction, GuardExtractionError> {
    let limits = limits.validate()?;
    let raw = recognizer::extract_guard_observations(adapter, language, path, source, limits)?;
    let source_text = std::str::from_utf8(source)
        .map_err(|_| crate::structural::StructuralError::NonUtf8Source)?;
    let digest =
        content_id("r3-guard-source", &(path.as_str(), source_text)).map_err(ModelError::from)?;

    let mut guards = Vec::with_capacity(raw.guards().len());
    for guard in raw.guards() {
        guards.push(harden_guard_observation(guard, path, limits)?);
    }

    let mut gaps = BTreeMap::new();
    for gap in raw.gaps() {
        insert_gap(
            &mut gaps,
            GuardCoverageGap {
                reason: gap.reason(),
                provenance: gap.provenance().clone(),
            },
        )?;
    }
    for (start, end) in computed_dynamic_guard_ranges(language, source_text, adapter)? {
        insert_gap(
            &mut gaps,
            GuardCoverageGap {
                reason: GuardCoverageGapReason::DynamicGuard,
                provenance: SourceLocation::new(path.clone(), start, end, digest.clone())?,
            },
        )?;
    }

    Ok(GuardExtraction {
        guards,
        gaps: gaps.into_values().collect(),
    })
}

fn harden_guard_observation(
    guard: &GuardObservation,
    path: &NormalizedRepoPath,
    limits: BusinessLogicLimits,
) -> Result<GuardObservation, GuardExtractionError> {
    let Some(location) = guard.provenance().first() else {
        return Err(GuardExtractionError::ParseFailed(
            "guard recognizer returned empty provenance".to_owned(),
        ));
    };
    let required_values = guard.required_values().to_vec();
    let values_key =
        content_id("r3.guard-required-values", &required_values).map_err(ModelError::from)?;
    let start = location.start_byte().to_string();
    let end = location.end_byte().to_string();
    let guard_id = StableSemanticId::from_parts(
        "r3.guard-observation",
        &[
            path.as_str(),
            guard_kind_key(guard.guard_kind()),
            comparison_shape_key(guard.comparison_shape()),
            dominance_scope_key(DominanceScope::Unknown),
            &values_key,
            &start,
            &end,
        ],
        limits,
    )?;

    Ok(GuardObservation::new(
        guard_id,
        guard.guard_kind(),
        guard.subject_actor().cloned(),
        guard.resource().cloned(),
        required_values,
        guard.comparison_shape(),
        DominanceScope::Unknown,
        guard.provenance().to_vec(),
        limits,
    )?)
}

fn insert_gap(
    gaps: &mut BTreeMap<(GuardCoverageGapReason, usize, usize), GuardCoverageGap>,
    gap: GuardCoverageGap,
) -> Result<(), GuardExtractionError> {
    let key = (
        gap.reason,
        gap.provenance.start_byte(),
        gap.provenance.end_byte(),
    );
    if !gaps.contains_key(&key) && gaps.len() >= MAX_GUARD_COVERAGE_GAPS {
        return Err(GuardExtractionError::TooManyCoverageGaps {
            count: gaps.len().saturating_add(1),
            max: MAX_GUARD_COVERAGE_GAPS,
        });
    }
    gaps.insert(key, gap);
    Ok(())
}

fn computed_dynamic_guard_ranges(
    language: StructuralLanguage,
    source: &str,
    adapter: RouteAdapter,
) -> Result<Vec<(usize, usize)>, GuardExtractionError> {
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let request_bindings = collect_request_controlled_bindings(&nodes, source, adapter);
    let mut dynamic_results = BTreeSet::new();

    for node in &nodes {
        if node.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = node.child_by_field_name("name") else {
            continue;
        };
        if name.kind() != "identifier" {
            continue;
        }
        let Some(binding) = node_text(name, source) else {
            continue;
        };
        let Some(value) = node.child_by_field_name("value") else {
            continue;
        };
        let value = unwrap_expression(value);
        if value.kind() == "call_expression"
            && call_has_request_controlled_computed_target(
                value,
                source,
                adapter,
                &request_bindings,
            )
        {
            dynamic_results.insert(binding.to_owned());
        }
    }

    let mut ranges = BTreeSet::new();
    for node in &nodes {
        if node.kind() != "if_statement" {
            continue;
        }
        let Some(condition) = node.child_by_field_name("condition") else {
            continue;
        };
        let Some(consequence) = node.child_by_field_name("consequence") else {
            continue;
        };
        let condition = unwrap_expression(condition);
        if contains_identifier(condition, source, &dynamic_results)
            && contains_direct_rejection_exit(consequence, source)
        {
            ranges.insert((condition.start_byte(), condition.end_byte()));
        }
    }
    Ok(ranges.into_iter().collect())
}

fn collect_request_controlled_bindings(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    adapter: RouteAdapter,
) -> BTreeSet<String> {
    let mut bindings = BTreeSet::new();
    for _ in 0..5 {
        let mut changed = false;
        for node in nodes {
            if node.kind() != "variable_declarator" {
                continue;
            }
            let Some(name) = node.child_by_field_name("name") else {
                continue;
            };
            if name.kind() != "identifier" {
                continue;
            }
            let Some(binding) = node_text(name, source) else {
                continue;
            };
            let Some(value) = node.child_by_field_name("value") else {
                continue;
            };
            if subtree_is_request_controlled(value, source, adapter, &bindings) {
                changed |= bindings.insert(binding.to_owned());
            }
        }
        if !changed {
            break;
        }
    }
    bindings
}

fn call_has_request_controlled_computed_target(
    call: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    request_bindings: &BTreeSet<String>,
) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let function = unwrap_expression(function);
    function.kind() == "subscript_expression"
        && subtree_is_request_controlled(function, source, adapter, request_bindings)
}

fn subtree_is_request_controlled(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    request_bindings: &BTreeSet<String>,
) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if expression_chain(unwrap_expression(current), source).is_some_and(|chain| {
            chain.first().is_some_and(|root| request_bindings.contains(root))
                || is_direct_request_chain(&chain, adapter)
        }) {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn is_direct_request_chain(chain: &[String], adapter: RouteAdapter) -> bool {
    let Some(root) = chain.first().map(String::as_str) else {
        return false;
    };
    match adapter {
        RouteAdapter::Express | RouteAdapter::NextPagesApi => root == "req",
        RouteAdapter::NextApp => matches!(root, "request" | "context"),
        RouteAdapter::SupabaseEdge => root == "request",
    }
}

fn contains_identifier(
    node: tree_sitter::Node<'_>,
    source: &str,
    identifiers: &BTreeSet<String>,
) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "identifier"
            && node_text(current, source).is_some_and(|value| identifiers.contains(value))
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn contains_direct_rejection_exit(node: tree_sitter::Node<'_>, source: &str) -> bool {
    if is_rejection_exit_node(node, source) {
        return true;
    }
    if node.kind() != "statement_block" {
        return false;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| is_rejection_exit_node(child, source))
}

fn is_rejection_exit_node(node: tree_sitter::Node<'_>, source: &str) -> bool {
    if !matches!(node.kind(), "return_statement" | "throw_statement") {
        return false;
    }
    if node.kind() == "throw_statement" {
        return true;
    }
    let text = node_text(node, source).unwrap_or_default();
    text.contains("401")
        || text.contains("403")
        || text.contains("Unauthorized")
        || text.contains("Forbidden")
        || text.trim() == "return;"
        || text.trim() == "return"
}

fn parse_tree(
    language: StructuralLanguage,
    source: &str,
) -> Result<tree_sitter::Tree, GuardExtractionError> {
    let language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| GuardExtractionError::ParseFailed(error.to_string()))?;
    parser.parse(source, None).ok_or_else(|| {
        GuardExtractionError::ParseFailed("guard contract parser returned no syntax tree".to_owned())
    })
}

fn collect_nodes<'tree>(
    root: tree_sitter::Node<'tree>,
) -> Result<Vec<tree_sitter::Node<'tree>>, GuardExtractionError> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if nodes.len() >= MAX_GUARD_AST_NODES {
            return Err(GuardExtractionError::TooManyAstNodes {
                count: nodes.len().saturating_add(1),
                max: MAX_GUARD_AST_NODES,
            });
        }
        nodes.push(node);
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    Ok(nodes)
}

fn unwrap_expression(mut node: tree_sitter::Node<'_>) -> tree_sitter::Node<'_> {
    loop {
        if matches!(node.kind(), "await_expression" | "parenthesized_expression")
            && let Some(child) = node.named_child(0)
        {
            node = child;
            continue;
        }
        return node;
    }
}

fn expression_chain(node: tree_sitter::Node<'_>, source: &str) -> Option<Vec<String>> {
    match node.kind() {
        "identifier" | "property_identifier" | "shorthand_property_identifier" => {
            Some(vec![node_text(node, source)?.to_owned()])
        }
        "member_expression" => {
            let object = node.child_by_field_name("object")?;
            let property = node.child_by_field_name("property")?;
            let mut chain = expression_chain(object, source)?;
            let property = node_text(property, source)?;
            if !is_identifier(property) {
                return None;
            }
            chain.push(property.to_owned());
            Some(chain)
        }
        _ => None,
    }
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

const fn guard_kind_key(kind: GuardKind) -> &'static str {
    match kind {
        GuardKind::Authentication => "authentication",
        GuardKind::RequiredRole => "required-role",
        GuardKind::TenantBinding => "tenant-binding",
        GuardKind::OwnershipBinding => "ownership-binding",
        GuardKind::ObjectMembership => "object-membership",
        GuardKind::PropertyAllowlist => "property-allowlist",
        GuardKind::PropertyDenylistRequirement => "property-denylist-requirement",
        GuardKind::ElevatedClientBoundary => "elevated-client-boundary",
        GuardKind::CustomInvariantRequirement => "custom-invariant-requirement",
    }
}

const fn comparison_shape_key(shape: ComparisonShape) -> &'static str {
    match shape {
        ComparisonShape::Equal => "equal",
        ComparisonShape::Membership => "membership",
        ComparisonShape::ConjunctionSupported => "conjunction-supported",
        ComparisonShape::ExplicitAllowlist => "explicit-allowlist",
        ComparisonShape::OtherSupported => "other-supported",
        ComparisonShape::Unknown => "unknown",
    }
}

const fn dominance_scope_key(scope: DominanceScope) -> &'static str {
    match scope {
        DominanceScope::SameHandlerPrefix => "same-handler-prefix",
        DominanceScope::SupportedMiddlewarePrefix => "supported-middleware-prefix",
        DominanceScope::LinkedHelper => "linked-helper",
        DominanceScope::Unknown => "unknown",
    }
}
