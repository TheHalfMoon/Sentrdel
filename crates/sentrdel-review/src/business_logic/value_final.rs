//! Final handler-parameter write qualification for bounded R3 value derivation.
//!
//! Earlier value qualifiers prove adapter seams, lexical visibility, and route identity. This
//! boundary closes one remaining identity class: a verified handler parameter stops being a
//! trusted request/context origin if repository source writes that binding anywhere in the same
//! handler function. Once that happens, direct origins seeded inside the same handler are also
//! conservatively invalidated so aliases cannot retain authority after losing an explicit
//! derivation edge. The analysis is deliberately conservative and static-only.

use std::collections::{BTreeMap, BTreeSet};

pub(crate) use super::model;
use super::model::{
    BusinessLogicLimits, SourceLocation, StableSemanticId, ValueOrigin, ValueOriginKind,
};
pub(crate) use super::route;
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage};
use crate::view::NormalizedRepoPath;

#[path = "value_gate.rs"]
mod gated;

pub use gated::{
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
enum ParameterWriteQualification {
    Clean,
    Reassigned {
        function_start: usize,
        function_end: usize,
    },
    Unqualified,
}

pub fn extract_value_origins(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<ValueExtraction, ValueExtractionError> {
    let limits = limits.validate().map_err(ValueExtractionError::Model)?;
    let extracted = gated::extract_value_origins(adapter, language, path, source, limits)?;
    let source_text = std::str::from_utf8(source)
        .map_err(|_| ValueExtractionError::Structural(StructuralError::NonUtf8Source))?;
    let tree = parse_tree(language, source_text)?;
    let nodes = collect_nodes(tree.root_node())?;

    let values_by_id: BTreeMap<String, &ValueOrigin> = extracted
        .values()
        .iter()
        .map(|value| (value.value_id().as_str().to_owned(), value))
        .collect();
    let mut unsafe_ids = BTreeSet::new();
    let mut tainted_functions = BTreeSet::new();

    for value in extracted.values() {
        if !is_direct_origin(value.origin_kind()) {
            continue;
        }
        match qualify_direct_origin_parameter_write(value, &nodes, source_text) {
            ParameterWriteQualification::Clean => {}
            ParameterWriteQualification::Reassigned {
                function_start,
                function_end,
            } => {
                unsafe_ids.insert(value.value_id().as_str().to_owned());
                tainted_functions.insert((function_start, function_end));
            }
            ParameterWriteQualification::Unqualified => {
                unsafe_ids.insert(value.value_id().as_str().to_owned());
            }
        }
    }

    if !tainted_functions.is_empty() {
        for value in extracted.values() {
            if !is_direct_origin(value.origin_kind()) {
                continue;
            }
            if origin_function_range(value, &nodes)
                .is_some_and(|range| tainted_functions.contains(&range))
            {
                unsafe_ids.insert(value.value_id().as_str().to_owned());
            }
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
            "r3.value-parameter-write-unknown",
            &[path.as_str(), &start, &end, value.value_id().as_str()],
            limits,
        )
        .map_err(ValueExtractionError::Model)?;
        let unknown = ValueOrigin::new(
            unknown_id.clone(),
            ValueOriginKind::Unknown,
            format!("unknown:parameter-write@{start}:{end}"),
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
    extracted: &gated::ValueExtraction,
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

fn qualify_direct_origin_parameter_write(
    value: &ValueOrigin,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
) -> ParameterWriteQualification {
    let Some(location) = value.provenance().first() else {
        return ParameterWriteQualification::Unqualified;
    };
    let Some(root) = semantic_root(value.semantic_key()) else {
        return ParameterWriteQualification::Unqualified;
    };
    let Some(function) =
        innermost_function_for_range(nodes, location.start_byte(), location.end_byte())
    else {
        return ParameterWriteQualification::Unqualified;
    };
    if function_parameter_names(function, source)
        .iter()
        .filter(|parameter| parameter.as_str() == root)
        .count()
        != 1
    {
        return ParameterWriteQualification::Clean;
    }

    let reassigned = nodes.iter().copied().any(|node| {
        if !function_contains_node(function, node) || !node_reassigns_name(node, source, root) {
            return false;
        }
        innermost_function_for_range(nodes, node.start_byte(), node.end_byte()).is_some_and(
            |owner| {
                owner.start_byte() == function.start_byte()
                    && owner.end_byte() == function.end_byte()
            },
        )
    });

    if reassigned {
        ParameterWriteQualification::Reassigned {
            function_start: function.start_byte(),
            function_end: function.end_byte(),
        }
    } else {
        ParameterWriteQualification::Clean
    }
}

fn origin_function_range(
    value: &ValueOrigin,
    nodes: &[tree_sitter::Node<'_>],
) -> Option<(usize, usize)> {
    let location = value.provenance().first()?;
    let function = innermost_function_for_range(nodes, location.start_byte(), location.end_byte())?;
    Some((function.start_byte(), function.end_byte()))
}

fn node_reassigns_name(node: tree_sitter::Node<'_>, source: &str, target: &str) -> bool {
    match node.kind() {
        "assignment_expression" | "augmented_assignment_expression" => node
            .child_by_field_name("left")
            .is_some_and(|left| assignment_target_has_name(left, source, target)),
        "update_expression" => node
            .child_by_field_name("argument")
            .or_else(|| node.named_child(0))
            .is_some_and(|argument| assignment_target_has_name(argument, source, target)),
        "for_in_statement" => node.child_by_field_name("left").is_some_and(|left| {
            !matches!(left.kind(), "lexical_declaration" | "variable_declaration")
                && assignment_target_has_name(left, source, target)
        }),
        _ => false,
    }
}

fn assignment_target_has_name(node: tree_sitter::Node<'_>, source: &str, target: &str) -> bool {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            node_text(node, source) == Some(target)
        }
        "array_pattern" | "object_pattern" | "assignment_pattern" | "rest_pattern"
        | "pair_pattern" => pattern_binding_names(node, source)
            .iter()
            .any(|binding| binding == target),
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|child| assignment_target_has_name(child, source, target)),
        _ => false,
    }
}

fn function_contains_node(function: tree_sitter::Node<'_>, node: tree_sitter::Node<'_>) -> bool {
    function.start_byte() <= node.start_byte() && node.end_byte() <= function.end_byte()
}

fn semantic_root(semantic_key: &str) -> Option<&str> {
    let key = semantic_key
        .strip_prefix("destructure-source:")
        .unwrap_or(semantic_key);
    let end = key.find(['.', '(', '[']).unwrap_or(key.len());
    let root = key.get(..end)?;
    is_identifier(root).then_some(root)
}

fn function_parameter_names(node: tree_sitter::Node<'_>, source: &str) -> Vec<String> {
    let parameter_node = node
        .child_by_field_name("parameters")
        .or_else(|| node.child_by_field_name("parameter"));
    let Some(parameter_node) = parameter_node else {
        return Vec::new();
    };
    if parameter_node.kind() != "formal_parameters" {
        return parameter_binding_name(parameter_node, source)
            .into_iter()
            .collect();
    }
    let mut cursor = parameter_node.walk();
    parameter_node
        .named_children(&mut cursor)
        .filter_map(|parameter| parameter_binding_name(parameter, source))
        .collect()
}

fn parameter_binding_name(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    let mut current = node;
    loop {
        if current.kind() == "identifier" {
            return node_text(current, source).map(str::to_owned);
        }
        if let Some(pattern) = current
            .child_by_field_name("pattern")
            .or_else(|| current.child_by_field_name("left"))
        {
            current = pattern;
            continue;
        }
        if current.named_child_count() == 1 {
            current = current.named_child(0)?;
            continue;
        }
        return None;
    }
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
            "final parameter-write parser returned no syntax tree".to_owned(),
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
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first == '$' || first.is_ascii_alphabetic())
        && chars.all(|character| {
            character == '_' || character == '$' || character.is_ascii_alphanumeric()
        })
}
