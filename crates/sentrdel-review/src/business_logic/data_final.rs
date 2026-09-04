//! Final qualification boundary for canonical R3-T013 data-operation extraction.
//!
//! The structural candidate remains conservative. This wrapper independently re-qualifies every
//! broad request-controlled mutation candidate and upgrades dynamic candidates only when the exact
//! mutation argument is `req.body`, `request.body`, or a direct `req/request.json()` call rooted in
//! one unique visible parameter of the same enclosing function. Transformed expressions, free
//! lexical lookalikes, outer bindings, nested functions, reassigned request bindings, request-body
//! overwrites, and lexical shadowing never gain request-controlled authority.

use std::collections::{BTreeMap, BTreeSet};

use sentrdel_schema::coverage::CoverageState;

use super::data_candidate;
use super::model::{
    BusinessLogicLimits, DataOperation, FieldSet, FieldSetMode, SourceLocation, ValueOrigin,
};
use super::route::RouteAdapter;
use crate::structural::StructuralLanguage;
use crate::view::NormalizedRepoPath;

pub use data_candidate::{
    DataExtractionError, MAX_DATA_AST_NODES, MAX_DATA_COVERAGE_GAPS, MAX_DATA_FIELDS_PER_OPERATION,
    MAX_DATA_FILTERS_PER_OPERATION, MAX_DATA_OPERATIONS, MAX_DATA_SUPPORTING_VALUES,
    SUPABASE_DATA_EXECUTES_QUERIES, SUPABASE_DATA_PROVES_DATABASE_RESULT,
    SUPABASE_DATA_PROVES_HOSTED_STATE, SUPABASE_DATA_PROVES_RUNTIME_REACHABILITY,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DataCoverageGapReason {
    DynamicResource,
    DynamicRpcName,
    DynamicSelectedFields,
    DynamicMutationFields,
    DynamicFilterField,
    UnsupportedFilter,
    UnresolvedFilterValue,
    UnsupportedChainMethod,
    UnqualifiedBroadRequestObject,
}

impl From<data_candidate::DataCoverageGapReason> for DataCoverageGapReason {
    fn from(value: data_candidate::DataCoverageGapReason) -> Self {
        match value {
            data_candidate::DataCoverageGapReason::DynamicResource => Self::DynamicResource,
            data_candidate::DataCoverageGapReason::DynamicRpcName => Self::DynamicRpcName,
            data_candidate::DataCoverageGapReason::DynamicSelectedFields => {
                Self::DynamicSelectedFields
            }
            data_candidate::DataCoverageGapReason::DynamicMutationFields => {
                Self::DynamicMutationFields
            }
            data_candidate::DataCoverageGapReason::DynamicFilterField => Self::DynamicFilterField,
            data_candidate::DataCoverageGapReason::UnsupportedFilter => Self::UnsupportedFilter,
            data_candidate::DataCoverageGapReason::UnresolvedFilterValue => {
                Self::UnresolvedFilterValue
            }
            data_candidate::DataCoverageGapReason::UnsupportedChainMethod => {
                Self::UnsupportedChainMethod
            }
            data_candidate::DataCoverageGapReason::UnqualifiedBroadRequestObject => {
                Self::UnqualifiedBroadRequestObject
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataCoverageGap {
    reason: DataCoverageGapReason,
    provenance: SourceLocation,
}

impl DataCoverageGap {
    #[must_use]
    pub const fn reason(&self) -> DataCoverageGapReason {
        self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataExtraction {
    operations: Vec<DataOperation>,
    gaps: Vec<DataCoverageGap>,
    supporting_values: Vec<ValueOrigin>,
}

impl DataExtraction {
    #[must_use]
    pub fn operations(&self) -> &[DataOperation] {
        &self.operations
    }

    #[must_use]
    pub fn gaps(&self) -> &[DataCoverageGap] {
        &self.gaps
    }

    #[must_use]
    pub fn supporting_values(&self) -> &[ValueOrigin] {
        &self.supporting_values
    }
}

pub fn extract_supabase_data_operations(
    value_adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<DataExtraction, DataExtractionError> {
    let limits = limits.validate().map_err(DataExtractionError::Model)?;
    let candidate = data_candidate::extract_supabase_data_operations(
        value_adapter,
        language,
        path,
        source,
        limits,
    )?;
    let source_text = std::str::from_utf8(source).map_err(|_| {
        DataExtractionError::Structural(crate::structural::StructuralError::NonUtf8Source)
    })?;
    let tree = parse_tree(language, source_text)?;
    let nodes = collect_nodes(tree.root_node())?;

    let mut qualified_ranges = BTreeSet::new();
    let mut rejected_broad_ranges = BTreeMap::new();
    for operation in candidate.operations() {
        let Some(fields) = operation.mutation_fields() else {
            continue;
        };
        if !matches!(
            fields.mode(),
            FieldSetMode::Dynamic | FieldSetMode::BroadRequestObject
        ) {
            continue;
        }
        let range = (
            fields.provenance().start_byte(),
            fields.provenance().end_byte(),
        );
        let qualified = node_for_range(&nodes, range.0, range.1)
            .is_some_and(|node| qualifies_broad_request_object(node, &nodes, source_text));
        if qualified {
            qualified_ranges.insert(range);
        } else if fields.mode() == FieldSetMode::BroadRequestObject {
            rejected_broad_ranges
                .entry(range)
                .or_insert_with(|| fields.provenance().clone());
        }
    }

    let mut gaps = BTreeMap::new();
    for gap in candidate.gaps() {
        let range = (gap.provenance().start_byte(), gap.provenance().end_byte());
        if qualified_ranges.contains(&range)
            && matches!(
                gap.reason(),
                data_candidate::DataCoverageGapReason::DynamicMutationFields
                    | data_candidate::DataCoverageGapReason::UnqualifiedBroadRequestObject
            )
        {
            continue;
        }
        insert_gap(
            &mut gaps,
            DataCoverageGap {
                reason: gap.reason().into(),
                provenance: gap.provenance().clone(),
            },
        )?;
    }
    for provenance in rejected_broad_ranges.values() {
        insert_gap(
            &mut gaps,
            DataCoverageGap {
                reason: DataCoverageGapReason::UnqualifiedBroadRequestObject,
                provenance: provenance.clone(),
            },
        )?;
    }

    let gaps = gaps.into_values().collect::<Vec<_>>();
    let mut operations = Vec::with_capacity(candidate.operations().len());
    for operation in candidate.operations() {
        let Some(fields) = operation.mutation_fields() else {
            operations.push(operation.clone());
            continue;
        };
        let range = (
            fields.provenance().start_byte(),
            fields.provenance().end_byte(),
        );

        if qualified_ranges.contains(&range) {
            let mutation_fields = FieldSet::new(
                FieldSetMode::BroadRequestObject,
                Vec::new(),
                Vec::new(),
                fields.provenance().clone(),
                limits,
            )?;
            let coverage_state = if operation_has_gap(operation, &gaps) {
                operation.coverage_state().clone()
            } else {
                CoverageState::Covered
            };
            operations.push(rebuild_operation(
                operation,
                mutation_fields,
                coverage_state,
                limits,
            )?);
            continue;
        }

        if rejected_broad_ranges.contains_key(&range) {
            let mutation_fields = FieldSet::new(
                FieldSetMode::Dynamic,
                Vec::new(),
                Vec::new(),
                fields.provenance().clone(),
                limits,
            )?;
            operations.push(rebuild_operation(
                operation,
                mutation_fields,
                CoverageState::Partial,
                limits,
            )?);
            continue;
        }

        operations.push(operation.clone());
    }

    operations.sort_by(|left, right| left.operation_id().cmp(right.operation_id()));
    Ok(DataExtraction {
        operations,
        gaps,
        supporting_values: candidate.supporting_values().to_vec(),
    })
}

fn rebuild_operation(
    operation: &DataOperation,
    mutation_fields: FieldSet,
    coverage_state: CoverageState,
    limits: BusinessLogicLimits,
) -> Result<DataOperation, DataExtractionError> {
    Ok(DataOperation::new(
        operation.operation_id().clone(),
        operation.operation_kind(),
        operation.resource().clone(),
        operation.provider_client().cloned(),
        operation.filters().to_vec(),
        operation.read_fields().cloned(),
        Some(mutation_fields),
        operation.rpc_name().map(str::to_owned),
        operation.handler_symbol().cloned(),
        operation.provenance().to_vec(),
        coverage_state,
        limits,
    )?)
}

fn operation_has_gap(operation: &DataOperation, gaps: &[DataCoverageGap]) -> bool {
    operation.provenance().first().is_some_and(|location| {
        gaps.iter().any(|gap| {
            location.start_byte() <= gap.provenance.start_byte()
                && gap.provenance.end_byte() <= location.end_byte()
        })
    })
}

fn insert_gap(
    gaps: &mut BTreeMap<(DataCoverageGapReason, usize, usize), DataCoverageGap>,
    gap: DataCoverageGap,
) -> Result<(), DataExtractionError> {
    let key = (
        gap.reason,
        gap.provenance.start_byte(),
        gap.provenance.end_byte(),
    );
    if !gaps.contains_key(&key) && gaps.len() >= MAX_DATA_COVERAGE_GAPS {
        return Err(DataExtractionError::TooManyCoverageGaps {
            count: gaps.len().saturating_add(1),
            max: MAX_DATA_COVERAGE_GAPS,
        });
    }
    gaps.insert(key, gap);
    Ok(())
}

fn parse_tree(
    language: StructuralLanguage,
    source: &str,
) -> Result<tree_sitter::Tree, DataExtractionError> {
    let language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| DataExtractionError::ParseFailed(error.to_string()))?;
    parser.parse(source, None).ok_or_else(|| {
        DataExtractionError::ParseFailed(
            "data qualification parser returned no syntax tree".to_owned(),
        )
    })
}

fn collect_nodes<'tree>(
    root: tree_sitter::Node<'tree>,
) -> Result<Vec<tree_sitter::Node<'tree>>, DataExtractionError> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if nodes.len() >= MAX_DATA_AST_NODES {
            return Err(DataExtractionError::TooManyAstNodes {
                count: nodes.len().saturating_add(1),
                max: MAX_DATA_AST_NODES,
            });
        }
        nodes.push(node);
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    Ok(nodes)
}

fn node_for_range<'tree>(
    nodes: &[tree_sitter::Node<'tree>],
    start: usize,
    end: usize,
) -> Option<tree_sitter::Node<'tree>> {
    nodes
        .iter()
        .copied()
        .find(|node| node.start_byte() == start && node.end_byte() == end)
}

fn qualifies_broad_request_object(
    node: tree_sitter::Node<'_>,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
) -> bool {
    let node = unwrap_expression(node);
    let root = if node.kind() == "member_expression" {
        let Some(object) = node.child_by_field_name("object") else {
            return false;
        };
        let Some(property) = node.child_by_field_name("property") else {
            return false;
        };
        if object.kind() != "identifier" || node_text(property, source) != Some("body") {
            return false;
        }
        let Some(root) = node_text(object, source) else {
            return false;
        };
        root
    } else if node.kind() == "call_expression" {
        let Some(function) = node.child_by_field_name("function") else {
            return false;
        };
        if function.kind() != "member_expression" {
            return false;
        }
        let Some(object) = function.child_by_field_name("object") else {
            return false;
        };
        let Some(property) = function.child_by_field_name("property") else {
            return false;
        };
        if object.kind() != "identifier" || node_text(property, source) != Some("json") {
            return false;
        }
        let Some(root) = node_text(object, source) else {
            return false;
        };
        root
    } else {
        return false;
    };

    if !matches!(root, "req" | "request") {
        return false;
    }
    let Some(function) = innermost_function_for_range(nodes, node.start_byte(), node.end_byte())
    else {
        return false;
    };
    if !handler_parameter_is_visible(function, nodes, source, root, node.start_byte()) {
        return false;
    }
    !function_reassigns_request_source(function, nodes, source, root)
}

fn handler_parameter_is_visible(
    function: tree_sitter::Node<'_>,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    name: &str,
    use_offset: usize,
) -> bool {
    if function_parameter_names(function, source)
        .iter()
        .filter(|parameter| parameter.as_str() == name)
        .count()
        != 1
    {
        return false;
    }

    for node in nodes {
        if node.start_byte() < function.start_byte() || node.end_byte() > function.end_byte() {
            continue;
        }
        let Some(owner) = innermost_function_for_range(nodes, node.start_byte(), node.end_byte())
        else {
            continue;
        };
        if owner.id() != function.id() {
            continue;
        }

        let shadow_scope = match node.kind() {
            "variable_declarator" => {
                let Some(pattern) = node.child_by_field_name("name") else {
                    continue;
                };
                if !pattern_binding_names(pattern, source)
                    .iter()
                    .any(|binding| binding == name)
                {
                    continue;
                }
                nearest_statement_block(*node, function).unwrap_or(function)
            }
            "function_declaration" | "class_declaration" => {
                let Some(binding) = node
                    .child_by_field_name("name")
                    .and_then(|binding| node_text(binding, source))
                else {
                    continue;
                };
                if binding != name {
                    continue;
                }
                nearest_statement_block(*node, function).unwrap_or(function)
            }
            "catch_clause" => {
                let Some(parameter) = node.child_by_field_name("parameter") else {
                    continue;
                };
                if !pattern_binding_names(parameter, source)
                    .iter()
                    .any(|binding| binding == name)
                {
                    continue;
                }
                node.child_by_field_name("body").unwrap_or(*node)
            }
            _ => continue,
        };

        if shadow_scope.start_byte() <= use_offset && use_offset < shadow_scope.end_byte() {
            return false;
        }
    }
    true
}

fn function_reassigns_request_source(
    function: tree_sitter::Node<'_>,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    target: &str,
) -> bool {
    nodes.iter().copied().any(|node| {
        if node.start_byte() < function.start_byte() || node.end_byte() > function.end_byte() {
            return false;
        }
        let owner = innermost_function_for_range(nodes, node.start_byte(), node.end_byte());
        if !owner.is_some_and(|owner| owner.id() == function.id()) {
            return false;
        }
        match node.kind() {
            "assignment_expression" | "augmented_assignment_expression" => node
                .child_by_field_name("left")
                .is_some_and(|left| assignment_target_invalidates_request(left, source, target)),
            "update_expression" => node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))
                .is_some_and(|argument| node_text(argument, source) == Some(target)),
            "for_in_statement" => node
                .child_by_field_name("left")
                .is_some_and(|left| assignment_target_invalidates_request(left, source, target)),
            _ => false,
        }
    })
}

fn assignment_target_invalidates_request(
    node: tree_sitter::Node<'_>,
    source: &str,
    target: &str,
) -> bool {
    if node_text(node, source) == Some(target)
        || pattern_binding_names(node, source)
            .iter()
            .any(|binding| binding == target)
    {
        return true;
    }
    let node = unwrap_expression(node);
    if node.kind() != "member_expression" {
        return false;
    }
    let Some(object) = node.child_by_field_name("object") else {
        return false;
    };
    let Some(property) = node.child_by_field_name("property") else {
        return false;
    };
    object.kind() == "identifier"
        && node_text(object, source) == Some(target)
        && node_text(property, source) == Some("body")
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

fn nearest_statement_block<'tree>(
    node: tree_sitter::Node<'tree>,
    stop: tree_sitter::Node<'tree>,
) -> Option<tree_sitter::Node<'tree>> {
    let mut cursor = Some(node);
    while let Some(current) = cursor {
        if current.kind() == "statement_block" {
            return Some(current);
        }
        if current.id() == stop.id() {
            return None;
        }
        cursor = current.parent();
    }
    None
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

fn unwrap_expression(mut node: tree_sitter::Node<'_>) -> tree_sitter::Node<'_> {
    loop {
        if matches!(
            node.kind(),
            "await_expression"
                | "parenthesized_expression"
                | "as_expression"
                | "satisfies_expression"
                | "non_null_expression"
                | "type_assertion"
        ) && let Some(child) = node.named_child(0)
        {
            node = child;
            continue;
        }
        return node;
    }
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

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first == b'$' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric())
}

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}
