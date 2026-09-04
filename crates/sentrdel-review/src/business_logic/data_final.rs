//! Final qualification boundary for canonical R3-T013 data-operation extraction.
//!
//! The structural candidate remains conservative. This wrapper upgrades a dynamic mutation to
//! `BROAD_REQUEST_OBJECT` only when the exact mutation argument is `req.body`, `request.body`, or
//! a direct `req/request.json()` call rooted in one unique parameter of the same enclosing
//! function and that parameter is never reassigned in that function. Lexical names alone, outer
//! bindings, nested functions, and reassigned parameters never gain request-controlled authority.

use std::collections::BTreeSet;

use sentrdel_schema::coverage::CoverageState;

use super::data_candidate;
use super::model::{BusinessLogicLimits, DataOperation, FieldSet, FieldSetMode};
use super::route::RouteAdapter;
use crate::structural::StructuralLanguage;
use crate::view::NormalizedRepoPath;

pub use data_candidate::{
    DataCoverageGap, DataCoverageGapReason, DataExtractionError, MAX_DATA_AST_NODES,
    MAX_DATA_COVERAGE_GAPS, MAX_DATA_FIELDS_PER_OPERATION, MAX_DATA_FILTERS_PER_OPERATION,
    MAX_DATA_OPERATIONS, MAX_DATA_SUPPORTING_VALUES, SUPABASE_DATA_EXECUTES_QUERIES,
    SUPABASE_DATA_PROVES_DATABASE_RESULT, SUPABASE_DATA_PROVES_HOSTED_STATE,
    SUPABASE_DATA_PROVES_RUNTIME_REACHABILITY,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataExtraction {
    operations: Vec<DataOperation>,
    gaps: Vec<DataCoverageGap>,
    supporting_values: Vec<super::model::ValueOrigin>,
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
    pub fn supporting_values(&self) -> &[super::model::ValueOrigin] {
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
    for operation in candidate.operations() {
        let Some(fields) = operation.mutation_fields() else {
            continue;
        };
        if fields.mode() != FieldSetMode::Dynamic {
            continue;
        }
        let range = (
            fields.provenance().start_byte(),
            fields.provenance().end_byte(),
        );
        if node_for_range(&nodes, range.0, range.1)
            .is_some_and(|node| qualifies_broad_request_object(node, &nodes, source_text))
        {
            qualified_ranges.insert(range);
        }
    }

    let gaps = candidate
        .gaps()
        .iter()
        .filter(|gap| {
            let range = (gap.provenance().start_byte(), gap.provenance().end_byte());
            !(qualified_ranges.contains(&range)
                && matches!(
                    gap.reason(),
                    DataCoverageGapReason::DynamicMutationFields
                        | DataCoverageGapReason::UnqualifiedBroadRequestObject
                ))
        })
        .cloned()
        .collect::<Vec<_>>();

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
        if !qualified_ranges.contains(&range) {
            operations.push(operation.clone());
            continue;
        }

        let mutation_fields = FieldSet::new(
            FieldSetMode::BroadRequestObject,
            Vec::new(),
            Vec::new(),
            fields.provenance().clone(),
            limits,
        )?;
        let operation_range = operation
            .provenance()
            .first()
            .map(|location| (location.start_byte(), location.end_byte()));
        let has_remaining_gap = operation_range.is_some_and(|(start, end)| {
            gaps.iter().any(|gap| {
                start <= gap.provenance().start_byte() && gap.provenance().end_byte() <= end
            })
        });
        operations.push(DataOperation::new(
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
            if has_remaining_gap {
                operation.coverage_state().clone()
            } else {
                CoverageState::Covered
            },
            limits,
        )?);
    }

    operations.sort_by(|left, right| left.operation_id().cmp(right.operation_id()));
    Ok(DataExtraction {
        operations,
        gaps,
        supporting_values: candidate.supporting_values().to_vec(),
    })
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
    if function_parameter_count(function, source, root) != 1 {
        return false;
    }
    !function_reassigns_name(function, nodes, source, root)
}

fn unwrap_expression(mut node: tree_sitter::Node<'_>) -> tree_sitter::Node<'_> {
    loop {
        match node.kind() {
            "await_expression" | "parenthesized_expression" => {
                let Some(child) = node.named_child(0) else {
                    return node;
                };
                node = child;
            }
            _ => return node,
        }
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

fn function_parameter_count(function: tree_sitter::Node<'_>, source: &str, target: &str) -> usize {
    let Some(parameters) = function
        .child_by_field_name("parameters")
        .or_else(|| function.child_by_field_name("parameter"))
    else {
        return 0;
    };
    let mut count = 0;
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" && node_text(node, source) == Some(target) {
            count += 1;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    count
}

fn function_reassigns_name(
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
        if !owner.is_some_and(|owner| {
            owner.start_byte() == function.start_byte() && owner.end_byte() == function.end_byte()
        }) {
            return false;
        }
        match node.kind() {
            "assignment_expression" | "augmented_assignment_expression" => node
                .child_by_field_name("left")
                .is_some_and(|left| node_text(left, source) == Some(target)),
            "update_expression" => node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))
                .is_some_and(|argument| node_text(argument, source) == Some(target)),
            "for_in_statement" => node
                .child_by_field_name("left")
                .is_some_and(|left| node_text(left, source) == Some(target)),
            _ => false,
        }
    })
}

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}
