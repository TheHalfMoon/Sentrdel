//! Conservative alias-origin qualification for R3 typed guard extraction.
//!
//! The lower guard layers qualify derived alias bindings and mutations. This final layer rejects
//! observations only when the supported alias origin (`auth` or `supabase`) resolves to a local
//! lexical binding at the origin call site. Unrelated sibling or nested bindings do not poison a
//! valid fixed adapter seam. Ambiguity fails visible as unsupported coverage and never strengthens
//! authorization evidence.

use std::collections::{BTreeMap, BTreeSet};

pub(crate) use super::model;
use super::model::{BusinessLogicLimits, GuardObservation, SourceLocation};
pub(crate) use super::route;
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage};
use crate::view::NormalizedRepoPath;

#[path = "guard_mutation_scope.rs"]
mod origin_base;

pub use origin_base::{
    GuardCoverageGapReason, GuardExtractionError, MAX_GUARD_AST_NODES, MAX_GUARD_COVERAGE_GAPS,
    MAX_GUARD_FACT_ITERATIONS, MAX_GUARD_OBSERVATIONS,
    STATIC_GUARD_RECOGNITION_PROVES_RUNTIME_AUTHORIZATION,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopedBinding {
    name: String,
    scope_start: usize,
    scope_end: usize,
}

impl ScopedBinding {
    fn visible_at(&self, offset: usize) -> bool {
        self.scope_start <= offset && offset < self.scope_end
    }
}

pub fn extract_guard_observations(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<GuardExtraction, GuardExtractionError> {
    let raw = origin_base::extract_guard_observations(adapter, language, path, source, limits)?;
    let source = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let bindings = collect_local_bindings(&nodes, source, tree.root_node());
    let unsafe_aliases = collect_unsafe_origin_aliases(&nodes, source, adapter, &bindings);

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

    let mut guards = Vec::with_capacity(raw.guards().len());
    for guard in raw.guards() {
        if guard_mentions_alias(guard, &nodes, source, &unsafe_aliases) {
            let Some(location) = guard.provenance().first() else {
                return Err(GuardExtractionError::ParseFailed(
                    "guard origin qualifier returned empty provenance".to_owned(),
                ));
            };
            insert_gap(
                &mut gaps,
                GuardCoverageGap {
                    reason: GuardCoverageGapReason::UnsupportedGuardShape,
                    provenance: location.clone(),
                },
            )?;
        } else {
            guards.push(guard.clone());
        }
    }

    Ok(GuardExtraction {
        guards,
        gaps: gaps.into_values().collect(),
    })
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

fn collect_unsafe_origin_aliases(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    adapter: RouteAdapter,
    bindings: &[ScopedBinding],
) -> BTreeSet<String> {
    let mut unsafe_aliases = BTreeSet::new();
    for _ in 0..MAX_GUARD_FACT_ITERATIONS {
        let mut changed = false;
        for node in nodes {
            if node.kind() != "variable_declarator" {
                continue;
            }
            let Some(name_node) = node.child_by_field_name("name") else {
                continue;
            };
            if name_node.kind() != "identifier" {
                continue;
            }
            let Some(name) = node_text(name_node, source) else {
                continue;
            };
            let Some(value) = node.child_by_field_name("value") else {
                continue;
            };
            let value = unwrap_expression(value);

            if adapter == RouteAdapter::NextApp
                && is_auth_call(value, source)
                && origin_shadowed_at("auth", value.start_byte(), bindings)
            {
                changed |= unsafe_aliases.insert(name.to_owned());
            }
            if adapter == RouteAdapter::SupabaseEdge
                && is_supabase_get_user_call(value, source)
                && origin_shadowed_at("supabase", value.start_byte(), bindings)
            {
                changed |= unsafe_aliases.insert(name.to_owned());
            }

            if let Some(chain) = expression_chain(value, source) {
                if chain.len() == 2 && unsafe_aliases.contains(&chain[0]) && chain[1] == "user" {
                    changed |= unsafe_aliases.insert(name.to_owned());
                }
                if chain.len() == 3
                    && unsafe_aliases.contains(&chain[0])
                    && chain[1] == "data"
                    && chain[2] == "user"
                {
                    changed |= unsafe_aliases.insert(name.to_owned());
                }
            }
        }
        if !changed {
            break;
        }
    }
    unsafe_aliases
}

fn origin_shadowed_at(name: &str, offset: usize, bindings: &[ScopedBinding]) -> bool {
    bindings
        .iter()
        .any(|binding| binding.name == name && binding.visible_at(offset))
}

fn collect_local_bindings(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    root: tree_sitter::Node<'_>,
) -> Vec<ScopedBinding> {
    let mut bindings = Vec::new();
    for node in nodes {
        match node.kind() {
            "variable_declarator" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let scope = variable_binding_scope(*node, root);
                    push_binding_identifiers(name, source, scope, &mut bindings);
                }
            }
            "function_declaration" | "generator_function_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let scope = enclosing_lexical_scope(*node, root);
                    push_binding_identifiers(name, source, scope, &mut bindings);
                }
                push_function_parameters(*node, source, &mut bindings);
            }
            "function_expression" | "generator_function" | "arrow_function" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let scope = (node.start_byte(), node.end_byte());
                    push_binding_identifiers(name, source, scope, &mut bindings);
                }
                push_function_parameters(*node, source, &mut bindings);
            }
            "method_definition" => {
                push_function_parameters(*node, source, &mut bindings);
            }
            "class_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let scope = enclosing_lexical_scope(*node, root);
                    push_binding_identifiers(name, source, scope, &mut bindings);
                }
            }
            "catch_clause" => {
                if let Some(parameter) = node.child_by_field_name("parameter") {
                    push_binding_identifiers(
                        parameter,
                        source,
                        (node.start_byte(), node.end_byte()),
                        &mut bindings,
                    );
                }
            }
            "import_clause" | "namespace_import" | "named_imports" | "import_specifier" => {
                push_binding_identifiers(
                    *node,
                    source,
                    (root.start_byte(), root.end_byte()),
                    &mut bindings,
                );
            }
            _ => {}
        }
    }
    bindings
}

fn push_function_parameters(
    function: tree_sitter::Node<'_>,
    source: &str,
    bindings: &mut Vec<ScopedBinding>,
) {
    let scope = (function.start_byte(), function.end_byte());
    if let Some(parameters) = function.child_by_field_name("parameters") {
        push_binding_identifiers(parameters, source, scope, bindings);
    }
    if let Some(parameter) = function.child_by_field_name("parameter") {
        push_binding_identifiers(parameter, source, scope, bindings);
    }
}

fn push_binding_identifiers(
    node: tree_sitter::Node<'_>,
    source: &str,
    scope: (usize, usize),
    bindings: &mut Vec<ScopedBinding>,
) {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    ) {
        if let Some(name) = node_text(node, source) {
            bindings.push(ScopedBinding {
                name: name.to_owned(),
                scope_start: scope.0,
                scope_end: scope.1,
            });
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        push_binding_identifiers(child, source, scope, bindings);
    }
}

fn variable_binding_scope(
    node: tree_sitter::Node<'_>,
    root: tree_sitter::Node<'_>,
) -> (usize, usize) {
    let is_var = node.parent().is_some_and(|parent| {
        parent.kind() == "variable_declaration"
            && (0..parent.child_count())
                .filter_map(|index| parent.child(index))
                .any(|child| child.kind() == "var")
    });
    if is_var {
        let function = enclosing_function(node, root);
        return (function.start_byte(), function.end_byte());
    }
    let function = enclosing_function(node, root);
    nearest_statement_block(node, function)
        .map(|block| (block.start_byte(), block.end_byte()))
        .unwrap_or((function.start_byte(), function.end_byte()))
}

fn enclosing_lexical_scope(
    node: tree_sitter::Node<'_>,
    root: tree_sitter::Node<'_>,
) -> (usize, usize) {
    let function = enclosing_function(node, root);
    nearest_statement_block(node.parent().unwrap_or(root), function)
        .map(|block| (block.start_byte(), block.end_byte()))
        .unwrap_or((function.start_byte(), function.end_byte()))
}

fn enclosing_function<'tree>(
    node: tree_sitter::Node<'tree>,
    root: tree_sitter::Node<'tree>,
) -> tree_sitter::Node<'tree> {
    let mut cursor = Some(node);
    while let Some(current) = cursor {
        if is_function_boundary(current) {
            return current;
        }
        cursor = current.parent();
    }
    root
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

fn guard_mentions_alias(
    guard: &GuardObservation,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    aliases: &BTreeSet<String>,
) -> bool {
    if aliases.is_empty() {
        return false;
    }
    for location in guard.provenance() {
        let start = location.start_byte();
        let end = location.end_byte();
        for node in nodes {
            if node.kind() != "identifier" || node.start_byte() < start || node.end_byte() > end {
                continue;
            }
            if node_text(*node, source).is_some_and(|name| aliases.contains(name)) {
                return true;
            }
        }
    }
    false
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
        GuardExtractionError::ParseFailed(
            "guard origin-scope parser returned no syntax tree".to_owned(),
        )
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

fn expression_chain(node: tree_sitter::Node<'_>, source: &str) -> Option<Vec<String>> {
    let node = unwrap_expression(node);
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

fn is_auth_call(node: tree_sitter::Node<'_>, source: &str) -> bool {
    node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .and_then(|function| expression_chain(function, source))
            .is_some_and(|chain| chain.len() == 1 && chain[0] == "auth")
}

fn is_supabase_get_user_call(node: tree_sitter::Node<'_>, source: &str) -> bool {
    node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .and_then(|function| expression_chain(function, source))
            .is_some_and(|chain| {
                chain.len() == 3
                    && chain[0] == "supabase"
                    && chain[1] == "auth"
                    && chain[2] == "getUser"
            })
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
