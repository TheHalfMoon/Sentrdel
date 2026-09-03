//! Lexical pre-declaration shadow qualification for bounded R3 typed guard extraction.
//!
//! Lower guard layers resolve ordinary alias scope, mutation, origin shadowing, and hoisted
//! function bindings. JavaScript variable bindings created by destructuring additionally shadow
//! same-name outer bindings across their effective lexical scope before the declaration executes
//! (including `let`/`const` temporal-dead-zone semantics and `var` hoisting). This final qualifier
//! prevents a pre-declaration reference from being interpreted as an outer authorization alias.
//! Ambiguous observations fail visible as unsupported coverage and never strengthen authority.

use std::collections::BTreeMap;

pub(crate) use super::model;
use super::model::{BusinessLogicLimits, GuardObservation, SourceLocation};
pub(crate) use super::route;
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage};
use crate::view::NormalizedRepoPath;

#[path = "guard_hoisted_scope.rs"]
mod qualified;

pub use qualified::{
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

#[derive(Clone, Debug)]
struct PreDeclarationPatternBinding {
    name: String,
    declaration_start: usize,
    function_start: usize,
    function_end: usize,
    lexical_start: usize,
    lexical_end: usize,
}

impl PreDeclarationPatternBinding {
    fn shadows_at(&self, offset: usize) -> bool {
        offset < self.declaration_start
            && self.function_start <= offset
            && offset < self.function_end
            && self.lexical_start <= offset
            && offset < self.lexical_end
    }
}

pub fn extract_guard_observations(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<GuardExtraction, GuardExtractionError> {
    let raw = qualified::extract_guard_observations(adapter, language, path, source, limits)?;
    let source = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let bindings = collect_predeclaration_pattern_bindings(&nodes, source, tree.root_node());

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
        if guard_mentions_predeclaration_shadow(guard, &nodes, source, &bindings) {
            let Some(location) = guard.provenance().first() else {
                return Err(GuardExtractionError::ParseFailed(
                    "guard TDZ qualifier returned empty provenance".to_owned(),
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

fn collect_predeclaration_pattern_bindings(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    root: tree_sitter::Node<'_>,
) -> Vec<PreDeclarationPatternBinding> {
    let mut bindings = Vec::new();
    for node in nodes {
        if node.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = node.child_by_field_name("name") else {
            continue;
        };
        if name.kind() == "identifier" {
            continue;
        }
        let scope = variable_binding_scope(*node, root);
        push_pattern_binding_identifiers(
            name,
            source,
            node.start_byte(),
            scope,
            &mut bindings,
        );
    }
    bindings
}

fn push_pattern_binding_identifiers(
    node: tree_sitter::Node<'_>,
    source: &str,
    declaration_start: usize,
    scope: (usize, usize, usize, usize),
    bindings: &mut Vec<PreDeclarationPatternBinding>,
) {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    ) {
        if let Some(name) = node_text(node, source) {
            bindings.push(PreDeclarationPatternBinding {
                name: name.to_owned(),
                declaration_start,
                function_start: scope.0,
                function_end: scope.1,
                lexical_start: scope.2,
                lexical_end: scope.3,
            });
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        push_pattern_binding_identifiers(child, source, declaration_start, scope, bindings);
    }
}

fn variable_binding_scope(
    node: tree_sitter::Node<'_>,
    root: tree_sitter::Node<'_>,
) -> (usize, usize, usize, usize) {
    let function = enclosing_function(node, root);
    let is_var = node.parent().is_some_and(|parent| {
        parent.kind() == "variable_declaration"
            && parent.child(0).is_some_and(|child| child.kind() == "var")
    });
    if is_var {
        return (
            function.start_byte(),
            function.end_byte(),
            function.start_byte(),
            function.end_byte(),
        );
    }
    let lexical = nearest_statement_block(node, function).unwrap_or(function);
    (
        function.start_byte(),
        function.end_byte(),
        lexical.start_byte(),
        lexical.end_byte(),
    )
}

fn guard_mentions_predeclaration_shadow(
    guard: &GuardObservation,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    bindings: &[PreDeclarationPatternBinding],
) -> bool {
    for location in guard.provenance() {
        let start = location.start_byte();
        let end = location.end_byte();
        for node in nodes {
            if node.kind() != "identifier" || node.start_byte() < start || node.end_byte() > end {
                continue;
            }
            let Some(name) = node_text(*node, source) else {
                continue;
            };
            if bindings
                .iter()
                .any(|binding| binding.name == name && binding.shadows_at(node.start_byte()))
            {
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
        GuardExtractionError::ParseFailed("guard TDZ parser returned no syntax tree".to_owned())
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
