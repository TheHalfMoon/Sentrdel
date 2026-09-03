//! Conservative non-variable binding qualification for R3 typed guard extraction.
//!
//! The underlying scope qualifier proves supported alias bindings only from bounded static source.
//! This final layer rejects alias-backed observations only when the alias reference resolves to a
//! visible parameter, catch binding, import, function/class declaration, or destructuring binding
//! at that reference site. Unrelated bindings elsewhere in the file do not poison a valid local
//! alias. Ambiguity fails visible as unsupported coverage; it never strengthens authorization
//! evidence.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) use super::model;
use super::model::{BusinessLogicLimits, GuardObservation, SourceLocation};
pub(crate) use super::route;
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage};
use crate::view::NormalizedRepoPath;

#[path = "guard_scope.rs"]
mod scoped;

pub use scoped::{
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

#[derive(Default)]
struct PotentialAliases {
    session: BTreeSet<String>,
    supabase_result: BTreeSet<String>,
    verified_user: BTreeSet<String>,
    request_body: BTreeSet<String>,
}

impl PotentialAliases {
    fn contains(&self, name: &str) -> bool {
        self.session.contains(name)
            || self.supabase_result.contains(name)
            || self.verified_user.contains(name)
            || self.request_body.contains(name)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingKind {
    Variable,
    NonVariable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScopedBinding {
    name: String,
    kind: BindingKind,
    declaration_start: usize,
    function_start: usize,
    function_end: usize,
    lexical_start: usize,
    lexical_end: usize,
}

impl ScopedBinding {
    fn visible_at(&self, offset: usize) -> bool {
        self.declaration_start <= offset
            && self.function_start <= offset
            && offset < self.function_end
            && self.lexical_start <= offset
            && offset < self.lexical_end
    }

    fn resolution_key(&self) -> (usize, usize, Reverse<usize>, u8) {
        (
            self.function_end.saturating_sub(self.function_start),
            self.lexical_end.saturating_sub(self.lexical_start),
            Reverse(self.declaration_start),
            match self.kind {
                BindingKind::NonVariable => 0,
                BindingKind::Variable => 1,
            },
        )
    }
}

pub fn extract_guard_observations(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<GuardExtraction, GuardExtractionError> {
    let raw = scoped::extract_guard_observations(adapter, language, path, source, limits)?;
    let source = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let aliases = collect_potential_aliases(&nodes, source, adapter);
    let bindings = collect_scoped_bindings(&nodes, source, tree.root_node());

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
        if guard_mentions_shadowed_alias(guard, &nodes, source, &aliases, &bindings) {
            let Some(location) = guard.provenance().first() else {
                return Err(GuardExtractionError::ParseFailed(
                    "guard scope qualifier returned empty provenance".to_owned(),
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

fn collect_potential_aliases(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    adapter: RouteAdapter,
) -> PotentialAliases {
    let mut aliases = PotentialAliases::default();
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

            if adapter == RouteAdapter::NextApp && is_auth_call(value, source) {
                changed |= aliases.session.insert(name.to_owned());
            }
            if adapter == RouteAdapter::SupabaseEdge && is_supabase_get_user_call(value, source) {
                changed |= aliases.supabase_result.insert(name.to_owned());
            }
            if is_request_json_call(value, source, adapter)
                || expression_chain(value, source)
                    .as_deref()
                    .is_some_and(|chain| is_direct_request_body_chain(chain, adapter))
            {
                changed |= aliases.request_body.insert(name.to_owned());
            }

            if let Some(chain) = expression_chain(value, source) {
                if chain.len() == 1 && aliases.request_body.contains(&chain[0]) {
                    changed |= aliases.request_body.insert(name.to_owned());
                }
                if chain.len() == 2 && aliases.session.contains(&chain[0]) && chain[1] == "user" {
                    changed |= aliases.verified_user.insert(name.to_owned());
                }
                if chain.len() == 3
                    && aliases.supabase_result.contains(&chain[0])
                    && chain[1] == "data"
                    && chain[2] == "user"
                {
                    changed |= aliases.verified_user.insert(name.to_owned());
                }
            }
        }
        if !changed {
            break;
        }
    }
    aliases
}

fn collect_scoped_bindings(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    root: tree_sitter::Node<'_>,
) -> Vec<ScopedBinding> {
    let mut bindings = Vec::new();
    for node in nodes {
        match node.kind() {
            "variable_declarator" => {
                let Some(name) = node.child_by_field_name("name") else {
                    continue;
                };
                let scope = variable_binding_scope(*node, root);
                if name.kind() == "identifier" {
                    push_binding_identifiers(
                        name,
                        source,
                        BindingKind::Variable,
                        node.start_byte(),
                        scope,
                        &mut bindings,
                    );
                } else {
                    push_binding_identifiers(
                        name,
                        source,
                        BindingKind::NonVariable,
                        node.start_byte(),
                        scope,
                        &mut bindings,
                    );
                }
            }
            "function_declaration" | "generator_function_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let scope = enclosing_lexical_scope(*node, root);
                    push_binding_identifiers(
                        name,
                        source,
                        BindingKind::NonVariable,
                        scope.2,
                        scope,
                        &mut bindings,
                    );
                }
                push_function_parameters(*node, source, &mut bindings);
            }
            "function_expression" | "generator_function" | "arrow_function" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let scope = function_binding_scope(*node);
                    push_binding_identifiers(
                        name,
                        source,
                        BindingKind::NonVariable,
                        scope.2,
                        scope,
                        &mut bindings,
                    );
                }
                push_function_parameters(*node, source, &mut bindings);
            }
            "method_definition" => {
                push_function_parameters(*node, source, &mut bindings);
            }
            "class_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let scope = enclosing_lexical_scope(*node, root);
                    push_binding_identifiers(
                        name,
                        source,
                        BindingKind::NonVariable,
                        scope.2,
                        scope,
                        &mut bindings,
                    );
                }
            }
            "catch_clause" => {
                if let Some(parameter) = node.child_by_field_name("parameter") {
                    let function = enclosing_function(*node, root);
                    let scope = (
                        function.start_byte(),
                        function.end_byte(),
                        node.start_byte(),
                        node.end_byte(),
                    );
                    push_binding_identifiers(
                        parameter,
                        source,
                        BindingKind::NonVariable,
                        node.start_byte(),
                        scope,
                        &mut bindings,
                    );
                }
            }
            "import_clause" => {
                let scope = (
                    root.start_byte(),
                    root.end_byte(),
                    root.start_byte(),
                    root.end_byte(),
                );
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if child.kind() == "identifier" {
                        push_binding_identifiers(
                            child,
                            source,
                            BindingKind::NonVariable,
                            root.start_byte(),
                            scope,
                            &mut bindings,
                        );
                    }
                }
            }
            "namespace_import" => {
                let scope = (
                    root.start_byte(),
                    root.end_byte(),
                    root.start_byte(),
                    root.end_byte(),
                );
                push_binding_identifiers(
                    *node,
                    source,
                    BindingKind::NonVariable,
                    root.start_byte(),
                    scope,
                    &mut bindings,
                );
            }
            "import_specifier" => {
                if let Some(local) = node
                    .child_by_field_name("alias")
                    .or_else(|| node.child_by_field_name("name"))
                {
                    let scope = (
                        root.start_byte(),
                        root.end_byte(),
                        root.start_byte(),
                        root.end_byte(),
                    );
                    push_binding_identifiers(
                        local,
                        source,
                        BindingKind::NonVariable,
                        root.start_byte(),
                        scope,
                        &mut bindings,
                    );
                }
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
    let scope = function_binding_scope(function);
    if let Some(parameters) = function.child_by_field_name("parameters") {
        push_binding_identifiers(
            parameters,
            source,
            BindingKind::NonVariable,
            scope.2,
            scope,
            bindings,
        );
    }
    if let Some(parameter) = function.child_by_field_name("parameter") {
        push_binding_identifiers(
            parameter,
            source,
            BindingKind::NonVariable,
            scope.2,
            scope,
            bindings,
        );
    }
}

fn push_binding_identifiers(
    node: tree_sitter::Node<'_>,
    source: &str,
    kind: BindingKind,
    declaration_start: usize,
    scope: (usize, usize, usize, usize),
    bindings: &mut Vec<ScopedBinding>,
) {
    if matches!(
        node.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    ) {
        if let Some(name) = node_text(node, source) {
            bindings.push(ScopedBinding {
                name: name.to_owned(),
                kind,
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
        push_binding_identifiers(child, source, kind, declaration_start, scope, bindings);
    }
}

fn variable_binding_scope(
    node: tree_sitter::Node<'_>,
    root: tree_sitter::Node<'_>,
) -> (usize, usize, usize, usize) {
    let function = enclosing_function(node, root);
    let is_var = node
        .parent()
        .is_some_and(|parent| parent.kind() == "variable_declaration");
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

fn enclosing_lexical_scope(
    node: tree_sitter::Node<'_>,
    root: tree_sitter::Node<'_>,
) -> (usize, usize, usize, usize) {
    let function = enclosing_function(node, root);
    let lexical =
        nearest_statement_block(node.parent().unwrap_or(root), function).unwrap_or(function);
    (
        function.start_byte(),
        function.end_byte(),
        lexical.start_byte(),
        lexical.end_byte(),
    )
}

fn function_binding_scope(function: tree_sitter::Node<'_>) -> (usize, usize, usize, usize) {
    let lexical = function
        .child_by_field_name("body")
        .filter(|body| body.kind() == "statement_block")
        .unwrap_or(function);
    (
        function.start_byte(),
        function.end_byte(),
        lexical.start_byte(),
        lexical.end_byte(),
    )
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

fn guard_mentions_shadowed_alias(
    guard: &GuardObservation,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    aliases: &PotentialAliases,
    bindings: &[ScopedBinding],
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
            if aliases.contains(name) && resolves_to_non_variable(name, node.start_byte(), bindings)
            {
                return true;
            }
        }
    }
    false
}

fn resolves_to_non_variable(name: &str, offset: usize, bindings: &[ScopedBinding]) -> bool {
    bindings
        .iter()
        .filter(|binding| binding.name == name && binding.visible_at(offset))
        .min_by_key(|binding| binding.resolution_key())
        .is_some_and(|binding| binding.kind == BindingKind::NonVariable)
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
            "guard binding-scope parser returned no syntax tree".to_owned(),
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

fn is_request_json_call(node: tree_sitter::Node<'_>, source: &str, adapter: RouteAdapter) -> bool {
    matches!(adapter, RouteAdapter::NextApp | RouteAdapter::SupabaseEdge)
        && node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .and_then(|function| expression_chain(function, source))
            .is_some_and(|chain| chain.len() == 2 && chain[0] == "request" && chain[1] == "json")
}

fn is_direct_request_body_chain(chain: &[String], adapter: RouteAdapter) -> bool {
    let root = chain.first().map(String::as_str);
    let second = chain.get(1).map(String::as_str);
    match adapter {
        RouteAdapter::Express | RouteAdapter::NextPagesApi => {
            root == Some("req") && second == Some("body")
        }
        RouteAdapter::NextApp | RouteAdapter::SupabaseEdge => false,
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
