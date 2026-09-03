//! Hoisted-function shadow qualification for bounded R3 typed guard extraction.
//!
//! Lower layers resolve parameters, imports, variables, mutations, destructuring, and adapter
//! origins at their use sites. JavaScript function declarations are additionally hoisted across
//! their enclosing lexical block. This final qualifier accounts for that one binding form without
//! widening supported guard authority. Ambiguous or shadowed observations fail visible.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) use super::model;
use super::model::{BusinessLogicLimits, GuardObservation, SourceLocation};
pub(crate) use super::route;
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage};
use crate::view::NormalizedRepoPath;

#[path = "guard_origin_scope.rs"]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingKind {
    Variable,
    HoistedFunction,
}

#[derive(Clone, Debug)]
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
        let declaration_visible = self.kind == BindingKind::HoistedFunction
            || self.declaration_start <= offset;
        declaration_visible
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
                BindingKind::HoistedFunction => 0,
                BindingKind::Variable => 1,
            },
        )
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
    let bindings = collect_bindings(&nodes, source, tree.root_node());
    let aliases = collect_potential_aliases(&nodes, source, adapter);
    let unsafe_origin_aliases =
        collect_hoisted_origin_aliases(&nodes, source, adapter, &bindings);

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
        if guard_uses_hoisted_shadow(guard, &nodes, source, &aliases, &bindings)
            || guard_mentions_alias(guard, &nodes, source, &unsafe_origin_aliases)
        {
            let Some(location) = guard.provenance().first() else {
                return Err(GuardExtractionError::ParseFailed(
                    "hoisted guard qualifier returned empty provenance".to_owned(),
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

fn collect_bindings(
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
                if name.kind() != "identifier" {
                    continue;
                }
                let Some(name) = node_text(name, source) else {
                    continue;
                };
                let function = enclosing_function(*node, root);
                let lexical = nearest_statement_block(*node, function).unwrap_or(function);
                bindings.push(ScopedBinding {
                    name: name.to_owned(),
                    kind: BindingKind::Variable,
                    declaration_start: node.start_byte(),
                    function_start: function.start_byte(),
                    function_end: function.end_byte(),
                    lexical_start: lexical.start_byte(),
                    lexical_end: lexical.end_byte(),
                });
            }
            "function_declaration" | "generator_function_declaration" => {
                let Some(name) = node.child_by_field_name("name") else {
                    continue;
                };
                let Some(name) = node_text(name, source) else {
                    continue;
                };
                let parent = node.parent().unwrap_or(root);
                let function = enclosing_function(parent, root);
                let lexical = nearest_statement_block(parent, function).unwrap_or(function);
                bindings.push(ScopedBinding {
                    name: name.to_owned(),
                    kind: BindingKind::HoistedFunction,
                    declaration_start: lexical.start_byte(),
                    function_start: function.start_byte(),
                    function_end: function.end_byte(),
                    lexical_start: lexical.start_byte(),
                    lexical_end: lexical.end_byte(),
                });
            }
            _ => {}
        }
    }
    bindings
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

fn collect_hoisted_origin_aliases(
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
                && resolves_to_hoisted_function("auth", value.start_byte(), bindings)
            {
                changed |= unsafe_aliases.insert(name.to_owned());
            }
            if adapter == RouteAdapter::SupabaseEdge
                && is_supabase_get_user_call(value, source)
                && resolves_to_hoisted_function("supabase", value.start_byte(), bindings)
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

fn guard_uses_hoisted_shadow(
    guard: &GuardObservation,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    aliases: &PotentialAliases,
    bindings: &[ScopedBinding],
) -> bool {
    for location in guard.provenance() {
        for node in nodes {
            if node.kind() != "identifier"
                || node.start_byte() < location.start_byte()
                || node.end_byte() > location.end_byte()
            {
                continue;
            }
            let Some(name) = node_text(*node, source) else {
                continue;
            };
            if aliases.contains(name)
                && resolves_to_hoisted_function(name, node.start_byte(), bindings)
            {
                return true;
            }
        }
    }
    false
}

fn resolves_to_hoisted_function(name: &str, offset: usize, bindings: &[ScopedBinding]) -> bool {
    bindings
        .iter()
        .filter(|binding| binding.name == name && binding.visible_at(offset))
        .min_by_key(|binding| binding.resolution_key())
        .is_some_and(|binding| binding.kind == BindingKind::HoistedFunction)
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
        for node in nodes {
            if node.kind() != "identifier"
                || node.start_byte() < location.start_byte()
                || node.end_byte() > location.end_byte()
            {
                continue;
            }
            if node_text(*node, source).is_some_and(|name| aliases.contains(name)) {
                return true;
            }
        }
    }
    false
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
            "hoisted guard qualifier parser returned no syntax tree".to_owned(),
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
    matches!(adapter, RouteAdapter::Express | RouteAdapter::NextPagesApi)
        && root == Some("req")
        && second == Some("body")
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
