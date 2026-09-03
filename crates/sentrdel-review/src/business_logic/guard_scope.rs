//! Scope qualification for bounded R3 typed guard extraction.
//!
//! The underlying recognizer identifies supported static guard shapes. This layer prevents
//! file-wide name facts from granting a typed guard when the supporting alias is shadowed,
//! reassigned, or outside the alias's lexical/function scope. Ambiguous alias-backed guards
//! fail visible as unsupported coverage instead of becoming false authorization evidence.

use std::collections::{BTreeMap, BTreeSet};

pub(crate) use super::model;
pub(crate) use super::route;
use super::model::{BusinessLogicLimits, GuardObservation, SourceLocation};
use super::route::RouteAdapter;
use crate::structural::StructuralLanguage;
use crate::view::NormalizedRepoPath;

#[path = "guard.rs"]
mod recognizer;

pub use recognizer::{
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
struct BindingScope {
    declaration_start: usize,
    function_start: usize,
    function_end: usize,
    lexical_start: usize,
    lexical_end: usize,
}

impl BindingScope {
    fn visible_at(self, offset: usize) -> bool {
        self.declaration_start <= offset
            && self.function_start <= offset
            && offset < self.function_end
            && self.lexical_start <= offset
            && offset < self.lexical_end
    }
}

#[derive(Default)]
struct AliasSets {
    session: BTreeSet<String>,
    supabase_result: BTreeSet<String>,
    verified_user: BTreeSet<String>,
    request_body: BTreeSet<String>,
}

impl AliasSets {
    fn contains(&self, name: &str) -> bool {
        self.session.contains(name)
            || self.supabase_result.contains(name)
            || self.verified_user.contains(name)
            || self.request_body.contains(name)
    }
}

#[derive(Default)]
struct QualifiedAliases {
    potential: AliasSets,
    safe: BTreeMap<String, BindingScope>,
}

pub fn extract_guard_observations(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<GuardExtraction, GuardExtractionError> {
    let raw = recognizer::extract_guard_observations(adapter, language, path, source, limits)?;
    let source = std::str::from_utf8(source)
        .map_err(|_| crate::structural::StructuralError::NonUtf8Source)?;
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let aliases = qualify_aliases(&nodes, source, adapter, tree.root_node());

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
        if guard_depends_on_unsafe_alias(guard, &nodes, source, &aliases) {
            let Some(location) = guard.provenance().first() else {
                return Err(GuardExtractionError::ParseFailed(
                    "guard recognizer returned empty provenance".to_owned(),
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

fn qualify_aliases(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    adapter: RouteAdapter,
    root: tree_sitter::Node<'_>,
) -> QualifiedAliases {
    let declarations = declaration_scopes(nodes, source, root);
    let reassigned = reassigned_bindings(nodes, source);
    let mut potential = AliasSets::default();
    let mut safe_session = BTreeMap::new();
    let mut safe_supabase = BTreeMap::new();
    let mut safe_user = BTreeMap::new();
    let mut safe_body = BTreeMap::new();

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
            let scope = unique_stable_scope(name, &declarations, &reassigned);

            if adapter == RouteAdapter::NextApp && is_auth_call(value, source) {
                changed |= potential.session.insert(name.to_owned());
                if let Some(scope) = scope {
                    changed |= insert_safe(&mut safe_session, name, scope);
                }
            }
            if adapter == RouteAdapter::SupabaseEdge && is_supabase_get_user_call(value, source) {
                changed |= potential.supabase_result.insert(name.to_owned());
                if let Some(scope) = scope {
                    changed |= insert_safe(&mut safe_supabase, name, scope);
                }
            }

            if is_request_json_call(value, source, adapter)
                || expression_chain(value, source)
                    .as_deref()
                    .is_some_and(|chain| is_direct_request_body_chain(chain, adapter))
            {
                changed |= potential.request_body.insert(name.to_owned());
                if let Some(scope) = scope {
                    changed |= insert_safe(&mut safe_body, name, scope);
                }
            }

            if let Some(chain) = expression_chain(value, source) {
                if chain.len() == 1 && potential.request_body.contains(&chain[0]) {
                    changed |= potential.request_body.insert(name.to_owned());
                    if let Some(scope) = scope
                        && safe_visible(&safe_body, &chain[0], value.start_byte())
                    {
                        changed |= insert_safe(&mut safe_body, name, scope);
                    }
                }
                if chain.len() == 2
                    && potential.session.contains(&chain[0])
                    && chain[1] == "user"
                {
                    changed |= potential.verified_user.insert(name.to_owned());
                    if let Some(scope) = scope
                        && safe_visible(&safe_session, &chain[0], value.start_byte())
                    {
                        changed |= insert_safe(&mut safe_user, name, scope);
                    }
                }
                if chain.len() == 3
                    && potential.supabase_result.contains(&chain[0])
                    && chain[1] == "data"
                    && chain[2] == "user"
                {
                    changed |= potential.verified_user.insert(name.to_owned());
                    if let Some(scope) = scope
                        && safe_visible(&safe_supabase, &chain[0], value.start_byte())
                    {
                        changed |= insert_safe(&mut safe_user, name, scope);
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut safe = BTreeMap::new();
    for source_map in [&safe_session, &safe_supabase, &safe_user, &safe_body] {
        for (name, scope) in source_map {
            safe.entry(name.clone()).or_insert(*scope);
        }
    }
    QualifiedAliases { potential, safe }
}

fn insert_safe(map: &mut BTreeMap<String, BindingScope>, name: &str, scope: BindingScope) -> bool {
    if map.contains_key(name) {
        false
    } else {
        map.insert(name.to_owned(), scope);
        true
    }
}

fn safe_visible(map: &BTreeMap<String, BindingScope>, name: &str, offset: usize) -> bool {
    map.get(name).is_some_and(|scope| scope.visible_at(offset))
}

fn declaration_scopes(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    root: tree_sitter::Node<'_>,
) -> BTreeMap<String, Vec<BindingScope>> {
    let mut declarations: BTreeMap<String, Vec<BindingScope>> = BTreeMap::new();
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
        declarations
            .entry(name.to_owned())
            .or_default()
            .push(binding_scope(*node, root));
    }
    declarations
}

fn unique_stable_scope(
    name: &str,
    declarations: &BTreeMap<String, Vec<BindingScope>>,
    reassigned: &BTreeSet<String>,
) -> Option<BindingScope> {
    let scopes = declarations.get(name)?;
    if scopes.len() != 1 || reassigned.contains(name) {
        return None;
    }
    scopes.first().copied()
}

fn binding_scope(node: tree_sitter::Node<'_>, root: tree_sitter::Node<'_>) -> BindingScope {
    let mut lexical = root;
    let mut function = root;
    let mut cursor = node.parent();
    let mut found_lexical = false;
    while let Some(parent) = cursor {
        if !found_lexical && parent.kind() == "statement_block" {
            lexical = parent;
            found_lexical = true;
        }
        if is_function_boundary(parent) {
            function = parent;
            break;
        }
        cursor = parent.parent();
    }
    BindingScope {
        declaration_start: node.start_byte(),
        function_start: function.start_byte(),
        function_end: function.end_byte(),
        lexical_start: lexical.start_byte(),
        lexical_end: lexical.end_byte(),
    }
}

fn reassigned_bindings(nodes: &[tree_sitter::Node<'_>], source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for node in nodes {
        let target = match node.kind() {
            "assignment_expression" | "augmented_assignment_expression" => {
                node.child_by_field_name("left")
            }
            "update_expression" => node.named_child(0),
            _ => None,
        };
        let Some(target) = target.map(unwrap_expression) else {
            continue;
        };
        if target.kind() == "identifier"
            && let Some(name) = node_text(target, source)
        {
            names.insert(name.to_owned());
        }
    }
    names
}

fn guard_depends_on_unsafe_alias(
    guard: &GuardObservation,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    aliases: &QualifiedAliases,
) -> bool {
    for location in guard.provenance() {
        let start = location.start_byte();
        let end = location.end_byte();
        for node in nodes {
            if node.start_byte() < start || node.end_byte() > end || node.kind() != "identifier" {
                continue;
            }
            let Some(name) = node_text(*node, source) else {
                continue;
            };
            if aliases.potential.contains(name)
                && !aliases
                    .safe
                    .get(name)
                    .is_some_and(|scope| scope.visible_at(node.start_byte()))
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
        GuardExtractionError::ParseFailed("guard scope parser returned no syntax tree".to_owned())
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
