//! Bounded R3 typed guard extraction for supported JavaScript/TypeScript control-flow shapes.
//!
//! Repository source is untrusted data. Guard recognition records static source structure only;
//! it does not prove runtime authorization, target reachability, provider state, or exploitability.
//! This module executes no target code, performs no provider/network access, and creates no
//! Findings.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::content_id;

use super::model::{
    BusinessLogicLimits, ComparisonShape, DominanceScope, GuardKind, GuardObservation, ModelError,
    SourceLocation, StableSemanticId,
};
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage, StructuralRegistry};
use crate::view::NormalizedRepoPath;

pub const MAX_GUARD_OBSERVATIONS: usize = 4_096;
pub const MAX_GUARD_COVERAGE_GAPS: usize = 4_096;
pub const MAX_GUARD_AST_NODES: usize = 100_000;
pub const MAX_GUARD_FACT_ITERATIONS: usize = 5;
pub const STATIC_GUARD_RECOGNITION_PROVES_RUNTIME_AUTHORIZATION: bool = false;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GuardCoverageGapReason {
    DynamicGuard,
    UnsupportedGuardShape,
}

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

#[derive(Debug)]
pub enum GuardExtractionError {
    Structural(StructuralError),
    Model(ModelError),
    ParseFailed(String),
    TooManyAstNodes { count: usize, max: usize },
    TooManyGuards { count: usize, max: usize },
    TooManyCoverageGaps { count: usize, max: usize },
}

impl fmt::Display for GuardExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structural(source) => {
                write!(formatter, "guard structural validation failed: {source}")
            }
            Self::Model(source) => write!(formatter, "guard model validation failed: {source}"),
            Self::ParseFailed(error) => write!(formatter, "guard parser failed: {error}"),
            Self::TooManyAstNodes { count, max } => {
                write!(formatter, "guard AST node count {count} exceeds cap {max}")
            }
            Self::TooManyGuards { count, max } => {
                write!(
                    formatter,
                    "guard observation count {count} exceeds cap {max}"
                )
            }
            Self::TooManyCoverageGaps { count, max } => {
                write!(
                    formatter,
                    "guard coverage gap count {count} exceeds cap {max}"
                )
            }
        }
    }
}

impl Error for GuardExtractionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Structural(source) => Some(source),
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<StructuralError> for GuardExtractionError {
    fn from(value: StructuralError) -> Self {
        Self::Structural(value)
    }
}

impl From<ModelError> for GuardExtractionError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

#[derive(Default)]
struct GuardFacts {
    session_bindings: BTreeSet<String>,
    supabase_user_result_bindings: BTreeSet<String>,
    verified_user_bindings: BTreeSet<String>,
    request_body_bindings: BTreeSet<String>,
    dynamic_callable_bindings: BTreeSet<String>,
    dynamic_guard_results: BTreeSet<String>,
}

pub fn extract_guard_observations(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<GuardExtraction, GuardExtractionError> {
    let limits = limits.validate()?;
    let validator = StructuralRegistry::new(&[])?;
    validator.scan_language(language, path, source)?;
    let source = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;
    let digest =
        content_id("r3-guard-source", &(path.as_str(), source)).map_err(ModelError::from)?;
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let (facts, facts_converged) = collect_guard_facts(&nodes, source, adapter);
    let mut builder = GuardBuilder::new(path, digest, limits);
    if !facts_converged {
        let root = tree.root_node();
        builder.gap(
            GuardCoverageGapReason::UnsupportedGuardShape,
            root.start_byte(),
            root.end_byte(),
        )?;
    }

    for node in &nodes {
        match node.kind() {
            "if_statement" => observe_if_guard(*node, source, adapter, &facts, &mut builder)?,
            "variable_declarator" => {
                observe_property_allowlist(*node, source, adapter, &facts, &mut builder)?
            }
            _ => {}
        }
    }

    Ok(builder.finish())
}

struct GuardBuilder<'a> {
    path: &'a NormalizedRepoPath,
    digest: String,
    limits: BusinessLogicLimits,
    guards: BTreeMap<String, GuardObservation>,
    gaps: BTreeMap<(GuardCoverageGapReason, usize, usize), GuardCoverageGap>,
}

impl<'a> GuardBuilder<'a> {
    fn new(path: &'a NormalizedRepoPath, digest: String, limits: BusinessLogicLimits) -> Self {
        Self {
            path,
            digest,
            limits,
            guards: BTreeMap::new(),
            gaps: BTreeMap::new(),
        }
    }

    fn location(&self, start: usize, end: usize) -> Result<SourceLocation, GuardExtractionError> {
        Ok(SourceLocation::new(
            self.path.clone(),
            start,
            end,
            self.digest.clone(),
        )?)
    }

    fn guard(
        &mut self,
        guard_kind: GuardKind,
        required_values: Vec<String>,
        comparison_shape: ComparisonShape,
        dominance_scope: DominanceScope,
        start: usize,
        end: usize,
    ) -> Result<(), GuardExtractionError> {
        let start_text = start.to_string();
        let end_text = end.to_string();
        let values_key =
            content_id("r3.guard-required-values", &required_values).map_err(ModelError::from)?;
        let guard_id = StableSemanticId::from_parts(
            "r3.guard-observation",
            &[
                self.path.as_str(),
                guard_kind_key(guard_kind),
                comparison_shape_key(comparison_shape),
                dominance_scope_key(dominance_scope),
                &values_key,
                &start_text,
                &end_text,
            ],
            self.limits,
        )?;
        let key = guard_id.as_str().to_owned();
        if !self.guards.contains_key(&key) && self.guards.len() >= MAX_GUARD_OBSERVATIONS {
            return Err(GuardExtractionError::TooManyGuards {
                count: self.guards.len().saturating_add(1),
                max: MAX_GUARD_OBSERVATIONS,
            });
        }
        let guard = GuardObservation::new(
            guard_id,
            guard_kind,
            None,
            None,
            required_values,
            comparison_shape,
            dominance_scope,
            vec![self.location(start, end)?],
            self.limits,
        )?;
        self.guards.insert(key, guard);
        Ok(())
    }

    fn gap(
        &mut self,
        reason: GuardCoverageGapReason,
        start: usize,
        end: usize,
    ) -> Result<(), GuardExtractionError> {
        let key = (reason, start, end);
        if !self.gaps.contains_key(&key) && self.gaps.len() >= MAX_GUARD_COVERAGE_GAPS {
            return Err(GuardExtractionError::TooManyCoverageGaps {
                count: self.gaps.len().saturating_add(1),
                max: MAX_GUARD_COVERAGE_GAPS,
            });
        }
        self.gaps.insert(
            key,
            GuardCoverageGap {
                reason,
                provenance: self.location(start, end)?,
            },
        );
        Ok(())
    }

    fn finish(self) -> GuardExtraction {
        GuardExtraction {
            guards: self.guards.into_values().collect(),
            gaps: self.gaps.into_values().collect(),
        }
    }
}

fn collect_guard_facts(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    adapter: RouteAdapter,
) -> (GuardFacts, bool) {
    let mut facts = GuardFacts::default();
    for _ in 0..MAX_GUARD_FACT_ITERATIONS {
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
            let value = unwrap_expression(value);

            if adapter == RouteAdapter::NextApp && is_auth_call(value, source) {
                changed |= facts.session_bindings.insert(binding.to_owned());
            }
            if adapter == RouteAdapter::SupabaseEdge && is_supabase_get_user_call(value, source) {
                changed |= facts
                    .supabase_user_result_bindings
                    .insert(binding.to_owned());
            }
            if is_request_json_call(value, source, adapter)
                || expression_chain(value, source)
                    .as_deref()
                    .is_some_and(|chain| is_direct_request_body_chain(chain, adapter))
            {
                changed |= facts.request_body_bindings.insert(binding.to_owned());
            }
            if let Some(chain) = expression_chain(value, source) {
                if chain.len() == 2
                    && facts.session_bindings.contains(&chain[0])
                    && chain[1] == "user"
                {
                    changed |= facts.verified_user_bindings.insert(binding.to_owned());
                }
                if chain.len() == 3
                    && facts.supabase_user_result_bindings.contains(&chain[0])
                    && chain[1] == "data"
                    && chain[2] == "user"
                {
                    changed |= facts.verified_user_bindings.insert(binding.to_owned());
                }
            }

            if value.kind() == "call_expression"
                && call_has_request_controlled_argument(value, source, adapter, &facts)
                && !is_known_static_auth_or_body_call(value, source, adapter)
            {
                changed |= facts.dynamic_callable_bindings.insert(binding.to_owned());
            }
            if value.kind() == "call_expression"
                && call_function_identifier(value, source)
                    .is_some_and(|function| facts.dynamic_callable_bindings.contains(function))
            {
                changed |= facts.dynamic_guard_results.insert(binding.to_owned());
            }
        }
        if !changed {
            return (facts, true);
        }
    }
    (facts, false)
}

fn observe_if_guard(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
    builder: &mut GuardBuilder<'_>,
) -> Result<(), GuardExtractionError> {
    let Some(condition) = node.child_by_field_name("condition") else {
        return Ok(());
    };
    let Some(consequence) = node.child_by_field_name("consequence") else {
        return Ok(());
    };
    let condition = unwrap_expression(condition);
    if !contains_direct_rejection_exit(consequence, source) {
        if contains_rejection_exit(consequence, source) {
            builder.gap(
                GuardCoverageGapReason::UnsupportedGuardShape,
                condition.start_byte(),
                condition.end_byte(),
            )?;
        }
        return Ok(());
    }

    if condition_contains_dynamic_guard(condition, source, facts) {
        builder.gap(
            GuardCoverageGapReason::DynamicGuard,
            condition.start_byte(),
            condition.end_byte(),
        )?;
        return Ok(());
    }

    observe_condition_parts(condition, source, adapter, facts, builder)
}

fn observe_condition_parts(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
    builder: &mut GuardBuilder<'_>,
) -> Result<(), GuardExtractionError> {
    let node = unwrap_expression(node);
    if node.kind() == "binary_expression" {
        let Some(left) = node.child_by_field_name("left") else {
            return Ok(());
        };
        let Some(right) = node.child_by_field_name("right") else {
            return Ok(());
        };
        let operator = binary_operator(node, source).unwrap_or_default();
        if operator == "&&" {
            builder.gap(
                GuardCoverageGapReason::UnsupportedGuardShape,
                node.start_byte(),
                node.end_byte(),
            )?;
            return Ok(());
        }
        if operator == "||" {
            observe_condition_parts(left, source, adapter, facts, builder)?;
            observe_condition_parts(right, source, adapter, facts, builder)?;
            return Ok(());
        }
        if observe_role_comparison(
            (node, left, right),
            operator,
            source,
            adapter,
            facts,
            builder,
        )? || observe_identity_binding_comparison(
            node, left, right, operator, source, adapter, facts, builder,
        )? {
            return Ok(());
        }
    }

    if observe_negated_presence(node, source, adapter, facts, builder)?
        || observe_membership_guard(node, source, adapter, facts, builder)?
        || observe_elevated_boundary_guard(node, source, builder)?
    {
        return Ok(());
    }

    if contains_auth_relevant_dynamic_shape(node, source, adapter, facts) {
        builder.gap(
            GuardCoverageGapReason::UnsupportedGuardShape,
            node.start_byte(),
            node.end_byte(),
        )?;
    }
    Ok(())
}

fn observe_negated_presence(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
    builder: &mut GuardBuilder<'_>,
) -> Result<bool, GuardExtractionError> {
    if node.kind() != "unary_expression" {
        return Ok(false);
    }
    let text = node_text(node, source).unwrap_or_default().trim_start();
    if !text.starts_with('!') {
        return Ok(false);
    }
    let Some(argument) = node.named_child(0) else {
        return Ok(false);
    };
    let argument = unwrap_expression(argument);
    let Some(chain) = expression_chain(argument, source) else {
        return Ok(false);
    };

    if is_authenticated_presence_chain(&chain, adapter, facts) {
        builder.guard(
            GuardKind::Authentication,
            Vec::new(),
            ComparisonShape::OtherSupported,
            DominanceScope::SameHandlerPrefix,
            node.start_byte(),
            node.end_byte(),
        )?;
        return Ok(true);
    }
    Ok(false)
}

fn observe_role_comparison(
    comparison: (
        tree_sitter::Node<'_>,
        tree_sitter::Node<'_>,
        tree_sitter::Node<'_>,
    ),
    operator: &str,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
    builder: &mut GuardBuilder<'_>,
) -> Result<bool, GuardExtractionError> {
    let (node, left, right) = comparison;
    if !matches!(operator, "!==" | "!=") {
        return Ok(false);
    }
    let left = unwrap_expression(left);
    let right = unwrap_expression(right);
    let left_chain = expression_chain(left, source);
    let right_chain = expression_chain(right, source);

    let (role_chain, literal) = if let (Some(chain), Some(value)) =
        (left_chain.as_deref(), string_literal_value(right, source))
    {
        (chain, value)
    } else if let (Some(chain), Some(value)) =
        (right_chain.as_deref(), string_literal_value(left, source))
    {
        (chain, value)
    } else {
        return Ok(false);
    };
    if !is_verified_role_chain(role_chain, adapter, facts) {
        return Ok(false);
    }

    builder.guard(
        GuardKind::RequiredRole,
        vec![literal],
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
        node.start_byte(),
        node.end_byte(),
    )?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn observe_identity_binding_comparison(
    node: tree_sitter::Node<'_>,
    left: tree_sitter::Node<'_>,
    right: tree_sitter::Node<'_>,
    operator: &str,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
    builder: &mut GuardBuilder<'_>,
) -> Result<bool, GuardExtractionError> {
    if !matches!(operator, "!==" | "!=") {
        return Ok(false);
    }
    let Some(left_chain) = expression_chain(unwrap_expression(left), source) else {
        return Ok(false);
    };
    let Some(right_chain) = expression_chain(unwrap_expression(right), source) else {
        return Ok(false);
    };

    let left_field = left_chain.last().map(String::as_str).unwrap_or_default();
    let right_field = right_chain.last().map(String::as_str).unwrap_or_default();
    let left_actor = is_verified_actor_identity_chain(&left_chain, adapter, facts);
    let right_actor = is_verified_actor_identity_chain(&right_chain, adapter, facts);
    let left_user_id = is_verified_user_id_chain(&left_chain, adapter, facts);
    let right_user_id = is_verified_user_id_chain(&right_chain, adapter, facts);
    let left_tenant = is_verified_tenant_identity_chain(&left_chain, adapter, facts);
    let right_tenant = is_verified_tenant_identity_chain(&right_chain, adapter, facts);

    let kind = if (is_tenant_field(left_field) && right_tenant)
        || (is_tenant_field(right_field) && left_tenant)
    {
        Some(GuardKind::TenantBinding)
    } else if (is_ownership_field(left_field) && right_user_id)
        || (is_ownership_field(right_field) && left_user_id)
    {
        Some(GuardKind::OwnershipBinding)
    } else {
        None
    };
    let Some(kind) = kind else {
        let mismatched_identity = (is_tenant_field(left_field) && right_actor)
            || (is_tenant_field(right_field) && left_actor)
            || (is_ownership_field(left_field) && right_actor)
            || (is_ownership_field(right_field) && left_actor);
        if mismatched_identity {
            builder.gap(
                GuardCoverageGapReason::UnsupportedGuardShape,
                node.start_byte(),
                node.end_byte(),
            )?;
            return Ok(true);
        }
        return Ok(false);
    };

    builder.guard(
        kind,
        Vec::new(),
        ComparisonShape::Equal,
        DominanceScope::SameHandlerPrefix,
        node.start_byte(),
        node.end_byte(),
    )?;
    Ok(true)
}

fn observe_membership_guard(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
    builder: &mut GuardBuilder<'_>,
) -> Result<bool, GuardExtractionError> {
    if node.kind() != "unary_expression" {
        return Ok(false);
    }
    let text = node_text(node, source).unwrap_or_default().trim_start();
    if !text.starts_with('!') {
        return Ok(false);
    }
    let Some(call) = node.named_child(0).map(unwrap_expression) else {
        return Ok(false);
    };
    if call.kind() != "call_expression" {
        return Ok(false);
    }
    let Some(function) = call.child_by_field_name("function") else {
        return Ok(false);
    };
    let Some(function_chain) = expression_chain(function, source) else {
        return Ok(false);
    };
    let Some(method) = function_chain.last().map(String::as_str) else {
        return Ok(false);
    };
    if !matches!(method, "includes" | "has") {
        return Ok(false);
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Ok(false);
    };
    let mut cursor = arguments.walk();
    let argument_is_identity_or_request = arguments.named_children(&mut cursor).any(|argument| {
        expression_chain(unwrap_expression(argument), source).is_some_and(|chain| {
            is_verified_actor_identity_chain(&chain, adapter, facts)
                || is_request_controlled_chain(&chain, adapter, facts)
        })
    });
    if !argument_is_identity_or_request {
        return Ok(false);
    }

    builder.guard(
        GuardKind::ObjectMembership,
        Vec::new(),
        ComparisonShape::Membership,
        DominanceScope::SameHandlerPrefix,
        node.start_byte(),
        node.end_byte(),
    )?;
    Ok(true)
}

fn observe_elevated_boundary_guard(
    node: tree_sitter::Node<'_>,
    source: &str,
    builder: &mut GuardBuilder<'_>,
) -> Result<bool, GuardExtractionError> {
    if node.kind() != "unary_expression" {
        return Ok(false);
    }
    let text = node_text(node, source).unwrap_or_default().trim_start();
    if !text.starts_with('!') {
        return Ok(false);
    }
    let Some(argument) = node.named_child(0).map(unwrap_expression) else {
        return Ok(false);
    };
    let Some(chain) = expression_chain(argument, source) else {
        return Ok(false);
    };
    if !is_explicit_elevated_authorization_marker(&chain) {
        return Ok(false);
    }

    builder.guard(
        GuardKind::ElevatedClientBoundary,
        Vec::new(),
        ComparisonShape::OtherSupported,
        DominanceScope::SameHandlerPrefix,
        node.start_byte(),
        node.end_byte(),
    )?;
    Ok(true)
}

fn observe_property_allowlist(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
    builder: &mut GuardBuilder<'_>,
) -> Result<(), GuardExtractionError> {
    let Some(name) = node.child_by_field_name("name") else {
        return Ok(());
    };
    if name.kind() != "object_pattern" {
        return Ok(());
    }
    let Some(value) = node.child_by_field_name("value") else {
        return Ok(());
    };
    let value = unwrap_expression(value);
    let source_is_request_body = expression_chain(value, source)
        .as_deref()
        .is_some_and(|chain| {
            is_direct_request_body_chain(chain, adapter)
                || chain
                    .first()
                    .is_some_and(|root| facts.request_body_bindings.contains(root))
        });
    if !source_is_request_body {
        return Ok(());
    }
    let mut pattern_cursor = name.walk();
    let has_rest = name
        .named_children(&mut pattern_cursor)
        .any(|child| child.kind() == "rest_pattern");
    let properties = object_pattern_keys(name, source);
    if properties.is_empty() || has_rest {
        builder.gap(
            GuardCoverageGapReason::UnsupportedGuardShape,
            node.start_byte(),
            node.end_byte(),
        )?;
        return Ok(());
    }

    builder.guard(
        GuardKind::PropertyAllowlist,
        properties,
        ComparisonShape::ExplicitAllowlist,
        DominanceScope::SameHandlerPrefix,
        node.start_byte(),
        node.end_byte(),
    )
}

fn condition_contains_dynamic_guard(
    node: tree_sitter::Node<'_>,
    source: &str,
    facts: &GuardFacts,
) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "identifier"
            && node_text(current, source)
                .is_some_and(|name| facts.dynamic_guard_results.contains(name))
        {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn contains_auth_relevant_dynamic_shape(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "subscript_expression"
            && let Some(object) = current.child_by_field_name("object")
            && expression_chain(object, source).is_some_and(|chain| {
                is_authenticated_presence_chain(&chain, adapter, facts)
                    || is_verified_actor_identity_chain(&chain, adapter, facts)
            })
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

fn contains_rejection_exit(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if is_nested_function_boundary(current) {
            continue;
        }
        if is_rejection_exit_node(current, source) {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

fn is_nested_function_boundary(node: tree_sitter::Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_expression"
            | "function_declaration"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
    )
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

fn call_has_request_controlled_argument(
    call: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    facts: &GuardFacts,
) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut stack = vec![arguments];
    while let Some(node) = stack.pop() {
        if expression_chain(node, source)
            .is_some_and(|chain| is_request_controlled_chain(&chain, adapter, facts))
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

fn is_request_controlled_chain(
    chain: &[String],
    adapter: RouteAdapter,
    facts: &GuardFacts,
) -> bool {
    let Some(root) = chain.first().map(String::as_str) else {
        return false;
    };
    if facts.request_body_bindings.contains(root) {
        return true;
    }
    match adapter {
        RouteAdapter::Express | RouteAdapter::NextPagesApi => root == "req",
        RouteAdapter::NextApp => matches!(root, "request" | "context"),
        RouteAdapter::SupabaseEdge => root == "request",
    }
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

fn is_authenticated_presence_chain(
    chain: &[String],
    adapter: RouteAdapter,
    facts: &GuardFacts,
) -> bool {
    let Some(root) = chain.first() else {
        return false;
    };
    match adapter {
        RouteAdapter::Express => chain.len() == 2 && root == "req" && chain[1] == "user",
        RouteAdapter::NextApp => {
            (chain.len() == 1 && facts.session_bindings.contains(root))
                || (chain.len() == 2 && facts.session_bindings.contains(root) && chain[1] == "user")
                || (chain.len() == 1 && facts.verified_user_bindings.contains(root))
        }
        RouteAdapter::SupabaseEdge => {
            (chain.len() == 1 && facts.verified_user_bindings.contains(root))
                || (chain.len() == 3
                    && facts.supabase_user_result_bindings.contains(root)
                    && chain[1] == "data"
                    && chain[2] == "user")
        }
        RouteAdapter::NextPagesApi => false,
    }
}

fn is_verified_role_chain(chain: &[String], adapter: RouteAdapter, facts: &GuardFacts) -> bool {
    let Some(field) = chain.last().map(String::as_str) else {
        return false;
    };
    field == "role"
        && is_verified_actor_identity_chain(&chain[..chain.len().saturating_sub(1)], adapter, facts)
}

fn is_verified_user_id_chain(chain: &[String], adapter: RouteAdapter, facts: &GuardFacts) -> bool {
    let Some(field) = chain.last().map(String::as_str) else {
        return false;
    };
    matches!(field, "id" | "user_id" | "userId")
        && is_verified_actor_identity_chain(&chain[..chain.len().saturating_sub(1)], adapter, facts)
}

fn is_verified_tenant_identity_chain(
    chain: &[String],
    adapter: RouteAdapter,
    facts: &GuardFacts,
) -> bool {
    let Some(field) = chain.last().map(String::as_str) else {
        return false;
    };
    is_tenant_field(field)
        && is_verified_actor_identity_chain(&chain[..chain.len().saturating_sub(1)], adapter, facts)
}

fn is_verified_actor_identity_chain(
    chain: &[String],
    adapter: RouteAdapter,
    facts: &GuardFacts,
) -> bool {
    if chain.is_empty() {
        return false;
    }
    let root = chain[0].as_str();
    match adapter {
        RouteAdapter::Express => {
            chain.len() >= 2 && root == "req" && chain.get(1).is_some_and(|part| part == "user")
        }
        RouteAdapter::NextApp => {
            (facts.session_bindings.contains(root)
                && chain.get(1).is_some_and(|part| part == "user"))
                || facts.verified_user_bindings.contains(root)
        }
        RouteAdapter::SupabaseEdge => {
            facts.verified_user_bindings.contains(root)
                || (facts.supabase_user_result_bindings.contains(root)
                    && chain.get(1).is_some_and(|part| part == "data")
                    && chain.get(2).is_some_and(|part| part == "user"))
        }
        RouteAdapter::NextPagesApi => false,
    }
}

fn is_explicit_elevated_authorization_marker(chain: &[String]) -> bool {
    if chain.len() != 2 {
        return false;
    }
    matches!(chain[0].as_str(), "authorization" | "authz" | "permissions")
        && matches!(
            chain[1].as_str(),
            "elevatedClient" | "elevated_client" | "serviceRole" | "service_role"
        )
}

fn is_tenant_field(field: &str) -> bool {
    matches!(
        field,
        "tenant" | "tenant_id" | "tenantId" | "organization_id" | "organizationId"
    )
}

fn is_ownership_field(field: &str) -> bool {
    matches!(
        field,
        "owner_id" | "ownerId" | "user_id" | "userId" | "created_by" | "createdBy"
    )
}

fn object_pattern_keys(pattern: tree_sitter::Node<'_>, source: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut cursor = pattern.walk();
    for child in pattern.named_children(&mut cursor) {
        match child.kind() {
            "shorthand_property_identifier_pattern" | "shorthand_property_identifier" => {
                if let Some(value) = node_text(child, source)
                    && is_identifier(value)
                {
                    keys.push(value.to_owned());
                }
            }
            "pair_pattern" => {
                if let Some(key) = child.child_by_field_name("key")
                    && let Some(value) = node_text(key, source)
                    && is_identifier(value)
                {
                    keys.push(value.to_owned());
                }
            }
            _ => {}
        }
    }
    keys.sort();
    keys.dedup();
    keys
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
        GuardExtractionError::ParseFailed("guard parser returned no syntax tree".to_owned())
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

fn binary_operator<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    let operator = node.child_by_field_name("operator")?;
    node_text(operator, source).map(str::trim)
}

fn string_literal_value(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let text = node_text(node, source)?;
    if text.len() < 2 {
        return None;
    }
    Some(text[1..text.len() - 1].to_owned())
}

fn is_known_static_auth_or_body_call(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
) -> bool {
    (adapter == RouteAdapter::NextApp && is_auth_call(node, source))
        || (adapter == RouteAdapter::SupabaseEdge && is_supabase_get_user_call(node, source))
        || is_request_json_call(node, source, adapter)
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

fn call_function_identifier<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "identifier" {
        return None;
    }
    node_text(function, source)
}

fn unwrap_expression(mut node: tree_sitter::Node<'_>) -> tree_sitter::Node<'_> {
    loop {
        if matches!(
            node.kind(),
            "await_expression"
                | "parenthesized_expression"
                | "non_null_expression"
                | "as_expression"
                | "satisfies_expression"
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
