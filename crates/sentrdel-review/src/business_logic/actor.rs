//! Bounded R3 actor/auth context extraction for the frozen JavaScript/TypeScript adapters.
//!
//! Repository source is untrusted data. Static recognition of a supported auth seam records
//! only source structure; it never proves that a runtime token, session, user, tenant, or role
//! is valid. This module executes no target code, performs no network/provider access, loads no
//! repository rules, and creates no Findings.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::content_id;

use super::model::{
    ActorContext, ActorIdentityKind, ActorSourceKind, BusinessLogicLimits, ModelError,
    SourceLocation, StableSemanticId, TrustBasis,
};
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage, StructuralRegistry};
use crate::view::NormalizedRepoPath;

pub const MAX_ACTOR_CONTEXTS: usize = 4_096;
pub const MAX_ACTOR_COVERAGE_GAPS: usize = 4_096;
pub const MAX_ACTOR_AST_NODES: usize = 100_000;
pub const STATIC_AUTH_RECOGNITION_PROVES_RUNTIME_IDENTITY: bool = false;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActorCoverageGapReason {
    DynamicRequestAccess,
    DynamicAuthIdentity,
    UnsupportedAuthShape,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorCoverageGap {
    reason: ActorCoverageGapReason,
    provenance: SourceLocation,
}

impl ActorCoverageGap {
    #[must_use]
    pub const fn reason(&self) -> ActorCoverageGapReason {
        self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorExtraction {
    actors: Vec<ActorContext>,
    gaps: Vec<ActorCoverageGap>,
}

impl ActorExtraction {
    #[must_use]
    pub fn actors(&self) -> &[ActorContext] {
        &self.actors
    }

    #[must_use]
    pub fn gaps(&self) -> &[ActorCoverageGap] {
        &self.gaps
    }
}

#[derive(Debug)]
pub enum ActorExtractionError {
    Structural(StructuralError),
    Model(ModelError),
    ParseFailed(String),
    TooManyAstNodes { count: usize, max: usize },
    TooManyActors { count: usize, max: usize },
    TooManyCoverageGaps { count: usize, max: usize },
}

impl fmt::Display for ActorExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structural(source) => {
                write!(formatter, "actor structural validation failed: {source}")
            }
            Self::Model(source) => write!(formatter, "actor model validation failed: {source}"),
            Self::ParseFailed(error) => write!(formatter, "actor parser failed: {error}"),
            Self::TooManyAstNodes { count, max } => {
                write!(formatter, "actor AST node count {count} exceeds cap {max}")
            }
            Self::TooManyActors { count, max } => {
                write!(formatter, "actor observation count {count} exceeds cap {max}")
            }
            Self::TooManyCoverageGaps { count, max } => {
                write!(formatter, "actor coverage gap count {count} exceeds cap {max}")
            }
        }
    }
}

impl Error for ActorExtractionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Structural(source) => Some(source),
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<StructuralError> for ActorExtractionError {
    fn from(value: StructuralError) -> Self {
        Self::Structural(value)
    }
}

impl From<ModelError> for ActorExtractionError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

#[derive(Default)]
struct BindingFacts {
    session_bindings: BTreeSet<String>,
    supabase_user_result_bindings: BTreeSet<String>,
    verified_user_bindings: BTreeSet<String>,
    request_body_bindings: BTreeSet<String>,
}

pub fn extract_actor_contexts(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<ActorExtraction, ActorExtractionError> {
    let limits = limits.validate()?;

    // Reuse the fixed Sentrdel-owned structural parser boundary so malformed syntax, oversized
    // source, and unsupported input fail visibly before actor interpretation starts.
    let validator = StructuralRegistry::new(&[])?;
    validator.scan_language(language, path, source)?;
    let source = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;

    let digest =
        content_id("r3-actor-source", &(path.as_str(), source)).map_err(ModelError::from)?;
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let facts = collect_binding_facts(&nodes, source, adapter);
    let mut builder = ActorBuilder::new(path, digest, limits);

    for node in &nodes {
        match node.kind() {
            "member_expression" => {
                if is_nested_member_prefix(*node) {
                    continue;
                }
                if let Some(chain) = expression_chain(*node, source) {
                    if let Some(source_kind) = request_source_kind(&chain, adapter, &facts) {
                        builder.actor(
                            ActorIdentityKind::RequestControlled,
                            source_kind,
                            &chain.join("."),
                            TrustBasis::DirectObservation,
                            node.start_byte(),
                            node.end_byte(),
                        )?;
                        continue;
                    }
                    if let Some(identity_kind) = verified_identity_kind(&chain, adapter, &facts) {
                        builder.actor(
                            identity_kind,
                            ActorSourceKind::VerifiedAuthAdapter,
                            &chain.join("."),
                            TrustBasis::DirectObservation,
                            node.start_byte(),
                            node.end_byte(),
                        )?;
                    }
                }
            }
            "subscript_expression" => {
                let Some(object) = node.child_by_field_name("object") else {
                    continue;
                };
                let root = expression_chain(object, source)
                    .and_then(|chain| chain.first().cloned())
                    .or_else(|| node_text(object, source).map(str::to_owned));
                let Some(root) = root else {
                    continue;
                };
                if is_request_root(&root, adapter) {
                    builder.gap(
                        ActorCoverageGapReason::DynamicRequestAccess,
                        node.start_byte(),
                        node.end_byte(),
                    )?;
                    builder.actor(
                        ActorIdentityKind::Unknown,
                        ActorSourceKind::Unknown,
                        &format!("dynamic-request@{}", node.start_byte()),
                        TrustBasis::Unknown,
                        node.start_byte(),
                        node.end_byte(),
                    )?;
                } else if is_verified_auth_root(&root, adapter, &facts) {
                    builder.gap(
                        ActorCoverageGapReason::DynamicAuthIdentity,
                        node.start_byte(),
                        node.end_byte(),
                    )?;
                    builder.actor(
                        ActorIdentityKind::Unknown,
                        ActorSourceKind::Unknown,
                        &format!("dynamic-auth@{}", node.start_byte()),
                        TrustBasis::Unknown,
                        node.start_byte(),
                        node.end_byte(),
                    )?;
                }
            }
            "variable_declarator" => {
                observe_constant(*node, source, &mut builder)?;
                observe_unsupported_auth_binding(*node, source, &mut builder)?;
            }
            "call_expression" => {
                observe_request_call(*node, source, adapter, &facts, &mut builder)?;
            }
            _ => {}
        }
    }

    builder.finish()
}

struct ActorBuilder<'a> {
    path: &'a NormalizedRepoPath,
    digest: String,
    limits: BusinessLogicLimits,
    actors: BTreeMap<String, ActorContext>,
    gaps: BTreeMap<(ActorCoverageGapReason, usize, usize), ActorCoverageGap>,
}

impl<'a> ActorBuilder<'a> {
    fn new(
        path: &'a NormalizedRepoPath,
        digest: String,
        limits: BusinessLogicLimits,
    ) -> Self {
        Self {
            path,
            digest,
            limits,
            actors: BTreeMap::new(),
            gaps: BTreeMap::new(),
        }
    }

    fn location(&self, start: usize, end: usize) -> Result<SourceLocation, ActorExtractionError> {
        Ok(SourceLocation::new(
            self.path.clone(),
            start,
            end,
            self.digest.clone(),
        )?)
    }

    fn actor(
        &mut self,
        identity_kind: ActorIdentityKind,
        source_kind: ActorSourceKind,
        semantic_key: &str,
        trust_basis: TrustBasis,
        start: usize,
        end: usize,
    ) -> Result<(), ActorExtractionError> {
        let start_text = start.to_string();
        let end_text = end.to_string();
        let identity_text = identity_kind_key(identity_kind);
        let source_text = source_kind_key(source_kind);
        let actor_id = StableSemanticId::from_parts(
            "r3.actor-context",
            &[
                self.path.as_str(),
                semantic_key,
                identity_text,
                source_text,
                &start_text,
                &end_text,
            ],
            self.limits,
        )?;
        let key = actor_id.as_str().to_owned();
        if !self.actors.contains_key(&key) && self.actors.len() >= MAX_ACTOR_CONTEXTS {
            return Err(ActorExtractionError::TooManyActors {
                count: self.actors.len().saturating_add(1),
                max: MAX_ACTOR_CONTEXTS,
            });
        }
        let actor = ActorContext::new(
            actor_id,
            identity_kind,
            source_kind,
            semantic_key,
            trust_basis,
            vec![self.location(start, end)?],
            self.limits,
        )?;
        self.actors.insert(key, actor);
        Ok(())
    }

    fn gap(
        &mut self,
        reason: ActorCoverageGapReason,
        start: usize,
        end: usize,
    ) -> Result<(), ActorExtractionError> {
        let key = (reason, start, end);
        if !self.gaps.contains_key(&key) && self.gaps.len() >= MAX_ACTOR_COVERAGE_GAPS {
            return Err(ActorExtractionError::TooManyCoverageGaps {
                count: self.gaps.len().saturating_add(1),
                max: MAX_ACTOR_COVERAGE_GAPS,
            });
        }
        self.gaps.insert(
            key,
            ActorCoverageGap {
                reason,
                provenance: self.location(start, end)?,
            },
        );
        Ok(())
    }

    fn finish(self) -> Result<ActorExtraction, ActorExtractionError> {
        Ok(ActorExtraction {
            actors: self.actors.into_values().collect(),
            gaps: self.gaps.into_values().collect(),
        })
    }
}

fn parse_tree(
    language: StructuralLanguage,
    source: &str,
) -> Result<tree_sitter::Tree, ActorExtractionError> {
    let language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| ActorExtractionError::ParseFailed(error.to_string()))?;
    parser.parse(source, None).ok_or_else(|| {
        ActorExtractionError::ParseFailed("actor parser returned no syntax tree".to_owned())
    })
}

fn collect_nodes<'tree>(
    root: tree_sitter::Node<'tree>,
) -> Result<Vec<tree_sitter::Node<'tree>>, ActorExtractionError> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if nodes.len() >= MAX_ACTOR_AST_NODES {
            return Err(ActorExtractionError::TooManyAstNodes {
                count: nodes.len().saturating_add(1),
                max: MAX_ACTOR_AST_NODES,
            });
        }
        nodes.push(node);
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    Ok(nodes)
}

fn collect_binding_facts(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    adapter: RouteAdapter,
) -> BindingFacts {
    let mut facts = BindingFacts::default();
    for _ in 0..4 {
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
            if is_request_json_call(value, source, adapter) {
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
        }
        if !changed {
            break;
        }
    }
    facts
}

fn request_source_kind(
    chain: &[String],
    adapter: RouteAdapter,
    facts: &BindingFacts,
) -> Option<ActorSourceKind> {
    let root = chain.first()?.as_str();
    let second = chain.get(1).map(String::as_str);

    if facts.request_body_bindings.contains(root) {
        return Some(ActorSourceKind::RequestBody);
    }

    match adapter {
        RouteAdapter::Express => {
            if root != "req" {
                return None;
            }
            match second? {
                "params" => Some(ActorSourceKind::RequestParam),
                "query" => Some(ActorSourceKind::RequestQuery),
                "body" => Some(ActorSourceKind::RequestBody),
                "headers" | "header" => Some(ActorSourceKind::RequestHeader),
                _ => None,
            }
        }
        RouteAdapter::NextPagesApi => {
            if root != "req" {
                return None;
            }
            match second? {
                "query" => Some(ActorSourceKind::RequestQuery),
                "body" => Some(ActorSourceKind::RequestBody),
                "headers" | "header" => Some(ActorSourceKind::RequestHeader),
                _ => None,
            }
        }
        RouteAdapter::NextApp => {
            if root == "context" && second == Some("params") {
                return Some(ActorSourceKind::RequestParam);
            }
            if root == "request" && second == Some("headers") {
                return Some(ActorSourceKind::RequestHeader);
            }
            if root == "request"
                && chain.get(1).map(String::as_str) == Some("nextUrl")
                && chain.get(2).map(String::as_str) == Some("searchParams")
            {
                return Some(ActorSourceKind::RequestQuery);
            }
            None
        }
        RouteAdapter::SupabaseEdge => {
            if root == "request" && second == Some("headers") {
                Some(ActorSourceKind::RequestHeader)
            } else {
                None
            }
        }
    }
}

fn verified_identity_kind(
    chain: &[String],
    adapter: RouteAdapter,
    facts: &BindingFacts,
) -> Option<ActorIdentityKind> {
    let field = if adapter == RouteAdapter::Express
        && chain.first().map(String::as_str) == Some("req")
        && chain.get(1).map(String::as_str) == Some("user")
    {
        chain.get(2).map(String::as_str)
    } else if adapter == RouteAdapter::NextApp
        && chain
            .first()
            .is_some_and(|root| facts.session_bindings.contains(root))
        && chain.get(1).map(String::as_str) == Some("user")
    {
        chain.get(2).map(String::as_str)
    } else if chain
        .first()
        .is_some_and(|root| facts.verified_user_bindings.contains(root))
    {
        chain.get(1).map(String::as_str)
    } else {
        return None;
    };

    match field {
        None => Some(ActorIdentityKind::AuthenticatedUser),
        Some("id" | "sub" | "user_id" | "userId") => Some(ActorIdentityKind::AuthenticatedUser),
        Some("tenant" | "tenant_id" | "tenantId" | "organization_id" | "organizationId") => {
            Some(ActorIdentityKind::Tenant)
        }
        Some("role" | "roles") => Some(ActorIdentityKind::Role),
        Some(_) => None,
    }
}

fn observe_constant(
    node: tree_sitter::Node<'_>,
    source: &str,
    builder: &mut ActorBuilder<'_>,
) -> Result<(), ActorExtractionError> {
    let Some(name) = node.child_by_field_name("name") else {
        return Ok(());
    };
    let Some(value) = node.child_by_field_name("value") else {
        return Ok(());
    };
    if name.kind() != "identifier" || !is_literal_constant(unwrap_expression(value)) {
        return Ok(());
    }
    let Some(binding) = node_text(name, source) else {
        return Ok(());
    };
    builder.actor(
        ActorIdentityKind::Unknown,
        ActorSourceKind::Constant,
        &format!("constant-binding:{binding}"),
        TrustBasis::DirectObservation,
        value.start_byte(),
        value.end_byte(),
    )
}

fn observe_unsupported_auth_binding(
    node: tree_sitter::Node<'_>,
    source: &str,
    builder: &mut ActorBuilder<'_>,
) -> Result<(), ActorExtractionError> {
    let Some(name) = node.child_by_field_name("name") else {
        return Ok(());
    };
    if name.kind() == "identifier" {
        return Ok(());
    }
    let Some(value) = node.child_by_field_name("value") else {
        return Ok(());
    };
    let value = unwrap_expression(value);
    if !is_auth_call(value, source) && !is_supabase_get_user_call(value, source) {
        return Ok(());
    }
    builder.gap(
        ActorCoverageGapReason::UnsupportedAuthShape,
        node.start_byte(),
        node.end_byte(),
    )?;
    builder.actor(
        ActorIdentityKind::Unknown,
        ActorSourceKind::Unknown,
        &format!("unsupported-auth-binding@{}", node.start_byte()),
        TrustBasis::Unknown,
        node.start_byte(),
        node.end_byte(),
    )
}

fn observe_request_call(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
    facts: &BindingFacts,
    builder: &mut ActorBuilder<'_>,
) -> Result<(), ActorExtractionError> {
    let Some(function) = node.child_by_field_name("function") else {
        return Ok(());
    };
    let Some(chain) = expression_chain(function, source) else {
        return Ok(());
    };

    let source_kind = request_source_kind(&chain, adapter, facts);
    if matches!(source_kind, Some(ActorSourceKind::RequestHeader | ActorSourceKind::RequestQuery)) {
        builder.actor(
            ActorIdentityKind::RequestControlled,
            source_kind.expect("matched request source kind"),
            &format!("{}@{}", chain.join("."), node.start_byte()),
            TrustBasis::DirectObservation,
            node.start_byte(),
            node.end_byte(),
        )?;
    }
    Ok(())
}

fn is_auth_call(node: tree_sitter::Node<'_>, source: &str) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    node.child_by_field_name("function")
        .and_then(|function| expression_chain(function, source))
        .is_some_and(|chain| chain == ["auth".to_owned()])
}

fn is_supabase_get_user_call(node: tree_sitter::Node<'_>, source: &str) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    node.child_by_field_name("function")
        .and_then(|function| expression_chain(function, source))
        .is_some_and(|chain| {
            chain == [
                "supabase".to_owned(),
                "auth".to_owned(),
                "getUser".to_owned(),
            ]
        })
}

fn is_request_json_call(
    node: tree_sitter::Node<'_>,
    source: &str,
    adapter: RouteAdapter,
) -> bool {
    if !matches!(adapter, RouteAdapter::NextApp | RouteAdapter::SupabaseEdge)
        || node.kind() != "call_expression"
    {
        return false;
    }
    node.child_by_field_name("function")
        .and_then(|function| expression_chain(function, source))
        .is_some_and(|chain| chain == ["request".to_owned(), "json".to_owned()])
}

fn unwrap_expression(mut node: tree_sitter::Node<'_>) -> tree_sitter::Node<'_> {
    loop {
        if matches!(node.kind(), "await_expression" | "parenthesized_expression") {
            if let Some(child) = node.named_child(0) {
                node = child;
                continue;
            }
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

fn is_nested_member_prefix(node: tree_sitter::Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "member_expression" {
        return false;
    }
    parent.child_by_field_name("object").is_some_and(|object| {
        object.start_byte() == node.start_byte() && object.end_byte() == node.end_byte()
    })
}

fn is_literal_constant(node: tree_sitter::Node<'_>) -> bool {
    matches!(node.kind(), "string" | "number" | "true" | "false")
}

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first == b'_' || first == b'$' || first.is_ascii_alphabetic()) {
        return false;
    }
    bytes.all(|byte| byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric())
}

fn is_request_root(root: &str, adapter: RouteAdapter) -> bool {
    match adapter {
        RouteAdapter::Express | RouteAdapter::NextPagesApi => root == "req",
        RouteAdapter::NextApp => matches!(root, "request" | "context"),
        RouteAdapter::SupabaseEdge => root == "request",
    }
}

fn is_verified_auth_root(root: &str, adapter: RouteAdapter, facts: &BindingFacts) -> bool {
    (adapter == RouteAdapter::Express && root == "req")
        || facts.session_bindings.contains(root)
        || facts.verified_user_bindings.contains(root)
}

const fn identity_kind_key(kind: ActorIdentityKind) -> &'static str {
    match kind {
        ActorIdentityKind::AuthenticatedUser => "authenticated-user",
        ActorIdentityKind::Tenant => "tenant",
        ActorIdentityKind::Role => "role",
        ActorIdentityKind::Service => "service",
        ActorIdentityKind::Anonymous => "anonymous",
        ActorIdentityKind::RequestControlled => "request-controlled",
        ActorIdentityKind::Unknown => "unknown",
    }
}

const fn source_kind_key(kind: ActorSourceKind) -> &'static str {
    match kind {
        ActorSourceKind::VerifiedAuthAdapter => "verified-auth-adapter",
        ActorSourceKind::RequestParam => "request-param",
        ActorSourceKind::RequestQuery => "request-query",
        ActorSourceKind::RequestBody => "request-body",
        ActorSourceKind::RequestHeader => "request-header",
        ActorSourceKind::TokenClaim => "token-claim",
        ActorSourceKind::Constant => "constant",
        ActorSourceKind::DerivedSupported => "derived-supported",
        ActorSourceKind::Unknown => "unknown",
    }
}
