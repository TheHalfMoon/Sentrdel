//! Bounded R3 value-origin derivation for the frozen JavaScript/TypeScript adapters.
//!
//! Repository source is untrusted data. This module records static value origins and bounded
//! supported derivations only. Unsupported or dynamic expressions terminate in UNKNOWN; lexical
//! name equality alone never establishes value equivalence. The implementation executes no target
//! code, performs no provider/network access, uses no credentials, and creates no Findings.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::content_id;

use super::model::{
    BusinessLogicLimits, ModelError, SourceLocation, StableSemanticId, ValueOrigin, ValueOriginKind,
};
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage, StructuralRegistry};
use crate::view::NormalizedRepoPath;

pub const MAX_VALUE_ORIGINS: usize = 8_192;
pub const MAX_VALUE_COVERAGE_GAPS: usize = 4_096;
pub const MAX_VALUE_AST_NODES: usize = 100_000;
pub const STATIC_VALUE_DERIVATION_PROVES_RUNTIME_VALUE: bool = false;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ValueCoverageGapReason {
    DynamicExpression,
    AmbiguousBinding,
    UnsupportedDestructuring,
    DerivationDepthExceeded,
    DerivationFanInExceeded,
}

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

#[derive(Debug)]
pub enum ValueExtractionError {
    Structural(StructuralError),
    Model(ModelError),
    ParseFailed(String),
    TooManyAstNodes { count: usize, max: usize },
    TooManyValues { count: usize, max: usize },
    TooManyCoverageGaps { count: usize, max: usize },
}

impl fmt::Display for ValueExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structural(source) => {
                write!(formatter, "value structural validation failed: {source}")
            }
            Self::Model(source) => write!(formatter, "value model validation failed: {source}"),
            Self::ParseFailed(error) => write!(formatter, "value parser failed: {error}"),
            Self::TooManyAstNodes { count, max } => {
                write!(formatter, "value AST node count {count} exceeds cap {max}")
            }
            Self::TooManyValues { count, max } => {
                write!(formatter, "value origin count {count} exceeds cap {max}")
            }
            Self::TooManyCoverageGaps { count, max } => write!(
                formatter,
                "value coverage gap count {count} exceeds cap {max}"
            ),
        }
    }
}

impl Error for ValueExtractionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Structural(source) => Some(source),
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<StructuralError> for ValueExtractionError {
    fn from(value: StructuralError) -> Self {
        Self::Structural(value)
    }
}

impl From<ModelError> for ValueExtractionError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

#[derive(Clone)]
enum BindingSource<'tree> {
    Expression(tree_sitter::Node<'tree>),
    Property {
        object: tree_sitter::Node<'tree>,
        property: String,
    },
}

#[derive(Clone)]
struct BindingDef<'tree> {
    declaration: tree_sitter::Node<'tree>,
    source: BindingSource<'tree>,
}

struct BindingIndex<'tree> {
    definitions: BTreeMap<String, BindingDef<'tree>>,
    ambiguous_ranges: BTreeMap<String, Vec<(usize, usize)>>,
    unsupported_destructuring: Vec<(usize, usize)>,
    shadowed_origin_names: BTreeSet<String>,
}

#[derive(Default)]
struct OriginFacts {
    session_bindings: BTreeSet<String>,
    supabase_user_result_bindings: BTreeSet<String>,
    verified_user_bindings: BTreeSet<String>,
    request_body_bindings: BTreeSet<String>,
}

#[derive(Clone)]
struct ResolvedValue {
    id: StableSemanticId,
    kind: ValueOriginKind,
    depth: usize,
}

pub fn extract_value_origins(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<ValueExtraction, ValueExtractionError> {
    let limits = limits.validate()?;
    let validator = StructuralRegistry::new(&[])?;
    validator.scan_language(language, path, source)?;
    let source = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;
    let digest =
        content_id("r3-value-source", &(path.as_str(), source)).map_err(ModelError::from)?;
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let bindings = build_binding_index(&nodes, source);
    let facts = collect_origin_facts(&bindings, source, adapter, limits);
    let mut resolver = ValueResolver::new(path, digest, source, adapter, limits, bindings, facts);

    resolver.emit_index_gaps()?;

    let binding_names: Vec<String> = resolver.bindings.definitions.keys().cloned().collect();
    for name in binding_names {
        let _ = resolver.resolve_binding(&name)?;
    }

    for node in nodes {
        match node.kind() {
            "member_expression" if !is_nested_member_prefix(node) && !is_call_function(node) => {
                if let Some(chain) = expression_chain(node, source)
                    && let Some(kind) = classify_member_chain(&chain, adapter, &resolver.facts)
                {
                    resolver.builder.value(
                        kind,
                        &chain.join("."),
                        Vec::new(),
                        0,
                        node.start_byte(),
                        node.end_byte(),
                    )?;
                }
            }
            "subscript_expression" => {
                let _ = resolver.resolve_expression(node)?;
            }
            "call_expression" => {
                if classify_supported_call(node, source, adapter).is_some() {
                    let _ = resolver.resolve_expression(node)?;
                }
            }
            _ => {}
        }
    }

    Ok(resolver.finish())
}

struct ValueBuilder<'a> {
    path: &'a NormalizedRepoPath,
    digest: String,
    limits: BusinessLogicLimits,
    values: BTreeMap<String, ValueOrigin>,
    gaps: BTreeMap<(ValueCoverageGapReason, usize, usize), ValueCoverageGap>,
}

impl<'a> ValueBuilder<'a> {
    fn new(path: &'a NormalizedRepoPath, digest: String, limits: BusinessLogicLimits) -> Self {
        Self {
            path,
            digest,
            limits,
            values: BTreeMap::new(),
            gaps: BTreeMap::new(),
        }
    }

    fn location(&self, start: usize, end: usize) -> Result<SourceLocation, ValueExtractionError> {
        Ok(SourceLocation::new(
            self.path.clone(),
            start,
            end,
            self.digest.clone(),
        )?)
    }

    fn value(
        &mut self,
        kind: ValueOriginKind,
        semantic_key: &str,
        mut inputs: Vec<StableSemanticId>,
        depth: usize,
        start: usize,
        end: usize,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        inputs.sort();
        inputs.dedup();
        if inputs.len() > self.limits.max_derivation_fan_in {
            self.gap(ValueCoverageGapReason::DerivationFanInExceeded, start, end)?;
            return self.unknown("fan-in-cap", start, end);
        }
        if depth > self.limits.max_derivation_depth {
            self.gap(ValueCoverageGapReason::DerivationDepthExceeded, start, end)?;
            return self.unknown("depth-cap", start, end);
        }

        let start_text = start.to_string();
        let end_text = end.to_string();
        let input_key = if inputs.is_empty() {
            "none".to_owned()
        } else {
            let input_ids: Vec<&str> = inputs.iter().map(StableSemanticId::as_str).collect();
            content_id("r3.value-derivation-inputs", &input_ids).map_err(ModelError::from)?
        };
        let value_id = StableSemanticId::from_parts(
            "r3.value-origin",
            &[
                self.path.as_str(),
                value_kind_key(kind),
                semantic_key,
                &input_key,
                &start_text,
                &end_text,
            ],
            self.limits,
        )?;
        let key = value_id.as_str().to_owned();
        if !self.values.contains_key(&key) && self.values.len() >= MAX_VALUE_ORIGINS {
            return Err(ValueExtractionError::TooManyValues {
                count: self.values.len().saturating_add(1),
                max: MAX_VALUE_ORIGINS,
            });
        }
        let value = ValueOrigin::new(
            value_id.clone(),
            kind,
            semantic_key,
            None,
            inputs,
            depth,
            vec![self.location(start, end)?],
            self.limits,
        )?;
        self.values.insert(key, value);
        Ok(ResolvedValue {
            id: value_id,
            kind,
            depth,
        })
    }

    fn unknown(
        &mut self,
        reason: &str,
        start: usize,
        end: usize,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        let semantic_key = format!("unknown:{reason}@{start}:{end}");
        self.value(
            ValueOriginKind::Unknown,
            &semantic_key,
            Vec::new(),
            0,
            start,
            end,
        )
    }

    fn gap(
        &mut self,
        reason: ValueCoverageGapReason,
        start: usize,
        end: usize,
    ) -> Result<(), ValueExtractionError> {
        let key = (reason, start, end);
        if !self.gaps.contains_key(&key) && self.gaps.len() >= MAX_VALUE_COVERAGE_GAPS {
            return Err(ValueExtractionError::TooManyCoverageGaps {
                count: self.gaps.len().saturating_add(1),
                max: MAX_VALUE_COVERAGE_GAPS,
            });
        }
        self.gaps.insert(
            key,
            ValueCoverageGap {
                reason,
                provenance: self.location(start, end)?,
            },
        );
        Ok(())
    }

    fn finish(self) -> ValueExtraction {
        ValueExtraction {
            values: self.values.into_values().collect(),
            gaps: self.gaps.into_values().collect(),
        }
    }
}

struct ValueResolver<'a, 'tree> {
    source: &'a str,
    adapter: RouteAdapter,
    limits: BusinessLogicLimits,
    bindings: BindingIndex<'tree>,
    facts: OriginFacts,
    builder: ValueBuilder<'a>,
    binding_cache: BTreeMap<String, ResolvedValue>,
    resolving: BTreeSet<String>,
}

impl<'a, 'tree> ValueResolver<'a, 'tree> {
    fn new(
        path: &'a NormalizedRepoPath,
        digest: String,
        source: &'a str,
        adapter: RouteAdapter,
        limits: BusinessLogicLimits,
        bindings: BindingIndex<'tree>,
        facts: OriginFacts,
    ) -> Self {
        Self {
            source,
            adapter,
            limits,
            bindings,
            facts,
            builder: ValueBuilder::new(path, digest, limits),
            binding_cache: BTreeMap::new(),
            resolving: BTreeSet::new(),
        }
    }

    fn emit_index_gaps(&mut self) -> Result<(), ValueExtractionError> {
        for ranges in self.bindings.ambiguous_ranges.values() {
            for &(start, end) in ranges {
                self.builder
                    .gap(ValueCoverageGapReason::AmbiguousBinding, start, end)?;
            }
        }
        for &(start, end) in &self.bindings.unsupported_destructuring {
            self.builder
                .gap(ValueCoverageGapReason::UnsupportedDestructuring, start, end)?;
        }
        Ok(())
    }

    fn finish(self) -> ValueExtraction {
        self.builder.finish()
    }

    fn resolve_binding(&mut self, name: &str) -> Result<ResolvedValue, ValueExtractionError> {
        if let Some(value) = self.binding_cache.get(name) {
            return Ok(value.clone());
        }
        if let Some(ranges) = self.bindings.ambiguous_ranges.get(name) {
            let (start, end) = ranges.first().copied().unwrap_or((0, 0));
            return self.builder.unknown("ambiguous-binding", start, end);
        }
        let Some(definition) = self.bindings.definitions.get(name).cloned() else {
            return self.builder.unknown("unresolved-binding", 0, 0);
        };
        if !self.resolving.insert(name.to_owned()) {
            self.builder.gap(
                ValueCoverageGapReason::AmbiguousBinding,
                definition.declaration.start_byte(),
                definition.declaration.end_byte(),
            )?;
            return self.builder.unknown(
                "cyclic-binding",
                definition.declaration.start_byte(),
                definition.declaration.end_byte(),
            );
        }

        let source_value = match &definition.source {
            BindingSource::Expression(expression) => self.resolve_expression(*expression)?,
            BindingSource::Property { object, property } => {
                self.resolve_property(*object, property, definition.declaration)?
            }
        };
        self.resolving.remove(name);

        let depth = source_value.depth.saturating_add(1);
        let result = if depth > self.limits.max_derivation_depth {
            self.builder.gap(
                ValueCoverageGapReason::DerivationDepthExceeded,
                definition.declaration.start_byte(),
                definition.declaration.end_byte(),
            )?;
            self.builder.unknown(
                "binding-depth-cap",
                definition.declaration.start_byte(),
                definition.declaration.end_byte(),
            )?
        } else {
            let kind = if source_value.kind == ValueOriginKind::Unknown {
                ValueOriginKind::Unknown
            } else {
                ValueOriginKind::SupportedDerived
            };
            self.builder.value(
                kind,
                &format!("binding:{name}"),
                vec![source_value.id],
                depth,
                definition.declaration.start_byte(),
                definition.declaration.end_byte(),
            )?
        };
        self.binding_cache.insert(name.to_owned(), result.clone());
        Ok(result)
    }

    fn resolve_property(
        &mut self,
        object: tree_sitter::Node<'tree>,
        property: &str,
        provenance: tree_sitter::Node<'tree>,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        if let Some(mut chain) = expression_chain(unwrap_expression(object), self.source) {
            chain.push(property.to_owned());
            if let Some(kind) = classify_member_chain(&chain, self.adapter, &self.facts) {
                return self.builder.value(
                    kind,
                    &format!("destructure-source:{}", chain.join(".")),
                    Vec::new(),
                    0,
                    provenance.start_byte(),
                    provenance.end_byte(),
                );
            }
        }

        let source_value = self.resolve_expression(object)?;
        let depth = source_value.depth.saturating_add(1);
        if depth > self.limits.max_derivation_depth {
            self.builder.gap(
                ValueCoverageGapReason::DerivationDepthExceeded,
                provenance.start_byte(),
                provenance.end_byte(),
            )?;
            return self.builder.unknown(
                "property-depth-cap",
                provenance.start_byte(),
                provenance.end_byte(),
            );
        }
        let kind = if source_value.kind == ValueOriginKind::Unknown {
            ValueOriginKind::Unknown
        } else {
            ValueOriginKind::SupportedDerived
        };
        self.builder.value(
            kind,
            &format!("derived-member:{property}"),
            vec![source_value.id],
            depth,
            provenance.start_byte(),
            provenance.end_byte(),
        )
    }

    fn resolve_expression(
        &mut self,
        node: tree_sitter::Node<'tree>,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        let node = unwrap_expression(node);
        match node.kind() {
            "identifier" => self.resolve_identifier(node),
            "member_expression" => self.resolve_member(node),
            "subscript_expression" => self.resolve_subscript(node),
            "call_expression" => self.resolve_call(node),
            "array" => self.resolve_array(node),
            kind if is_literal_kind(kind) => self.builder.value(
                ValueOriginKind::Constant,
                &format!("constant@{}:{}", node.start_byte(), node.end_byte()),
                Vec::new(),
                0,
                node.start_byte(),
                node.end_byte(),
            ),
            _ => {
                self.builder.gap(
                    ValueCoverageGapReason::DynamicExpression,
                    node.start_byte(),
                    node.end_byte(),
                )?;
                self.builder
                    .unknown(node.kind(), node.start_byte(), node.end_byte())
            }
        }
    }

    fn resolve_identifier(
        &mut self,
        node: tree_sitter::Node<'tree>,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        let Some(name) = node_text(node, self.source) else {
            return self
                .builder
                .unknown("identifier-text", node.start_byte(), node.end_byte());
        };
        if let Some(ranges) = self.bindings.ambiguous_ranges.get(name) {
            let (start, end) = ranges
                .first()
                .copied()
                .unwrap_or((node.start_byte(), node.end_byte()));
            return self.builder.unknown("ambiguous-identifier", start, end);
        }
        if !self.bindings.definitions.contains_key(name) {
            self.builder.gap(
                ValueCoverageGapReason::AmbiguousBinding,
                node.start_byte(),
                node.end_byte(),
            )?;
            return self
                .builder
                .unknown("unbound-identifier", node.start_byte(), node.end_byte());
        }
        let binding = self.resolve_binding(name)?;
        self.builder.value(
            if binding.kind == ValueOriginKind::Unknown {
                ValueOriginKind::Unknown
            } else {
                ValueOriginKind::SupportedDerived
            },
            &format!("use:{name}"),
            vec![binding.id],
            binding.depth,
            node.start_byte(),
            node.end_byte(),
        )
    }

    fn resolve_member(
        &mut self,
        node: tree_sitter::Node<'tree>,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        if let Some(chain) = expression_chain(node, self.source)
            && let Some(kind) = classify_member_chain(&chain, self.adapter, &self.facts)
        {
            return self.builder.value(
                kind,
                &chain.join("."),
                Vec::new(),
                0,
                node.start_byte(),
                node.end_byte(),
            );
        }

        let Some(object) = node.child_by_field_name("object") else {
            self.builder.gap(
                ValueCoverageGapReason::DynamicExpression,
                node.start_byte(),
                node.end_byte(),
            )?;
            return self
                .builder
                .unknown("member-object", node.start_byte(), node.end_byte());
        };
        let Some(property) = node.child_by_field_name("property") else {
            self.builder.gap(
                ValueCoverageGapReason::DynamicExpression,
                node.start_byte(),
                node.end_byte(),
            )?;
            return self
                .builder
                .unknown("member-property", node.start_byte(), node.end_byte());
        };
        let Some(property) = node_text(property, self.source).filter(|value| is_identifier(value))
        else {
            self.builder.gap(
                ValueCoverageGapReason::DynamicExpression,
                node.start_byte(),
                node.end_byte(),
            )?;
            return self
                .builder
                .unknown("dynamic-member", node.start_byte(), node.end_byte());
        };

        let source_value = self.resolve_expression(object)?;
        let depth = source_value.depth.saturating_add(1);
        if depth > self.limits.max_derivation_depth {
            self.builder.gap(
                ValueCoverageGapReason::DerivationDepthExceeded,
                node.start_byte(),
                node.end_byte(),
            )?;
            return self
                .builder
                .unknown("member-depth-cap", node.start_byte(), node.end_byte());
        }
        self.builder.value(
            if source_value.kind == ValueOriginKind::Unknown {
                ValueOriginKind::Unknown
            } else {
                ValueOriginKind::SupportedDerived
            },
            &format!("member:{property}"),
            vec![source_value.id],
            depth,
            node.start_byte(),
            node.end_byte(),
        )
    }

    fn resolve_subscript(
        &mut self,
        node: tree_sitter::Node<'tree>,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        let object = node.child_by_field_name("object");
        let index = node.child_by_field_name("index");
        if let (Some(object), Some(index)) = (object, index)
            && let Some(property) = static_string_identifier(index, self.source)
        {
            if let Some(mut chain) = expression_chain(unwrap_expression(object), self.source) {
                chain.push(property.clone());
                if let Some(kind) = classify_member_chain(&chain, self.adapter, &self.facts) {
                    return self.builder.value(
                        kind,
                        &chain.join("."),
                        Vec::new(),
                        0,
                        node.start_byte(),
                        node.end_byte(),
                    );
                }
            }
            let source_value = self.resolve_expression(object)?;
            let depth = source_value.depth.saturating_add(1);
            if depth <= self.limits.max_derivation_depth {
                return self.builder.value(
                    if source_value.kind == ValueOriginKind::Unknown {
                        ValueOriginKind::Unknown
                    } else {
                        ValueOriginKind::SupportedDerived
                    },
                    &format!("subscript:{property}"),
                    vec![source_value.id],
                    depth,
                    node.start_byte(),
                    node.end_byte(),
                );
            }
        }

        self.builder.gap(
            ValueCoverageGapReason::DynamicExpression,
            node.start_byte(),
            node.end_byte(),
        )?;
        self.builder
            .unknown("dynamic-subscript", node.start_byte(), node.end_byte())
    }

    fn resolve_call(
        &mut self,
        node: tree_sitter::Node<'tree>,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        if let Some((kind, semantic_key)) = classify_supported_call(node, self.source, self.adapter)
        {
            return self.builder.value(
                kind,
                semantic_key,
                Vec::new(),
                0,
                node.start_byte(),
                node.end_byte(),
            );
        }
        if is_auth_call(node, self.source) || is_supabase_get_user_call(node, self.source) {
            return self
                .builder
                .unknown("auth-object", node.start_byte(), node.end_byte());
        }
        self.builder.gap(
            ValueCoverageGapReason::DynamicExpression,
            node.start_byte(),
            node.end_byte(),
        )?;
        self.builder
            .unknown("unsupported-call", node.start_byte(), node.end_byte())
    }

    fn resolve_array(
        &mut self,
        node: tree_sitter::Node<'tree>,
    ) -> Result<ResolvedValue, ValueExtractionError> {
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        if children.len() > self.limits.max_derivation_fan_in {
            self.builder.gap(
                ValueCoverageGapReason::DerivationFanInExceeded,
                node.start_byte(),
                node.end_byte(),
            )?;
            return self
                .builder
                .unknown("array-fan-in-cap", node.start_byte(), node.end_byte());
        }

        let mut inputs = Vec::with_capacity(children.len());
        let mut max_depth = 0;
        let mut any_unknown = false;
        for child in children {
            let value = self.resolve_expression(child)?;
            any_unknown |= value.kind == ValueOriginKind::Unknown;
            max_depth = max_depth.max(value.depth);
            inputs.push(value.id);
        }
        let depth = max_depth.saturating_add(1);
        if depth > self.limits.max_derivation_depth {
            self.builder.gap(
                ValueCoverageGapReason::DerivationDepthExceeded,
                node.start_byte(),
                node.end_byte(),
            )?;
            return self
                .builder
                .unknown("array-depth-cap", node.start_byte(), node.end_byte());
        }
        self.builder.value(
            if any_unknown {
                ValueOriginKind::Unknown
            } else {
                ValueOriginKind::SupportedDerived
            },
            &format!("array@{}:{}", node.start_byte(), node.end_byte()),
            inputs,
            depth,
            node.start_byte(),
            node.end_byte(),
        )
    }
}

fn build_binding_index<'tree>(
    nodes: &[tree_sitter::Node<'tree>],
    source: &str,
) -> BindingIndex<'tree> {
    let mut occurrences: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    let mut mutated = BTreeSet::new();
    let mut unsupported_destructuring = Vec::new();
    let mut shadowed_origin_names = BTreeSet::new();

    for &node in nodes {
        match node.kind() {
            "variable_declarator" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let names = pattern_binding_names(name, source);
                    for binding in names {
                        occurrences
                            .entry(binding.clone())
                            .or_default()
                            .push((name.start_byte(), name.end_byte()));
                        shadowed_origin_names.insert(binding);
                    }
                    if name.kind() == "object_pattern"
                        && object_pattern_bindings(name, source).is_none()
                    {
                        unsupported_destructuring.push((name.start_byte(), name.end_byte()));
                    }
                }
            }
            "formal_parameters" => {
                for binding in pattern_binding_names(node, source) {
                    occurrences
                        .entry(binding.clone())
                        .or_default()
                        .push((node.start_byte(), node.end_byte()));
                    shadowed_origin_names.insert(binding);
                }
            }
            "function_declaration" | "class_declaration" => {
                if let Some(name) = node.child_by_field_name("name")
                    && let Some(binding) = node_text(name, source)
                {
                    shadowed_origin_names.insert(binding.to_owned());
                }
            }
            "assignment_expression" | "augmented_assignment_expression" | "update_expression" => {
                if let Some(target) = node
                    .child_by_field_name("left")
                    .or_else(|| node.child_by_field_name("argument"))
                    .or_else(|| node.named_child(0))
                {
                    mutated.extend(pattern_binding_names(target, source));
                }
            }
            _ => {}
        }
    }

    let mut ambiguous_ranges = BTreeMap::new();
    for (name, ranges) in &occurrences {
        if ranges.len() != 1 || mutated.contains(name) {
            ambiguous_ranges.insert(name.clone(), ranges.clone());
        }
    }

    let mut definitions = BTreeMap::new();
    for &node in nodes {
        if node.kind() != "variable_declarator" || !is_const_declarator(node, source) {
            continue;
        }
        let Some(name_node) = node.child_by_field_name("name") else {
            continue;
        };
        let Some(value_node) = node.child_by_field_name("value") else {
            continue;
        };
        match name_node.kind() {
            "identifier" => {
                if let Some(name) = node_text(name_node, source)
                    && !ambiguous_ranges.contains_key(name)
                {
                    definitions.insert(
                        name.to_owned(),
                        BindingDef {
                            declaration: node,
                            source: BindingSource::Expression(value_node),
                        },
                    );
                }
            }
            "object_pattern" => {
                if let Some(bindings) = object_pattern_bindings(name_node, source) {
                    for (property, binding, binding_node) in bindings {
                        if !ambiguous_ranges.contains_key(&binding) {
                            definitions.insert(
                                binding,
                                BindingDef {
                                    declaration: binding_node,
                                    source: BindingSource::Property {
                                        object: value_node,
                                        property,
                                    },
                                },
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    BindingIndex {
        definitions,
        ambiguous_ranges,
        unsupported_destructuring,
        shadowed_origin_names,
    }
}

fn collect_origin_facts(
    bindings: &BindingIndex<'_>,
    source: &str,
    adapter: RouteAdapter,
    limits: BusinessLogicLimits,
) -> OriginFacts {
    let mut facts = OriginFacts::default();
    let rounds = limits.max_derivation_depth.min(32);
    for _ in 0..rounds {
        let mut changed = false;
        for (name, definition) in &bindings.definitions {
            let BindingSource::Expression(value) = &definition.source else {
                continue;
            };
            let value = unwrap_expression(*value);
            if adapter == RouteAdapter::NextApp
                && !bindings.shadowed_origin_names.contains("auth")
                && is_auth_call(value, source)
            {
                changed |= facts.session_bindings.insert(name.clone());
            }
            if adapter == RouteAdapter::SupabaseEdge
                && !bindings.shadowed_origin_names.contains("supabase")
                && is_supabase_get_user_call(value, source)
            {
                changed |= facts.supabase_user_result_bindings.insert(name.clone());
            }
            if is_request_json_call(value, source, adapter) {
                changed |= facts.request_body_bindings.insert(name.clone());
            }
            if let Some(chain) = expression_chain(value, source) {
                if chain.len() == 2 && chain[0] == "req" && chain[1] == "body" {
                    changed |= facts.request_body_bindings.insert(name.clone());
                }
                if chain.len() == 1 {
                    let root = &chain[0];
                    if facts.session_bindings.contains(root) {
                        changed |= facts.session_bindings.insert(name.clone());
                    }
                    if facts.supabase_user_result_bindings.contains(root) {
                        changed |= facts.supabase_user_result_bindings.insert(name.clone());
                    }
                    if facts.verified_user_bindings.contains(root) {
                        changed |= facts.verified_user_bindings.insert(name.clone());
                    }
                    if facts.request_body_bindings.contains(root) {
                        changed |= facts.request_body_bindings.insert(name.clone());
                    }
                }
                if chain.len() == 2
                    && facts.session_bindings.contains(&chain[0])
                    && chain[1] == "user"
                {
                    changed |= facts.verified_user_bindings.insert(name.clone());
                }
                if chain.len() == 3
                    && facts.supabase_user_result_bindings.contains(&chain[0])
                    && chain[1] == "data"
                    && chain[2] == "user"
                {
                    changed |= facts.verified_user_bindings.insert(name.clone());
                }
            }
        }
        if !changed {
            break;
        }
    }
    facts
}

fn classify_member_chain(
    chain: &[String],
    adapter: RouteAdapter,
    facts: &OriginFacts,
) -> Option<ValueOriginKind> {
    let root = chain.first()?.as_str();
    if facts.request_body_bindings.contains(root) {
        return Some(ValueOriginKind::RequestBody);
    }

    match adapter {
        RouteAdapter::Express => {
            if root != "req" {
                return None;
            }
            match chain.get(1).map(String::as_str)? {
                "params" => Some(ValueOriginKind::RequestPath),
                "query" => Some(ValueOriginKind::RequestQuery),
                "body" => Some(ValueOriginKind::RequestBody),
                "headers" | "header" => Some(ValueOriginKind::RequestHeader),
                "user" => classify_identity_field(chain.get(2).map(String::as_str)),
                _ => None,
            }
        }
        RouteAdapter::NextPagesApi => {
            if root != "req" {
                return None;
            }
            match chain.get(1).map(String::as_str)? {
                "query" => Some(ValueOriginKind::RequestQuery),
                "body" => Some(ValueOriginKind::RequestBody),
                "headers" | "header" => Some(ValueOriginKind::RequestHeader),
                _ => None,
            }
        }
        RouteAdapter::NextApp => {
            if root == "context" && chain.get(1).map(String::as_str) == Some("params") {
                return Some(ValueOriginKind::RequestPath);
            }
            if root == "request" && chain.get(1).map(String::as_str) == Some("headers") {
                return Some(ValueOriginKind::RequestHeader);
            }
            if root == "request"
                && chain.get(1).map(String::as_str) == Some("nextUrl")
                && chain.get(2).map(String::as_str) == Some("searchParams")
            {
                return Some(ValueOriginKind::RequestQuery);
            }
            if facts.session_bindings.contains(root)
                && chain.get(1).map(String::as_str) == Some("user")
            {
                return classify_identity_field(chain.get(2).map(String::as_str));
            }
            if facts.verified_user_bindings.contains(root) {
                return classify_identity_field(chain.get(1).map(String::as_str));
            }
            None
        }
        RouteAdapter::SupabaseEdge => {
            if root == "request" && chain.get(1).map(String::as_str) == Some("headers") {
                return Some(ValueOriginKind::RequestHeader);
            }
            if facts.verified_user_bindings.contains(root) {
                return classify_identity_field(chain.get(1).map(String::as_str));
            }
            if facts.supabase_user_result_bindings.contains(root)
                && chain.get(1).map(String::as_str) == Some("data")
                && chain.get(2).map(String::as_str) == Some("user")
            {
                return classify_identity_field(chain.get(3).map(String::as_str));
            }
            None
        }
    }
}

fn classify_identity_field(field: Option<&str>) -> Option<ValueOriginKind> {
    match field? {
        "id" | "sub" | "user_id" | "userId" => Some(ValueOriginKind::AuthenticatedUserId),
        "tenant" | "tenant_id" | "tenantId" | "organization_id" | "organizationId" => {
            Some(ValueOriginKind::AuthenticatedTenantId)
        }
        "role" | "roles" => Some(ValueOriginKind::AuthenticatedRole),
        _ => None,
    }
}

fn classify_supported_call<'a>(
    node: tree_sitter::Node<'_>,
    source: &'a str,
    adapter: RouteAdapter,
) -> Option<(ValueOriginKind, &'static str)> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    let chain = expression_chain(function, source)?;
    match adapter {
        RouteAdapter::Express | RouteAdapter::NextPagesApi => {
            if chain.len() == 2
                && chain[0] == "req"
                && matches!(chain[1].as_str(), "get" | "header")
            {
                Some((ValueOriginKind::RequestHeader, "req.header()"))
            } else {
                None
            }
        }
        RouteAdapter::NextApp => {
            if chain == ["request", "json"] {
                return Some((ValueOriginKind::RequestBody, "request.json()"));
            }
            if chain == ["request", "headers", "get"] {
                return Some((ValueOriginKind::RequestHeader, "request.headers.get()"));
            }
            if chain == ["request", "nextUrl", "searchParams", "get"] {
                return Some((
                    ValueOriginKind::RequestQuery,
                    "request.nextUrl.searchParams.get()",
                ));
            }
            None
        }
        RouteAdapter::SupabaseEdge => {
            if chain == ["request", "json"] {
                return Some((ValueOriginKind::RequestBody, "request.json()"));
            }
            if chain == ["request", "headers", "get"] {
                return Some((ValueOriginKind::RequestHeader, "request.headers.get()"));
            }
            None
        }
    }
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
        ValueExtractionError::ParseFailed("value parser returned no syntax tree".to_owned())
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

fn is_const_declarator(node: tree_sitter::Node<'_>, source: &str) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "lexical_declaration"
            && node_text(parent, source).is_some_and(|text| text.trim_start().starts_with("const "))
    })
}

fn object_pattern_bindings<'tree>(
    pattern: tree_sitter::Node<'tree>,
    source: &str,
) -> Option<Vec<(String, String, tree_sitter::Node<'tree>)>> {
    let mut bindings = Vec::new();
    let mut cursor = pattern.walk();
    for child in pattern.named_children(&mut cursor) {
        match child.kind() {
            "shorthand_property_identifier_pattern" | "shorthand_property_identifier" => {
                let name = node_text(child, source)?;
                if !is_identifier(name) {
                    return None;
                }
                bindings.push((name.to_owned(), name.to_owned(), child));
            }
            "pair_pattern" => {
                let key = child.child_by_field_name("key")?;
                let value = child.child_by_field_name("value")?;
                let property = node_text(key, source)?;
                let binding = node_text(value, source)?;
                if !is_identifier(property)
                    || value.kind() != "identifier"
                    || !is_identifier(binding)
                {
                    return None;
                }
                bindings.push((property.to_owned(), binding.to_owned(), child));
            }
            "rest_pattern" => return None,
            _ => return None,
        }
    }
    if bindings.is_empty() {
        None
    } else {
        Some(bindings)
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
            .is_some_and(|chain| chain == ["request", "json"])
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

fn static_string_identifier(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    let node = unwrap_expression(node);
    if node.kind() != "string" {
        return None;
    }
    let text = node_text(node, source)?;
    if text.len() < 2 {
        return None;
    }
    let value = &text[1..text.len() - 1];
    is_identifier(value).then(|| value.to_owned())
}

fn is_nested_member_prefix(node: tree_sitter::Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.kind() == "member_expression"
        && parent.child_by_field_name("object").is_some_and(|object| {
            object.start_byte() == node.start_byte() && object.end_byte() == node.end_byte()
        })
}

fn is_call_function(node: tree_sitter::Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| {
                    function.start_byte() == node.start_byte()
                        && function.end_byte() == node.end_byte()
                })
    })
}

fn is_literal_kind(kind: &str) -> bool {
    matches!(kind, "string" | "number" | "true" | "false" | "null")
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

const fn value_kind_key(kind: ValueOriginKind) -> &'static str {
    match kind {
        ValueOriginKind::RequestPath => "request-path",
        ValueOriginKind::RequestQuery => "request-query",
        ValueOriginKind::RequestBody => "request-body",
        ValueOriginKind::RequestHeader => "request-header",
        ValueOriginKind::AuthenticatedUserId => "authenticated-user-id",
        ValueOriginKind::AuthenticatedTenantId => "authenticated-tenant-id",
        ValueOriginKind::AuthenticatedRole => "authenticated-role",
        ValueOriginKind::Constant => "constant",
        ValueOriginKind::SupportedDerived => "supported-derived",
        ValueOriginKind::DatabaseResult => "database-result",
        ValueOriginKind::Unknown => "unknown",
    }
}
