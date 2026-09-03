//! Scope and adapter-seam qualification for bounded R3 value-origin derivation.
//!
//! The lower value extractor deliberately recognizes only static syntax. This qualifier prevents
//! file-wide lexical coincidences from becoming cross-handler or cross-scope value equivalence.
//! Only values proven to live in a supported handler scope survive with their typed origin; unsafe
//! or unresolved scope relationships degrade to UNKNOWN with fail-visible coverage.

use std::collections::{BTreeMap, BTreeSet};

pub(crate) use super::model;
use super::model::{
    BusinessLogicLimits, SourceLocation, StableSemanticId, ValueOrigin, ValueOriginKind,
};
pub(crate) use super::route;
use super::route::RouteAdapter;
use crate::structural::{StructuralError, StructuralLanguage};
use crate::view::NormalizedRepoPath;

#[path = "value.rs"]
mod core;

pub use core::{
    MAX_VALUE_AST_NODES, MAX_VALUE_COVERAGE_GAPS, MAX_VALUE_ORIGINS,
    STATIC_VALUE_DERIVATION_PROVES_RUNTIME_VALUE, ValueCoverageGapReason, ValueExtractionError,
};

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct HandlerScope {
    start: usize,
    end: usize,
    request_parameter: Option<String>,
    context_parameter: Option<String>,
}

impl HandlerScope {
    fn contains(&self, start: usize, end: usize) -> bool {
        self.start <= start && end <= self.end
    }
}

pub fn extract_value_origins(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<ValueExtraction, ValueExtractionError> {
    let limits = limits.validate().map_err(ValueExtractionError::Model)?;
    let raw = core::extract_value_origins(adapter, language, path, source, limits)?;
    let source = std::str::from_utf8(source)
        .map_err(|_| ValueExtractionError::Structural(StructuralError::NonUtf8Source))?;
    let tree = parse_tree(language, source)?;
    let nodes = collect_nodes(tree.root_node())?;
    let handlers = collect_verified_handlers(&nodes, source, adapter);

    let values_by_id: BTreeMap<String, &ValueOrigin> = raw
        .values()
        .iter()
        .map(|value| (value.value_id().as_str().to_owned(), value))
        .collect();
    let mut unsafe_ids = BTreeSet::new();

    for value in raw.values() {
        if !value_is_scope_safe(value, &nodes, source, &handlers) {
            unsafe_ids.insert(value.value_id().as_str().to_owned());
        }
    }

    loop {
        let mut changed = false;
        for value in raw.values() {
            let id = value.value_id().as_str();
            if unsafe_ids.contains(id) {
                continue;
            }
            let has_unsafe_or_missing_input = value.derivation_inputs().iter().any(|input| {
                unsafe_ids.contains(input.as_str()) || !values_by_id.contains_key(input.as_str())
            });
            if has_unsafe_or_missing_input {
                changed |= unsafe_ids.insert(id.to_owned());
            }
        }
        if !changed {
            break;
        }
    }

    let mut gaps = BTreeMap::new();
    for gap in raw.gaps() {
        let reason = if gap.reason() == ValueCoverageGapReason::DynamicExpression
            && is_static_subscript_range(
                &nodes,
                source,
                gap.provenance().start_byte(),
                gap.provenance().end_byte(),
            ) {
            ValueCoverageGapReason::DerivationDepthExceeded
        } else {
            gap.reason()
        };
        insert_gap(
            &mut gaps,
            ValueCoverageGap {
                reason,
                provenance: gap.provenance().clone(),
            },
        )?;
    }

    let mut values = BTreeMap::new();
    let mut unsafe_ranges = BTreeMap::<(usize, usize), SourceLocation>::new();
    for value in raw.values() {
        if unsafe_ids.contains(value.value_id().as_str()) {
            if let Some(location) = value.provenance().first() {
                unsafe_ranges
                    .entry((location.start_byte(), location.end_byte()))
                    .or_insert_with(|| location.clone());
            }
            continue;
        }
        values.insert(value.value_id().as_str().to_owned(), value.clone());
    }

    for location in cross_scope_binding_use_ranges(&raw, &nodes, source, &handlers)? {
        unsafe_ranges
            .entry((location.start_byte(), location.end_byte()))
            .or_insert(location);
    }

    for ((start, end), location) in unsafe_ranges {
        insert_gap(
            &mut gaps,
            ValueCoverageGap {
                reason: ValueCoverageGapReason::AmbiguousBinding,
                provenance: location.clone(),
            },
        )?;
        let start_text = start.to_string();
        let end_text = end.to_string();
        let unknown_id = StableSemanticId::from_parts(
            "r3.value-scope-unknown",
            &[path.as_str(), &start_text, &end_text],
            limits,
        )
        .map_err(ValueExtractionError::Model)?;
        let unknown = ValueOrigin::new(
            unknown_id.clone(),
            ValueOriginKind::Unknown,
            format!("unknown:scope@{start}:{end}"),
            None,
            Vec::new(),
            0,
            vec![location],
            limits,
        )
        .map_err(ValueExtractionError::Model)?;
        values.insert(unknown_id.as_str().to_owned(), unknown);
    }

    Ok(ValueExtraction {
        values: values.into_values().collect(),
        gaps: gaps.into_values().collect(),
    })
}

fn value_is_scope_safe(
    value: &ValueOrigin,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    handlers: &[HandlerScope],
) -> bool {
    let Some(location) = value.provenance().first() else {
        return false;
    };
    let Some(handler) =
        handler_for_range(handlers, nodes, location.start_byte(), location.end_byte())
    else {
        return false;
    };

    match value.origin_kind() {
        ValueOriginKind::DatabaseResult => false,
        ValueOriginKind::RequestPath
        | ValueOriginKind::RequestQuery
        | ValueOriginKind::RequestBody
        | ValueOriginKind::RequestHeader
        | ValueOriginKind::AuthenticatedUserId
        | ValueOriginKind::AuthenticatedTenantId
        | ValueOriginKind::AuthenticatedRole => {
            direct_origin_is_bound(value, nodes, source, handler, location.start_byte())
        }
        ValueOriginKind::SupportedDerived | ValueOriginKind::Unknown => {
            if let Some(name) = value.semantic_key().strip_prefix("use:") {
                visible_local_binding(nodes, source, handler, name, location.start_byte())
            } else {
                true
            }
        }
        ValueOriginKind::Constant => true,
    }
}

fn direct_origin_is_bound(
    value: &ValueOrigin,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    handler: &HandlerScope,
    use_offset: usize,
) -> bool {
    let Some(root) = semantic_root(value.semantic_key()) else {
        return false;
    };
    if handler.request_parameter.as_deref() == Some(root)
        || handler.context_parameter.as_deref() == Some(root)
    {
        return true;
    }
    visible_local_binding(nodes, source, handler, root, use_offset)
}

fn semantic_root(semantic_key: &str) -> Option<&str> {
    let key = semantic_key
        .strip_prefix("destructure-source:")
        .unwrap_or(semantic_key);
    let end = key.find(['.', '(', '[']).unwrap_or(key.len());
    let root = key.get(..end)?;
    is_identifier(root).then_some(root)
}

fn handler_for_range<'a>(
    handlers: &'a [HandlerScope],
    nodes: &[tree_sitter::Node<'_>],
    start: usize,
    end: usize,
) -> Option<&'a HandlerScope> {
    let function = innermost_function_for_range(nodes, start, end)?;
    handlers.iter().find(|handler| {
        handler.contains(start, end)
            && handler.start == function.start_byte()
            && handler.end == function.end_byte()
    })
}

fn visible_local_binding(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    handler: &HandlerScope,
    name: &str,
    use_offset: usize,
) -> bool {
    let mut matches = 0usize;
    for node in nodes {
        if node.kind() != "variable_declarator"
            || !handler.contains(node.start_byte(), node.end_byte())
        {
            continue;
        }
        let Some(function) =
            innermost_function_for_range(nodes, node.start_byte(), node.end_byte())
        else {
            continue;
        };
        if function.start_byte() != handler.start || function.end_byte() != handler.end {
            continue;
        }
        let Some(pattern) = node.child_by_field_name("name") else {
            continue;
        };
        if !pattern_binding_names(pattern, source)
            .iter()
            .any(|binding| binding == name)
        {
            continue;
        }
        if node.end_byte() > use_offset {
            continue;
        }
        let lexical = nearest_statement_block(*node, function).unwrap_or(function);
        if lexical.start_byte() <= use_offset && use_offset < lexical.end_byte() {
            matches = matches.saturating_add(1);
            if matches > 1 {
                return false;
            }
        }
    }
    matches == 1
}

fn cross_scope_binding_use_ranges(
    raw: &core::ValueExtraction,
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    handlers: &[HandlerScope],
) -> Result<Vec<SourceLocation>, ValueExtractionError> {
    let mut qualified_bindings = BTreeMap::<String, (HandlerScope, SourceLocation)>::new();
    for value in raw.values() {
        let Some(name) = value.semantic_key().strip_prefix("binding:") else {
            continue;
        };
        if value.origin_kind() == ValueOriginKind::Unknown
            || !value_is_scope_safe(value, nodes, source, handlers)
        {
            continue;
        }
        let Some(location) = value.provenance().first() else {
            continue;
        };
        let Some(handler) = handler_for_range(
            handlers,
            nodes,
            location.start_byte(),
            location.end_byte(),
        ) else {
            continue;
        };
        if raw
            .value_for_range(location.start_byte(), location.end_byte())
            .is_none()
        {
            continue;
        }
        qualified_bindings
            .entry(name.to_owned())
            .or_insert_with(|| (handler.clone(), location.clone()));
    }

    let mut ranges = BTreeMap::<(usize, usize), SourceLocation>::new();
    for node in nodes {
        if !identifier_is_binding_reference(*node) {
            continue;
        }
        let Some(name) = node_text(*node, source) else {
            continue;
        };
        let Some((handler, anchor)) = qualified_bindings.get(name) else {
            continue;
        };
        let same_function = innermost_function_for_range(
            nodes,
            node.start_byte(),
            node.end_byte(),
        )
        .is_some_and(|function| {
            function.start_byte() == handler.start && function.end_byte() == handler.end
        });
        if same_function {
            continue;
        }
        let location = SourceLocation::new(
            anchor.path().clone(),
            node.start_byte(),
            node.end_byte(),
            anchor.content_digest().to_owned(),
        )
        .map_err(ValueExtractionError::Model)?;
        ranges
            .entry((location.start_byte(), location.end_byte()))
            .or_insert(location);
    }
    Ok(ranges.into_values().collect())
}

fn identifier_is_binding_reference(node: tree_sitter::Node<'_>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let Some(parent) = node.parent() else {
        return false;
    };

    if parent.kind() == "member_expression"
        && parent
            .child_by_field_name("property")
            .is_some_and(|property| property.id() == node.id())
    {
        return false;
    }
    if matches!(parent.kind(), "pair" | "pair_pattern")
        && parent
            .child_by_field_name("key")
            .is_some_and(|key| key.id() == node.id())
    {
        return false;
    }

    let mut current = node;
    while let Some(ancestor) = current.parent() {
        if ancestor.kind() == "variable_declarator"
            && ancestor
                .child_by_field_name("name")
                .is_some_and(|name| {
                    name.start_byte() <= node.start_byte() && node.end_byte() <= name.end_byte()
                })
        {
            return false;
        }
        if matches!(
            ancestor.kind(),
            "import_statement"
                | "import_clause"
                | "import_specifier"
                | "namespace_import"
                | "named_imports"
        ) {
            return false;
        }
        if is_function_boundary(ancestor) {
            if ancestor
                .child_by_field_name("name")
                .is_some_and(|name| {
                    name.start_byte() <= node.start_byte() && node.end_byte() <= name.end_byte()
                })
                || ancestor
                    .child_by_field_name("parameters")
                    .or_else(|| ancestor.child_by_field_name("parameter"))
                    .is_some_and(|parameters| {
                        parameters.start_byte() <= node.start_byte()
                            && node.end_byte() <= parameters.end_byte()
                    })
            {
                return false;
            }
            break;
        }
        current = ancestor;
    }
    true
}

fn collect_verified_handlers(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    adapter: RouteAdapter,
) -> Vec<HandlerScope> {
    let mut handlers = Vec::new();
    for node in nodes {
        if !is_function_boundary(*node) {
            continue;
        }
        if !is_supported_handler(*node, source, adapter) {
            continue;
        }
        let parameters = function_parameter_names(*node, source);
        let request_parameter = parameters.first().cloned();
        let context_parameter = if adapter == RouteAdapter::NextApp {
            parameters.get(1).cloned()
        } else {
            None
        };
        handlers.push(HandlerScope {
            start: node.start_byte(),
            end: node.end_byte(),
            request_parameter,
            context_parameter,
        });
    }
    handlers.sort_by_key(|handler| (handler.start, handler.end));
    handlers.dedup_by_key(|handler| (handler.start, handler.end));
    handlers
}

fn is_supported_handler(node: tree_sitter::Node<'_>, source: &str, adapter: RouteAdapter) -> bool {
    match adapter {
        RouteAdapter::Express => {
            is_exported_named_function(node, source, "handler")
                || is_inline_express_route_callback(node, source)
        }
        RouteAdapter::NextPagesApi => is_exported_named_function(node, source, "handler"),
        RouteAdapter::NextApp => function_name(node, source).is_some_and(|name| {
            is_exported_function(node)
                && matches!(
                    name,
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD"
                )
        }),
        RouteAdapter::SupabaseEdge => is_deno_serve_callback(node, source),
    }
}

fn is_exported_named_function(node: tree_sitter::Node<'_>, source: &str, expected: &str) -> bool {
    is_exported_function(node) && function_name(node, source) == Some(expected)
}

fn is_exported_function(node: tree_sitter::Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "export_statement")
}

fn function_name<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name("name")
        .and_then(|name| node_text(name, source))
}

fn is_inline_express_route_callback(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let Some(call) = call_accepting_function(node) else {
        return false;
    };
    call.child_by_field_name("function")
        .and_then(|function| expression_chain(function, source))
        .is_some_and(|chain| {
            chain.len() == 2
                && matches!(chain[0].as_str(), "app" | "router")
                && matches!(
                    chain[1].as_str(),
                    "get"
                        | "post"
                        | "put"
                        | "patch"
                        | "delete"
                        | "options"
                        | "head"
                        | "all"
                        | "use"
                )
        })
}

fn is_deno_serve_callback(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let Some(call) = call_accepting_function(node) else {
        return false;
    };
    call.child_by_field_name("function")
        .and_then(|function| expression_chain(function, source))
        .is_some_and(|chain| chain == ["Deno", "serve"])
}

fn call_accepting_function(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let arguments = node.parent()?;
    if arguments.kind() != "arguments" {
        return None;
    }
    let call = arguments.parent()?;
    (call.kind() == "call_expression").then_some(call)
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

fn insert_gap(
    gaps: &mut BTreeMap<(ValueCoverageGapReason, usize, usize), ValueCoverageGap>,
    gap: ValueCoverageGap,
) -> Result<(), ValueExtractionError> {
    let key = (
        gap.reason,
        gap.provenance.start_byte(),
        gap.provenance.end_byte(),
    );
    if !gaps.contains_key(&key) && gaps.len() >= MAX_VALUE_COVERAGE_GAPS {
        return Err(ValueExtractionError::TooManyCoverageGaps {
            count: gaps.len().saturating_add(1),
            max: MAX_VALUE_COVERAGE_GAPS,
        });
    }
    gaps.insert(key, gap);
    Ok(())
}

fn is_static_subscript_range(
    nodes: &[tree_sitter::Node<'_>],
    source: &str,
    start: usize,
    end: usize,
) -> bool {
    nodes.iter().any(|node| {
        node.start_byte() == start
            && node.end_byte() == end
            && node.kind() == "subscript_expression"
            && node
                .child_by_field_name("index")
                .is_some_and(|index| static_string_identifier(index, source).is_some())
    })
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
        ValueExtractionError::ParseFailed("value scope parser returned no syntax tree".to_owned())
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
