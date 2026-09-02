//! Bounded R3 route extraction for the frozen initial JavaScript/TypeScript adapters.
//!
//! Repository source is data only. The caller selects a fixed Sentrdel-owned adapter and
//! grammar; this module never loads repository-provided grammars/rules, executes target code,
//! performs network access, or creates Findings.

use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::content_id;
use sentrdel_schema::coverage::CoverageState;

use super::model::{
    BusinessLogicLimits, FrameworkFamily, HttpMethod, ModelError, RouteObservation, SourceLocation,
    StableSemanticId,
};
use crate::structural::{StructuralError, StructuralLanguage, StructuralRegistry};
use crate::view::NormalizedRepoPath;

pub const MAX_ROUTE_OBSERVATIONS: usize = 4_096;
pub const MAX_ROUTE_COVERAGE_GAPS: usize = 4_096;
pub const MAX_ROUTE_CALLBACKS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RouteAdapter {
    Express,
    NextApp,
    NextPagesApi,
    SupabaseEdge,
}

impl RouteAdapter {
    #[must_use]
    pub const fn framework(self) -> FrameworkFamily {
        match self {
            Self::Express => FrameworkFamily::Express,
            Self::NextApp => FrameworkFamily::NextApp,
            Self::NextPagesApi => FrameworkFamily::NextPagesApi,
            Self::SupabaseEdge => FrameworkFamily::SupabaseEdge,
        }
    }

    const fn identity_key(self) -> &'static str {
        match self {
            Self::Express => "express",
            Self::NextApp => "next-app",
            Self::NextPagesApi => "next-pages-api",
            Self::SupabaseEdge => "supabase-edge",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RouteCoverageGapReason {
    DynamicRegistration,
    DynamicRoutePattern,
    UnsupportedMiddleware,
    UnresolvedCallback,
    UnsupportedRouteFile,
    UnsupportedHandlerExport,
    AmbiguousReceiverBinding,
    MethodNotStaticallyBound,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteCoverageGap {
    reason: RouteCoverageGapReason,
    adapter: RouteAdapter,
    provenance: SourceLocation,
}

impl RouteCoverageGap {
    #[must_use]
    pub const fn reason(&self) -> RouteCoverageGapReason {
        self.reason
    }

    #[must_use]
    pub const fn adapter(&self) -> RouteAdapter {
        self.adapter
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteExtraction {
    routes: Vec<RouteObservation>,
    gaps: Vec<RouteCoverageGap>,
}

impl RouteExtraction {
    #[must_use]
    pub fn routes(&self) -> &[RouteObservation] {
        &self.routes
    }

    #[must_use]
    pub fn gaps(&self) -> &[RouteCoverageGap] {
        &self.gaps
    }
}

#[derive(Debug)]
pub enum RouteExtractionError {
    Structural(StructuralError),
    Model(ModelError),
    TooManyRoutes { count: usize, max: usize },
    TooManyCoverageGaps { count: usize, max: usize },
    TooManyCallbacks { count: usize, max: usize },
}

impl fmt::Display for RouteExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structural(source) => {
                write!(formatter, "route structural validation failed: {source}")
            }
            Self::Model(source) => write!(formatter, "route model validation failed: {source}"),
            Self::TooManyRoutes { count, max } => {
                write!(
                    formatter,
                    "route observation count {count} exceeds cap {max}"
                )
            }
            Self::TooManyCoverageGaps { count, max } => {
                write!(
                    formatter,
                    "route coverage gap count {count} exceeds cap {max}"
                )
            }
            Self::TooManyCallbacks { count, max } => {
                write!(formatter, "route callback count {count} exceeds cap {max}")
            }
        }
    }
}

impl Error for RouteExtractionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Structural(source) => Some(source),
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<StructuralError> for RouteExtractionError {
    fn from(value: StructuralError) -> Self {
        Self::Structural(value)
    }
}

impl From<ModelError> for RouteExtractionError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub fn extract_routes(
    adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<RouteExtraction, RouteExtractionError> {
    let limits = limits.validate()?;

    // Reuse the fixed Sentrdel-owned grammar boundary from T008 solely to validate the
    // selected language and fail closed on malformed/missing syntax nodes before any
    // bounded adapter-specific extraction occurs.
    let validator = StructuralRegistry::new(&[])?;
    validator.scan_language(language, path, source)?;
    let source = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;
    let digest =
        content_id("r3-route-source", &(path.as_str(), source)).map_err(ModelError::from)?;
    let mask = code_mask(language, source)?;

    let mut builder = ExtractionBuilder::new(adapter, path, digest, limits);
    match adapter {
        RouteAdapter::Express => extract_express(language, source, &mask, &mut builder)?,
        RouteAdapter::NextApp => extract_next_app(source, &mask, &mut builder)?,
        RouteAdapter::NextPagesApi => extract_next_pages(source, &mask, &mut builder)?,
        RouteAdapter::SupabaseEdge => extract_supabase_edge(source, &mask, &mut builder)?,
    }
    builder.finish()
}

struct ExtractionBuilder<'a> {
    adapter: RouteAdapter,
    path: &'a NormalizedRepoPath,
    digest: String,
    limits: BusinessLogicLimits,
    routes: Vec<RouteObservation>,
    gaps: Vec<RouteCoverageGap>,
}

impl<'a> ExtractionBuilder<'a> {
    fn new(
        adapter: RouteAdapter,
        path: &'a NormalizedRepoPath,
        digest: String,
        limits: BusinessLogicLimits,
    ) -> Self {
        Self {
            adapter,
            path,
            digest,
            limits,
            routes: Vec::new(),
            gaps: Vec::new(),
        }
    }

    fn location(&self, start: usize, end: usize) -> Result<SourceLocation, RouteExtractionError> {
        Ok(SourceLocation::new(
            self.path.clone(),
            start,
            end,
            self.digest.clone(),
        )?)
    }

    fn gap(
        &mut self,
        reason: RouteCoverageGapReason,
        start: usize,
        end: usize,
    ) -> Result<(), RouteExtractionError> {
        let count = self.gaps.len().saturating_add(1);
        if count > MAX_ROUTE_COVERAGE_GAPS {
            return Err(RouteExtractionError::TooManyCoverageGaps {
                count,
                max: MAX_ROUTE_COVERAGE_GAPS,
            });
        }
        self.gaps.push(RouteCoverageGap {
            reason,
            adapter: self.adapter,
            provenance: self.location(start, end)?,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn route(
        &mut self,
        method: HttpMethod,
        route_kind: &str,
        route_pattern: &str,
        handler_key: &str,
        callback_keys: &[String],
        start: usize,
        end: usize,
        coverage_state: CoverageState,
    ) -> Result<(), RouteExtractionError> {
        let count = self.routes.len().saturating_add(1);
        if count > MAX_ROUTE_OBSERVATIONS {
            return Err(RouteExtractionError::TooManyRoutes {
                count,
                max: MAX_ROUTE_OBSERVATIONS,
            });
        }
        if callback_keys.len() > MAX_ROUTE_CALLBACKS {
            return Err(RouteExtractionError::TooManyCallbacks {
                count: callback_keys.len(),
                max: MAX_ROUTE_CALLBACKS,
            });
        }

        let method_key = method_identity(method);
        let route_id = StableSemanticId::from_parts(
            "r3-route",
            &[
                self.adapter.identity_key(),
                self.path.as_str(),
                route_kind,
                method_key,
                route_pattern,
                handler_key,
            ],
            self.limits,
        )?;
        let mut callback_chain = Vec::with_capacity(callback_keys.len());
        for (index, key) in callback_keys.iter().enumerate() {
            let index = index.to_string();
            callback_chain.push(StableSemanticId::from_parts(
                "r3-route-callback",
                &[
                    self.adapter.identity_key(),
                    self.path.as_str(),
                    route_pattern,
                    &index,
                    key,
                ],
                self.limits,
            )?);
        }
        let observation = RouteObservation::new(
            route_id,
            self.adapter.framework(),
            method,
            route_pattern,
            Some(handler_key.to_owned()),
            callback_chain,
            vec![self.location(start, end)?],
            coverage_state,
            self.limits,
        )?;
        self.routes.push(observation);
        Ok(())
    }

    fn finish(mut self) -> Result<RouteExtraction, RouteExtractionError> {
        self.routes.sort_by(|left, right| {
            left.route_id()
                .as_str()
                .cmp(right.route_id().as_str())
                .then_with(|| {
                    left.provenance()[0]
                        .start_byte()
                        .cmp(&right.provenance()[0].start_byte())
                })
        });
        self.gaps.sort_by(|left, right| {
            left.reason.cmp(&right.reason).then_with(|| {
                left.provenance
                    .start_byte()
                    .cmp(&right.provenance.start_byte())
            })
        });
        Ok(RouteExtraction {
            routes: self.routes,
            gaps: self.gaps,
        })
    }
}

fn extract_express(
    language: StructuralLanguage,
    source: &str,
    mask: &[u8],
    builder: &mut ExtractionBuilder<'_>,
) -> Result<(), RouteExtractionError> {
    let express_factory_binding_ambiguous =
        has_ambiguous_express_factory_binding(source, language)?;
    let app_binding_ambiguous = has_ambiguous_express_receiver_binding(
        source,
        language,
        "app",
        express_factory_binding_ambiguous,
    )?;
    let router_binding_ambiguous = has_ambiguous_express_receiver_binding(
        source,
        language,
        "router",
        express_factory_binding_ambiguous,
    )?;
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < mask.len() {
        if !is_ident_start(mask[index]) {
            index += 1;
            continue;
        }
        let receiver_start = index;
        let receiver_end = parse_ident_end(mask, index);
        let receiver = &source[receiver_start..receiver_end];
        if receiver != "app" && receiver != "router" {
            index = receiver_end;
            continue;
        }
        if !is_unqualified_identifier(mask, receiver_start) {
            index = receiver_end;
            continue;
        }
        let receiver_binding_ambiguous = match receiver {
            "app" => app_binding_ambiguous,
            "router" => router_binding_ambiguous,
            _ => false,
        };
        let mut cursor = skip_mask_ws(mask, receiver_end);
        if mask.get(cursor) == Some(&b'!') {
            let dot = skip_mask_ws(mask, cursor + 1);
            if mask.get(dot) == Some(&b'.') {
                let member_start = skip_mask_ws(mask, dot + 1);
                if let Some(member_end) = parse_ident_end_if_any(mask, member_start) {
                    let registration = &source[member_start..member_end];
                    let call_start = skip_mask_ws(mask, member_end);
                    if (is_express_registration_name(registration)
                        || is_other_express_http_method(registration))
                        && mask.get(call_start) == Some(&b'(')
                    {
                        let Some(call_end) = find_balanced(mask, call_start, b'(', b')') else {
                            return Err(RouteExtractionError::Structural(
                                StructuralError::MalformedSyntax,
                            ));
                        };
                        builder.gap(
                            if receiver_binding_ambiguous {
                                RouteCoverageGapReason::AmbiguousReceiverBinding
                            } else {
                                RouteCoverageGapReason::DynamicRegistration
                            },
                            receiver_start,
                            call_end + 1,
                        )?;
                        index = call_end + 1;
                        continue;
                    }
                }
            }
        }
        if mask.get(cursor..cursor.saturating_add(2)) == Some(b"?.") {
            let member_start = skip_mask_ws(mask, cursor + 2);
            if let Some(member_end) = parse_ident_end_if_any(mask, member_start) {
                let registration = &source[member_start..member_end];
                let call_start = skip_mask_ws(mask, member_end);
                if is_express_registration_name(registration) && mask.get(call_start) == Some(&b'(')
                {
                    let Some(call_end) = find_balanced(mask, call_start, b'(', b')') else {
                        return Err(RouteExtractionError::Structural(
                            StructuralError::MalformedSyntax,
                        ));
                    };
                    builder.gap(
                        RouteCoverageGapReason::DynamicRegistration,
                        receiver_start,
                        call_end + 1,
                    )?;
                    index = call_end + 1;
                    continue;
                }
            }
        }
        if mask.get(cursor) == Some(&b'[')
            && let Some(close) = find_balanced(mask, cursor, b'[', b']')
        {
            let after = skip_mask_ws(mask, close + 1);
            if mask.get(after) == Some(&b'(') {
                let end = find_balanced(mask, after, b'(', b')').unwrap_or(after);
                builder.gap(
                    RouteCoverageGapReason::DynamicRegistration,
                    receiver_start,
                    end.saturating_add(1),
                )?;
                index = end.saturating_add(1);
                continue;
            }
        }
        if mask.get(cursor) != Some(&b'.') {
            index = receiver_end;
            continue;
        }
        cursor = skip_mask_ws(mask, cursor + 1);
        if cursor >= mask.len() || !is_ident_start(mask[cursor]) {
            index = receiver_end;
            continue;
        }
        let method_end = parse_ident_end(mask, cursor);
        let registration = &source[cursor..method_end];
        let after_registration = skip_mask_ws(mask, method_end);
        if receiver_binding_ambiguous
            && (is_express_registration_name(registration)
                || is_other_express_http_method(registration))
        {
            let call_start = if mask.get(after_registration) == Some(&b'(') {
                Some(after_registration)
            } else if mask.get(after_registration..after_registration.saturating_add(2))
                == Some(b"?.")
            {
                let candidate = skip_mask_ws(mask, after_registration + 2);
                (mask.get(candidate) == Some(&b'(')).then_some(candidate)
            } else {
                None
            };
            if let Some(call_start) = call_start {
                let Some(call_end) = find_balanced(mask, call_start, b'(', b')') else {
                    return Err(RouteExtractionError::Structural(
                        StructuralError::MalformedSyntax,
                    ));
                };
                builder.gap(
                    RouteCoverageGapReason::AmbiguousReceiverBinding,
                    receiver_start,
                    call_end + 1,
                )?;
                index = call_end + 1;
                continue;
            }
        }
        if is_express_registration_name(registration)
            && mask.get(after_registration..after_registration.saturating_add(2)) == Some(b"?.")
        {
            let optional_call_start = skip_mask_ws(mask, after_registration + 2);
            if mask.get(optional_call_start) == Some(&b'(') {
                let Some(call_end) = find_balanced(mask, optional_call_start, b'(', b')') else {
                    return Err(RouteExtractionError::Structural(
                        StructuralError::MalformedSyntax,
                    ));
                };
                builder.gap(
                    RouteCoverageGapReason::DynamicRegistration,
                    receiver_start,
                    call_end + 1,
                )?;
                index = call_end + 1;
                continue;
            }
        }
        if registration == "route" && mask.get(after_registration) == Some(&b'(') {
            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {
                return Err(RouteExtractionError::Structural(
                    StructuralError::MalformedSyntax,
                ));
            };
            builder.gap(
                RouteCoverageGapReason::MethodNotStaticallyBound,
                receiver_start,
                call_end + 1,
            )?;
            index = call_end + 1;
            continue;
        }
        if matches!(registration, "use" | "param") && mask.get(after_registration) == Some(&b'(') {
            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {
                return Err(RouteExtractionError::Structural(
                    StructuralError::MalformedSyntax,
                ));
            };
            builder.gap(
                RouteCoverageGapReason::UnsupportedMiddleware,
                receiver_start,
                call_end + 1,
            )?;
            index = call_end + 1;
            continue;
        }
        if registration == "all" && mask.get(after_registration) == Some(&b'(') {
            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {
                return Err(RouteExtractionError::Structural(
                    StructuralError::MalformedSyntax,
                ));
            };
            builder.gap(
                RouteCoverageGapReason::MethodNotStaticallyBound,
                receiver_start,
                call_end + 1,
            )?;
            index = call_end + 1;
            continue;
        }
        if is_other_express_http_method(registration) && mask.get(after_registration) == Some(&b'(')
        {
            let Some(call_end) = find_balanced(mask, after_registration, b'(', b')') else {
                return Err(RouteExtractionError::Structural(
                    StructuralError::MalformedSyntax,
                ));
            };
            builder.gap(
                RouteCoverageGapReason::MethodNotStaticallyBound,
                receiver_start,
                call_end + 1,
            )?;
            index = call_end + 1;
            continue;
        }
        let Some(method) = parse_express_http_method(registration) else {
            index = method_end;
            continue;
        };
        cursor = after_registration;
        if mask.get(cursor) != Some(&b'(') {
            index = method_end;
            continue;
        }
        let call_start = cursor;
        let Some(call_end) = find_balanced(mask, call_start, b'(', b')') else {
            // Grammar validation should already reject this, so retain the fail-closed behavior.
            return Err(RouteExtractionError::Structural(
                StructuralError::MalformedSyntax,
            ));
        };
        let first = skip_source_ws_and_comments(source, call_start + 1, call_end);
        let Some((route_pattern, after_path)) = parse_string_literal(source, first) else {
            builder.gap(
                RouteCoverageGapReason::DynamicRoutePattern,
                receiver_start,
                call_end + 1,
            )?;
            index = call_end + 1;
            continue;
        };
        let after_path = skip_source_ws_and_comments(source, after_path, call_end);
        if after_path < call_end && bytes[after_path] != b',' {
            builder.gap(
                RouteCoverageGapReason::DynamicRoutePattern,
                receiver_start,
                call_end + 1,
            )?;
            index = call_end + 1;
            continue;
        }
        // Express overloads app.get(name) as an application-setting getter. It is not a route.
        if method == HttpMethod::Get && after_path >= call_end {
            index = call_end + 1;
            continue;
        }
        let mut callback_keys = Vec::new();
        let mut partial = false;
        if after_path >= call_end || bytes[after_path] != b',' {
            partial = true;
            builder.gap(
                RouteCoverageGapReason::UnresolvedCallback,
                receiver_start,
                call_end + 1,
            )?;
        } else {
            let callbacks = split_top_level_args(source, mask, after_path + 1, call_end);
            if callbacks.len() > MAX_ROUTE_CALLBACKS {
                return Err(RouteExtractionError::TooManyCallbacks {
                    count: callbacks.len(),
                    max: MAX_ROUTE_CALLBACKS,
                });
            }
            for (start, end) in callbacks {
                if let Some(key) = callback_key(source, mask, start, end) {
                    callback_keys.push(key);
                } else {
                    partial = true;
                    builder.gap(RouteCoverageGapReason::UnresolvedCallback, start, end)?;
                }
            }
            if callback_keys.is_empty() {
                partial = true;
            }
        }
        let handler_key = callback_keys
            .last()
            .cloned()
            .unwrap_or_else(|| format!("unresolved@{receiver_start}"));
        builder.route(
            method,
            "method-path-callback-chain",
            &route_pattern,
            &handler_key,
            &callback_keys,
            receiver_start,
            call_end + 1,
            if partial {
                CoverageState::Partial
            } else {
                CoverageState::Covered
            },
        )?;
        let suffix_dot = skip_mask_ws(mask, call_end + 1);
        if mask.get(suffix_dot) == Some(&b'.') {
            let member_start = skip_mask_ws(mask, suffix_dot + 1);
            if let Some(member_end) = parse_ident_end_if_any(mask, member_start) {
                let registration = &source[member_start..member_end];
                let suffix_call_start = skip_mask_ws(mask, member_end);
                if is_express_registration_name(registration)
                    && mask.get(suffix_call_start) == Some(&b'(')
                {
                    let Some(suffix_call_end) = find_balanced(mask, suffix_call_start, b'(', b')')
                    else {
                        return Err(RouteExtractionError::Structural(
                            StructuralError::MalformedSyntax,
                        ));
                    };
                    builder.gap(
                        RouteCoverageGapReason::DynamicRegistration,
                        suffix_dot,
                        suffix_call_end + 1,
                    )?;
                    index = suffix_call_end + 1;
                    continue;
                }
            }
        }
        index = call_end + 1;
    }
    Ok(())
}

fn extract_next_app(
    source: &str,
    mask: &[u8],
    builder: &mut ExtractionBuilder<'_>,
) -> Result<(), RouteExtractionError> {
    let Some(route_pattern) = next_app_route_pattern(builder.path.as_str()) else {
        builder.gap(
            RouteCoverageGapReason::UnsupportedRouteFile,
            0,
            source.len(),
        )?;
        return Ok(());
    };
    let mut found = false;
    let mut index = 0;
    while let Some(export_start) = find_word(mask, b"export", index) {
        let mut cursor = skip_mask_ws(mask, export_start + "export".len());
        let token_end = parse_ident_end_if_any(mask, cursor);
        let token = token_end.map(|end| &source[cursor..end]);
        if token == Some("async") {
            cursor = skip_mask_ws(mask, token_end.expect("async end"));
        }
        let word_end = parse_ident_end_if_any(mask, cursor);
        let word = word_end.map(|end| &source[cursor..end]);
        if word == Some("function") {
            cursor = skip_mask_ws(mask, word_end.expect("function end"));
            if let Some(name_end) = parse_ident_end_if_any(mask, cursor) {
                let name = &source[cursor..name_end];
                if let Some(method) = parse_next_http_method(name) {
                    let callback_keys = vec![name.to_owned()];
                    builder.route(
                        method,
                        "next-app-route-handler",
                        &route_pattern,
                        name,
                        &callback_keys,
                        export_start,
                        name_end,
                        CoverageState::Covered,
                    )?;
                    found = true;
                }
            }
        } else if matches!(word, Some("const" | "let" | "var")) {
            cursor = skip_mask_ws(mask, word_end.expect("variable declaration end"));
            if let Some(name_end) = parse_ident_end_if_any(mask, cursor) {
                let name = &source[cursor..name_end];
                if let Some(method) = parse_next_http_method(name) {
                    let mut rhs = skip_mask_ws(mask, name_end);
                    if mask.get(rhs) == Some(&b'=') {
                        rhs = skip_mask_ws(mask, rhs + 1);
                        if looks_like_function_value(mask, rhs) {
                            let callback_keys = vec![name.to_owned()];
                            builder.route(
                                method,
                                "next-app-route-handler",
                                &route_pattern,
                                name,
                                &callback_keys,
                                export_start,
                                name_end,
                                CoverageState::Covered,
                            )?;
                            found = true;
                        } else {
                            builder.gap(
                                RouteCoverageGapReason::UnsupportedHandlerExport,
                                export_start,
                                name_end,
                            )?;
                        }
                    } else {
                        builder.gap(
                            RouteCoverageGapReason::UnsupportedHandlerExport,
                            export_start,
                            name_end,
                        )?;
                    }
                }
                surface_additional_next_variable_methods(source, mask, name_end, builder)?;
            }
        } else if mask.get(cursor) == Some(&b'*') {
            builder.gap(
                RouteCoverageGapReason::UnsupportedHandlerExport,
                export_start,
                cursor + 1,
            )?;
        } else if mask.get(cursor) == Some(&b'{')
            && let Some(close) = find_balanced(mask, cursor, b'{', b'}')
            && export_list_mentions_next_http_method(source, mask, cursor + 1, close)
        {
            builder.gap(
                RouteCoverageGapReason::UnsupportedHandlerExport,
                export_start,
                close + 1,
            )?;
        }
        index = export_start + "export".len();
    }
    if !found {
        builder.gap(
            RouteCoverageGapReason::UnsupportedHandlerExport,
            0,
            source.len(),
        )?;
    }
    Ok(())
}

fn surface_additional_next_variable_methods(
    source: &str,
    mask: &[u8],
    mut index: usize,
    builder: &mut ExtractionBuilder<'_>,
) -> Result<(), RouteExtractionError> {
    let mut paren = 0usize;
    let mut brace = 0usize;
    let mut bracket = 0usize;
    while index < mask.len() {
        match mask[index] {
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'{' => brace += 1,
            b'}' => brace = brace.saturating_sub(1),
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b';' if paren == 0 && brace == 0 && bracket == 0 => break,
            b'\n' | b'\r'
                if paren == 0
                    && brace == 0
                    && bracket == 0
                    && top_level_newline_ends_statement(source, index) =>
            {
                break;
            }
            b',' if paren == 0 && brace == 0 && bracket == 0 => {
                let name_start = skip_mask_ws(mask, index + 1);
                if let Some(name_end) = parse_ident_end_if_any(mask, name_start) {
                    let name = &source[name_start..name_end];
                    let after_name = skip_mask_ws(mask, name_end);
                    if parse_next_http_method(name).is_some()
                        && matches!(mask.get(after_name), Some(&b'=') | Some(&b':'))
                    {
                        builder.gap(
                            RouteCoverageGapReason::UnsupportedHandlerExport,
                            name_start,
                            name_end,
                        )?;
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

fn top_level_newline_ends_statement(source: &str, newline: usize) -> bool {
    let bytes = source.as_bytes();
    let mut previous = newline;
    while previous > 0 && bytes[previous - 1].is_ascii_whitespace() {
        previous -= 1;
    }
    let previous = previous
        .checked_sub(1)
        .and_then(|index| bytes.get(index))
        .copied();

    let mut next = newline.saturating_add(1);
    while next < bytes.len() && bytes[next].is_ascii_whitespace() {
        next += 1;
    }
    if next >= bytes.len() {
        return true;
    }
    if matches!(bytes[next], b',' | b'.') || bytes.get(next..next.saturating_add(2)) == Some(b"?.")
    {
        return false;
    }

    !matches!(
        previous,
        Some(
            b'=' | b','
                | b'('
                | b'['
                | b'{'
                | b':'
                | b'?'
                | b'+'
                | b'-'
                | b'*'
                | b'/'
                | b'%'
                | b'&'
                | b'|'
                | b'^'
                | b'!'
                | b'~'
                | b'<'
                | b'>'
        )
    )
}

fn export_list_mentions_next_http_method(
    source: &str,
    mask: &[u8],
    mut index: usize,
    end: usize,
) -> bool {
    while index < end {
        if is_ident_start(mask[index]) {
            let token_end = parse_ident_end(mask, index);
            if token_end <= end && parse_next_http_method(&source[index..token_end]).is_some() {
                return true;
            }
            index = token_end;
        } else {
            index += 1;
        }
    }
    false
}

fn extract_next_pages(
    source: &str,
    mask: &[u8],
    builder: &mut ExtractionBuilder<'_>,
) -> Result<(), RouteExtractionError> {
    let Some(route_pattern) = next_pages_route_pattern(builder.path.as_str()) else {
        builder.gap(
            RouteCoverageGapReason::UnsupportedRouteFile,
            0,
            source.len(),
        )?;
        return Ok(());
    };

    let mut search_index = 0usize;
    let mut default_export = None;
    while let Some(export_start) = find_word(mask, b"export", search_index) {
        let cursor = skip_mask_ws(mask, export_start + "export".len());
        if let Some(default_end) = parse_ident_end_if_any(mask, cursor)
            && &source[cursor..default_end] == "default"
        {
            default_export = Some((export_start, skip_mask_ws(mask, default_end)));
            break;
        }
        search_index = export_start + "export".len();
    }

    let Some((export_start, value_start)) = default_export else {
        builder.gap(
            RouteCoverageGapReason::UnsupportedHandlerExport,
            0,
            source.len(),
        )?;
        return Ok(());
    };

    if !looks_like_function_value(mask, value_start) {
        builder.gap(
            RouteCoverageGapReason::UnsupportedHandlerExport,
            export_start,
            source.len(),
        )?;
        return Ok(());
    }

    let mut cursor = value_start;
    if let Some(async_end) = parse_ident_end_if_any(mask, cursor)
        && &source[cursor..async_end] == "async"
    {
        cursor = skip_mask_ws(mask, async_end);
    }

    let handler_key = if let Some(token_end) = parse_ident_end_if_any(mask, cursor) {
        if &source[cursor..token_end] == "function" {
            cursor = skip_mask_ws(mask, token_end);
            parse_ident_end_if_any(mask, cursor)
                .map(|handler_end| source[cursor..handler_end].to_owned())
                .unwrap_or_else(|| format!("inline@{export_start}"))
        } else {
            format!("inline@{export_start}")
        }
    } else {
        format!("inline@{export_start}")
    };

    let callbacks = vec![handler_key.clone()];
    builder.route(
        HttpMethod::OtherSupported,
        "next-pages-api-default-handler",
        &route_pattern,
        &handler_key,
        &callbacks,
        export_start,
        source.len(),
        CoverageState::Partial,
    )?;
    builder.gap(
        RouteCoverageGapReason::MethodNotStaticallyBound,
        export_start,
        source.len(),
    )?;
    Ok(())
}

fn extract_supabase_edge(
    source: &str,
    mask: &[u8],
    builder: &mut ExtractionBuilder<'_>,
) -> Result<(), RouteExtractionError> {
    let Some(function_name) = supabase_function_name(builder.path.as_str()) else {
        builder.gap(
            RouteCoverageGapReason::UnsupportedRouteFile,
            0,
            source.len(),
        )?;
        return Ok(());
    };
    let route_pattern = format!("/functions/v1/{function_name}");
    let deno_shadowed = has_local_deno_binding(source)?;
    let mut index = 0;
    let mut found = false;
    while let Some(deno_start) = find_word(mask, b"Deno", index) {
        if !is_unqualified_identifier(mask, deno_start) {
            index = deno_start + "Deno".len();
            continue;
        }
        let mut cursor = skip_mask_ws(mask, deno_start + "Deno".len());
        if mask.get(cursor) != Some(&b'.') {
            index = deno_start + 1;
            continue;
        }
        cursor = skip_mask_ws(mask, cursor + 1);
        let Some(serve_end) = parse_ident_end_if_any(mask, cursor) else {
            index = deno_start + 1;
            continue;
        };
        if &source[cursor..serve_end] != "serve" {
            index = serve_end;
            continue;
        }
        let call_start = skip_mask_ws(mask, serve_end);
        if mask.get(call_start) != Some(&b'(') {
            index = serve_end;
            continue;
        }
        let Some(call_end) = find_balanced(mask, call_start, b'(', b')') else {
            return Err(RouteExtractionError::Structural(
                StructuralError::MalformedSyntax,
            ));
        };
        if deno_shadowed {
            builder.gap(
                RouteCoverageGapReason::AmbiguousReceiverBinding,
                deno_start,
                call_end + 1,
            )?;
            found = true;
            index = call_end + 1;
            continue;
        }
        let args = split_top_level_args(source, mask, call_start + 1, call_end);
        let callback = match args.as_slice() {
            [(start, end)] => callback_key(source, mask, *start, *end),
            [_, (start, end)] => callback_key(source, mask, *start, *end),
            _ => None,
        };
        match callback {
            Some(handler_key) => {
                let callbacks = vec![handler_key.clone()];
                builder.route(
                    HttpMethod::OtherSupported,
                    "supabase-edge-deno-serve",
                    &route_pattern,
                    &handler_key,
                    &callbacks,
                    deno_start,
                    call_end + 1,
                    CoverageState::Partial,
                )?;
                builder.gap(
                    RouteCoverageGapReason::MethodNotStaticallyBound,
                    deno_start,
                    call_end + 1,
                )?;
            }
            None => builder.gap(
                RouteCoverageGapReason::UnresolvedCallback,
                deno_start,
                call_end + 1,
            )?,
        }
        found = true;
        index = call_end + 1;
    }
    if !found {
        builder.gap(
            RouteCoverageGapReason::UnsupportedHandlerExport,
            0,
            source.len(),
        )?;
    }
    Ok(())
}

fn has_ambiguous_express_factory_binding(
    source: &str,
    structural_language: StructuralLanguage,
) -> Result<bool, StructuralError> {
    let language: tree_sitter::Language = match structural_language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| StructuralError::ParseFailed(error.to_string()))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        StructuralError::ParseFailed(
            "Express factory binding parser returned no syntax tree".to_owned(),
        )
    })?;
    let mut cursor = tree.root_node().walk();
    loop {
        let node = cursor.node();
        if matches!(
            node.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && source.get(node.byte_range()) == Some("express")
            && identifier_is_binding(node)
            && !express_binding_is_known_factory_source(node, source)
        {
            return Ok(true);
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(false);
            }
        }
    }
}

fn express_binding_is_known_factory_source(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() != "import_clause" {
        return false;
    }

    let mut ancestor = Some(parent);
    while let Some(current) = ancestor {
        if current.kind() == "import_statement" {
            let Some(module) = current.child_by_field_name("source") else {
                return false;
            };
            return matches!(
                source.get(module.byte_range()),
                Some("\"express\"") | Some("'express'")
            );
        }
        ancestor = current.parent();
    }
    false
}

fn has_ambiguous_express_receiver_binding(
    source: &str,
    structural_language: StructuralLanguage,
    receiver: &str,
    express_factory_binding_ambiguous: bool,
) -> Result<bool, StructuralError> {
    let language: tree_sitter::Language = match structural_language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| StructuralError::ParseFailed(error.to_string()))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        StructuralError::ParseFailed("Express binding parser returned no syntax tree".to_owned())
    })?;
    let mut cursor = tree.root_node().walk();
    loop {
        let node = cursor.node();
        if matches!(
            node.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && source.get(node.byte_range()) == Some(receiver)
            && identifier_is_binding(node)
            && !express_binding_is_known_receiver(node, source, express_factory_binding_ambiguous)
        {
            return Ok(true);
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(false);
            }
        }
    }
}

fn express_binding_is_known_receiver(
    node: tree_sitter::Node<'_>,
    source: &str,
    express_factory_binding_ambiguous: bool,
) -> bool {
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        match current.kind() {
            "function_declaration" | "generator_function_declaration" => {
                let Some(parameters) = current.child_by_field_name("parameters") else {
                    return false;
                };
                let node_is_parameter = node.start_byte() >= parameters.start_byte()
                    && node.end_byte() <= parameters.end_byte();
                return node_is_parameter
                    && current
                        .parent()
                        .is_some_and(|parent| parent.kind() == "export_statement");
            }
            "variable_declarator" => {
                let Some(value) = current.child_by_field_name("value") else {
                    return false;
                };
                return !express_factory_binding_ambiguous
                    && is_bounded_express_factory_call(value, source);
            }
            "program" => return false,
            _ => ancestor = current.parent(),
        }
    }
    false
}

fn is_bounded_express_factory_call(value: tree_sitter::Node<'_>, source: &str) -> bool {
    if value.kind() != "call_expression" {
        return false;
    }
    let Some(function) = value.child_by_field_name("function") else {
        return false;
    };
    match function.kind() {
        "identifier" => source.get(function.byte_range()) == Some("express"),
        "member_expression" => {
            let Some(object) = function.child_by_field_name("object") else {
                return false;
            };
            let Some(property) = function.child_by_field_name("property") else {
                return false;
            };
            source.get(object.byte_range()) == Some("express")
                && source.get(property.byte_range()) == Some("Router")
        }
        _ => false,
    }
}

fn has_local_deno_binding(source: &str) -> Result<bool, StructuralError> {
    let language: tree_sitter::Language = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| StructuralError::ParseFailed(error.to_string()))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        StructuralError::ParseFailed("Deno binding parser returned no syntax tree".to_owned())
    })?;
    let mut cursor = tree.root_node().walk();
    loop {
        let node = cursor.node();
        if matches!(
            node.kind(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && source.get(node.byte_range()) == Some("Deno")
            && identifier_is_binding(node)
        {
            return Ok(true);
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(false);
            }
        }
    }
}

fn identifier_is_binding(node: tree_sitter::Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let same_as_field = |field: &str| {
        parent.child_by_field_name(field).is_some_and(|candidate| {
            candidate.start_byte() == node.start_byte() && candidate.end_byte() == node.end_byte()
        })
    };
    match parent.kind() {
        "variable_declarator" | "function_declaration" | "class_declaration" => {
            same_as_field("name")
        }
        "assignment_expression" | "assignment_pattern" => same_as_field("left"),
        "catch_clause" => same_as_field("parameter"),
        "pair_pattern" => same_as_field("value"),
        "object_pattern" | "array_pattern" => true,
        "formal_parameters"
        | "required_parameter"
        | "optional_parameter"
        | "rest_pattern"
        | "import_specifier"
        | "import_clause"
        | "namespace_import"
        | "shorthand_property_identifier_pattern" => true,
        _ => parent.parent().is_some_and(|grandparent| {
            matches!(
                grandparent.kind(),
                "formal_parameters" | "required_parameter" | "optional_parameter"
            )
        }),
    }
}

fn method_identity(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Options => "OPTIONS",
        HttpMethod::Head => "HEAD",
        HttpMethod::OtherSupported => "OTHER_SUPPORTED",
    }
}

fn is_express_registration_name(value: &str) -> bool {
    parse_express_http_method(value).is_some()
        || is_other_express_http_method(value)
        || matches!(value, "all" | "param" | "route" | "use")
}

fn is_other_express_http_method(value: &str) -> bool {
    matches!(
        value,
        "connect"
            | "trace"
            | "copy"
            | "lock"
            | "mkcol"
            | "move"
            | "notify"
            | "propfind"
            | "proppatch"
            | "purge"
            | "report"
            | "search"
            | "subscribe"
            | "unlock"
            | "unsubscribe"
    )
}

fn parse_express_http_method(value: &str) -> Option<HttpMethod> {
    match value {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "patch" => Some(HttpMethod::Patch),
        "delete" => Some(HttpMethod::Delete),
        "options" => Some(HttpMethod::Options),
        "head" => Some(HttpMethod::Head),
        _ => None,
    }
}

fn parse_next_http_method(value: &str) -> Option<HttpMethod> {
    match value {
        "GET" => Some(HttpMethod::Get),
        "POST" => Some(HttpMethod::Post),
        "PUT" => Some(HttpMethod::Put),
        "PATCH" => Some(HttpMethod::Patch),
        "DELETE" => Some(HttpMethod::Delete),
        "OPTIONS" => Some(HttpMethod::Options),
        "HEAD" => Some(HttpMethod::Head),
        _ => None,
    }
}

fn next_app_route_pattern(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    let app = parts.iter().position(|part| *part == "app")?;
    let file = *parts.last()?;
    if !matches!(file, "route.js" | "route.ts") {
        return None;
    }
    let mut route_parts = Vec::new();
    for part in &parts[app + 1..parts.len() - 1] {
        if part.starts_with('(')
            || part.starts_with('@')
            || part.starts_with('_')
            || part.is_empty()
        {
            return None;
        }
        route_parts.push(*part);
    }
    Some(if route_parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", route_parts.join("/"))
    })
}

fn next_pages_route_pattern(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    let pages = parts.iter().position(|part| *part == "pages")?;
    if parts.get(pages + 1) != Some(&"api") {
        return None;
    }
    let file = *parts.last()?;
    let stem = file
        .strip_suffix(".js")
        .or_else(|| file.strip_suffix(".ts"))?;
    let mut route_parts: Vec<&str> = parts[pages + 1..parts.len() - 1].to_vec();
    if stem != "index" {
        route_parts.push(stem);
    }
    Some(format!("/{}", route_parts.join("/")))
}

fn supabase_function_name(path: &str) -> Option<&str> {
    let parts: Vec<&str> = path.split('/').collect();
    match parts.as_slice() {
        ["supabase", "functions", function_name, "index.ts"] if !function_name.is_empty() => {
            Some(*function_name)
        }
        _ => None,
    }
}

fn callback_key(source: &str, mask: &[u8], start: usize, end: usize) -> Option<String> {
    let (start, end) = trim_source_trivia_range(source, start, end);
    let value = source.get(start..end)?.trim();
    if value.is_empty() || value.starts_with("...") || matches!(value, "true" | "false" | "null") {
        return None;
    }
    if looks_like_function_value(mask, start) {
        return Some(format!("inline@{start}"));
    }
    if value
        .bytes()
        .all(|byte| is_ident_continue(byte) || byte == b'.')
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| is_ident_start(*byte))
        })
    {
        return Some(value.to_owned());
    }
    None
}

fn split_top_level_args(
    source: &str,
    mask: &[u8],
    start: usize,
    end: usize,
) -> Vec<(usize, usize)> {
    let mut args = Vec::new();
    let mut item_start = start;
    let mut index = start;
    let mut paren = 0usize;
    let mut brace = 0usize;
    let mut bracket = 0usize;
    while index < end {
        match mask[index] {
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'{' => brace += 1,
            b'}' => brace = brace.saturating_sub(1),
            b'[' => bracket += 1,
            b']' => bracket = bracket.saturating_sub(1),
            b',' if paren == 0 && brace == 0 && bracket == 0 => {
                let (trimmed_start, trimmed_end) =
                    trim_source_trivia_range(source, item_start, index);
                if trimmed_start < trimmed_end {
                    args.push((trimmed_start, trimmed_end));
                }
                item_start = index + 1;
            }
            _ => {}
        }
        index += 1;
    }
    let (trimmed_start, trimmed_end) = trim_source_trivia_range(source, item_start, end);
    if trimmed_start < trimmed_end {
        args.push((trimmed_start, trimmed_end));
    }
    args
}

fn parse_string_literal(source: &str, start: usize) -> Option<(String, usize)> {
    let bytes = source.as_bytes();
    let quote = *bytes.get(start)?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let mut index = start + 1;
    let mut value = String::new();
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'\\' {
            // Reject escaped/dynamic route spellings rather than normalizing them incorrectly.
            return None;
        }
        if byte == quote {
            return Some((value, index + 1));
        }
        if byte == b'\n' || byte == b'\r' {
            return None;
        }
        let ch = source[index..].chars().next()?;
        value.push(ch);
        index += ch.len_utf8();
    }
    None
}

fn find_balanced(mask: &[u8], open: usize, open_byte: u8, close_byte: u8) -> Option<usize> {
    if mask.get(open) != Some(&open_byte) {
        return None;
    }
    let mut depth = 1usize;
    let mut index = open + 1;
    while index < mask.len() {
        if mask[index] == open_byte {
            depth += 1;
        } else if mask[index] == close_byte {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
        index += 1;
    }
    None
}

fn code_mask(language: StructuralLanguage, source: &str) -> Result<Vec<u8>, StructuralError> {
    let mut mask = source.as_bytes().to_vec();
    for (start, end) in non_code_ranges(language, source)? {
        mask[start..end].fill(b' ');
    }
    Ok(mask)
}

fn non_code_ranges(
    language: StructuralLanguage,
    source: &str,
) -> Result<Vec<(usize, usize)>, StructuralError> {
    let parser_language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&parser_language)
        .map_err(|error| StructuralError::ParseFailed(error.to_string()))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        StructuralError::ParseFailed("route mask parser returned no syntax tree".to_owned())
    })?;

    let mut ranges = Vec::new();
    let mut cursor = tree.root_node().walk();
    loop {
        let node = cursor.node();
        match node.kind() {
            "string" | "comment" | "regex" => {
                ranges.push((node.start_byte(), node.end_byte()));
            }
            "template_string" => push_template_literal_ranges(node, &mut ranges),
            _ => {}
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return Ok(merge_mask_ranges(ranges));
            }
        }
    }
}

fn push_template_literal_ranges(node: tree_sitter::Node<'_>, ranges: &mut Vec<(usize, usize)>) {
    let mut visible_end = node.start_byte();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() == "template_substitution" {
                if visible_end < child.start_byte() {
                    ranges.push((visible_end, child.start_byte()));
                }
                visible_end = child.end_byte();
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    if visible_end < node.end_byte() {
        ranges.push((visible_end, node.end_byte()));
    }
}

fn merge_mask_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if start >= end {
            continue;
        }
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

fn find_word(mask: &[u8], word: &[u8], from: usize) -> Option<usize> {
    let mut index = from;
    while index + word.len() <= mask.len() {
        if &mask[index..index + word.len()] == word
            && (index == 0 || !is_ident_continue(mask[index - 1]))
            && (index + word.len() == mask.len() || !is_ident_continue(mask[index + word.len()]))
        {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn looks_like_function_value(mask: &[u8], mut index: usize) -> bool {
    if let Some(end) = parse_ident_end_if_any(mask, index) {
        let token = &mask[index..end];
        if token == b"async" {
            index = skip_mask_ws(mask, end);
        } else if token == b"function" {
            return true;
        }
    }
    if let Some(end) = parse_ident_end_if_any(mask, index) {
        if &mask[index..end] == b"function" {
            return true;
        }
        let after = skip_mask_ws(mask, end);
        return mask.get(after..after.saturating_add(2)) == Some(b"=>");
    }
    if mask.get(index) == Some(&b'(')
        && let Some(close) = find_balanced(mask, index, b'(', b')')
    {
        let after = skip_mask_ws(mask, close + 1);
        return mask.get(after..after.saturating_add(2)) == Some(b"=>");
    }
    false
}

fn is_unqualified_identifier(mask: &[u8], start: usize) -> bool {
    let mut index = start;
    while index > 0 {
        index -= 1;
        if !mask[index].is_ascii_whitespace() {
            return !matches!(mask[index], b'.' | b'#');
        }
    }
    true
}

fn parse_ident_end_if_any(mask: &[u8], start: usize) -> Option<usize> {
    (start < mask.len() && is_ident_start(mask[start])).then(|| parse_ident_end(mask, start))
}

fn parse_ident_end(mask: &[u8], start: usize) -> usize {
    let mut end = start + 1;
    while end < mask.len() && is_ident_continue(mask[end]) {
        end += 1;
    }
    end
}

const fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

const fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit()
}

fn skip_mask_ws(mask: &[u8], mut index: usize) -> usize {
    while index < mask.len() && mask[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn skip_source_ws_and_comments(source: &str, mut index: usize, end: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        while index < end && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index + 1 >= end {
            return index;
        }
        if &bytes[index..index + 2] == b"//" {
            index += 2;
            while index < end && !matches!(bytes[index], b'\n' | b'\r') {
                index += 1;
            }
            continue;
        }
        if &bytes[index..index + 2] == b"/*" {
            let mut cursor = index + 2;
            while cursor + 1 < end && &bytes[cursor..cursor + 2] != b"*/" {
                cursor += 1;
            }
            if cursor + 1 >= end {
                return end;
            }
            index = cursor + 2;
            continue;
        }
        return index;
    }
}

fn trim_source_trivia_range(source: &str, start: usize, mut end: usize) -> (usize, usize) {
    let bytes = source.as_bytes();
    let start = skip_source_ws_and_comments(source, start, end);
    loop {
        while end > start && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        if end >= start + 2
            && &bytes[end - 2..end] == b"*/"
            && let Some(relative) = source[start..end - 2].rfind("/*")
        {
            end = start + relative;
            continue;
        }
        let line_start = source[start..end]
            .rfind(['\n', '\r'])
            .map_or(start, |relative| start + relative + 1);
        if let Some(relative) = source[line_start..end].find("//") {
            end = line_start + relative;
            continue;
        }
        return (start, end);
    }
}
