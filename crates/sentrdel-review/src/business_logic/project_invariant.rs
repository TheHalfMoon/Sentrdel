//! Bounded R3-T025 project-invariant loading and evaluator dispatch.
//!
//! Repository declarations are untrusted data. This module admits only a narrow,
//! Sentrdel-owned TOML-like grammar for `.sentrdel/invariants.toml`: an exact
//! integer version, `[[invariant]]` records, quoted strings, and flat arrays of
//! quoted strings. Unknown syntax and authority-bearing keys fail the whole
//! project declaration closed. Built-in analysis remains independent.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sentrdel_schema::coverage::CoverageState;

use crate::view::NormalizedRepoPath;

use super::elevated_client::{
    ElevatedClientInputs, R3_SERVER_CONTEXT_EXPRESS, R3_SERVER_CONTEXT_NEXT_APP,
    R3_SERVER_CONTEXT_NEXT_PAGES_API, R3_SERVER_CONTEXT_SUPABASE_EDGE, evaluate_elevated_client,
};
use super::invariant::{
    ProjectInvariantLimits, validate_project_invariant_id, validate_project_invariant_keys,
};
use super::model::{
    ActorContext, ActorIdentityKind, BusinessLogicLimits, CrossLayerPath, DataOperation,
    DataOperationKind, GuardKind, GuardObservation, HttpMethod, InvariantDefinition,
    InvariantEvaluation, InvariantKind, InvariantRequirement, InvariantScope, InvariantSource,
    ProviderClientAuthority, ResourceKind, ResourceRef, RouteObservation, SourceLocation,
    StableSemanticId, ValueOrigin,
};
use super::protected_properties::{ProtectedPropertiesInputs, evaluate_protected_properties};
use super::r2_support::R2SupportCorrelation;
use super::required_role::{RequiredRoleInputs, evaluate_required_role};
use super::tenant_binding::{TenantBindingInputs, evaluate_tenant_binding};

pub const PROJECT_INVARIANT_PATH: &str = ".sentrdel/invariants.toml";
pub const PROJECT_INVARIANT_VERSION: u32 = 1;
pub const DEFAULT_MAX_PROJECT_INVARIANT_LINES: usize = 2_048;
pub const DEFAULT_MAX_PROJECT_SCOPE_TEXT_BYTES: usize = 1_024;
pub const DEFAULT_MAX_PROJECT_COLLECTION_ITEMS: usize = 64;
pub const DEFAULT_MAX_PROJECT_COLLECTION_ITEM_BYTES: usize = 256;
pub const DEFAULT_MAX_PROJECT_DIAGNOSTICS: usize = 32;
pub const DEFAULT_MAX_PROJECT_SCOPE_PATH_BYTES: usize = 4_096;

pub const PROJECT_INVARIANT_CREATES_FINDINGS: bool = false;
pub const PROJECT_INVARIANT_EXECUTES_TARGET_CODE: bool = false;
pub const PROJECT_INVARIANT_PERFORMS_NETWORK_ACCESS: bool = false;
pub const PROJECT_INVARIANT_REQUESTS_PROVIDER_CREDENTIALS: bool = false;
pub const PROJECT_INVARIANT_PARSE_FAILURE_DISABLES_BUILTINS: bool = false;
pub const PROJECT_INVARIANT_CAN_WEAKEN_BUILTINS: bool = false;

const PROJECT_INVARIANT_NAMESPACE: &str = "sentrdel.r3.project-invariant";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectInvariantLoadState {
    Missing,
    Loaded,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInvariantDiagnostic {
    code: String,
    message: String,
}

impl ProjectInvariantDiagnostic {
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInvariantLoad {
    state: ProjectInvariantLoadState,
    definitions: Vec<InvariantDefinition>,
    diagnostics: Vec<ProjectInvariantDiagnostic>,
}

impl ProjectInvariantLoad {
    #[must_use]
    pub const fn state(&self) -> ProjectInvariantLoadState {
        self.state
    }

    #[must_use]
    pub fn definitions(&self) -> &[InvariantDefinition] {
        &self.definitions
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[ProjectInvariantDiagnostic] {
        &self.diagnostics
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RawValue {
    Scalar(String),
    List(Vec<String>),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RawInvariant {
    fields: BTreeMap<String, RawValue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParseFailure {
    code: &'static str,
    message: String,
}

impl ParseFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn load_project_invariants(
    content: Option<&str>,
    declaration_path: &NormalizedRepoPath,
    content_digest: &str,
    project_limits: ProjectInvariantLimits,
    model_limits: BusinessLogicLimits,
) -> ProjectInvariantLoad {
    let Some(content) = content else {
        return ProjectInvariantLoad {
            state: ProjectInvariantLoadState::Missing,
            definitions: Vec::new(),
            diagnostics: Vec::new(),
        };
    };

    let result = parse_project_invariants(
        content,
        declaration_path,
        content_digest,
        project_limits,
        model_limits,
    );
    match result {
        Ok(mut definitions) => {
            definitions.sort_by(|left, right| {
                left.invariant_id()
                    .as_str()
                    .cmp(right.invariant_id().as_str())
            });
            ProjectInvariantLoad {
                state: ProjectInvariantLoadState::Loaded,
                definitions,
                diagnostics: Vec::new(),
            }
        }
        Err(failure) => ProjectInvariantLoad {
            state: ProjectInvariantLoadState::Rejected,
            definitions: Vec::new(),
            diagnostics: vec![ProjectInvariantDiagnostic {
                code: failure.code.to_owned(),
                message: failure.message,
            }],
        },
    }
}

fn parse_project_invariants(
    content: &str,
    declaration_path: &NormalizedRepoPath,
    content_digest: &str,
    project_limits: ProjectInvariantLimits,
    model_limits: BusinessLogicLimits,
) -> Result<Vec<InvariantDefinition>, ParseFailure> {
    let project_limits = project_limits
        .validate()
        .map_err(|error| ParseFailure::new("invalid_limits", error.to_string()))?;
    model_limits
        .validate()
        .map_err(|error| ParseFailure::new("invalid_model_limits", error.to_string()))?;

    if declaration_path.as_str() != PROJECT_INVARIANT_PATH {
        return Err(ParseFailure::new(
            "wrong_declaration_path",
            format!("project invariants are accepted only from {PROJECT_INVARIANT_PATH}"),
        ));
    }
    if content.len() > project_limits.max_file_bytes {
        return Err(ParseFailure::new(
            "file_too_large",
            format!(
                "project invariant file size {} exceeds cap {}",
                content.len(),
                project_limits.max_file_bytes
            ),
        ));
    }
    if content_digest.trim().is_empty() {
        return Err(ParseFailure::new(
            "invalid_provenance",
            "project invariant content digest must not be empty",
        ));
    }

    let line_count = content.lines().count();
    if line_count > DEFAULT_MAX_PROJECT_INVARIANT_LINES {
        return Err(ParseFailure::new(
            "too_many_lines",
            format!(
                "project invariant line count {line_count} exceeds cap {DEFAULT_MAX_PROJECT_INVARIANT_LINES}"
            ),
        ));
    }

    let mut version = None;
    let mut records = Vec::new();
    let mut current: Option<RawInvariant> = None;

    for (index, raw_line) in content.lines().enumerate() {
        let line_number = index + 1;
        if raw_line.len() > project_limits.max_value_bytes.saturating_add(256) {
            return Err(ParseFailure::new(
                "line_too_large",
                format!("line {line_number} exceeds the bounded parser line size"),
            ));
        }
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[invariant]]" {
            if version != Some(PROJECT_INVARIANT_VERSION) {
                return Err(ParseFailure::new(
                    "version_must_precede_records",
                    format!("line {line_number}: exact version must precede invariant records"),
                ));
            }
            if let Some(record) = current.take() {
                records.push(record);
                if records.len() >= project_limits.max_invariants {
                    return Err(ParseFailure::new(
                        "too_many_invariants",
                        format!(
                            "project invariant count exceeds cap {}",
                            project_limits.max_invariants
                        ),
                    ));
                }
            }
            current = Some(RawInvariant::default());
            continue;
        }
        if line.starts_with('[') {
            return Err(ParseFailure::new(
                "unsupported_structure",
                format!("line {line_number}: only [[invariant]] records are supported"),
            ));
        }

        let (key, value) = split_assignment(line, line_number)?;
        if current.is_none() {
            if key != "version" {
                return Err(ParseFailure::new(
                    "unsupported_top_level_key",
                    format!("line {line_number}: unsupported top-level key {key}"),
                ));
            }
            if version.is_some() {
                return Err(ParseFailure::new(
                    "duplicate_version",
                    format!("line {line_number}: version is duplicated"),
                ));
            }
            if value != PROJECT_INVARIANT_VERSION.to_string() {
                return Err(ParseFailure::new(
                    "unsupported_version",
                    format!(
                        "line {line_number}: only version {PROJECT_INVARIANT_VERSION} is supported"
                    ),
                ));
            }
            version = Some(PROJECT_INVARIANT_VERSION);
            continue;
        }

        validate_project_invariant_keys(&[key], project_limits).map_err(|error| {
            let code = if error.to_string().contains("authority-bearing") {
                "forbidden_authority_key"
            } else {
                "unsupported_key"
            };
            ParseFailure::new(code, format!("line {line_number}: {error}"))
        })?;

        let parsed = parse_raw_value(value, line_number, project_limits)?;
        let record = current.as_mut().expect("record checked above");
        if record.fields.len() >= project_limits.max_keys {
            return Err(ParseFailure::new(
                "too_many_keys",
                format!(
                    "line {line_number}: project invariant key count exceeds cap {}",
                    project_limits.max_keys
                ),
            ));
        }
        if record.fields.insert(key.to_owned(), parsed).is_some() {
            return Err(ParseFailure::new(
                "duplicate_key",
                format!("line {line_number}: project invariant key is duplicated: {key}"),
            ));
        }
    }

    if let Some(record) = current.take() {
        records.push(record);
    }
    if version != Some(PROJECT_INVARIANT_VERSION) {
        return Err(ParseFailure::new(
            "missing_version",
            format!("project invariant declaration requires version {PROJECT_INVARIANT_VERSION}"),
        ));
    }
    if records.len() > project_limits.max_invariants {
        return Err(ParseFailure::new(
            "too_many_invariants",
            format!(
                "project invariant count {} exceeds cap {}",
                records.len(),
                project_limits.max_invariants
            ),
        ));
    }

    let mut seen_ids = BTreeSet::new();
    let mut definitions = Vec::with_capacity(records.len());
    for record in records {
        let id = required_scalar(&record, "id")?;
        validate_project_invariant_id(id, project_limits)
            .map_err(|error| ParseFailure::new("invalid_id", error.to_string()))?;
        if !seen_ids.insert(id.to_owned()) {
            return Err(ParseFailure::new(
                "duplicate_id",
                format!("project invariant id is duplicated: {id}"),
            ));
        }
        definitions.push(build_definition(
            &record,
            declaration_path,
            content_digest,
            content.len(),
            project_limits,
            model_limits,
        )?);
    }
    Ok(definitions)
}

fn split_assignment(line: &str, line_number: usize) -> Result<(&str, &str), ParseFailure> {
    let Some((raw_key, raw_value)) = line.split_once('=') else {
        return Err(ParseFailure::new(
            "malformed_assignment",
            format!("line {line_number}: expected key = value"),
        ));
    };
    let key = raw_key.trim();
    let value = raw_value.trim();
    if key.is_empty() || value.is_empty() || key.chars().any(char::is_whitespace) {
        return Err(ParseFailure::new(
            "malformed_assignment",
            format!("line {line_number}: malformed key = value assignment"),
        ));
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err(ParseFailure::new(
            "unsupported_key_syntax",
            format!("line {line_number}: key syntax is outside the frozen grammar"),
        ));
    }
    Ok((key, value))
}

fn parse_raw_value(
    value: &str,
    line_number: usize,
    limits: ProjectInvariantLimits,
) -> Result<RawValue, ParseFailure> {
    if value.len() > limits.max_value_bytes {
        return Err(ParseFailure::new(
            "value_too_large",
            format!(
                "line {line_number}: value size {} exceeds cap {}",
                value.len(),
                limits.max_value_bytes
            ),
        ));
    }
    if value.starts_with('"') {
        return parse_string(value, line_number).map(RawValue::Scalar);
    }
    if value.starts_with('[') {
        return parse_string_list(value, line_number).map(RawValue::List);
    }
    Err(ParseFailure::new(
        "unsupported_value_syntax",
        format!(
            "line {line_number}: only quoted strings and flat quoted-string arrays are supported"
        ),
    ))
}

fn parse_string(value: &str, line_number: usize) -> Result<String, ParseFailure> {
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(ParseFailure::new(
            "malformed_string",
            format!("line {line_number}: malformed quoted string"),
        ));
    }
    let inner = &value[1..value.len() - 1];
    if inner.is_empty()
        || inner.contains('"')
        || inner.contains('\\')
        || inner.chars().any(char::is_control)
    {
        return Err(ParseFailure::new(
            "unsupported_string",
            format!(
                "line {line_number}: string is empty or uses unsupported escaping/control syntax"
            ),
        ));
    }
    Ok(inner.to_owned())
}

fn parse_string_list(value: &str, line_number: usize) -> Result<Vec<String>, ParseFailure> {
    if !value.ends_with(']') {
        return Err(ParseFailure::new(
            "malformed_list",
            format!("line {line_number}: malformed list"),
        ));
    }
    let inner = value[1..value.len() - 1].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let parts = inner.split(',').collect::<Vec<_>>();
    if parts.len() > DEFAULT_MAX_PROJECT_COLLECTION_ITEMS {
        return Err(ParseFailure::new(
            "collection_too_large",
            format!(
                "line {line_number}: collection count {} exceeds cap {DEFAULT_MAX_PROJECT_COLLECTION_ITEMS}",
                parts.len()
            ),
        ));
    }
    let mut values = Vec::with_capacity(parts.len());
    for part in parts {
        let parsed = parse_string(part.trim(), line_number)?;
        if parsed.len() > DEFAULT_MAX_PROJECT_COLLECTION_ITEM_BYTES {
            return Err(ParseFailure::new(
                "collection_item_too_large",
                format!(
                    "line {line_number}: collection item size {} exceeds cap {DEFAULT_MAX_PROJECT_COLLECTION_ITEM_BYTES}",
                    parsed.len()
                ),
            ));
        }
        values.push(parsed);
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn build_definition(
    record: &RawInvariant,
    declaration_path: &NormalizedRepoPath,
    content_digest: &str,
    content_len: usize,
    project_limits: ProjectInvariantLimits,
    model_limits: BusinessLogicLimits,
) -> Result<InvariantDefinition, ParseFailure> {
    let keys = record.fields.keys().map(String::as_str).collect::<Vec<_>>();
    validate_project_invariant_keys(&keys, project_limits)
        .map_err(|error| ParseFailure::new("invalid_keys", error.to_string()))?;

    let id = required_scalar(record, "id")?;
    let invariant_type = required_scalar(record, "type")?;
    validate_type_keys(invariant_type, record)?;

    let route = optional_scalar(record, "route")?
        .map(|value| validate_scope_text("route", value))
        .transpose()?;
    let methods = optional_list(record, "methods")?
        .map(parse_methods)
        .transpose()?
        .unwrap_or_default();
    let operations = optional_list(record, "operations")?
        .map(parse_operations)
        .transpose()?
        .unwrap_or_default();
    let target_paths = optional_list(record, "paths")?
        .map(parse_paths)
        .transpose()?
        .unwrap_or_default();
    let resource = optional_scalar(record, "resource")?
        .map(|value| parse_resource(value, model_limits))
        .transpose()?;

    let (kind, requirement) = match invariant_type {
        "tenant_binding" => {
            let resource = resource.clone().ok_or_else(|| {
                ParseFailure::new("missing_resource", "tenant_binding requires resource")
            })?;
            let tenant_field = validate_field_name(required_scalar(record, "tenant_field")?)?;
            let actor = match required_scalar(record, "actor")? {
                "authenticated_user_id" => ActorIdentityKind::AuthenticatedUser,
                "authenticated_tenant_id" => ActorIdentityKind::Tenant,
                value => {
                    return Err(ParseFailure::new(
                        "unsupported_actor",
                        format!("unsupported project invariant actor class: {value}"),
                    ));
                }
            };
            let _ = resource;
            (
                InvariantKind::TenantBinding,
                InvariantRequirement::TenantBinding {
                    resource_tenant_field: tenant_field,
                    required_actor_identity: actor,
                },
            )
        }
        "required_role" => {
            let roles = required_non_empty_list(record, "roles")?
                .into_iter()
                .map(|role| validate_symbol("role", &role))
                .collect::<Result<Vec<_>, _>>()?;
            require_non_empty_scope(route.as_deref(), &methods, &operations, &target_paths)?;
            (
                InvariantKind::RequiredRole,
                InvariantRequirement::RequiredRole {
                    required_roles: roles,
                },
            )
        }
        "protected_properties" => {
            if resource.is_none() {
                return Err(ParseFailure::new(
                    "missing_resource",
                    "protected_properties requires resource",
                ));
            }
            let properties = required_non_empty_list(record, "properties")?
                .into_iter()
                .map(|property| validate_field_name(&property))
                .collect::<Result<Vec<_>, _>>()?;
            if operations.is_empty()
                || operations.iter().any(|operation| {
                    !matches!(
                        operation,
                        DataOperationKind::Insert
                            | DataOperationKind::Update
                            | DataOperationKind::Upsert
                    )
                })
            {
                return Err(ParseFailure::new(
                    "unsupported_mutation_scope",
                    "protected_properties requires non-empty INSERT/UPDATE/UPSERT operations",
                ));
            }
            (
                InvariantKind::ProtectedProperties,
                InvariantRequirement::ProtectedProperties {
                    protected_properties: properties,
                    mutation_operations: operations.clone(),
                },
            )
        }
        "elevated_client_context" => {
            require_non_empty_scope(route.as_deref(), &methods, &operations, &target_paths)?;
            let guards = required_non_empty_list(record, "required_guards")?
                .into_iter()
                .map(|guard| parse_guard_kind(&guard))
                .collect::<Result<Vec<_>, _>>()?;
            let contexts = match optional_list(record, "allowed_contexts")? {
                Some(values) => values
                    .into_iter()
                    .map(|context| parse_server_context(&context))
                    .collect::<Result<Vec<_>, _>>()?,
                None => vec![
                    R3_SERVER_CONTEXT_EXPRESS.to_owned(),
                    R3_SERVER_CONTEXT_NEXT_APP.to_owned(),
                    R3_SERVER_CONTEXT_NEXT_PAGES_API.to_owned(),
                    R3_SERVER_CONTEXT_SUPABASE_EDGE.to_owned(),
                ],
            };
            (
                InvariantKind::ElevatedClientContext,
                InvariantRequirement::ElevatedClientContext {
                    allowed_server_contexts: contexts,
                    required_guard_kinds: guards,
                },
            )
        }
        value => {
            return Err(ParseFailure::new(
                "unsupported_invariant_type",
                format!("unsupported project invariant type: {value}"),
            ));
        }
    };

    let invariant_id =
        StableSemanticId::from_parts(PROJECT_INVARIANT_NAMESPACE, &[id], model_limits)
            .map_err(|error| ParseFailure::new("invalid_model_identity", error.to_string()))?;
    let scope = InvariantScope::new(
        route,
        methods,
        resource,
        operations,
        target_paths,
        model_limits,
    )
    .map_err(|error| ParseFailure::new("invalid_scope", error.to_string()))?;
    let provenance = SourceLocation::new(
        declaration_path.clone(),
        0,
        content_len,
        content_digest.to_owned(),
    )
    .map_err(|error| ParseFailure::new("invalid_provenance", error.to_string()))?;

    InvariantDefinition::new(
        invariant_id,
        kind,
        InvariantSource::ProjectDeclaration,
        scope,
        requirement,
        vec![provenance],
        model_limits,
    )
    .map_err(|error| ParseFailure::new("invalid_definition", error.to_string()))
}

fn validate_type_keys(invariant_type: &str, record: &RawInvariant) -> Result<(), ParseFailure> {
    let common = [
        "id",
        "type",
        "resource",
        "route",
        "methods",
        "operations",
        "paths",
    ];
    let specific: &[&str] = match invariant_type {
        "tenant_binding" => &["tenant_field", "actor"],
        "required_role" => &["roles"],
        "protected_properties" => &["properties"],
        "elevated_client_context" => &["required_guards", "allowed_contexts"],
        value => {
            return Err(ParseFailure::new(
                "unsupported_invariant_type",
                format!("unsupported project invariant type: {value}"),
            ));
        }
    };
    for key in record.fields.keys() {
        if !common.contains(&key.as_str()) && !specific.contains(&key.as_str()) {
            return Err(ParseFailure::new(
                "key_not_valid_for_type",
                format!("key {key} is not valid for project invariant type {invariant_type}"),
            ));
        }
    }
    Ok(())
}

fn required_scalar<'a>(record: &'a RawInvariant, key: &str) -> Result<&'a str, ParseFailure> {
    match record.fields.get(key) {
        Some(RawValue::Scalar(value)) => Ok(value),
        Some(RawValue::List(_)) => Err(ParseFailure::new(
            "wrong_value_kind",
            format!("project invariant key {key} requires a quoted string"),
        )),
        None => Err(ParseFailure::new(
            "missing_required_key",
            format!("project invariant key is required: {key}"),
        )),
    }
}

fn optional_scalar<'a>(
    record: &'a RawInvariant,
    key: &str,
) -> Result<Option<&'a str>, ParseFailure> {
    match record.fields.get(key) {
        Some(RawValue::Scalar(value)) => Ok(Some(value)),
        Some(RawValue::List(_)) => Err(ParseFailure::new(
            "wrong_value_kind",
            format!("project invariant key {key} requires a quoted string"),
        )),
        None => Ok(None),
    }
}

fn optional_list(record: &RawInvariant, key: &str) -> Result<Option<Vec<String>>, ParseFailure> {
    match record.fields.get(key) {
        Some(RawValue::List(values)) => Ok(Some(values.clone())),
        Some(RawValue::Scalar(_)) => Err(ParseFailure::new(
            "wrong_value_kind",
            format!("project invariant key {key} requires a quoted-string array"),
        )),
        None => Ok(None),
    }
}

fn required_non_empty_list(record: &RawInvariant, key: &str) -> Result<Vec<String>, ParseFailure> {
    let values = optional_list(record, key)?.ok_or_else(|| {
        ParseFailure::new(
            "missing_required_key",
            format!("project invariant key is required: {key}"),
        )
    })?;
    if values.is_empty() {
        return Err(ParseFailure::new(
            "empty_required_set",
            format!("project invariant set must not be empty: {key}"),
        ));
    }
    Ok(values)
}

fn validate_scope_text(field: &str, value: &str) -> Result<String, ParseFailure> {
    if value.len() > DEFAULT_MAX_PROJECT_SCOPE_TEXT_BYTES || value.trim() != value {
        return Err(ParseFailure::new(
            "scope_text_invalid",
            format!("project invariant {field} exceeds bounds or is padded"),
        ));
    }
    Ok(value.to_owned())
}

fn validate_field_name(value: &str) -> Result<String, ParseFailure> {
    if value.len() > DEFAULT_MAX_PROJECT_COLLECTION_ITEM_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(ParseFailure::new(
            "invalid_field_name",
            format!("unsupported project invariant field/property name: {value}"),
        ));
    }
    Ok(value.to_owned())
}

fn validate_symbol(kind: &str, value: &str) -> Result<String, ParseFailure> {
    if value.len() > DEFAULT_MAX_PROJECT_COLLECTION_ITEM_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b':' | b'.')
        })
    {
        return Err(ParseFailure::new(
            "invalid_symbol",
            format!("unsupported project invariant {kind} value: {value}"),
        ));
    }
    Ok(value.to_owned())
}

fn parse_methods(values: Vec<String>) -> Result<Vec<HttpMethod>, ParseFailure> {
    if values.len() > DEFAULT_MAX_PROJECT_COLLECTION_ITEMS {
        return Err(ParseFailure::new(
            "collection_too_large",
            "too many HTTP methods",
        ));
    }
    values
        .into_iter()
        .map(|value| match value.as_str() {
            "GET" => Ok(HttpMethod::Get),
            "POST" => Ok(HttpMethod::Post),
            "PUT" => Ok(HttpMethod::Put),
            "PATCH" => Ok(HttpMethod::Patch),
            "DELETE" => Ok(HttpMethod::Delete),
            "OPTIONS" => Ok(HttpMethod::Options),
            "HEAD" => Ok(HttpMethod::Head),
            _ => Err(ParseFailure::new(
                "unsupported_http_method",
                format!("unsupported project invariant HTTP method: {value}"),
            )),
        })
        .collect()
}

fn parse_operations(values: Vec<String>) -> Result<Vec<DataOperationKind>, ParseFailure> {
    if values.len() > DEFAULT_MAX_PROJECT_COLLECTION_ITEMS {
        return Err(ParseFailure::new(
            "collection_too_large",
            "too many operation kinds",
        ));
    }
    values
        .into_iter()
        .map(|value| match value.as_str() {
            "READ" => Ok(DataOperationKind::Read),
            "INSERT" => Ok(DataOperationKind::Insert),
            "UPDATE" => Ok(DataOperationKind::Update),
            "UPSERT" => Ok(DataOperationKind::Upsert),
            "DELETE" => Ok(DataOperationKind::Delete),
            "RPC" => Ok(DataOperationKind::Rpc),
            _ => Err(ParseFailure::new(
                "unsupported_operation",
                format!("unsupported project invariant operation: {value}"),
            )),
        })
        .collect()
}

fn parse_paths(values: Vec<String>) -> Result<Vec<NormalizedRepoPath>, ParseFailure> {
    if values.len() > DEFAULT_MAX_PROJECT_COLLECTION_ITEMS {
        return Err(ParseFailure::new(
            "collection_too_large",
            "too many target paths",
        ));
    }
    values
        .into_iter()
        .map(|value| {
            NormalizedRepoPath::parse(&value, DEFAULT_MAX_PROJECT_SCOPE_PATH_BYTES)
                .map_err(|error| ParseFailure::new("invalid_target_path", error.to_string()))
        })
        .collect()
}

fn parse_resource(value: &str, limits: BusinessLogicLimits) -> Result<ResourceRef, ParseFailure> {
    if value.len() > DEFAULT_MAX_PROJECT_SCOPE_TEXT_BYTES {
        return Err(ParseFailure::new(
            "resource_too_large",
            "project invariant resource exceeds the frozen size cap",
        ));
    }
    let Some((namespace, resource_name)) = value.split_once('.') else {
        return Err(ParseFailure::new(
            "invalid_resource",
            "project invariant resource must use namespace.resource form",
        ));
    };
    if namespace.is_empty()
        || resource_name.is_empty()
        || resource_name.contains('.')
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        || !resource_name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ParseFailure::new(
            "invalid_resource",
            format!("unsupported project invariant resource identity: {value}"),
        ));
    }
    ResourceRef::new(
        Some("supabase".to_owned()),
        Some(namespace.to_owned()),
        resource_name,
        ResourceKind::Table,
        None,
        limits,
    )
    .map_err(|error| ParseFailure::new("invalid_resource", error.to_string()))
}

fn parse_guard_kind(value: &str) -> Result<GuardKind, ParseFailure> {
    match value {
        "authentication" => Ok(GuardKind::Authentication),
        "required_role" => Ok(GuardKind::RequiredRole),
        "tenant_binding" => Ok(GuardKind::TenantBinding),
        "ownership_binding" => Ok(GuardKind::OwnershipBinding),
        "object_membership" => Ok(GuardKind::ObjectMembership),
        "property_allowlist" => Ok(GuardKind::PropertyAllowlist),
        "elevated_client_boundary" => Ok(GuardKind::ElevatedClientBoundary),
        _ => Err(ParseFailure::new(
            "unsupported_guard_kind",
            format!("unsupported project invariant guard kind: {value}"),
        )),
    }
}

fn parse_server_context(value: &str) -> Result<String, ParseFailure> {
    match value {
        R3_SERVER_CONTEXT_EXPRESS
        | R3_SERVER_CONTEXT_NEXT_APP
        | R3_SERVER_CONTEXT_NEXT_PAGES_API
        | R3_SERVER_CONTEXT_SUPABASE_EDGE => Ok(value.to_owned()),
        _ => Err(ParseFailure::new(
            "unsupported_server_context",
            format!("unsupported project invariant server context: {value}"),
        )),
    }
}

fn require_non_empty_scope(
    route: Option<&str>,
    _methods: &[HttpMethod],
    operations: &[DataOperationKind],
    paths: &[NormalizedRepoPath],
) -> Result<(), ParseFailure> {
    if route.is_none() && operations.is_empty() && paths.is_empty() {
        return Err(ParseFailure::new(
            "missing_scope",
            "project invariant type requires a bounded route/operation/path scope; methods alone are insufficient",
        ));
    }
    Ok(())
}

pub struct ProjectInvariantEvaluationInputs<'a> {
    pub path: &'a CrossLayerPath,
    pub route: &'a RouteObservation,
    pub guard_coverage_state: &'a CoverageState,
    pub actors: &'a [ActorContext],
    pub guards: &'a [GuardObservation],
    pub values: &'a [ValueOrigin],
    pub operation: &'a DataOperation,
    pub client: Option<&'a ProviderClientAuthority>,
    pub r2_support: Option<&'a R2SupportCorrelation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectInvariantEvaluationError {
    NotProjectDeclaration,
    MissingProviderClient,
    MissingR2Support,
    Family(String),
}

impl fmt::Display for ProjectInvariantEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotProjectDeclaration => formatter
                .write_str("project invariant evaluator requires ProjectDeclaration source"),
            Self::MissingProviderClient => {
                formatter.write_str("elevated project invariant requires provider-client context")
            }
            Self::MissingR2Support => formatter
                .write_str("elevated project invariant requires canonical R2 support context"),
            Self::Family(message) => write!(
                formatter,
                "project invariant family evaluation failed: {message}"
            ),
        }
    }
}

impl std::error::Error for ProjectInvariantEvaluationError {}

pub fn evaluate_project_invariant(
    invariant: &InvariantDefinition,
    inputs: ProjectInvariantEvaluationInputs<'_>,
    limits: BusinessLogicLimits,
) -> Result<InvariantEvaluation, ProjectInvariantEvaluationError> {
    if invariant.source() != InvariantSource::ProjectDeclaration {
        return Err(ProjectInvariantEvaluationError::NotProjectDeclaration);
    }
    match invariant.kind() {
        InvariantKind::TenantBinding => evaluate_tenant_binding(
            TenantBindingInputs {
                invariant,
                path: inputs.path,
                route: inputs.route,
                actors: inputs.actors,
                guards: inputs.guards,
                values: inputs.values,
                operation: inputs.operation,
            },
            limits,
        )
        .map_err(|error| ProjectInvariantEvaluationError::Family(error.to_string())),
        InvariantKind::RequiredRole => evaluate_required_role(
            RequiredRoleInputs {
                invariant,
                path: inputs.path,
                route: inputs.route,
                guard_coverage_state: inputs.guard_coverage_state,
                guards: inputs.guards,
                operation: inputs.operation,
            },
            limits,
        )
        .map_err(|error| ProjectInvariantEvaluationError::Family(error.to_string())),
        InvariantKind::ProtectedProperties => evaluate_protected_properties(
            ProtectedPropertiesInputs {
                invariant,
                path: inputs.path,
                route: inputs.route,
                operation: inputs.operation,
            },
            limits,
        )
        .map_err(|error| ProjectInvariantEvaluationError::Family(error.to_string())),
        InvariantKind::ElevatedClientContext => {
            let client = inputs
                .client
                .ok_or(ProjectInvariantEvaluationError::MissingProviderClient)?;
            let r2_support = inputs
                .r2_support
                .ok_or(ProjectInvariantEvaluationError::MissingR2Support)?;
            evaluate_elevated_client(
                ElevatedClientInputs {
                    invariant,
                    path: inputs.path,
                    route: inputs.route,
                    guard_coverage_state: inputs.guard_coverage_state,
                    guards: inputs.guards,
                    operation: inputs.operation,
                    client,
                    r2_support,
                },
                limits,
            )
            .map_err(|error| ProjectInvariantEvaluationError::Family(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::business_logic::invariant::combine_tightening_requirement_states;
    use crate::business_logic::model::InvariantEvaluationState;

    const SAFE: &str = include_str!(
        "../../../../fixtures/repos/r3-business-logic/project-invariants/safe-tightening/.sentrdel/invariants.toml"
    );
    const FORBIDDEN_SUPPRESSION: &str = include_str!(
        "../../../../fixtures/repos/r3-business-logic/project-invariants/forbidden-suppression/.sentrdel/invariants.toml"
    );
    const FORBIDDEN_AUTHORITY: &str = include_str!(
        "../../../../fixtures/repos/r3-business-logic/project-invariants/forbidden-authority/.sentrdel/invariants.toml"
    );
    const BUILTIN_IMPERSONATION: &str = include_str!(
        "../../../../fixtures/repos/r3-business-logic/project-invariants/builtin-impersonation/.sentrdel/invariants.toml"
    );

    fn path() -> NormalizedRepoPath {
        NormalizedRepoPath::parse(PROJECT_INVARIANT_PATH, DEFAULT_MAX_PROJECT_SCOPE_PATH_BYTES)
            .expect("project invariant path")
    }

    fn load(content: Option<&str>) -> ProjectInvariantLoad {
        load_project_invariants(
            content,
            &path(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ProjectInvariantLimits::default(),
            BusinessLogicLimits::default(),
        )
    }

    #[test]
    fn safe_fixture_loads_as_tightening_project_definition() {
        let loaded = load(Some(SAFE));
        assert_eq!(loaded.state(), ProjectInvariantLoadState::Loaded);
        assert!(loaded.diagnostics().is_empty());
        assert_eq!(loaded.definitions().len(), 1);
        let invariant = &loaded.definitions()[0];
        assert_eq!(invariant.source(), InvariantSource::ProjectDeclaration);
        assert_eq!(invariant.kind(), InvariantKind::TenantBinding);
        assert_eq!(invariant.scope().route_pattern(), Some("/accounts/:id"));
        assert_eq!(
            invariant.scope().http_methods(),
            &[HttpMethod::Get, HttpMethod::Patch]
        );
        let resource = invariant.scope().resource().expect("resource scope");
        assert_eq!(resource.provider(), Some("supabase"));
        assert_eq!(resource.namespace(), Some("public"));
        assert_eq!(resource.resource_name(), "accounts");
    }

    #[test]
    fn missing_file_adds_no_project_requirement() {
        let loaded = load(None);
        assert_eq!(loaded.state(), ProjectInvariantLoadState::Missing);
        assert!(loaded.definitions().is_empty());
        assert!(loaded.diagnostics().is_empty());
    }

    #[test]
    fn suppression_and_authority_fixtures_fail_whole_document_closed() {
        for content in [FORBIDDEN_SUPPRESSION, FORBIDDEN_AUTHORITY] {
            let loaded = load(Some(content));
            assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
            assert!(loaded.definitions().is_empty());
            assert_eq!(loaded.diagnostics().len(), 1);
            assert_eq!(loaded.diagnostics()[0].code(), "forbidden_authority_key");
        }
    }

    #[test]
    fn builtin_namespace_impersonation_is_rejected() {
        let loaded = load(Some(BUILTIN_IMPERSONATION));
        assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
        assert!(loaded.definitions().is_empty());
        assert_eq!(loaded.diagnostics()[0].code(), "invalid_id");
    }

    #[test]
    fn unknown_version_unknown_key_and_wrong_type_fail_closed() {
        for content in [
            "version = 2\n",
            "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = [\"admin\"]\nfuture_magic = \"x\"\n",
            "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = \"admin\"\n",
        ] {
            let loaded = load(Some(content));
            assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
            assert!(loaded.definitions().is_empty());
        }
    }

    #[test]
    fn duplicate_ids_and_irrelevant_cross_type_keys_are_rejected() {
        let duplicate = "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = [\"admin\"]\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/b\"\nroles = [\"admin\"]\n";
        assert_eq!(
            load(Some(duplicate)).state(),
            ProjectInvariantLoadState::Rejected
        );

        let irrelevant = "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = [\"admin\"]\nproperties = [\"role\"]\n";
        let loaded = load(Some(irrelevant));
        assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
        assert_eq!(loaded.diagnostics()[0].code(), "key_not_valid_for_type");
    }

    #[test]
    fn escaping_or_absolute_target_paths_are_rejected() {
        for target in ["../escape", "/absolute", "src\\escape.rs"] {
            let content = format!(
                "version = 1\n[[invariant]]\nid = \"admin-check\"\ntype = \"required_role\"\npaths = [\"{target}\"]\nroles = [\"admin\"]\n"
            );
            let loaded = load(Some(&content));
            assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
            assert!(loaded.definitions().is_empty());
        }
    }

    #[test]
    fn malformed_or_executable_shaped_values_never_become_clean_configuration() {
        for content in [
            "version = 1\n[[invariant]\nid = \"a\"\n",
            "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = []\n",
            "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = [\"admin\"]\ncommand = \"echo owned\"\n",
        ] {
            let loaded = load(Some(content));
            assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
            assert!(loaded.definitions().is_empty());
        }
    }

    #[test]
    fn malformed_list_items_are_rejected_without_reinterpretation_or_panic() {
        for content in [
            "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = [admin\"]\n",
            "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = [é\"]\n",
            "version = 1\n[[invariant]]\nid = \"a\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = [\"admin\", viewer\"]\n",
        ] {
            let loaded = load(Some(content));
            assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
            assert!(loaded.definitions().is_empty());
            assert_eq!(loaded.diagnostics()[0].code(), "malformed_string");
        }
    }

    #[test]
    fn privileged_and_elevated_methods_alone_do_not_create_global_scope() {
        for invariant in [
            "version = 1\n[[invariant]]\nid = \"role\"\ntype = \"required_role\"\nmethods = [\"DELETE\"]\nroles = [\"admin\"]\n",
            "version = 1\n[[invariant]]\nid = \"elevated\"\ntype = \"elevated_client_context\"\nmethods = [\"POST\"]\nrequired_guards = [\"required_role\"]\n",
        ] {
            let loaded = load(Some(invariant));
            assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
            assert_eq!(loaded.diagnostics()[0].code(), "missing_scope");
        }
    }

    #[test]
    fn malformed_project_configuration_cannot_relax_builtin_state() {
        let loaded = load(Some(
            "version = 1\n[[invariant]]\nid = \"role\"\ntype = \"required_role\"\nroute = \"/admin\"\nroles = []\n",
        ));
        assert_eq!(loaded.state(), ProjectInvariantLoadState::Rejected);
        assert!(loaded.definitions().is_empty());
        assert_eq!(
            combine_tightening_requirement_states(
                InvariantEvaluationState::Violated,
                InvariantEvaluationState::NotApplicable
            ),
            InvariantEvaluationState::Violated
        );
        assert_eq!(
            combine_tightening_requirement_states(
                InvariantEvaluationState::Unknown,
                InvariantEvaluationState::Satisfied
            ),
            InvariantEvaluationState::Unknown
        );
    }

    #[test]
    fn collection_and_file_caps_fail_closed() {
        let roles = (0..=DEFAULT_MAX_PROJECT_COLLECTION_ITEMS)
            .map(|index| format!("\"role{index}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let content = format!(
            "version = 1\n[[invariant]]\nid = \"admin-check\"\ntype = \"required_role\"\nroute = \"/a\"\nroles = [{roles}]\n"
        );
        assert_eq!(
            load(Some(&content)).state(),
            ProjectInvariantLoadState::Rejected
        );

        let oversized = "x".repeat(ProjectInvariantLimits::default().max_file_bytes + 1);
        assert_eq!(
            load(Some(&oversized)).state(),
            ProjectInvariantLoadState::Rejected
        );
    }

    #[test]
    fn all_supported_types_freeze_to_project_source_without_new_authority() {
        let content = r#"version = 1
[[invariant]]
id = "tenant"
type = "tenant_binding"
resource = "public.accounts"
tenant_field = "user_id"
actor = "authenticated_user_id"
[[invariant]]
id = "role"
type = "required_role"
route = "/admin"
roles = ["admin"]
[[invariant]]
id = "props"
type = "protected_properties"
resource = "public.profiles"
operations = ["UPDATE"]
properties = ["role"]
[[invariant]]
id = "elevated"
type = "elevated_client_context"
route = "/internal"
required_guards = ["required_role"]
allowed_contexts = ["express-server"]
"#;
        let loaded = load(Some(content));
        assert_eq!(loaded.state(), ProjectInvariantLoadState::Loaded);
        assert_eq!(loaded.definitions().len(), 4);
        assert!(
            loaded
                .definitions()
                .iter()
                .all(|value| value.source() == InvariantSource::ProjectDeclaration)
        );
        let kinds = loaded
            .definitions()
            .iter()
            .map(InvariantDefinition::kind)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            kinds,
            BTreeSet::from([
                InvariantKind::TenantBinding,
                InvariantKind::RequiredRole,
                InvariantKind::ProtectedProperties,
                InvariantKind::ElevatedClientContext,
            ])
        );
        const { assert!(!PROJECT_INVARIANT_CREATES_FINDINGS) };
        const { assert!(!PROJECT_INVARIANT_EXECUTES_TARGET_CODE) };
        const { assert!(!PROJECT_INVARIANT_PERFORMS_NETWORK_ACCESS) };
        const { assert!(!PROJECT_INVARIANT_REQUESTS_PROVIDER_CREDENTIALS) };
        const { assert!(!PROJECT_INVARIANT_PARSE_FAILURE_DISABLES_BUILTINS) };
        const { assert!(!PROJECT_INVARIANT_CAN_WEAKEN_BUILTINS) };
        const { assert!(DEFAULT_MAX_PROJECT_DIAGNOSTICS > 0) };
    }
}
