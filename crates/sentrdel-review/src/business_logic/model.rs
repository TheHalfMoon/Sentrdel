//! Bounded internal cross-layer IR for R3 business-logic analysis.
//!
//! These types are static analysis observations and interpretations only. They
//! do not prove runtime reachability, hosted state, exploitability, or access.
//! Collection-bearing records can only be created through validated constructors;
//! their bounded, normalized collections are not publicly mutable.

use sentrdel_schema::canonical::{CanonicalError, content_id};
use sentrdel_schema::coverage::CoverageState;
use std::error::Error;
use std::fmt;

use crate::view::NormalizedRepoPath;

pub const DEFAULT_MAX_ID_PART_BYTES: usize = 4 * 1024;
pub const DEFAULT_MAX_ID_TOTAL_BYTES: usize = 16 * 1024;
pub const DEFAULT_MAX_PROVENANCE_PER_RECORD: usize = 64;
pub const DEFAULT_MAX_RELATED_IDS: usize = 128;
pub const DEFAULT_MAX_DERIVATION_FAN_IN: usize = 32;
pub const DEFAULT_MAX_DERIVATION_DEPTH: usize = 16;
pub const DEFAULT_MAX_PATH_LINKS: usize = 128;
pub const DEFAULT_MAX_PATH_CANDIDATES: usize = 4_096;
pub const DEFAULT_MAX_DIAGNOSTICS: usize = 1_024;
pub const DEFAULT_MAX_CONTENT_DIGEST_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BusinessLogicLimits {
    pub max_id_part_bytes: usize,
    pub max_id_total_bytes: usize,
    pub max_provenance_per_record: usize,
    pub max_related_ids: usize,
    pub max_derivation_fan_in: usize,
    pub max_derivation_depth: usize,
    pub max_path_links: usize,
    pub max_path_candidates: usize,
    pub max_diagnostics: usize,
}

impl Default for BusinessLogicLimits {
    fn default() -> Self {
        Self {
            max_id_part_bytes: DEFAULT_MAX_ID_PART_BYTES,
            max_id_total_bytes: DEFAULT_MAX_ID_TOTAL_BYTES,
            max_provenance_per_record: DEFAULT_MAX_PROVENANCE_PER_RECORD,
            max_related_ids: DEFAULT_MAX_RELATED_IDS,
            max_derivation_fan_in: DEFAULT_MAX_DERIVATION_FAN_IN,
            max_derivation_depth: DEFAULT_MAX_DERIVATION_DEPTH,
            max_path_links: DEFAULT_MAX_PATH_LINKS,
            max_path_candidates: DEFAULT_MAX_PATH_CANDIDATES,
            max_diagnostics: DEFAULT_MAX_DIAGNOSTICS,
        }
    }
}

impl BusinessLogicLimits {
    pub fn validate(self) -> Result<Self, ModelError> {
        if self.max_id_part_bytes == 0
            || self.max_id_total_bytes == 0
            || self.max_provenance_per_record == 0
            || self.max_related_ids == 0
            || self.max_derivation_fan_in == 0
            || self.max_derivation_depth == 0
            || self.max_path_links == 0
            || self.max_path_candidates == 0
            || self.max_diagnostics == 0
        {
            return Err(ModelError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug)]
pub enum ModelError {
    InvalidLimits,
    EmptyIdentityParts,
    EmptyIdentityPart {
        index: usize,
    },
    IdentityPartTooLarge {
        index: usize,
        bytes: usize,
        max: usize,
    },
    IdentityTooLarge {
        bytes: usize,
        max: usize,
    },
    EmptyField(&'static str),
    FieldTooLarge {
        field: &'static str,
        bytes: usize,
        max: usize,
    },
    InvalidSourceRange,
    EmptyContentDigest,
    EmptyProvenance,
    EmptyRequiredCollection(&'static str),
    InvariantRequirementKindMismatch {
        kind: InvariantKind,
        requirement_kind: InvariantKind,
    },
    ContentDigestTooLarge {
        bytes: usize,
        max: usize,
    },
    TooManyProvenance {
        count: usize,
        max: usize,
    },
    TooManyRelatedIds {
        count: usize,
        max: usize,
    },
    TooManyCollectionItems {
        field: &'static str,
        count: usize,
        max: usize,
    },
    TooManyPathLinks {
        count: usize,
        max: usize,
    },
    DerivationFanInExceeded {
        count: usize,
        max: usize,
    },
    DerivationDepthExceeded {
        depth: usize,
        max: usize,
    },
    Canonical(CanonicalError),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("business-logic limits must be non-zero"),
            Self::EmptyIdentityParts => {
                formatter.write_str("semantic identity requires at least one part")
            }
            Self::EmptyIdentityPart { index } => write!(
                formatter,
                "semantic identity part {index} must not be empty"
            ),
            Self::IdentityPartTooLarge { index, bytes, max } => write!(
                formatter,
                "semantic identity part {index} size {bytes} exceeds cap {max}"
            ),
            Self::IdentityTooLarge { bytes, max } => write!(
                formatter,
                "semantic identity total size {bytes} exceeds cap {max}"
            ),
            Self::EmptyField(field) => {
                write!(formatter, "business-logic field {field} must not be empty")
            }
            Self::FieldTooLarge { field, bytes, max } => write!(
                formatter,
                "business-logic field {field} size {bytes} exceeds cap {max}"
            ),
            Self::InvalidSourceRange => formatter.write_str("source byte range is invalid"),
            Self::EmptyContentDigest => {
                formatter.write_str("source content digest must not be empty")
            }
            Self::EmptyProvenance => {
                formatter.write_str("semantic record requires explicit source provenance")
            }
            Self::EmptyRequiredCollection(field) => {
                write!(
                    formatter,
                    "required business-logic collection {field} must not be empty"
                )
            }
            Self::InvariantRequirementKindMismatch {
                kind,
                requirement_kind,
            } => write!(
                formatter,
                "invariant kind {kind:?} cannot use requirement kind {requirement_kind:?}"
            ),
            Self::ContentDigestTooLarge { bytes, max } => write!(
                formatter,
                "source content digest size {bytes} exceeds cap {max}"
            ),
            Self::TooManyProvenance { count, max } => {
                write!(formatter, "provenance count {count} exceeds cap {max}")
            }
            Self::TooManyRelatedIds { count, max } => write!(
                formatter,
                "related semantic id count {count} exceeds cap {max}"
            ),
            Self::TooManyCollectionItems { field, count, max } => write!(
                formatter,
                "business-logic collection {field} count {count} exceeds cap {max}"
            ),
            Self::TooManyPathLinks { count, max } => {
                write!(formatter, "path link count {count} exceeds cap {max}")
            }
            Self::DerivationFanInExceeded { count, max } => write!(
                formatter,
                "value derivation fan-in {count} exceeds cap {max}"
            ),
            Self::DerivationDepthExceeded { depth, max } => write!(
                formatter,
                "value derivation depth {depth} exceeds cap {max}"
            ),
            Self::Canonical(source) => {
                write!(formatter, "stable semantic identity failed: {source}")
            }
        }
    }
}

impl Error for ModelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Canonical(source) => Some(source),
            _ => None,
        }
    }
}

impl From<CanonicalError> for ModelError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StableSemanticId(String);

impl StableSemanticId {
    pub fn from_parts(
        namespace: &str,
        parts: &[&str],
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        if parts.is_empty() {
            return Err(ModelError::EmptyIdentityParts);
        }

        validate_bounded_text(namespace, "identity_namespace", limits)?;
        let mut total_bytes = namespace.len();
        for (index, part) in parts.iter().enumerate() {
            if part.trim().is_empty() {
                return Err(ModelError::EmptyIdentityPart { index });
            }
            if part.len() > limits.max_id_part_bytes {
                return Err(ModelError::IdentityPartTooLarge {
                    index,
                    bytes: part.len(),
                    max: limits.max_id_part_bytes,
                });
            }
            total_bytes = total_bytes.saturating_add(part.len());
        }
        if total_bytes > limits.max_id_total_bytes {
            return Err(ModelError::IdentityTooLarge {
                bytes: total_bytes,
                max: limits.max_id_total_bytes,
            });
        }

        Ok(Self(content_id(namespace, &parts)?))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SourceLocation {
    path: NormalizedRepoPath,
    start_byte: usize,
    end_byte: usize,
    content_digest: String,
}

impl SourceLocation {
    pub fn new(
        path: NormalizedRepoPath,
        start_byte: usize,
        end_byte: usize,
        content_digest: impl Into<String>,
    ) -> Result<Self, ModelError> {
        if end_byte < start_byte {
            return Err(ModelError::InvalidSourceRange);
        }
        let content_digest = content_digest.into();
        if content_digest.trim().is_empty() {
            return Err(ModelError::EmptyContentDigest);
        }
        if content_digest.len() > DEFAULT_MAX_CONTENT_DIGEST_BYTES {
            return Err(ModelError::ContentDigestTooLarge {
                bytes: content_digest.len(),
                max: DEFAULT_MAX_CONTENT_DIGEST_BYTES,
            });
        }
        Ok(Self {
            path,
            start_byte,
            end_byte,
            content_digest,
        })
    }

    #[must_use]
    pub fn path(&self) -> &NormalizedRepoPath {
        &self.path
    }

    #[must_use]
    pub const fn start_byte(&self) -> usize {
        self.start_byte
    }

    #[must_use]
    pub const fn end_byte(&self) -> usize {
        self.end_byte
    }

    #[must_use]
    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FrameworkFamily {
    Express,
    NextApp,
    NextPagesApi,
    SupabaseEdge,
    OtherSupported,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Head,
    OtherSupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteObservation {
    route_id: StableSemanticId,
    framework: FrameworkFamily,
    method: HttpMethod,
    route_pattern: String,
    handler_semantic_key: Option<String>,
    callback_chain: Vec<StableSemanticId>,
    provenance: Vec<SourceLocation>,
    coverage_state: CoverageState,
}

impl RouteObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        route_id: StableSemanticId,
        framework: FrameworkFamily,
        method: HttpMethod,
        route_pattern: impl Into<String>,
        handler_semantic_key: Option<String>,
        callback_chain: Vec<StableSemanticId>,
        provenance: Vec<SourceLocation>,
        coverage_state: CoverageState,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let route_pattern = route_pattern.into();
        validate_bounded_text(&route_pattern, "route_pattern", limits)?;
        validate_optional_text(
            handler_semantic_key.as_deref(),
            "handler_semantic_key",
            limits,
        )?;
        Ok(Self {
            route_id,
            framework,
            method,
            route_pattern,
            handler_semantic_key,
            // Callback chains are execution-order sequences, not set-like related IDs.
            callback_chain: preserve_semantic_id_sequence(callback_chain, limits)?,
            provenance: normalize_provenance(provenance, limits)?,
            coverage_state,
        })
    }

    #[must_use]
    pub fn route_id(&self) -> &StableSemanticId {
        &self.route_id
    }
    #[must_use]
    pub const fn framework(&self) -> FrameworkFamily {
        self.framework
    }
    #[must_use]
    pub const fn method(&self) -> HttpMethod {
        self.method
    }
    #[must_use]
    pub fn route_pattern(&self) -> &str {
        &self.route_pattern
    }
    #[must_use]
    pub fn handler_semantic_key(&self) -> Option<&str> {
        self.handler_semantic_key.as_deref()
    }
    #[must_use]
    pub fn callback_chain(&self) -> &[StableSemanticId] {
        &self.callback_chain
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
    #[must_use]
    pub fn coverage_state(&self) -> &CoverageState {
        &self.coverage_state
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActorIdentityKind {
    AuthenticatedUser,
    Tenant,
    Role,
    Service,
    Anonymous,
    RequestControlled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ActorSourceKind {
    VerifiedAuthAdapter,
    RequestParam,
    RequestBody,
    RequestHeader,
    TokenClaim,
    Constant,
    DerivedSupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TrustBasis {
    DirectObservation,
    SupportedDerivation,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorContext {
    actor_id: StableSemanticId,
    identity_kind: ActorIdentityKind,
    source_kind: ActorSourceKind,
    semantic_key: String,
    trust_basis: TrustBasis,
    provenance: Vec<SourceLocation>,
}

impl ActorContext {
    pub fn new(
        actor_id: StableSemanticId,
        identity_kind: ActorIdentityKind,
        source_kind: ActorSourceKind,
        semantic_key: impl Into<String>,
        trust_basis: TrustBasis,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let semantic_key = semantic_key.into();
        validate_bounded_text(&semantic_key, "actor_semantic_key", limits)?;
        Ok(Self {
            actor_id,
            identity_kind,
            source_kind,
            semantic_key,
            trust_basis,
            provenance: normalize_provenance(provenance, limits)?,
        })
    }

    #[must_use]
    pub fn actor_id(&self) -> &StableSemanticId {
        &self.actor_id
    }
    #[must_use]
    pub const fn identity_kind(&self) -> ActorIdentityKind {
        self.identity_kind
    }
    #[must_use]
    pub const fn source_kind(&self) -> ActorSourceKind {
        self.source_kind
    }
    #[must_use]
    pub fn semantic_key(&self) -> &str {
        &self.semantic_key
    }
    #[must_use]
    pub const fn trust_basis(&self) -> TrustBasis {
        self.trust_basis
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GuardKind {
    Authentication,
    RequiredRole,
    TenantBinding,
    OwnershipBinding,
    ObjectMembership,
    PropertyAllowlist,
    PropertyDenylistRequirement,
    ElevatedClientBoundary,
    CustomInvariantRequirement,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ComparisonShape {
    Equal,
    Membership,
    ConjunctionSupported,
    ExplicitAllowlist,
    OtherSupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DominanceScope {
    SameHandlerPrefix,
    SupportedMiddlewarePrefix,
    LinkedHelper,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardObservation {
    guard_id: StableSemanticId,
    guard_kind: GuardKind,
    subject_actor: Option<StableSemanticId>,
    resource: Option<ResourceRef>,
    required_values: Vec<String>,
    comparison_shape: ComparisonShape,
    dominance_scope: DominanceScope,
    provenance: Vec<SourceLocation>,
}

impl GuardObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        guard_id: StableSemanticId,
        guard_kind: GuardKind,
        subject_actor: Option<StableSemanticId>,
        resource: Option<ResourceRef>,
        required_values: Vec<String>,
        comparison_shape: ComparisonShape,
        dominance_scope: DominanceScope,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        Ok(Self {
            guard_id,
            guard_kind,
            subject_actor,
            resource,
            required_values: normalize_bounded_strings(
                required_values,
                "guard_required_values",
                limits,
            )?,
            comparison_shape,
            dominance_scope,
            provenance: normalize_provenance(provenance, limits)?,
        })
    }

    #[must_use]
    pub fn guard_id(&self) -> &StableSemanticId {
        &self.guard_id
    }
    #[must_use]
    pub const fn guard_kind(&self) -> GuardKind {
        self.guard_kind
    }
    #[must_use]
    pub fn subject_actor(&self) -> Option<&StableSemanticId> {
        self.subject_actor.as_ref()
    }
    #[must_use]
    pub fn resource(&self) -> Option<&ResourceRef> {
        self.resource.as_ref()
    }
    #[must_use]
    pub fn required_values(&self) -> &[String] {
        &self.required_values
    }
    #[must_use]
    pub const fn comparison_shape(&self) -> ComparisonShape {
        self.comparison_shape
    }
    #[must_use]
    pub const fn dominance_scope(&self) -> DominanceScope {
        self.dominance_scope
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ValueOriginKind {
    RequestPath,
    RequestQuery,
    RequestBody,
    RequestHeader,
    AuthenticatedUserId,
    AuthenticatedTenantId,
    AuthenticatedRole,
    Constant,
    SupportedDerived,
    DatabaseResult,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValueOrigin {
    value_id: StableSemanticId,
    origin_kind: ValueOriginKind,
    semantic_key: String,
    source_actor: Option<StableSemanticId>,
    derivation_inputs: Vec<StableSemanticId>,
    derivation_depth: usize,
    provenance: Vec<SourceLocation>,
}

impl ValueOrigin {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        value_id: StableSemanticId,
        origin_kind: ValueOriginKind,
        semantic_key: impl Into<String>,
        source_actor: Option<StableSemanticId>,
        derivation_inputs: Vec<StableSemanticId>,
        derivation_depth: usize,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let semantic_key = semantic_key.into();
        validate_bounded_text(&semantic_key, "value_semantic_key", limits)?;
        if derivation_inputs.len() > limits.max_derivation_fan_in {
            return Err(ModelError::DerivationFanInExceeded {
                count: derivation_inputs.len(),
                max: limits.max_derivation_fan_in,
            });
        }
        if derivation_depth > limits.max_derivation_depth {
            return Err(ModelError::DerivationDepthExceeded {
                depth: derivation_depth,
                max: limits.max_derivation_depth,
            });
        }
        let mut derivation_inputs = derivation_inputs;
        derivation_inputs.sort();
        derivation_inputs.dedup();
        Ok(Self {
            value_id,
            origin_kind,
            semantic_key,
            source_actor,
            derivation_inputs,
            derivation_depth,
            provenance: normalize_provenance(provenance, limits)?,
        })
    }

    #[must_use]
    pub fn value_id(&self) -> &StableSemanticId {
        &self.value_id
    }
    #[must_use]
    pub const fn origin_kind(&self) -> ValueOriginKind {
        self.origin_kind
    }
    #[must_use]
    pub fn semantic_key(&self) -> &str {
        &self.semantic_key
    }
    #[must_use]
    pub fn source_actor(&self) -> Option<&StableSemanticId> {
        self.source_actor.as_ref()
    }
    #[must_use]
    pub fn derivation_inputs(&self) -> &[StableSemanticId] {
        &self.derivation_inputs
    }
    #[must_use]
    pub const fn derivation_depth(&self) -> usize {
        self.derivation_depth
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProviderAuthorityClass {
    UserScoped,
    PublishableOrAnon,
    ElevatedSecretOrServiceRole,
    ServerUnknown,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderClientAuthority {
    client_id: StableSemanticId,
    provider: String,
    authority_class: ProviderAuthorityClass,
    source_evidence_ids: Vec<String>,
    provenance: Vec<SourceLocation>,
}

impl ProviderClientAuthority {
    pub fn new(
        client_id: StableSemanticId,
        provider: impl Into<String>,
        authority_class: ProviderAuthorityClass,
        source_evidence_ids: Vec<String>,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let provider = provider.into();
        validate_bounded_text(&provider, "provider", limits)?;
        Ok(Self {
            client_id,
            provider,
            authority_class,
            source_evidence_ids: normalize_bounded_strings(
                source_evidence_ids,
                "source_evidence_ids",
                limits,
            )?,
            provenance: normalize_provenance(provenance, limits)?,
        })
    }

    #[must_use]
    pub fn client_id(&self) -> &StableSemanticId {
        &self.client_id
    }
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
    #[must_use]
    pub const fn authority_class(&self) -> ProviderAuthorityClass {
        self.authority_class
    }
    #[must_use]
    pub fn source_evidence_ids(&self) -> &[String] {
        &self.source_evidence_ids
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourceKind {
    Table,
    View,
    Function,
    StorageObject,
    ApplicationResource,
    OtherSupported,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResourceRef {
    provider: Option<String>,
    namespace: Option<String>,
    resource_name: String,
    resource_kind: ResourceKind,
    r2_subject: Option<String>,
}

impl ResourceRef {
    pub fn new(
        provider: Option<String>,
        namespace: Option<String>,
        resource_name: impl Into<String>,
        resource_kind: ResourceKind,
        r2_subject: Option<String>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let resource_name = resource_name.into();
        validate_optional_text(provider.as_deref(), "resource_provider", limits)?;
        validate_optional_text(namespace.as_deref(), "resource_namespace", limits)?;
        validate_bounded_text(&resource_name, "resource_name", limits)?;
        validate_optional_text(r2_subject.as_deref(), "r2_subject", limits)?;
        Ok(Self {
            provider,
            namespace,
            resource_name,
            resource_kind,
            r2_subject,
        })
    }

    #[must_use]
    pub fn provider(&self) -> Option<&str> {
        self.provider.as_deref()
    }
    #[must_use]
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
    #[must_use]
    pub fn resource_name(&self) -> &str {
        &self.resource_name
    }
    #[must_use]
    pub const fn resource_kind(&self) -> ResourceKind {
        self.resource_kind
    }
    #[must_use]
    pub fn r2_subject(&self) -> Option<&str> {
        self.r2_subject.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DataOperationKind {
    Read,
    Insert,
    Update,
    Upsert,
    Delete,
    Rpc,
    OtherSupported,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FilterOperator {
    Eq,
    In,
    MatchSupported,
    OtherSupported,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FilterPredicate {
    field_semantic_key: String,
    operator: FilterOperator,
    value_origin: StableSemanticId,
    provenance: SourceLocation,
}

impl FilterPredicate {
    pub fn new(
        field_semantic_key: impl Into<String>,
        operator: FilterOperator,
        value_origin: StableSemanticId,
        provenance: SourceLocation,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let field_semantic_key = field_semantic_key.into();
        validate_bounded_text(&field_semantic_key, "filter_field_semantic_key", limits)?;
        Ok(Self {
            field_semantic_key,
            operator,
            value_origin,
            provenance,
        })
    }

    #[must_use]
    pub fn field_semantic_key(&self) -> &str {
        &self.field_semantic_key
    }
    #[must_use]
    pub const fn operator(&self) -> FilterOperator {
        self.operator
    }
    #[must_use]
    pub fn value_origin(&self) -> &StableSemanticId {
        &self.value_origin
    }
    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum FieldSetMode {
    Explicit,
    BroadRequestObject,
    Dynamic,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldSet {
    mode: FieldSetMode,
    fields: Vec<String>,
    value_origins: Vec<(String, StableSemanticId)>,
    provenance: SourceLocation,
}

impl FieldSet {
    pub fn new(
        mode: FieldSetMode,
        fields: Vec<String>,
        value_origins: Vec<(String, StableSemanticId)>,
        provenance: SourceLocation,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let fields = normalize_bounded_strings(fields, "field_set_fields", limits)?;
        if value_origins.len() > limits.max_related_ids {
            return Err(ModelError::TooManyCollectionItems {
                field: "field_set_value_origins",
                count: value_origins.len(),
                max: limits.max_related_ids,
            });
        }
        let mut value_origins = value_origins;
        for (field, _) in &value_origins {
            validate_bounded_text(field, "field_set_value_origin_key", limits)?;
        }
        value_origins.sort();
        value_origins.dedup();
        Ok(Self {
            mode,
            fields,
            value_origins,
            provenance,
        })
    }

    #[must_use]
    pub const fn mode(&self) -> FieldSetMode {
        self.mode
    }
    #[must_use]
    pub fn fields(&self) -> &[String] {
        &self.fields
    }
    #[must_use]
    pub fn value_origins(&self) -> &[(String, StableSemanticId)] {
        &self.value_origins
    }
    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataOperation {
    operation_id: StableSemanticId,
    operation_kind: DataOperationKind,
    resource: ResourceRef,
    provider_client: Option<StableSemanticId>,
    filters: Vec<FilterPredicate>,
    read_fields: Option<FieldSet>,
    mutation_fields: Option<FieldSet>,
    rpc_name: Option<String>,
    handler_symbol: Option<StableSemanticId>,
    provenance: Vec<SourceLocation>,
    coverage_state: CoverageState,
}

impl DataOperation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: StableSemanticId,
        operation_kind: DataOperationKind,
        resource: ResourceRef,
        provider_client: Option<StableSemanticId>,
        mut filters: Vec<FilterPredicate>,
        read_fields: Option<FieldSet>,
        mutation_fields: Option<FieldSet>,
        rpc_name: Option<String>,
        handler_symbol: Option<StableSemanticId>,
        provenance: Vec<SourceLocation>,
        coverage_state: CoverageState,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        if filters.len() > limits.max_related_ids {
            return Err(ModelError::TooManyCollectionItems {
                field: "data_operation_filters",
                count: filters.len(),
                max: limits.max_related_ids,
            });
        }
        filters.sort();
        filters.dedup();
        validate_optional_text(rpc_name.as_deref(), "rpc_name", limits)?;
        Ok(Self {
            operation_id,
            operation_kind,
            resource,
            provider_client,
            filters,
            read_fields,
            mutation_fields,
            rpc_name,
            handler_symbol,
            provenance: normalize_provenance(provenance, limits)?,
            coverage_state,
        })
    }

    #[must_use]
    pub fn operation_id(&self) -> &StableSemanticId {
        &self.operation_id
    }
    #[must_use]
    pub const fn operation_kind(&self) -> DataOperationKind {
        self.operation_kind
    }
    #[must_use]
    pub fn resource(&self) -> &ResourceRef {
        &self.resource
    }
    #[must_use]
    pub fn provider_client(&self) -> Option<&StableSemanticId> {
        self.provider_client.as_ref()
    }
    #[must_use]
    pub fn filters(&self) -> &[FilterPredicate] {
        &self.filters
    }
    #[must_use]
    pub fn read_fields(&self) -> Option<&FieldSet> {
        self.read_fields.as_ref()
    }
    #[must_use]
    pub fn mutation_fields(&self) -> Option<&FieldSet> {
        self.mutation_fields.as_ref()
    }
    #[must_use]
    pub fn rpc_name(&self) -> Option<&str> {
        self.rpc_name.as_deref()
    }
    #[must_use]
    pub fn handler_symbol(&self) -> Option<&StableSemanticId> {
        self.handler_symbol.as_ref()
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
    #[must_use]
    pub fn coverage_state(&self) -> &CoverageState {
        &self.coverage_state
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LinkBasis {
    SameHandlerStructural,
    SupportedCallbackChain,
    SupportedImportBinding,
    ScipReference,
    ExplicitAdapterLink,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfidenceBasis {
    Extracted,
    Inferred,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CrossLayerLink {
    link_id: StableSemanticId,
    source_semantic_id: StableSemanticId,
    target_semantic_id: StableSemanticId,
    relation: String,
    basis: LinkBasis,
    confidence_basis: ConfidenceBasis,
    provenance: Vec<SourceLocation>,
}

impl CrossLayerLink {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        link_id: StableSemanticId,
        source_semantic_id: StableSemanticId,
        target_semantic_id: StableSemanticId,
        relation: impl Into<String>,
        basis: LinkBasis,
        confidence_basis: ConfidenceBasis,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let relation = relation.into();
        validate_bounded_text(&relation, "link_relation", limits)?;
        Ok(Self {
            link_id,
            source_semantic_id,
            target_semantic_id,
            relation,
            basis,
            confidence_basis,
            provenance: normalize_provenance(provenance, limits)?,
        })
    }

    #[must_use]
    pub fn link_id(&self) -> &StableSemanticId {
        &self.link_id
    }
    #[must_use]
    pub fn source_semantic_id(&self) -> &StableSemanticId {
        &self.source_semantic_id
    }
    #[must_use]
    pub fn target_semantic_id(&self) -> &StableSemanticId {
        &self.target_semantic_id
    }
    #[must_use]
    pub fn relation(&self) -> &str {
        &self.relation
    }
    #[must_use]
    pub const fn basis(&self) -> LinkBasis {
        self.basis
    }
    #[must_use]
    pub const fn confidence_basis(&self) -> ConfidenceBasis {
        self.confidence_basis
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathState {
    Supported,
    Partial,
    Ambiguous,
    BoundedRejection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossLayerPath {
    path_id: StableSemanticId,
    route_id: StableSemanticId,
    actor_ids: Vec<StableSemanticId>,
    guard_ids: Vec<StableSemanticId>,
    data_operation_id: StableSemanticId,
    provider_client_id: Option<StableSemanticId>,
    links: Vec<CrossLayerLink>,
    r2_evidence_ids: Vec<String>,
    path_state: PathState,
    provenance: Vec<SourceLocation>,
}

impl CrossLayerPath {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path_id: StableSemanticId,
        route_id: StableSemanticId,
        actor_ids: Vec<StableSemanticId>,
        guard_ids: Vec<StableSemanticId>,
        data_operation_id: StableSemanticId,
        provider_client_id: Option<StableSemanticId>,
        mut links: Vec<CrossLayerLink>,
        r2_evidence_ids: Vec<String>,
        path_state: PathState,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        if links.len() > limits.max_path_links {
            return Err(ModelError::TooManyPathLinks {
                count: links.len(),
                max: limits.max_path_links,
            });
        }
        links.sort();
        links.dedup();
        Ok(Self {
            path_id,
            route_id,
            actor_ids: normalize_semantic_ids(actor_ids, limits)?,
            guard_ids: normalize_semantic_ids(guard_ids, limits)?,
            data_operation_id,
            provider_client_id,
            links,
            r2_evidence_ids: normalize_bounded_strings(r2_evidence_ids, "r2_evidence_ids", limits)?,
            path_state,
            provenance: normalize_provenance(provenance, limits)?,
        })
    }

    #[must_use]
    pub fn path_id(&self) -> &StableSemanticId {
        &self.path_id
    }
    #[must_use]
    pub fn route_id(&self) -> &StableSemanticId {
        &self.route_id
    }
    #[must_use]
    pub fn actor_ids(&self) -> &[StableSemanticId] {
        &self.actor_ids
    }
    #[must_use]
    pub fn guard_ids(&self) -> &[StableSemanticId] {
        &self.guard_ids
    }
    #[must_use]
    pub fn data_operation_id(&self) -> &StableSemanticId {
        &self.data_operation_id
    }
    #[must_use]
    pub fn provider_client_id(&self) -> Option<&StableSemanticId> {
        self.provider_client_id.as_ref()
    }
    #[must_use]
    pub fn links(&self) -> &[CrossLayerLink] {
        &self.links
    }
    #[must_use]
    pub fn r2_evidence_ids(&self) -> &[String] {
        &self.r2_evidence_ids
    }
    #[must_use]
    pub const fn path_state(&self) -> PathState {
        self.path_state
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InvariantKind {
    TenantBinding,
    RequiredRole,
    ProtectedProperties,
    ElevatedClientContext,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InvariantSource {
    BuiltIn,
    ProjectDeclaration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvariantScope {
    route_pattern: Option<String>,
    http_methods: Vec<HttpMethod>,
    resource: Option<ResourceRef>,
    operation_kinds: Vec<DataOperationKind>,
    target_paths: Vec<NormalizedRepoPath>,
}

impl InvariantScope {
    pub fn new(
        route_pattern: Option<String>,
        mut http_methods: Vec<HttpMethod>,
        resource: Option<ResourceRef>,
        mut operation_kinds: Vec<DataOperationKind>,
        mut target_paths: Vec<NormalizedRepoPath>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        validate_optional_text(route_pattern.as_deref(), "invariant_route_pattern", limits)?;
        enforce_collection_cap(
            "invariant_http_methods",
            http_methods.len(),
            limits.max_related_ids,
        )?;
        enforce_collection_cap(
            "invariant_operation_kinds",
            operation_kinds.len(),
            limits.max_related_ids,
        )?;
        enforce_collection_cap(
            "invariant_target_paths",
            target_paths.len(),
            limits.max_related_ids,
        )?;
        http_methods.sort();
        http_methods.dedup();
        operation_kinds.sort();
        operation_kinds.dedup();
        target_paths.sort();
        target_paths.dedup();
        Ok(Self {
            route_pattern,
            http_methods,
            resource,
            operation_kinds,
            target_paths,
        })
    }

    #[must_use]
    pub fn route_pattern(&self) -> Option<&str> {
        self.route_pattern.as_deref()
    }
    #[must_use]
    pub fn http_methods(&self) -> &[HttpMethod] {
        &self.http_methods
    }
    #[must_use]
    pub fn resource(&self) -> Option<&ResourceRef> {
        self.resource.as_ref()
    }
    #[must_use]
    pub fn operation_kinds(&self) -> &[DataOperationKind] {
        &self.operation_kinds
    }
    #[must_use]
    pub fn target_paths(&self) -> &[NormalizedRepoPath] {
        &self.target_paths
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvariantRequirement {
    TenantBinding {
        resource_tenant_field: String,
        required_actor_identity: ActorIdentityKind,
    },
    RequiredRole {
        required_roles: Vec<String>,
    },
    ProtectedProperties {
        protected_properties: Vec<String>,
        mutation_operations: Vec<DataOperationKind>,
    },
    ElevatedClientContext {
        allowed_server_contexts: Vec<String>,
        required_guard_kinds: Vec<GuardKind>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvariantDefinition {
    invariant_id: StableSemanticId,
    kind: InvariantKind,
    source: InvariantSource,
    scope: InvariantScope,
    requirements: InvariantRequirement,
    provenance: Vec<SourceLocation>,
}

impl InvariantDefinition {
    pub fn new(
        invariant_id: StableSemanticId,
        kind: InvariantKind,
        source: InvariantSource,
        scope: InvariantScope,
        requirements: InvariantRequirement,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        validate_invariant_requirement_kind(kind, &requirements)?;
        Ok(Self {
            invariant_id,
            kind,
            source,
            scope,
            requirements: normalize_invariant_requirement(requirements, limits)?,
            provenance: normalize_provenance(provenance, limits)?,
        })
    }

    #[must_use]
    pub fn invariant_id(&self) -> &StableSemanticId {
        &self.invariant_id
    }
    #[must_use]
    pub const fn kind(&self) -> InvariantKind {
        self.kind
    }
    #[must_use]
    pub const fn source(&self) -> InvariantSource {
        self.source
    }
    #[must_use]
    pub fn scope(&self) -> &InvariantScope {
        &self.scope
    }
    #[must_use]
    pub fn requirements(&self) -> &InvariantRequirement {
        &self.requirements
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InvariantEvaluationState {
    Satisfied,
    Violated,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvariantEvaluation {
    evaluation_id: StableSemanticId,
    invariant_id: StableSemanticId,
    path_id: Option<StableSemanticId>,
    state: InvariantEvaluationState,
    supporting_observation_ids: Vec<StableSemanticId>,
    contradicting_observation_ids: Vec<StableSemanticId>,
    coverage_reasons: Vec<String>,
    provenance: Vec<SourceLocation>,
}

impl InvariantEvaluation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        evaluation_id: StableSemanticId,
        invariant_id: StableSemanticId,
        path_id: Option<StableSemanticId>,
        state: InvariantEvaluationState,
        supporting_observation_ids: Vec<StableSemanticId>,
        contradicting_observation_ids: Vec<StableSemanticId>,
        coverage_reasons: Vec<String>,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        Ok(Self {
            evaluation_id,
            invariant_id,
            path_id,
            state,
            supporting_observation_ids: normalize_semantic_ids(supporting_observation_ids, limits)?,
            contradicting_observation_ids: normalize_semantic_ids(
                contradicting_observation_ids,
                limits,
            )?,
            coverage_reasons: normalize_bounded_strings(
                coverage_reasons,
                "coverage_reasons",
                limits,
            )?,
            provenance: normalize_provenance(provenance, limits)?,
        })
    }

    #[must_use]
    pub fn evaluation_id(&self) -> &StableSemanticId {
        &self.evaluation_id
    }
    #[must_use]
    pub fn invariant_id(&self) -> &StableSemanticId {
        &self.invariant_id
    }
    #[must_use]
    pub fn path_id(&self) -> Option<&StableSemanticId> {
        self.path_id.as_ref()
    }
    #[must_use]
    pub const fn state(&self) -> InvariantEvaluationState {
        self.state
    }
    #[must_use]
    pub fn supporting_observation_ids(&self) -> &[StableSemanticId] {
        &self.supporting_observation_ids
    }
    #[must_use]
    pub fn contradicting_observation_ids(&self) -> &[StableSemanticId] {
        &self.contradicting_observation_ids
    }
    #[must_use]
    pub fn coverage_reasons(&self) -> &[String] {
        &self.coverage_reasons
    }
    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum BusinessLogicCoverageArea {
    Routes,
    ActorIdentity,
    Guards,
    ValueOrigins,
    DataOperations,
    LocalLinking,
    SemanticLinking,
    R2ProviderCorrelation,
    ProjectInvariants,
    InvariantEvaluation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BusinessLogicCoverage {
    area: BusinessLogicCoverageArea,
    state: CoverageState,
    reason_code: String,
    scope: String,
    input_digests: Vec<String>,
    producer: String,
}

impl BusinessLogicCoverage {
    pub fn new(
        area: BusinessLogicCoverageArea,
        state: CoverageState,
        reason_code: impl Into<String>,
        scope: impl Into<String>,
        input_digests: Vec<String>,
        producer: impl Into<String>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, ModelError> {
        let limits = limits.validate()?;
        let reason_code = reason_code.into();
        let scope = scope.into();
        let producer = producer.into();
        validate_bounded_text(&reason_code, "coverage_reason_code", limits)?;
        validate_bounded_text(&scope, "coverage_scope", limits)?;
        validate_bounded_text(&producer, "coverage_producer", limits)?;
        Ok(Self {
            area,
            state,
            reason_code,
            scope,
            input_digests: normalize_bounded_strings(
                input_digests,
                "coverage_input_digests",
                limits,
            )?,
            producer,
        })
    }

    #[must_use]
    pub const fn area(&self) -> BusinessLogicCoverageArea {
        self.area
    }
    #[must_use]
    pub fn state(&self) -> &CoverageState {
        &self.state
    }
    #[must_use]
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
    #[must_use]
    pub fn input_digests(&self) -> &[String] {
        &self.input_digests
    }
    #[must_use]
    pub fn producer(&self) -> &str {
        &self.producer
    }
}

fn validate_bounded_text(
    value: &str,
    field: &'static str,
    limits: BusinessLogicLimits,
) -> Result<(), ModelError> {
    if value.trim().is_empty() {
        return Err(ModelError::EmptyField(field));
    }
    if value.len() > limits.max_id_part_bytes {
        return Err(ModelError::FieldTooLarge {
            field,
            bytes: value.len(),
            max: limits.max_id_part_bytes,
        });
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    field: &'static str,
    limits: BusinessLogicLimits,
) -> Result<(), ModelError> {
    if let Some(value) = value {
        validate_bounded_text(value, field, limits)?;
    }
    Ok(())
}

fn require_non_empty_collection(field: &'static str, count: usize) -> Result<(), ModelError> {
    if count == 0 {
        return Err(ModelError::EmptyRequiredCollection(field));
    }
    Ok(())
}

fn enforce_collection_cap(field: &'static str, count: usize, max: usize) -> Result<(), ModelError> {
    if count > max {
        return Err(ModelError::TooManyCollectionItems { field, count, max });
    }
    Ok(())
}

fn preserve_semantic_id_sequence(
    values: Vec<StableSemanticId>,
    limits: BusinessLogicLimits,
) -> Result<Vec<StableSemanticId>, ModelError> {
    let limits = limits.validate()?;
    validate_related_id_count(values.len(), limits)?;
    Ok(values)
}

pub(crate) fn normalize_semantic_ids(
    mut values: Vec<StableSemanticId>,
    limits: BusinessLogicLimits,
) -> Result<Vec<StableSemanticId>, ModelError> {
    let limits = limits.validate()?;
    validate_related_id_count(values.len(), limits)?;
    values.sort();
    values.dedup();
    Ok(values)
}

pub(crate) fn normalize_bounded_strings(
    mut values: Vec<String>,
    field: &'static str,
    limits: BusinessLogicLimits,
) -> Result<Vec<String>, ModelError> {
    let limits = limits.validate()?;
    enforce_collection_cap(field, values.len(), limits.max_related_ids)?;
    for value in &values {
        validate_bounded_text(value, field, limits)?;
    }
    values.sort();
    values.dedup();
    Ok(values)
}

fn normalize_provenance(
    mut values: Vec<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<Vec<SourceLocation>, ModelError> {
    let limits = limits.validate()?;
    if values.is_empty() {
        return Err(ModelError::EmptyProvenance);
    }
    validate_provenance_count(values.len(), limits)?;
    values.sort();
    values.dedup();
    Ok(values)
}

fn invariant_requirement_kind(requirement: &InvariantRequirement) -> InvariantKind {
    match requirement {
        InvariantRequirement::TenantBinding { .. } => InvariantKind::TenantBinding,
        InvariantRequirement::RequiredRole { .. } => InvariantKind::RequiredRole,
        InvariantRequirement::ProtectedProperties { .. } => InvariantKind::ProtectedProperties,
        InvariantRequirement::ElevatedClientContext { .. } => InvariantKind::ElevatedClientContext,
    }
}

fn validate_invariant_requirement_kind(
    kind: InvariantKind,
    requirement: &InvariantRequirement,
) -> Result<(), ModelError> {
    let requirement_kind = invariant_requirement_kind(requirement);
    if kind != requirement_kind {
        return Err(ModelError::InvariantRequirementKindMismatch {
            kind,
            requirement_kind,
        });
    }
    Ok(())
}

fn normalize_invariant_requirement(
    requirement: InvariantRequirement,
    limits: BusinessLogicLimits,
) -> Result<InvariantRequirement, ModelError> {
    match requirement {
        InvariantRequirement::TenantBinding {
            resource_tenant_field,
            required_actor_identity,
        } => {
            validate_bounded_text(&resource_tenant_field, "resource_tenant_field", limits)?;
            Ok(InvariantRequirement::TenantBinding {
                resource_tenant_field,
                required_actor_identity,
            })
        }
        InvariantRequirement::RequiredRole { required_roles } => {
            let required_roles =
                normalize_bounded_strings(required_roles, "required_roles", limits)?;
            require_non_empty_collection("required_roles", required_roles.len())?;
            Ok(InvariantRequirement::RequiredRole { required_roles })
        }
        InvariantRequirement::ProtectedProperties {
            protected_properties,
            mut mutation_operations,
        } => {
            enforce_collection_cap(
                "mutation_operations",
                mutation_operations.len(),
                limits.max_related_ids,
            )?;
            mutation_operations.sort();
            mutation_operations.dedup();
            let protected_properties =
                normalize_bounded_strings(protected_properties, "protected_properties", limits)?;
            require_non_empty_collection("protected_properties", protected_properties.len())?;
            require_non_empty_collection("mutation_operations", mutation_operations.len())?;
            Ok(InvariantRequirement::ProtectedProperties {
                protected_properties,
                mutation_operations,
            })
        }
        InvariantRequirement::ElevatedClientContext {
            allowed_server_contexts,
            mut required_guard_kinds,
        } => {
            enforce_collection_cap(
                "required_guard_kinds",
                required_guard_kinds.len(),
                limits.max_related_ids,
            )?;
            required_guard_kinds.sort();
            required_guard_kinds.dedup();
            let allowed_server_contexts = normalize_bounded_strings(
                allowed_server_contexts,
                "allowed_server_contexts",
                limits,
            )?;
            require_non_empty_collection("required_guard_kinds", required_guard_kinds.len())?;
            Ok(InvariantRequirement::ElevatedClientContext {
                allowed_server_contexts,
                required_guard_kinds,
            })
        }
    }
}

pub fn validate_provenance_count(
    count: usize,
    limits: BusinessLogicLimits,
) -> Result<(), ModelError> {
    let limits = limits.validate()?;
    if count > limits.max_provenance_per_record {
        return Err(ModelError::TooManyProvenance {
            count,
            max: limits.max_provenance_per_record,
        });
    }
    Ok(())
}

pub fn validate_related_id_count(
    count: usize,
    limits: BusinessLogicLimits,
) -> Result<(), ModelError> {
    let limits = limits.validate()?;
    if count > limits.max_related_ids {
        return Err(ModelError::TooManyRelatedIds {
            count,
            max: limits.max_related_ids,
        });
    }
    Ok(())
}

pub fn validate_value_derivation(
    value: &ValueOrigin,
    limits: BusinessLogicLimits,
) -> Result<(), ModelError> {
    let limits = limits.validate()?;
    if value.derivation_inputs.len() > limits.max_derivation_fan_in {
        return Err(ModelError::DerivationFanInExceeded {
            count: value.derivation_inputs.len(),
            max: limits.max_derivation_fan_in,
        });
    }
    if value.derivation_depth > limits.max_derivation_depth {
        return Err(ModelError::DerivationDepthExceeded {
            depth: value.derivation_depth,
            max: limits.max_derivation_depth,
        });
    }
    validate_provenance_count(value.provenance.len(), limits)
}

pub fn validate_path_shape(
    path: &CrossLayerPath,
    limits: BusinessLogicLimits,
) -> Result<(), ModelError> {
    let limits = limits.validate()?;
    if path.links.len() > limits.max_path_links {
        return Err(ModelError::TooManyPathLinks {
            count: path.links.len(),
            max: limits.max_path_links,
        });
    }
    validate_related_id_count(path.actor_ids.len(), limits)?;
    validate_related_id_count(path.guard_ids.len(), limits)?;
    validate_provenance_count(path.provenance.len(), limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(namespace: &str, value: &str) -> StableSemanticId {
        StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default())
            .expect("stable id")
    }

    fn source(path: &str, start: usize) -> SourceLocation {
        SourceLocation::new(
            NormalizedRepoPath::parse(path, 4_096).expect("normalized path"),
            start,
            start + 1,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("source location")
    }

    #[test]
    fn stable_ids_are_deterministic_order_sensitive_and_domain_separated() {
        let limits = BusinessLogicLimits::default();
        let first = StableSemanticId::from_parts("r3.route", &["GET", "/a"], limits).unwrap();
        let replay = StableSemanticId::from_parts("r3.route", &["GET", "/a"], limits).unwrap();
        let reordered = StableSemanticId::from_parts("r3.route", &["/a", "GET"], limits).unwrap();
        let other_domain =
            StableSemanticId::from_parts("r3.actor", &["GET", "/a"], limits).unwrap();
        assert_eq!(first, replay);
        assert_ne!(first, reordered);
        assert_ne!(first, other_domain);
        assert!(first.as_str().starts_with("sha256:"));
    }

    #[test]
    fn identity_and_resource_limits_fail_closed() {
        let limits = BusinessLogicLimits {
            max_id_part_bytes: 2,
            max_id_total_bytes: 4,
            ..BusinessLogicLimits::default()
        };
        assert!(matches!(
            StableSemanticId::from_parts("r3.route", &["toolong"], limits),
            Err(ModelError::FieldTooLarge { .. } | ModelError::IdentityPartTooLarge { .. })
        ));
        assert!(
            BusinessLogicLimits {
                max_path_links: 0,
                ..BusinessLogicLimits::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn unknown_is_explicit_and_never_aliases_satisfied() {
        assert_ne!(
            InvariantEvaluationState::Unknown,
            InvariantEvaluationState::Satisfied
        );
        assert_eq!(PathState::Ambiguous, PathState::Ambiguous);
        assert_eq!(DominanceScope::Unknown, DominanceScope::Unknown);
    }

    #[test]
    fn route_constructor_preserves_callback_order_and_normalizes_provenance() {
        let limits = BusinessLogicLimits::default();
        let a = id("r3.callback", "a");
        let b = id("r3.callback", "b");
        let route = RouteObservation::new(
            id("r3.route", "route"),
            FrameworkFamily::Express,
            HttpMethod::Get,
            "/accounts/:id",
            Some("handler".to_owned()),
            vec![b.clone(), a.clone(), b],
            vec![
                source("src/b.js", 2),
                source("src/a.js", 1),
                source("src/b.js", 2),
            ],
            CoverageState::Covered,
            limits,
        )
        .unwrap();
        assert_eq!(
            route.callback_chain(),
            &[id("r3.callback", "b"), a, id("r3.callback", "b")]
        );
        assert_eq!(route.provenance().len(), 2);
        assert!(route.provenance()[0].path() < route.provenance()[1].path());

        let tight = BusinessLogicLimits {
            max_related_ids: 1,
            ..limits
        };
        assert!(matches!(
            RouteObservation::new(
                id("r3.route", "too-many"),
                FrameworkFamily::Express,
                HttpMethod::Get,
                "/a",
                None,
                vec![id("r3.callback", "a"), id("r3.callback", "b")],
                Vec::new(),
                CoverageState::Partial,
                tight,
            ),
            Err(ModelError::TooManyRelatedIds { .. })
        ));
    }

    #[test]
    fn semantic_record_construction_rejects_empty_provenance() {
        let limits = BusinessLogicLimits::default();
        assert!(matches!(
            RouteObservation::new(
                id("r3.route", "missing-provenance"),
                FrameworkFamily::Express,
                HttpMethod::Get,
                "/accounts/:id",
                None,
                Vec::new(),
                Vec::new(),
                CoverageState::Partial,
                limits,
            ),
            Err(ModelError::EmptyProvenance)
        ));

        assert!(matches!(
            InvariantEvaluation::new(
                id("r3.evaluation", "missing-provenance"),
                id("r3.invariant", "tenant-binding"),
                None,
                InvariantEvaluationState::Unknown,
                Vec::new(),
                Vec::new(),
                vec!["missing-link".to_owned()],
                Vec::new(),
                limits,
            ),
            Err(ModelError::EmptyProvenance)
        ));
    }

    #[test]
    fn derivation_caps_are_enforced_at_construction() {
        let limits = BusinessLogicLimits {
            max_derivation_fan_in: 1,
            max_derivation_depth: 1,
            ..BusinessLogicLimits::default()
        };
        assert!(matches!(
            ValueOrigin::new(
                id("r3.value", "derived"),
                ValueOriginKind::SupportedDerived,
                "derived",
                None,
                vec![id("r3.value", "a"), id("r3.value", "b")],
                1,
                Vec::new(),
                limits,
            ),
            Err(ModelError::DerivationFanInExceeded { .. })
        ));
    }

    #[test]
    fn cross_layer_path_constructor_normalizes_and_caps_every_collection() {
        let limits = BusinessLogicLimits::default();
        let actor_a = id("r3.actor", "a");
        let actor_b = id("r3.actor", "b");
        let path = CrossLayerPath::new(
            id("r3.path", "p"),
            id("r3.route", "r"),
            vec![actor_b.clone(), actor_a.clone(), actor_b],
            vec![id("r3.guard", "g")],
            id("r3.data", "d"),
            None,
            Vec::new(),
            vec![
                "evidence:z".to_owned(),
                "evidence:a".to_owned(),
                "evidence:z".to_owned(),
            ],
            PathState::Partial,
            vec![source("src/z.js", 5), source("src/a.js", 1)],
            limits,
        )
        .unwrap();
        assert_eq!(path.actor_ids(), &[actor_a, id("r3.actor", "b")]);
        assert_eq!(
            path.r2_evidence_ids(),
            &["evidence:a".to_owned(), "evidence:z".to_owned()]
        );
        assert_eq!(
            path.provenance()[0].path(),
            &NormalizedRepoPath::parse("src/a.js", 4_096).unwrap()
        );
    }

    #[test]
    fn invariant_definition_rejects_empty_required_sets() {
        let limits = BusinessLogicLimits::default();
        let scope = InvariantScope::new(None, Vec::new(), None, Vec::new(), Vec::new(), limits)
            .expect("scope");
        let provenance = vec![source("src/invariants.rs", 1)];

        for (kind, requirement, expected_field) in [
            (
                InvariantKind::RequiredRole,
                InvariantRequirement::RequiredRole {
                    required_roles: Vec::new(),
                },
                "required_roles",
            ),
            (
                InvariantKind::ProtectedProperties,
                InvariantRequirement::ProtectedProperties {
                    protected_properties: Vec::new(),
                    mutation_operations: vec![DataOperationKind::Update],
                },
                "protected_properties",
            ),
            (
                InvariantKind::ProtectedProperties,
                InvariantRequirement::ProtectedProperties {
                    protected_properties: vec!["is_admin".to_owned()],
                    mutation_operations: Vec::new(),
                },
                "mutation_operations",
            ),
            (
                InvariantKind::ElevatedClientContext,
                InvariantRequirement::ElevatedClientContext {
                    allowed_server_contexts: Vec::new(),
                    required_guard_kinds: Vec::new(),
                },
                "required_guard_kinds",
            ),
        ] {
            assert!(matches!(
                InvariantDefinition::new(
                    id("r3.invariant", expected_field),
                    kind,
                    InvariantSource::ProjectDeclaration,
                    scope.clone(),
                    requirement,
                    provenance.clone(),
                    limits,
                ),
                Err(ModelError::EmptyRequiredCollection(field)) if field == expected_field
            ));
        }

        InvariantDefinition::new(
            id("r3.invariant", "elevated-optional-contexts"),
            InvariantKind::ElevatedClientContext,
            InvariantSource::ProjectDeclaration,
            scope,
            InvariantRequirement::ElevatedClientContext {
                allowed_server_contexts: Vec::new(),
                required_guard_kinds: vec![GuardKind::Authentication],
            },
            provenance,
            limits,
        )
        .expect("optional allowed server contexts remain optional");
    }

    #[test]
    fn invariant_definition_rejects_every_kind_requirement_mismatch() {
        let limits = BusinessLogicLimits::default();
        let scope = InvariantScope::new(None, Vec::new(), None, Vec::new(), Vec::new(), limits)
            .expect("scope");
        let provenance = vec![source("src/invariants.rs", 1)];
        let kinds = [
            InvariantKind::TenantBinding,
            InvariantKind::RequiredRole,
            InvariantKind::ProtectedProperties,
            InvariantKind::ElevatedClientContext,
        ];

        for kind in kinds {
            for requirement_kind in kinds {
                if kind == requirement_kind {
                    continue;
                }
                let requirement = match requirement_kind {
                    InvariantKind::TenantBinding => InvariantRequirement::TenantBinding {
                        resource_tenant_field: "tenant_id".to_owned(),
                        required_actor_identity: ActorIdentityKind::AuthenticatedUser,
                    },
                    InvariantKind::RequiredRole => InvariantRequirement::RequiredRole {
                        required_roles: vec!["admin".to_owned()],
                    },
                    InvariantKind::ProtectedProperties => {
                        InvariantRequirement::ProtectedProperties {
                            protected_properties: vec!["is_admin".to_owned()],
                            mutation_operations: vec![DataOperationKind::Update],
                        }
                    }
                    InvariantKind::ElevatedClientContext => {
                        InvariantRequirement::ElevatedClientContext {
                            allowed_server_contexts: Vec::new(),
                            required_guard_kinds: vec![GuardKind::Authentication],
                        }
                    }
                };
                assert!(matches!(
                    InvariantDefinition::new(
                        id("r3.invariant", "mismatch"),
                        kind,
                        InvariantSource::ProjectDeclaration,
                        scope.clone(),
                        requirement,
                        provenance.clone(),
                        limits,
                    ),
                    Err(ModelError::InvariantRequirementKindMismatch {
                        kind: actual_kind,
                        requirement_kind: actual_requirement_kind,
                    }) if actual_kind == kind && actual_requirement_kind == requirement_kind
                ));
            }
        }
    }

    #[test]
    fn invariant_definition_normalizes_nested_requirement_sets() {
        let limits = BusinessLogicLimits::default();
        let scope = InvariantScope::new(
            Some("/admin".to_owned()),
            vec![HttpMethod::Delete, HttpMethod::Delete],
            None,
            vec![DataOperationKind::Delete],
            Vec::new(),
            limits,
        )
        .unwrap();
        let definition = InvariantDefinition::new(
            id("r3.invariant", "admin"),
            InvariantKind::RequiredRole,
            InvariantSource::BuiltIn,
            scope,
            InvariantRequirement::RequiredRole {
                required_roles: vec!["z".to_owned(), "admin".to_owned(), "z".to_owned()],
            },
            vec![source("src/invariants.rs", 1)],
            limits,
        )
        .unwrap();
        match definition.requirements() {
            InvariantRequirement::RequiredRole { required_roles } => {
                assert_eq!(required_roles, &["admin".to_owned(), "z".to_owned()]);
            }
            other => panic!("unexpected requirement: {other:?}"),
        }
    }
}
