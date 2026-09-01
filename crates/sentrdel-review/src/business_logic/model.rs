//! Bounded internal cross-layer IR for R3 business-logic analysis.
//!
//! These types are static analysis observations and interpretations only. They
//! do not prove runtime reachability, hosted state, exploitability, or access.

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
    InvalidSourceRange,
    EmptyContentDigest,
    TooManyProvenance {
        count: usize,
        max: usize,
    },
    TooManyRelatedIds {
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
            Self::EmptyIdentityPart { index } => {
                write!(
                    formatter,
                    "semantic identity part {index} must not be empty"
                )
            }
            Self::IdentityPartTooLarge { index, bytes, max } => write!(
                formatter,
                "semantic identity part {index} size {bytes} exceeds cap {max}"
            ),
            Self::IdentityTooLarge { bytes, max } => write!(
                formatter,
                "semantic identity total size {bytes} exceeds cap {max}"
            ),
            Self::InvalidSourceRange => formatter.write_str("source byte range is invalid"),
            Self::EmptyContentDigest => {
                formatter.write_str("source content digest must not be empty")
            }
            Self::TooManyProvenance { count, max } => {
                write!(formatter, "provenance count {count} exceeds cap {max}")
            }
            Self::TooManyRelatedIds { count, max } => write!(
                formatter,
                "related semantic id count {count} exceeds cap {max}"
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

        let mut total_bytes = 0_usize;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLocation {
    pub path: NormalizedRepoPath,
    pub start_byte: usize,
    pub end_byte: usize,
    pub content_digest: String,
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
        Ok(Self {
            path,
            start_byte,
            end_byte,
            content_digest,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameworkFamily {
    Express,
    NextApp,
    NextPagesApi,
    SupabaseEdge,
    OtherSupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub route_id: StableSemanticId,
    pub framework: FrameworkFamily,
    pub method: HttpMethod,
    pub route_pattern: String,
    pub handler_semantic_key: Option<String>,
    pub callback_chain: Vec<StableSemanticId>,
    pub provenance: Vec<SourceLocation>,
    pub coverage_state: CoverageState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorIdentityKind {
    AuthenticatedUser,
    Tenant,
    Role,
    Service,
    Anonymous,
    RequestControlled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustBasis {
    DirectObservation,
    SupportedDerivation,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorContext {
    pub actor_id: StableSemanticId,
    pub identity_kind: ActorIdentityKind,
    pub source_kind: ActorSourceKind,
    pub semantic_key: String,
    pub trust_basis: TrustBasis,
    pub provenance: Vec<SourceLocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComparisonShape {
    Equal,
    Membership,
    ConjunctionSupported,
    ExplicitAllowlist,
    OtherSupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DominanceScope {
    SameHandlerPrefix,
    SupportedMiddlewarePrefix,
    LinkedHelper,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardObservation {
    pub guard_id: StableSemanticId,
    pub guard_kind: GuardKind,
    pub subject_actor: Option<StableSemanticId>,
    pub resource: Option<ResourceRef>,
    pub required_values: Vec<String>,
    pub comparison_shape: ComparisonShape,
    pub dominance_scope: DominanceScope,
    pub provenance: Vec<SourceLocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub value_id: StableSemanticId,
    pub origin_kind: ValueOriginKind,
    pub semantic_key: String,
    pub source_actor: Option<StableSemanticId>,
    pub derivation_inputs: Vec<StableSemanticId>,
    pub derivation_depth: usize,
    pub provenance: Vec<SourceLocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAuthorityClass {
    UserScoped,
    PublishableOrAnon,
    ElevatedSecretOrServiceRole,
    ServerUnknown,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderClientAuthority {
    pub client_id: StableSemanticId,
    pub provider: String,
    pub authority_class: ProviderAuthorityClass,
    pub source_evidence_ids: Vec<String>,
    pub provenance: Vec<SourceLocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    Table,
    View,
    Function,
    StorageObject,
    ApplicationResource,
    OtherSupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRef {
    pub provider: Option<String>,
    pub namespace: Option<String>,
    pub resource_name: String,
    pub resource_kind: ResourceKind,
    pub r2_subject: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataOperationKind {
    Read,
    Insert,
    Update,
    Upsert,
    Delete,
    Rpc,
    OtherSupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilterOperator {
    Eq,
    In,
    MatchSupported,
    OtherSupported,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilterPredicate {
    pub field_semantic_key: String,
    pub operator: FilterOperator,
    pub value_origin: StableSemanticId,
    pub provenance: SourceLocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldSetMode {
    Explicit,
    BroadRequestObject,
    Dynamic,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldSet {
    pub mode: FieldSetMode,
    pub fields: Vec<String>,
    pub value_origins: Vec<(String, StableSemanticId)>,
    pub provenance: SourceLocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataOperation {
    pub operation_id: StableSemanticId,
    pub operation_kind: DataOperationKind,
    pub resource: ResourceRef,
    pub provider_client: Option<StableSemanticId>,
    pub filters: Vec<FilterPredicate>,
    pub read_fields: Option<FieldSet>,
    pub mutation_fields: Option<FieldSet>,
    pub rpc_name: Option<String>,
    pub handler_symbol: Option<StableSemanticId>,
    pub provenance: Vec<SourceLocation>,
    pub coverage_state: CoverageState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinkBasis {
    SameHandlerStructural,
    SupportedCallbackChain,
    SupportedImportBinding,
    ScipReference,
    ExplicitAdapterLink,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfidenceBasis {
    Extracted,
    Inferred,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossLayerLink {
    pub link_id: StableSemanticId,
    pub source_semantic_id: StableSemanticId,
    pub target_semantic_id: StableSemanticId,
    pub relation: String,
    pub basis: LinkBasis,
    pub confidence_basis: ConfidenceBasis,
    pub provenance: Vec<SourceLocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathState {
    Supported,
    Partial,
    Ambiguous,
    BoundedRejection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossLayerPath {
    pub path_id: StableSemanticId,
    pub route_id: StableSemanticId,
    pub actor_ids: Vec<StableSemanticId>,
    pub guard_ids: Vec<StableSemanticId>,
    pub data_operation_id: StableSemanticId,
    pub provider_client_id: Option<StableSemanticId>,
    pub links: Vec<CrossLayerLink>,
    pub r2_evidence_ids: Vec<String>,
    pub path_state: PathState,
    pub provenance: Vec<SourceLocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvariantKind {
    TenantBinding,
    RequiredRole,
    ProtectedProperties,
    ElevatedClientContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvariantSource {
    BuiltIn,
    ProjectDeclaration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvariantScope {
    pub route_pattern: Option<String>,
    pub http_methods: Vec<HttpMethod>,
    pub resource: Option<ResourceRef>,
    pub operation_kinds: Vec<DataOperationKind>,
    pub target_paths: Vec<NormalizedRepoPath>,
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
    pub invariant_id: StableSemanticId,
    pub kind: InvariantKind,
    pub source: InvariantSource,
    pub scope: InvariantScope,
    pub requirements: InvariantRequirement,
    pub provenance: Vec<SourceLocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvariantEvaluationState {
    Satisfied,
    Violated,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvariantEvaluation {
    pub evaluation_id: StableSemanticId,
    pub invariant_id: StableSemanticId,
    pub path_id: Option<StableSemanticId>,
    pub state: InvariantEvaluationState,
    pub supporting_observation_ids: Vec<StableSemanticId>,
    pub contradicting_observation_ids: Vec<StableSemanticId>,
    pub coverage_reasons: Vec<String>,
    pub provenance: Vec<SourceLocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    pub area: BusinessLogicCoverageArea,
    pub state: CoverageState,
    pub reason_code: String,
    pub scope: String,
    pub input_digests: Vec<String>,
    pub producer: String,
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
            Err(ModelError::IdentityPartTooLarge { .. })
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
    fn derivation_caps_are_enforced_before_correlation() {
        let limits = BusinessLogicLimits {
            max_derivation_fan_in: 1,
            max_derivation_depth: 1,
            ..BusinessLogicLimits::default()
        };
        let value = ValueOrigin {
            value_id: id("r3.value", "derived"),
            origin_kind: ValueOriginKind::SupportedDerived,
            semantic_key: "derived".to_owned(),
            source_actor: None,
            derivation_inputs: vec![id("r3.value", "a"), id("r3.value", "b")],
            derivation_depth: 1,
            provenance: Vec::new(),
        };
        assert!(matches!(
            validate_value_derivation(&value, limits),
            Err(ModelError::DerivationFanInExceeded { .. })
        ));
    }
}
