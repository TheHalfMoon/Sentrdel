//! Final authority gate for canonical R3-T013 data-operation extraction.
//!
//! The raw structural extractor deliberately recognizes only the frozen fluent API shape. This
//! gate removes provider identity until later R2/local correlation and requires canonical T012
//! request-body proof before a mutation may be classified as a broad request-controlled object.
//! Unsupported or ambiguous cases remain PARTIAL/Dynamic; this module grants no runtime, provider,
//! credential, Finding, or query-execution authority.

use sentrdel_schema::coverage::CoverageState;

use super::data_raw;
use super::model::{
    BusinessLogicLimits, DataOperation, FieldSet, FieldSetMode, ModelError, ResourceRef,
    SourceLocation, ValueOriginKind,
};
use super::route::RouteAdapter;
use super::value;
use crate::structural::StructuralLanguage;
use crate::view::NormalizedRepoPath;

pub use data_raw::{
    MAX_DATA_AST_NODES, MAX_DATA_COVERAGE_GAPS, MAX_DATA_FIELDS_PER_OPERATION,
    MAX_DATA_FILTERS_PER_OPERATION, MAX_DATA_OPERATIONS, MAX_DATA_SUPPORTING_VALUES,
    SUPABASE_DATA_EXECUTES_QUERIES, SUPABASE_DATA_PROVES_DATABASE_RESULT,
    SUPABASE_DATA_PROVES_HOSTED_STATE, SUPABASE_DATA_PROVES_RUNTIME_REACHABILITY,
    DataExtractionError,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DataCoverageGapReason {
    DynamicResource,
    DynamicRpcName,
    DynamicSelectedFields,
    DynamicMutationFields,
    DynamicFilterField,
    UnsupportedFilter,
    UnresolvedFilterValue,
    UnsupportedChainMethod,
    AmbiguousRequestObject,
    UnqualifiedBroadRequestObject,
}

impl From<data_raw::DataCoverageGapReason> for DataCoverageGapReason {
    fn from(value: data_raw::DataCoverageGapReason) -> Self {
        match value {
            data_raw::DataCoverageGapReason::DynamicResource => Self::DynamicResource,
            data_raw::DataCoverageGapReason::DynamicRpcName => Self::DynamicRpcName,
            data_raw::DataCoverageGapReason::DynamicSelectedFields => Self::DynamicSelectedFields,
            data_raw::DataCoverageGapReason::DynamicMutationFields => Self::DynamicMutationFields,
            data_raw::DataCoverageGapReason::DynamicFilterField => Self::DynamicFilterField,
            data_raw::DataCoverageGapReason::UnsupportedFilter => Self::UnsupportedFilter,
            data_raw::DataCoverageGapReason::UnresolvedFilterValue => Self::UnresolvedFilterValue,
            data_raw::DataCoverageGapReason::UnsupportedChainMethod => Self::UnsupportedChainMethod,
            data_raw::DataCoverageGapReason::AmbiguousRequestObject => Self::AmbiguousRequestObject,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataCoverageGap {
    reason: DataCoverageGapReason,
    provenance: SourceLocation,
}

impl DataCoverageGap {
    #[must_use]
    pub const fn reason(&self) -> DataCoverageGapReason {
        self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &SourceLocation {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataExtraction {
    operations: Vec<DataOperation>,
    gaps: Vec<DataCoverageGap>,
    supporting_values: Vec<super::model::ValueOrigin>,
}

impl DataExtraction {
    #[must_use]
    pub fn operations(&self) -> &[DataOperation] {
        &self.operations
    }

    #[must_use]
    pub fn gaps(&self) -> &[DataCoverageGap] {
        &self.gaps
    }

    #[must_use]
    pub fn supporting_values(&self) -> &[super::model::ValueOrigin] {
        &self.supporting_values
    }
}

pub fn extract_supabase_data_operations(
    value_adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<DataExtraction, DataExtractionError> {
    let limits = limits.validate().map_err(DataExtractionError::Model)?;
    let raw = data_raw::extract_supabase_data_operations(
        value_adapter,
        language,
        path,
        source,
        limits,
    )?;
    let values = value::extract_value_origins(value_adapter, language, path, source, limits)
        .map_err(DataExtractionError::Value)?;

    let request_body_ranges = values
        .values()
        .iter()
        .filter(|value| value.origin_kind() == ValueOriginKind::RequestBody)
        .flat_map(|value| value.provenance().iter())
        .map(|location| (location.start_byte(), location.end_byte()))
        .collect::<std::collections::BTreeSet<_>>();

    let mut gaps = raw
        .gaps()
        .iter()
        .map(|gap| DataCoverageGap {
            reason: gap.reason().into(),
            provenance: gap.provenance().clone(),
        })
        .collect::<Vec<_>>();
    let mut operations = Vec::with_capacity(raw.operations().len());

    for operation in raw.operations() {
        let mut coverage_state = operation.coverage_state().clone();
        let mutation_fields = match operation.mutation_fields() {
            Some(fields) if fields.mode() == FieldSetMode::BroadRequestObject => {
                let range = (
                    fields.provenance().start_byte(),
                    fields.provenance().end_byte(),
                );
                if request_body_ranges.contains(&range) {
                    Some(fields.clone())
                } else {
                    coverage_state = CoverageState::Partial;
                    gaps.push(DataCoverageGap {
                        reason: DataCoverageGapReason::UnqualifiedBroadRequestObject,
                        provenance: fields.provenance().clone(),
                    });
                    Some(FieldSet::new(
                        FieldSetMode::Dynamic,
                        Vec::new(),
                        Vec::new(),
                        fields.provenance().clone(),
                        limits,
                    )?)
                }
            }
            Some(fields) => Some(fields.clone()),
            None => None,
        };

        // Provider/client identity is intentionally deferred. T013 records local data-operation
        // shape only; T017/T018 may later attach validated provider/client authority evidence.
        let resource = ResourceRef::new(
            None,
            operation.resource().namespace().map(str::to_owned),
            operation.resource().resource_name(),
            operation.resource().resource_kind(),
            operation.resource().r2_subject().map(str::to_owned),
            limits,
        )?;
        operations.push(DataOperation::new(
            operation.operation_id().clone(),
            operation.operation_kind(),
            resource,
            None,
            operation.filters().to_vec(),
            operation.read_fields().cloned(),
            mutation_fields,
            operation.rpc_name().map(str::to_owned),
            operation.handler_symbol().cloned(),
            operation.provenance().to_vec(),
            coverage_state,
            limits,
        )?);
    }

    operations.sort_by(|left, right| left.operation_id().cmp(right.operation_id()));
    gaps.sort_by(|left, right| {
        left.reason
            .cmp(&right.reason)
            .then_with(|| left.provenance.start_byte().cmp(&right.provenance.start_byte()))
            .then_with(|| left.provenance.end_byte().cmp(&right.provenance.end_byte()))
    });
    gaps.dedup_by(|left, right| {
        left.reason == right.reason
            && left.provenance.start_byte() == right.provenance.start_byte()
            && left.provenance.end_byte() == right.provenance.end_byte()
    });

    Ok(DataExtraction {
        operations,
        gaps,
        supporting_values: raw.supporting_values().to_vec(),
    })
}

const _: fn(ModelError) -> DataExtractionError = DataExtractionError::Model;
