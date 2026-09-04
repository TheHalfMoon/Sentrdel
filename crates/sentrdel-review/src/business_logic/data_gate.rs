//! Bounded Supabase JavaScript/TypeScript data-operation extraction for canonical R3-T013.
//!
//! Repository source is data only. This module observes a deliberately small static fluent-API
//! subset selected explicitly by the caller. It never executes a query or target code, performs
//! provider/network access, receives provider credentials, creates Findings, or claims hosted or
//! runtime database state. Provider/client identity is intentionally deferred to later canonical
//! correlation tasks. Broad request-controlled mutation objects require canonical T012 proof.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use sentrdel_schema::canonical::content_id;
use sentrdel_schema::coverage::CoverageState;

use super::model::{
    BusinessLogicLimits, DataOperation, DataOperationKind, FieldSet, FieldSetMode, FilterOperator,
    FilterPredicate, ModelError, ResourceKind, ResourceRef, SourceLocation, StableSemanticId,
    ValueOrigin, ValueOriginKind,
};
use super::route::RouteAdapter;
use super::value::{self, ValueExtractionError};
use crate::structural::{StructuralError, StructuralLanguage, StructuralRegistry};
use crate::view::NormalizedRepoPath;

pub const MAX_DATA_AST_NODES: usize = 65_536;
pub const MAX_DATA_OPERATIONS: usize = 4_096;
pub const MAX_DATA_COVERAGE_GAPS: usize = 4_096;
pub const MAX_DATA_FILTERS_PER_OPERATION: usize = 64;
pub const MAX_DATA_FIELDS_PER_OPERATION: usize = 256;
pub const MAX_DATA_SUPPORTING_VALUES: usize = 4_096;
pub const SUPABASE_DATA_EXECUTES_QUERIES: bool = false;
pub const SUPABASE_DATA_PROVES_HOSTED_STATE: bool = false;
pub const SUPABASE_DATA_PROVES_RUNTIME_REACHABILITY: bool = false;
pub const SUPABASE_DATA_PROVES_DATABASE_RESULT: bool = false;

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
    UnqualifiedBroadRequestObject,
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
    supporting_values: Vec<ValueOrigin>,
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
    pub fn supporting_values(&self) -> &[ValueOrigin] {
        &self.supporting_values
    }
}

#[derive(Debug)]
pub enum DataExtractionError {
    Structural(StructuralError),
    Value(ValueExtractionError),
    Model(ModelError),
    TooManyAstNodes { count: usize, max: usize },
    TooManyOperations { count: usize, max: usize },
    TooManyCoverageGaps { count: usize, max: usize },
    TooManyFilters { count: usize, max: usize },
    TooManyFields { count: usize, max: usize },
    TooManySupportingValues { count: usize, max: usize },
    ParseFailed(String),
}

impl fmt::Display for DataExtractionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Structural(source) => {
                write!(formatter, "data structural validation failed: {source}")
            }
            Self::Value(source) => write!(
                formatter,
                "data value-origin qualification failed: {source}"
            ),
            Self::Model(source) => write!(formatter, "data model validation failed: {source}"),
            Self::TooManyAstNodes { count, max } => {
                write!(formatter, "data AST node count {count} exceeds cap {max}")
            }
            Self::TooManyOperations { count, max } => {
                write!(formatter, "data operation count {count} exceeds cap {max}")
            }
            Self::TooManyCoverageGaps { count, max } => write!(
                formatter,
                "data coverage gap count {count} exceeds cap {max}"
            ),
            Self::TooManyFilters { count, max } => {
                write!(formatter, "data filter count {count} exceeds cap {max}")
            }
            Self::TooManyFields { count, max } => {
                write!(formatter, "data field count {count} exceeds cap {max}")
            }
            Self::TooManySupportingValues { count, max } => write!(
                formatter,
                "data supporting value count {count} exceeds cap {max}"
            ),
            Self::ParseFailed(message) => write!(formatter, "data parse failed: {message}"),
        }
    }
}

impl Error for DataExtractionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Structural(source) => Some(source),
            Self::Value(source) => Some(source),
            Self::Model(source) => Some(source),
            _ => None,
        }
    }
}

impl From<StructuralError> for DataExtractionError {
    fn from(value: StructuralError) -> Self {
        Self::Structural(value)
    }
}

impl From<ValueExtractionError> for DataExtractionError {
    fn from(value: ValueExtractionError) -> Self {
        Self::Value(value)
    }
}

impl From<ModelError> for DataExtractionError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

pub fn extract_supabase_data_operations(
    value_adapter: RouteAdapter,
    language: StructuralLanguage,
    path: &NormalizedRepoPath,
    source: &[u8],
    limits: BusinessLogicLimits,
) -> Result<DataExtraction, DataExtractionError> {
    let limits = limits.validate()?;
    let validator = StructuralRegistry::new(&[])?;
    validator.scan_language(language, path, source)?;
    let source_text = std::str::from_utf8(source).map_err(|_| StructuralError::NonUtf8Source)?;
    let digest =
        content_id("r3-data-source", &(path.as_str(), source_text)).map_err(ModelError::from)?;
    let tree = parse_tree(language, source_text)?;
    let nodes = collect_nodes(tree.root_node())?;
    let values = value::extract_value_origins(value_adapter, language, path, source, limits)?;

    let mut value_by_range = BTreeMap::new();
    let mut request_body_ranges = BTreeSet::new();
    for value in values.values() {
        for location in value.provenance() {
            value_by_range
                .entry((location.start_byte(), location.end_byte()))
                .or_insert_with(|| value.value_id().clone());
            if value.origin_kind() == ValueOriginKind::RequestBody {
                request_body_ranges.insert((location.start_byte(), location.end_byte()));
            }
        }
    }

    let mut builder = ExtractionBuilder::new(
        path,
        source_text,
        digest,
        limits,
        value_by_range,
        request_body_ranges,
    );
    for node in &nodes {
        if node.kind() != "call_expression" {
            continue;
        }
        let Some(method) = call_method(*node, source_text) else {
            continue;
        };
        if is_direct_data_operation(method) {
            builder.observe_operation(*node, method)?;
        }
    }
    builder.finish()
}

struct ExtractionBuilder<'a> {
    path: &'a NormalizedRepoPath,
    source: &'a str,
    digest: String,
    limits: BusinessLogicLimits,
    value_by_range: BTreeMap<(usize, usize), StableSemanticId>,
    request_body_ranges: BTreeSet<(usize, usize)>,
    operations: Vec<DataOperation>,
    gaps: Vec<DataCoverageGap>,
    supporting_values: BTreeMap<String, ValueOrigin>,
}

impl<'a> ExtractionBuilder<'a> {
    fn new(
        path: &'a NormalizedRepoPath,
        source: &'a str,
        digest: String,
        limits: BusinessLogicLimits,
        value_by_range: BTreeMap<(usize, usize), StableSemanticId>,
        request_body_ranges: BTreeSet<(usize, usize)>,
    ) -> Self {
        Self {
            path,
            source,
            digest,
            limits,
            value_by_range,
            request_body_ranges,
            operations: Vec::new(),
            gaps: Vec::new(),
            supporting_values: BTreeMap::new(),
        }
    }

    fn location(&self, start: usize, end: usize) -> Result<SourceLocation, DataExtractionError> {
        Ok(SourceLocation::new(
            self.path.clone(),
            start,
            end,
            self.digest.clone(),
        )?)
    }

    fn gap(
        &mut self,
        reason: DataCoverageGapReason,
        start: usize,
        end: usize,
    ) -> Result<(), DataExtractionError> {
        let count = self.gaps.len().saturating_add(1);
        if count > MAX_DATA_COVERAGE_GAPS {
            return Err(DataExtractionError::TooManyCoverageGaps {
                count,
                max: MAX_DATA_COVERAGE_GAPS,
            });
        }
        self.gaps.push(DataCoverageGap {
            reason,
            provenance: self.location(start, end)?,
        });
        Ok(())
    }

    fn observe_operation(
        &mut self,
        call: tree_sitter::Node<'_>,
        method: &str,
    ) -> Result<(), DataExtractionError> {
        if self.operations.len() >= MAX_DATA_OPERATIONS {
            return Err(DataExtractionError::TooManyOperations {
                count: self.operations.len().saturating_add(1),
                max: MAX_DATA_OPERATIONS,
            });
        }
        if method == "rpc" {
            return self.observe_rpc(call);
        }

        let Some(function) = call.child_by_field_name("function") else {
            return Ok(());
        };
        let Some(receiver) = function.child_by_field_name("object") else {
            return Ok(());
        };
        if receiver.kind() != "call_expression"
            || call_method(receiver, self.source) != Some("from")
        {
            // A select chained after a mutation is metadata for that mutation, not a second read.
            return Ok(());
        }

        let from_args = call_arguments(receiver);
        let Some(resource_node) = from_args.first().copied() else {
            self.gap(
                DataCoverageGapReason::DynamicResource,
                receiver.start_byte(),
                receiver.end_byte(),
            )?;
            return Ok(());
        };
        let Some(resource_name) = static_string(resource_node, self.source) else {
            self.gap(
                DataCoverageGapReason::DynamicResource,
                resource_node.start_byte(),
                resource_node.end_byte(),
            )?;
            return Ok(());
        };

        let operation_kind = match method {
            "select" => DataOperationKind::Read,
            "insert" => DataOperationKind::Insert,
            "update" => DataOperationKind::Update,
            "upsert" => DataOperationKind::Upsert,
            "delete" => DataOperationKind::Delete,
            _ => return Ok(()),
        };

        let mut partial = false;
        let mut read_fields = None;
        let mut mutation_fields = None;
        if operation_kind == DataOperationKind::Read {
            let (fields, is_partial) = self.selected_fields(call)?;
            read_fields = fields;
            partial |= is_partial;
        } else if matches!(
            operation_kind,
            DataOperationKind::Insert | DataOperationKind::Update | DataOperationKind::Upsert
        ) {
            let args = call_arguments(call);
            if let Some(argument) = args.first().copied() {
                let (fields, is_partial) = self.mutation_field_set(argument)?;
                mutation_fields = Some(fields);
                partial |= is_partial;
            } else {
                partial = true;
                self.gap(
                    DataCoverageGapReason::DynamicMutationFields,
                    call.start_byte(),
                    call.end_byte(),
                )?;
                mutation_fields = Some(FieldSet::new(
                    FieldSetMode::Unknown,
                    Vec::new(),
                    Vec::new(),
                    self.location(call.start_byte(), call.end_byte())?,
                    self.limits,
                )?);
            }
        }

        let mut filters = Vec::new();
        let mut current = call;
        while let Some(next) = chained_call_after(current) {
            let Some(chain_method) = call_method(next, self.source) else {
                break;
            };
            match chain_method {
                "eq" | "in" | "match" => {
                    let (mut observed, is_partial) = self.filters_for_call(next, chain_method)?;
                    filters.append(&mut observed);
                    partial |= is_partial;
                }
                "select" if operation_kind != DataOperationKind::Read => {
                    let (fields, is_partial) = self.selected_fields(next)?;
                    read_fields = fields;
                    partial |= is_partial;
                }
                "single" | "maybeSingle" => {}
                _ => {
                    partial = true;
                    self.gap(
                        DataCoverageGapReason::UnsupportedChainMethod,
                        next.start_byte(),
                        next.end_byte(),
                    )?;
                    break;
                }
            }
            current = next;
        }
        if filters.len() > MAX_DATA_FILTERS_PER_OPERATION {
            return Err(DataExtractionError::TooManyFilters {
                count: filters.len(),
                max: MAX_DATA_FILTERS_PER_OPERATION,
            });
        }

        let resource = ResourceRef::new(
            None,
            None,
            resource_name,
            ResourceKind::Table,
            None,
            self.limits,
        )?;
        let end = current.end_byte().max(call.end_byte());
        let start_string = call.start_byte().to_string();
        let end_string = end.to_string();
        let operation_id = StableSemanticId::from_parts(
            "r3-data-operation",
            &[
                self.path.as_str(),
                operation_kind_key(operation_kind),
                resource.resource_name(),
                &start_string,
                &end_string,
            ],
            self.limits,
        )?;
        self.operations.push(DataOperation::new(
            operation_id,
            operation_kind,
            resource,
            None,
            filters,
            read_fields,
            mutation_fields,
            None,
            None,
            vec![self.location(call.start_byte(), end)?],
            if partial {
                CoverageState::Partial
            } else {
                CoverageState::Covered
            },
            self.limits,
        )?);
        Ok(())
    }

    fn observe_rpc(&mut self, call: tree_sitter::Node<'_>) -> Result<(), DataExtractionError> {
        let args = call_arguments(call);
        let Some(name_node) = args.first().copied() else {
            self.gap(
                DataCoverageGapReason::DynamicRpcName,
                call.start_byte(),
                call.end_byte(),
            )?;
            return Ok(());
        };
        let Some(rpc_name) = static_string(name_node, self.source) else {
            self.gap(
                DataCoverageGapReason::DynamicRpcName,
                name_node.start_byte(),
                name_node.end_byte(),
            )?;
            return Ok(());
        };

        let mut partial = false;
        let mutation_fields = if let Some(argument) = args.get(1).copied() {
            let (fields, is_partial) = self.mutation_field_set(argument)?;
            partial |= is_partial;
            Some(fields)
        } else {
            None
        };

        let mut current = call;
        while let Some(next) = chained_call_after(current) {
            let Some(method) = call_method(next, self.source) else {
                break;
            };
            if matches!(method, "single" | "maybeSingle") {
                current = next;
                continue;
            }
            partial = true;
            self.gap(
                DataCoverageGapReason::UnsupportedChainMethod,
                next.start_byte(),
                next.end_byte(),
            )?;
            break;
        }

        let resource = ResourceRef::new(
            None,
            None,
            rpc_name.clone(),
            ResourceKind::Function,
            None,
            self.limits,
        )?;
        let end = current.end_byte().max(call.end_byte());
        let start_string = call.start_byte().to_string();
        let end_string = end.to_string();
        let operation_id = StableSemanticId::from_parts(
            "r3-data-operation",
            &[
                self.path.as_str(),
                "rpc",
                &rpc_name,
                &start_string,
                &end_string,
            ],
            self.limits,
        )?;
        self.operations.push(DataOperation::new(
            operation_id,
            DataOperationKind::Rpc,
            resource,
            None,
            Vec::new(),
            None,
            mutation_fields,
            Some(rpc_name),
            None,
            vec![self.location(call.start_byte(), end)?],
            if partial {
                CoverageState::Partial
            } else {
                CoverageState::Covered
            },
            self.limits,
        )?);
        Ok(())
    }

    fn selected_fields(
        &mut self,
        call: tree_sitter::Node<'_>,
    ) -> Result<(Option<FieldSet>, bool), DataExtractionError> {
        let args = call_arguments(call);
        let Some(argument) = args.first().copied() else {
            self.gap(
                DataCoverageGapReason::DynamicSelectedFields,
                call.start_byte(),
                call.end_byte(),
            )?;
            return Ok((
                Some(FieldSet::new(
                    FieldSetMode::Unknown,
                    Vec::new(),
                    Vec::new(),
                    self.location(call.start_byte(), call.end_byte())?,
                    self.limits,
                )?),
                true,
            ));
        };
        let Some(raw) = static_string(argument, self.source) else {
            return self.dynamic_selected_fields(argument, FieldSetMode::Dynamic);
        };
        let Some(fields) = parse_static_field_list(&raw) else {
            return self.dynamic_selected_fields(argument, FieldSetMode::Dynamic);
        };
        self.check_field_count(fields.len())?;
        Ok((
            Some(FieldSet::new(
                FieldSetMode::Explicit,
                fields,
                Vec::new(),
                self.location(argument.start_byte(), argument.end_byte())?,
                self.limits,
            )?),
            false,
        ))
    }

    fn dynamic_selected_fields(
        &mut self,
        node: tree_sitter::Node<'_>,
        mode: FieldSetMode,
    ) -> Result<(Option<FieldSet>, bool), DataExtractionError> {
        self.gap(
            DataCoverageGapReason::DynamicSelectedFields,
            node.start_byte(),
            node.end_byte(),
        )?;
        Ok((
            Some(FieldSet::new(
                mode,
                Vec::new(),
                Vec::new(),
                self.location(node.start_byte(), node.end_byte())?,
                self.limits,
            )?),
            true,
        ))
    }

    fn mutation_field_set(
        &mut self,
        argument: tree_sitter::Node<'_>,
    ) -> Result<(FieldSet, bool), DataExtractionError> {
        if argument.kind() == "object" {
            return self.object_field_set(argument);
        }
        if argument.kind() == "array" {
            return self.array_field_set(argument);
        }
        if self.is_verified_request_body(argument) {
            return Ok((
                FieldSet::new(
                    FieldSetMode::BroadRequestObject,
                    Vec::new(),
                    Vec::new(),
                    self.location(argument.start_byte(), argument.end_byte())?,
                    self.limits,
                )?,
                false,
            ));
        }

        self.gap(
            DataCoverageGapReason::DynamicMutationFields,
            argument.start_byte(),
            argument.end_byte(),
        )?;
        if looks_request_like(self.source, argument) {
            self.gap(
                DataCoverageGapReason::UnqualifiedBroadRequestObject,
                argument.start_byte(),
                argument.end_byte(),
            )?;
        }
        Ok((
            FieldSet::new(
                FieldSetMode::Dynamic,
                Vec::new(),
                Vec::new(),
                self.location(argument.start_byte(), argument.end_byte())?,
                self.limits,
            )?,
            true,
        ))
    }

    fn object_field_set(
        &mut self,
        object: tree_sitter::Node<'_>,
    ) -> Result<(FieldSet, bool), DataExtractionError> {
        let mut fields = Vec::new();
        let mut value_origins = Vec::new();
        let mut dynamic = false;
        let mut cursor = object.walk();
        for child in object.named_children(&mut cursor) {
            match child.kind() {
                "pair" => {
                    let Some(key) = child.child_by_field_name("key") else {
                        dynamic = true;
                        continue;
                    };
                    let Some(field) = static_property_name(key, self.source) else {
                        dynamic = true;
                        continue;
                    };
                    let Some(value) = child.child_by_field_name("value") else {
                        dynamic = true;
                        continue;
                    };
                    fields.push(field.clone());
                    if let Some(origin) = self
                        .value_by_range
                        .get(&(value.start_byte(), value.end_byte()))
                        .cloned()
                    {
                        value_origins.push((field, origin));
                    }
                }
                "shorthand_property_identifier" => {
                    let Some(field) = node_text(child, self.source).map(str::to_owned) else {
                        dynamic = true;
                        continue;
                    };
                    if !is_field_name(&field) {
                        dynamic = true;
                        continue;
                    }
                    fields.push(field.clone());
                    if let Some(origin) = self
                        .value_by_range
                        .get(&(child.start_byte(), child.end_byte()))
                        .cloned()
                    {
                        value_origins.push((field, origin));
                    }
                }
                _ => dynamic = true,
            }
        }
        self.check_field_count(fields.len())?;
        if dynamic {
            self.gap(
                DataCoverageGapReason::DynamicMutationFields,
                object.start_byte(),
                object.end_byte(),
            )?;
        }
        Ok((
            FieldSet::new(
                if dynamic {
                    FieldSetMode::Dynamic
                } else {
                    FieldSetMode::Explicit
                },
                fields,
                value_origins,
                self.location(object.start_byte(), object.end_byte())?,
                self.limits,
            )?,
            dynamic,
        ))
    }

    fn array_field_set(
        &mut self,
        array: tree_sitter::Node<'_>,
    ) -> Result<(FieldSet, bool), DataExtractionError> {
        let mut fields = BTreeSet::new();
        let mut value_origins = Vec::new();
        let mut dynamic = false;
        let mut cursor = array.walk();
        for child in array.named_children(&mut cursor) {
            if child.kind() != "object" {
                dynamic = true;
                continue;
            }
            let (item, item_dynamic) = self.object_field_set(child)?;
            dynamic |= item_dynamic;
            fields.extend(item.fields().iter().cloned());
            value_origins.extend(item.value_origins().iter().cloned());
        }
        self.check_field_count(fields.len())?;
        if dynamic {
            self.gap(
                DataCoverageGapReason::DynamicMutationFields,
                array.start_byte(),
                array.end_byte(),
            )?;
        }
        Ok((
            FieldSet::new(
                if dynamic {
                    FieldSetMode::Dynamic
                } else {
                    FieldSetMode::Explicit
                },
                fields.into_iter().collect(),
                value_origins,
                self.location(array.start_byte(), array.end_byte())?,
                self.limits,
            )?,
            dynamic,
        ))
    }

    fn filters_for_call(
        &mut self,
        call: tree_sitter::Node<'_>,
        method: &str,
    ) -> Result<(Vec<FilterPredicate>, bool), DataExtractionError> {
        match method {
            "eq" | "in" => self.binary_filter(call, method),
            "match" => self.match_filters(call),
            _ => Ok((Vec::new(), false)),
        }
    }

    fn binary_filter(
        &mut self,
        call: tree_sitter::Node<'_>,
        method: &str,
    ) -> Result<(Vec<FilterPredicate>, bool), DataExtractionError> {
        let args = call_arguments(call);
        if args.len() < 2 {
            self.gap(
                DataCoverageGapReason::UnsupportedFilter,
                call.start_byte(),
                call.end_byte(),
            )?;
            return Ok((Vec::new(), true));
        }
        let field_node = args[0];
        let Some(field) =
            static_string(field_node, self.source).filter(|value| is_field_name(value))
        else {
            self.gap(
                DataCoverageGapReason::DynamicFilterField,
                field_node.start_byte(),
                field_node.end_byte(),
            )?;
            return Ok((Vec::new(), true));
        };
        let value_node = args[1];
        let (value_origin, partial) = self.value_id_for_filter(value_node)?;
        let predicate = FilterPredicate::new(
            field,
            if method == "eq" {
                FilterOperator::Eq
            } else {
                FilterOperator::In
            },
            value_origin,
            self.location(call.start_byte(), call.end_byte())?,
            self.limits,
        )?;
        Ok((vec![predicate], partial))
    }

    fn match_filters(
        &mut self,
        call: tree_sitter::Node<'_>,
    ) -> Result<(Vec<FilterPredicate>, bool), DataExtractionError> {
        let args = call_arguments(call);
        let Some(object) = args.first().copied().filter(|node| node.kind() == "object") else {
            self.gap(
                DataCoverageGapReason::UnsupportedFilter,
                call.start_byte(),
                call.end_byte(),
            )?;
            return Ok((Vec::new(), true));
        };
        let mut filters = Vec::new();
        let mut partial = false;
        let mut cursor = object.walk();
        for child in object.named_children(&mut cursor) {
            if child.kind() != "pair" {
                partial = true;
                self.gap(
                    DataCoverageGapReason::UnsupportedFilter,
                    child.start_byte(),
                    child.end_byte(),
                )?;
                continue;
            }
            let Some(key) = child.child_by_field_name("key") else {
                partial = true;
                continue;
            };
            let Some(field) =
                static_property_name(key, self.source).filter(|value| is_field_name(value))
            else {
                partial = true;
                self.gap(
                    DataCoverageGapReason::DynamicFilterField,
                    key.start_byte(),
                    key.end_byte(),
                )?;
                continue;
            };
            let Some(value) = child.child_by_field_name("value") else {
                partial = true;
                continue;
            };
            let (value_origin, value_partial) = self.value_id_for_filter(value)?;
            partial |= value_partial;
            filters.push(FilterPredicate::new(
                field,
                FilterOperator::MatchSupported,
                value_origin,
                self.location(child.start_byte(), child.end_byte())?,
                self.limits,
            )?);
        }
        if filters.len() > MAX_DATA_FILTERS_PER_OPERATION {
            return Err(DataExtractionError::TooManyFilters {
                count: filters.len(),
                max: MAX_DATA_FILTERS_PER_OPERATION,
            });
        }
        Ok((filters, partial))
    }

    fn value_id_for_filter(
        &mut self,
        node: tree_sitter::Node<'_>,
    ) -> Result<(StableSemanticId, bool), DataExtractionError> {
        if let Some(value) = self
            .value_by_range
            .get(&(node.start_byte(), node.end_byte()))
            .cloned()
        {
            return Ok((value, false));
        }

        self.gap(
            DataCoverageGapReason::UnresolvedFilterValue,
            node.start_byte(),
            node.end_byte(),
        )?;
        if self.supporting_values.len() >= MAX_DATA_SUPPORTING_VALUES {
            return Err(DataExtractionError::TooManySupportingValues {
                count: self.supporting_values.len().saturating_add(1),
                max: MAX_DATA_SUPPORTING_VALUES,
            });
        }
        let start = node.start_byte().to_string();
        let end = node.end_byte().to_string();
        let id = StableSemanticId::from_parts(
            "r3-data-unknown-filter-value",
            &[self.path.as_str(), &start, &end],
            self.limits,
        )?;
        let unknown = ValueOrigin::new(
            id.clone(),
            ValueOriginKind::Unknown,
            format!("unknown:data-filter@{start}:{end}"),
            None,
            Vec::new(),
            0,
            vec![self.location(node.start_byte(), node.end_byte())?],
            self.limits,
        )?;
        self.supporting_values
            .entry(id.as_str().to_owned())
            .or_insert(unknown);
        Ok((id, true))
    }

    fn is_verified_request_body(&self, node: tree_sitter::Node<'_>) -> bool {
        self.request_body_ranges
            .contains(&(node.start_byte(), node.end_byte()))
    }

    fn check_field_count(&self, count: usize) -> Result<(), DataExtractionError> {
        if count > MAX_DATA_FIELDS_PER_OPERATION {
            return Err(DataExtractionError::TooManyFields {
                count,
                max: MAX_DATA_FIELDS_PER_OPERATION,
            });
        }
        Ok(())
    }

    fn finish(mut self) -> Result<DataExtraction, DataExtractionError> {
        self.operations.sort_by(|left, right| {
            left.operation_id()
                .as_str()
                .cmp(right.operation_id().as_str())
        });
        self.operations
            .dedup_by(|left, right| left.operation_id() == right.operation_id());
        self.gaps.sort_by(|left, right| {
            left.reason
                .cmp(&right.reason)
                .then_with(|| {
                    left.provenance
                        .start_byte()
                        .cmp(&right.provenance.start_byte())
                })
                .then_with(|| left.provenance.end_byte().cmp(&right.provenance.end_byte()))
        });
        self.gaps.dedup_by(|left, right| {
            left.reason == right.reason
                && left.provenance.start_byte() == right.provenance.start_byte()
                && left.provenance.end_byte() == right.provenance.end_byte()
        });
        let mut supporting_values: Vec<_> = self.supporting_values.into_values().collect();
        supporting_values.sort_by(|left, right| left.value_id().cmp(right.value_id()));
        Ok(DataExtraction {
            operations: self.operations,
            gaps: self.gaps,
            supporting_values,
        })
    }
}

fn parse_tree(
    language: StructuralLanguage,
    source: &str,
) -> Result<tree_sitter::Tree, DataExtractionError> {
    let language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| DataExtractionError::ParseFailed(error.to_string()))?;
    parser.parse(source, None).ok_or_else(|| {
        DataExtractionError::ParseFailed("data parser returned no syntax tree".to_owned())
    })
}

fn collect_nodes<'tree>(
    root: tree_sitter::Node<'tree>,
) -> Result<Vec<tree_sitter::Node<'tree>>, DataExtractionError> {
    let mut nodes = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if nodes.len() >= MAX_DATA_AST_NODES {
            return Err(DataExtractionError::TooManyAstNodes {
                count: nodes.len().saturating_add(1),
                max: MAX_DATA_AST_NODES,
            });
        }
        nodes.push(node);
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    Ok(nodes)
}

fn is_direct_data_operation(method: &str) -> bool {
    matches!(
        method,
        "select" | "insert" | "update" | "upsert" | "delete" | "rpc"
    )
}

fn operation_kind_key(kind: DataOperationKind) -> &'static str {
    match kind {
        DataOperationKind::Read => "read",
        DataOperationKind::Insert => "insert",
        DataOperationKind::Update => "update",
        DataOperationKind::Upsert => "upsert",
        DataOperationKind::Delete => "delete",
        DataOperationKind::Rpc => "rpc",
        DataOperationKind::OtherSupported => "other-supported",
    }
}

fn call_method<'a>(call: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    let function = call.child_by_field_name("function")?;
    if function.kind() != "member_expression" {
        return None;
    }
    let property = function.child_by_field_name("property")?;
    (property.kind() == "property_identifier" || property.kind() == "identifier")
        .then(|| node_text(property, source))?
}

fn call_arguments(call: tree_sitter::Node<'_>) -> Vec<tree_sitter::Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).collect()
}

fn chained_call_after(current: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let member = current.parent()?;
    if member.kind() != "member_expression" {
        return None;
    }
    let object = member.child_by_field_name("object")?;
    if object.start_byte() != current.start_byte() || object.end_byte() != current.end_byte() {
        return None;
    }
    let call = member.parent()?;
    if call.kind() != "call_expression" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    (function.start_byte() == member.start_byte() && function.end_byte() == member.end_byte())
        .then_some(call)
}

fn static_string(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let raw = node_text(node, source)?;
    let bytes = raw.as_bytes();
    if bytes.len() < 2 || bytes[0] != *bytes.last()? || !matches!(bytes[0], b'\'' | b'"') {
        return None;
    }
    let inner = raw.get(1..raw.len().saturating_sub(1))?;
    if inner.contains('\\') || inner.contains('\n') || inner.contains('\r') {
        return None;
    }
    Some(inner.to_owned())
}

fn static_property_name(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "property_identifier" | "identifier" | "shorthand_property_identifier" => {
            let value = node_text(node, source)?;
            is_field_name(value).then(|| value.to_owned())
        }
        "string" => static_string(node, source).filter(|value| is_field_name(value)),
        _ => None,
    }
}

fn parse_static_field_list(raw: &str) -> Option<Vec<String>> {
    if raw.trim().is_empty() || raw.contains('*') || raw.contains(['(', ')', ':']) {
        return None;
    }
    let mut fields = Vec::new();
    for field in raw.split(',') {
        let field = field.trim();
        if !is_field_name(field) {
            return None;
        }
        fields.push(field.to_owned());
    }
    fields.sort();
    fields.dedup();
    Some(fields)
}

fn is_field_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.split('.').all(is_identifier)
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first == b'$' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric())
}

fn looks_request_like(source: &str, node: tree_sitter::Node<'_>) -> bool {
    let Some(text) = node_text(node, source) else {
        return false;
    };
    text == "req.body"
        || text == "request.body"
        || text == "req.json()"
        || text == "request.json()"
        || text == "await req.json()"
        || text == "await request.json()"
}

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}