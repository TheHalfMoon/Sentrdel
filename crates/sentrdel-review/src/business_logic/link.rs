//! Bounded local/inter-file semantic linking for canonical R3-T016.
//!
//! Target repository source remains data only. This module never loads modules, executes target
//! code, runs package managers, reads repository configuration, uses provider credentials, or
//! performs network access. Local resolution supports only explicit repository-relative ESM paths
//! with an explicit JavaScript/TypeScript extension and an exact provided target document.
//!
//! SCIP inputs are downstream facts only. This module does not qualify SCIP producers or artifacts;
//! callers may provide `AdmittedScipReference` values only for facts already admitted by the
//! existing bounded SCIP ingestion/producer-qualification boundary. Missing, ambiguous, heuristic,
//! or incomplete semantic-index coverage never becomes a clean fallback.

use std::{collections::BTreeMap, error::Error, fmt};

use sentrdel_schema::{canonical::content_id, coverage::CoverageState};

use super::model::{
    BusinessLogicLimits, ConfidenceBasis, CrossLayerLink, LinkBasis, ModelError, RouteObservation,
    SourceLocation, StableSemanticId,
};
use crate::{
    structural::{StructuralError, StructuralLanguage, StructuralRegistry},
    view::{
        DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath, RepoViewError,
    },
};

pub const MAX_LINK_DOCUMENTS: usize = 4_096;
pub const MAX_LOCAL_IMPORT_BINDINGS: usize = 8_192;
pub const MAX_INTER_FILE_LINKS: usize = 8_192;
pub const MAX_SCIP_REFERENCES: usize = 8_192;
pub const LOCAL_LINK_RELATION: &str = "resolves_to";
pub const CALLBACK_CHAIN_RELATION: &str = "callback_chain";
pub const SCIP_LINK_RELATION: &str = "semantic_reference";
pub const R3_LINK_EXECUTES_TARGET_CODE: bool = false;
pub const R3_LINK_PERFORMS_NETWORK_ACCESS: bool = false;
pub const R3_LINK_QUALIFIES_SCIP_PRODUCERS: bool = false;
pub const R3_LINK_CREATES_FINDINGS: bool = false;

const SUPPORTED_MODULE_EXTENSIONS: &[&str] = &[
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkDocument {
    path: NormalizedRepoPath,
    language: StructuralLanguage,
    source: Vec<u8>,
}

impl LinkDocument {
    pub fn new(
        path: NormalizedRepoPath,
        language: StructuralLanguage,
        source: Vec<u8>,
    ) -> Result<Self, LinkingError> {
        if source.len() > DEFAULT_MAX_FILE_BYTES as usize {
            return Err(LinkingError::DocumentTooLarge {
                path,
                bytes: source.len(),
                max: DEFAULT_MAX_FILE_BYTES as usize,
            });
        }
        Ok(Self {
            path,
            language,
            source,
        })
    }

    #[must_use]
    pub fn path(&self) -> &NormalizedRepoPath {
        &self.path
    }

    #[must_use]
    pub const fn language(&self) -> StructuralLanguage {
        self.language
    }

    #[must_use]
    pub fn source(&self) -> &[u8] {
        &self.source
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LinkingDiagnosticReason {
    NoLocalLinkCandidates,
    IncompleteRouteObservation,
    MissingRouteCallback,
    UnsupportedModuleSpecifier,
    UnsupportedImportBinding,
    DynamicImportBinding,
    MissingTargetDocument,
    MissingTargetExport,
    AmbiguousImportBinding,
    AmbiguousTargetExport,
    ScipUnavailable,
    ScipAmbiguous,
    ScipIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkingDiagnostic {
    reason: LinkingDiagnosticReason,
    provenance: Vec<SourceLocation>,
}

impl LinkingDiagnostic {
    #[must_use]
    pub const fn reason(&self) -> LinkingDiagnosticReason {
        self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> &[SourceLocation] {
        &self.provenance
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkingCoverage {
    local_state: CoverageState,
    semantic_state: CoverageState,
}

impl LinkingCoverage {
    #[must_use]
    pub fn local_state(&self) -> &CoverageState {
        &self.local_state
    }

    #[must_use]
    pub fn semantic_state(&self) -> &CoverageState {
        &self.semantic_state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScipProducerBasis {
    CompilerBacked,
    Heuristic,
}

impl ScipProducerBasis {
    const fn confidence(self) -> ConfidenceBasis {
        match self {
            Self::CompilerBacked => ConfidenceBasis::Extracted,
            Self::Heuristic => ConfidenceBasis::Inferred,
        }
    }

    const fn identity_key(self) -> &'static str {
        match self {
            Self::CompilerBacked => "compiler-backed",
            Self::Heuristic => "heuristic",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmittedScipReference {
    source_semantic_id: StableSemanticId,
    target_semantic_id: StableSemanticId,
    qualification_id: String,
    artifact_digest: String,
    producer_basis: ScipProducerBasis,
    provenance: Vec<SourceLocation>,
}

impl AdmittedScipReference {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source_semantic_id: StableSemanticId,
        target_semantic_id: StableSemanticId,
        qualification_id: impl Into<String>,
        artifact_digest: impl Into<String>,
        producer_basis: ScipProducerBasis,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, LinkingError> {
        let limits = limits.validate()?;
        let qualification_id = qualification_id.into();
        let artifact_digest = artifact_digest.into();
        let _admission_identity = StableSemanticId::from_parts(
            "r3-scip-admission",
            &[
                &qualification_id,
                &artifact_digest,
                producer_basis.identity_key(),
            ],
            limits,
        )?;
        if provenance.is_empty() {
            return Err(LinkingError::MissingScipProvenance);
        }
        if provenance.len() > limits.max_provenance_per_record {
            return Err(LinkingError::TooManyScipProvenance {
                count: provenance.len(),
                max: limits.max_provenance_per_record,
            });
        }
        let mut provenance = provenance;
        provenance.sort();
        provenance.dedup();
        Ok(Self {
            source_semantic_id,
            target_semantic_id,
            qualification_id,
            artifact_digest,
            producer_basis,
            provenance,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScipSemanticInput {
    Unavailable,
    Ambiguous {
        provenance: Vec<SourceLocation>,
    },
    Admitted {
        references: Vec<AdmittedScipReference>,
        complete: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkingResult {
    links: Vec<CrossLayerLink>,
    coverage: LinkingCoverage,
    diagnostics: Vec<LinkingDiagnostic>,
}

impl LinkingResult {
    #[must_use]
    pub fn links(&self) -> &[CrossLayerLink] {
        &self.links
    }

    #[must_use]
    pub fn coverage(&self) -> &LinkingCoverage {
        &self.coverage
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[LinkingDiagnostic] {
        &self.diagnostics
    }
}

#[derive(Debug)]
pub enum LinkingError {
    InvalidLimits,
    TooManyDocuments {
        count: usize,
        max: usize,
    },
    TooManyImportBindings {
        count: usize,
        max: usize,
    },
    TooManyLinks {
        count: usize,
        max: usize,
    },
    TooManyScipReferences {
        count: usize,
        max: usize,
    },
    TooManyDiagnostics {
        count: usize,
        max: usize,
    },
    DocumentTooLarge {
        path: NormalizedRepoPath,
        bytes: usize,
        max: usize,
    },
    DuplicateDocumentPath(NormalizedRepoPath),
    NonUtf8Document(NormalizedRepoPath),
    ParseFailed(NormalizedRepoPath),
    MissingScipProvenance,
    TooManyScipProvenance {
        count: usize,
        max: usize,
    },
    Structural(StructuralError),
    Model(ModelError),
    Path(RepoViewError),
}

impl fmt::Display for LinkingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("R3 linking limits must be non-zero"),
            Self::TooManyDocuments { count, max } => {
                write!(formatter, "R3 linking document count {count} exceeds cap {max}")
            }
            Self::TooManyImportBindings { count, max } => write!(
                formatter,
                "R3 local import binding count {count} exceeds cap {max}"
            ),
            Self::TooManyLinks { count, max } => {
                write!(formatter, "R3 semantic link count {count} exceeds cap {max}")
            }
            Self::TooManyScipReferences { count, max } => write!(
                formatter,
                "R3 admitted SCIP reference count {count} exceeds cap {max}"
            ),
            Self::TooManyDiagnostics { count, max } => {
                write!(formatter, "R3 linking diagnostic count {count} exceeds cap {max}")
            }
            Self::DocumentTooLarge { path, bytes, max } => write!(
                formatter,
                "R3 linking document {path} size {bytes} exceeds cap {max}"
            ),
            Self::DuplicateDocumentPath(path) => {
                write!(formatter, "duplicate R3 linking document path: {path}")
            }
            Self::NonUtf8Document(path) => {
                write!(formatter, "R3 linking document is not UTF-8: {path}")
            }
            Self::ParseFailed(path) => write!(formatter, "R3 linking parse failed for {path}"),
            Self::MissingScipProvenance => {
                formatter.write_str("admitted SCIP reference requires explicit source provenance")
            }
            Self::TooManyScipProvenance { count, max } => write!(
                formatter,
                "admitted SCIP provenance count {count} exceeds cap {max}"
            ),
            Self::Structural(source) => write!(formatter, "R3 linking structural error: {source}"),
            Self::Model(source) => write!(formatter, "R3 linking model error: {source}"),
            Self::Path(source) => write!(formatter, "R3 linking path error: {source}"),
        }
    }
}

impl Error for LinkingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Structural(source) => Some(source),
            Self::Model(source) => Some(source),
            Self::Path(source) => Some(source),
            _ => None,
        }
    }
}

impl From<StructuralError> for LinkingError {
    fn from(value: StructuralError) -> Self {
        Self::Structural(value)
    }
}

impl From<ModelError> for LinkingError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

impl From<RepoViewError> for LinkingError {
    fn from(value: RepoViewError) -> Self {
        Self::Path(value)
    }
}

#[derive(Clone, Debug)]
struct ImportBinding {
    local_name: String,
    imported_name: String,
    target_path: Option<NormalizedRepoPath>,
    reason: Option<LinkingDiagnosticReason>,
    provenance: SourceLocation,
}

#[derive(Clone, Debug)]
struct ParsedDocument {
    imports: Vec<ImportBinding>,
    exports: BTreeMap<String, Vec<SourceLocation>>,
    has_unsupported_import: bool,
    has_dynamic_import: bool,
}

pub fn link_inter_file_semantics(
    routes: &[RouteObservation],
    documents: &[LinkDocument],
    scip: ScipSemanticInput,
    limits: BusinessLogicLimits,
) -> Result<LinkingResult, LinkingError> {
    let limits = limits.validate().map_err(|error| match error {
        ModelError::InvalidLimits => LinkingError::InvalidLimits,
        other => LinkingError::Model(other),
    })?;
    let document_cap = MAX_LINK_DOCUMENTS.min(limits.max_path_candidates);
    if documents.len() > document_cap {
        return Err(LinkingError::TooManyDocuments {
            count: documents.len(),
            max: document_cap,
        });
    }

    let validator = StructuralRegistry::new(&[])?;
    let mut parsed = BTreeMap::<String, ParsedDocument>::new();
    let mut total_imports = 0usize;
    for document in documents {
        if parsed.contains_key(document.path.as_str()) {
            return Err(LinkingError::DuplicateDocumentPath(document.path.clone()));
        }
        validator.scan_language(document.language, &document.path, &document.source)?;
        let source = std::str::from_utf8(&document.source)
            .map_err(|_| LinkingError::NonUtf8Document(document.path.clone()))?;
        let digest = content_id("r3-link-source", &(document.path.as_str(), source))
            .map_err(ModelError::from)?;
        let tree = parse_tree(document.language, source, &document.path)?;
        let facts = collect_module_facts(document, source, &digest, tree.root_node())?;
        total_imports = total_imports.saturating_add(facts.imports.len());
        let import_cap = MAX_LOCAL_IMPORT_BINDINGS.min(limits.max_path_candidates);
        if total_imports > import_cap {
            return Err(LinkingError::TooManyImportBindings {
                count: total_imports,
                max: import_cap,
            });
        }
        parsed.insert(document.path.as_str().to_owned(), facts);
    }

    let max_links = MAX_INTER_FILE_LINKS.min(limits.max_path_candidates);
    let mut links = BTreeMap::<String, CrossLayerLink>::new();
    let mut diagnostics = Vec::new();
    let mut local_partial = false;
    let mut local_candidates = 0usize;

    for route in routes {
        if route.coverage_state() != &CoverageState::Covered {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::IncompleteRouteObservation,
                route.provenance().to_vec(),
                limits,
            )?;
        }

        let callbacks = route.callback_chain();
        if callbacks.is_empty() {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::MissingRouteCallback,
                route.provenance().to_vec(),
                limits,
            )?;
            continue;
        }

        local_candidates = local_candidates.saturating_add(callbacks.len());
        let mut source_id = route.route_id().clone();
        for callback in callbacks {
            let link = CrossLayerLink::new(
                StableSemanticId::from_parts(
                    "r3-callback-link",
                    &[source_id.as_str(), callback.as_str()],
                    limits,
                )?,
                source_id,
                callback.clone(),
                CALLBACK_CHAIN_RELATION,
                LinkBasis::SupportedCallbackChain,
                ConfidenceBasis::Extracted,
                route.provenance().to_vec(),
                limits,
            )?;
            insert_link(&mut links, link, max_links)?;
            source_id = callback.clone();
        }

        let Some(route_location) = route.provenance().first() else {
            continue;
        };
        let Some(importer) = parsed.get(route_location.path().as_str()) else {
            continue;
        };
        let Some(handler) = route.handler_semantic_key() else {
            if importer.has_dynamic_import || importer.has_unsupported_import {
                local_partial = true;
            }
            continue;
        };

        if !is_identifier(handler) {
            if importer.has_dynamic_import {
                local_partial = true;
                push_diagnostic(
                    &mut diagnostics,
                    LinkingDiagnosticReason::DynamicImportBinding,
                    route.provenance().to_vec(),
                    limits,
                )?;
            }
            if importer.has_unsupported_import {
                local_partial = true;
                push_diagnostic(
                    &mut diagnostics,
                    LinkingDiagnosticReason::UnsupportedImportBinding,
                    route.provenance().to_vec(),
                    limits,
                )?;
            }
            continue;
        }

        let matching = importer
            .imports
            .iter()
            .filter(|binding| binding.local_name == handler)
            .collect::<Vec<_>>();
        if matching.is_empty() {
            if importer.has_dynamic_import {
                local_partial = true;
                push_diagnostic(
                    &mut diagnostics,
                    LinkingDiagnosticReason::DynamicImportBinding,
                    route.provenance().to_vec(),
                    limits,
                )?;
            }
            if importer.has_unsupported_import {
                local_partial = true;
                push_diagnostic(
                    &mut diagnostics,
                    LinkingDiagnosticReason::UnsupportedImportBinding,
                    route.provenance().to_vec(),
                    limits,
                )?;
            }
            continue;
        }

        local_candidates = local_candidates.saturating_add(1);
        if matching.len() != 1 {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::AmbiguousImportBinding,
                matching
                    .iter()
                    .map(|binding| binding.provenance.clone())
                    .collect(),
                limits,
            )?;
            continue;
        }

        let binding = matching[0];
        if let Some(reason) = binding.reason {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                reason,
                vec![binding.provenance.clone()],
                limits,
            )?;
            continue;
        }
        let Some(target_path) = binding.target_path.as_ref() else {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::MissingTargetDocument,
                vec![binding.provenance.clone()],
                limits,
            )?;
            continue;
        };
        let Some(target) = parsed.get(target_path.as_str()) else {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::MissingTargetDocument,
                vec![binding.provenance.clone()],
                limits,
            )?;
            continue;
        };
        let Some(target_exports) = target.exports.get(&binding.imported_name) else {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::MissingTargetExport,
                vec![binding.provenance.clone()],
                limits,
            )?;
            continue;
        };
        if target_exports.len() != 1 {
            local_partial = true;
            let mut provenance = vec![binding.provenance.clone()];
            provenance.extend(target_exports.iter().cloned());
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::AmbiguousTargetExport,
                provenance,
                limits,
            )?;
            continue;
        }

        let target_symbol = StableSemanticId::from_parts(
            "r3-linked-export",
            &[target_path.as_str(), &binding.imported_name],
            limits,
        )?;
        let callback = callbacks.last().expect("non-empty callback chain").clone();
        let mut provenance = route.provenance().to_vec();
        provenance.push(binding.provenance.clone());
        provenance.push(target_exports[0].clone());
        provenance.sort();
        provenance.dedup();
        let link = CrossLayerLink::new(
            StableSemanticId::from_parts(
                "r3-import-link",
                &[
                    callback.as_str(),
                    target_symbol.as_str(),
                    target_path.as_str(),
                    &binding.imported_name,
                ],
                limits,
            )?,
            callback,
            target_symbol,
            LOCAL_LINK_RELATION,
            LinkBasis::SupportedImportBinding,
            ConfidenceBasis::Extracted,
            provenance,
            limits,
        )?;
        insert_link(&mut links, link, max_links)?;
    }

    if local_candidates == 0 {
        local_partial = true;
        push_diagnostic(
            &mut diagnostics,
            LinkingDiagnosticReason::NoLocalLinkCandidates,
            Vec::new(),
            limits,
        )?;
    }

    let semantic_state = add_scip_links(
        &mut links,
        &mut diagnostics,
        scip,
        limits,
        max_links,
    )?;
    let mut links = links.into_values().collect::<Vec<_>>();
    links.sort();
    diagnostics.sort_by(|left, right| {
        left.reason
            .cmp(&right.reason)
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
    diagnostics.dedup();

    Ok(LinkingResult {
        links,
        coverage: LinkingCoverage {
            local_state: if local_partial {
                CoverageState::Partial
            } else {
                CoverageState::Covered
            },
            semantic_state,
        },
        diagnostics,
    })
}

fn add_scip_links(
    links: &mut BTreeMap<String, CrossLayerLink>,
    diagnostics: &mut Vec<LinkingDiagnostic>,
    scip: ScipSemanticInput,
    limits: BusinessLogicLimits,
    max_links: usize,
) -> Result<CoverageState, LinkingError> {
    match scip {
        ScipSemanticInput::Unavailable => {
            push_diagnostic(
                diagnostics,
                LinkingDiagnosticReason::ScipUnavailable,
                Vec::new(),
                limits,
            )?;
            Ok(CoverageState::Unavailable)
        }
        ScipSemanticInput::Ambiguous { mut provenance } => {
            provenance.sort();
            provenance.dedup();
            push_diagnostic(
                diagnostics,
                LinkingDiagnosticReason::ScipAmbiguous,
                provenance,
                limits,
            )?;
            Ok(CoverageState::Partial)
        }
        ScipSemanticInput::Admitted {
            references,
            complete,
        } => {
            let scip_cap = MAX_SCIP_REFERENCES.min(limits.max_path_candidates);
            if references.len() > scip_cap {
                return Err(LinkingError::TooManyScipReferences {
                    count: references.len(),
                    max: scip_cap,
                });
            }
            let heuristic = references
                .iter()
                .any(|reference| reference.producer_basis == ScipProducerBasis::Heuristic);
            for reference in &references {
                let link = CrossLayerLink::new(
                    StableSemanticId::from_parts(
                        "r3-scip-link",
                        &[
                            reference.source_semantic_id.as_str(),
                            reference.target_semantic_id.as_str(),
                            &reference.qualification_id,
                            &reference.artifact_digest,
                            reference.producer_basis.identity_key(),
                        ],
                        limits,
                    )?,
                    reference.source_semantic_id.clone(),
                    reference.target_semantic_id.clone(),
                    SCIP_LINK_RELATION,
                    LinkBasis::ScipReference,
                    reference.producer_basis.confidence(),
                    reference.provenance.clone(),
                    limits,
                )?;
                insert_link(links, link, max_links)?;
            }
            if !complete || references.is_empty() || heuristic {
                push_diagnostic(
                    diagnostics,
                    LinkingDiagnosticReason::ScipIncomplete,
                    references
                        .iter()
                        .flat_map(|reference| reference.provenance.iter().cloned())
                        .collect(),
                    limits,
                )?;
                Ok(CoverageState::Partial)
            } else {
                Ok(CoverageState::Covered)
            }
        }
    }
}

fn collect_module_facts(
    document: &LinkDocument,
    source: &str,
    digest: &str,
    root: tree_sitter::Node<'_>,
) -> Result<ParsedDocument, LinkingError> {
    let mut imports = Vec::new();
    let mut exports = BTreeMap::<String, Vec<SourceLocation>>::new();
    let mut has_unsupported_import = false;
    let has_dynamic_import = contains_dynamic_import(root, source);

    let mut cursor = root.walk();
    for statement in root.named_children(&mut cursor) {
        let Some(text) = node_text(statement, source) else {
            continue;
        };
        match statement.kind() {
            "import_statement" => {
                if !collect_import_statement(document, text, statement, digest, &mut imports)? {
                    has_unsupported_import = true;
                }
            }
            "export_statement" => {
                collect_export_statement(document, text, statement, digest, &mut exports)?;
            }
            _ => {}
        }
    }

    Ok(ParsedDocument {
        imports,
        exports,
        has_unsupported_import,
        has_dynamic_import,
    })
}

fn collect_import_statement(
    document: &LinkDocument,
    text: &str,
    statement: tree_sitter::Node<'_>,
    digest: &str,
    imports: &mut Vec<ImportBinding>,
) -> Result<bool, LinkingError> {
    let trimmed = text.trim();
    if trimmed.starts_with("import type ") {
        return Ok(true);
    }
    let provenance = location(
        &document.path,
        statement.start_byte(),
        statement.end_byte(),
        digest,
    )?;
    let Some((binding_text, specifier)) = split_static_import(trimmed) else {
        return Ok(false);
    };
    let (target_path, path_reason) = resolve_explicit_local_import(&document.path, specifier)?;

    if binding_text.starts_with("* as ") || binding_text.contains(',') && !binding_text.starts_with('{') {
        return Ok(false);
    }

    if let Some(named) = binding_text
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    {
        let mut supported = true;
        for item in named
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            let words = item.split_whitespace().collect::<Vec<_>>();
            let (imported, local) = match words.as_slice() {
                [name] => (*name, *name),
                [name, "as", alias] => (*name, *alias),
                _ => {
                    supported = false;
                    continue;
                }
            };
            if !is_identifier(imported) || !is_identifier(local) {
                supported = false;
                continue;
            }
            imports.push(ImportBinding {
                local_name: local.to_owned(),
                imported_name: imported.to_owned(),
                target_path: target_path.clone(),
                reason: path_reason,
                provenance: provenance.clone(),
            });
        }
        return Ok(supported);
    }

    if is_identifier(binding_text) {
        imports.push(ImportBinding {
            local_name: binding_text.to_owned(),
            imported_name: "default".to_owned(),
            target_path,
            reason: path_reason,
            provenance,
        });
        return Ok(true);
    }

    Ok(false)
}

fn collect_export_statement(
    document: &LinkDocument,
    text: &str,
    statement: tree_sitter::Node<'_>,
    digest: &str,
    exports: &mut BTreeMap<String, Vec<SourceLocation>>,
) -> Result<(), LinkingError> {
    let trimmed = text.trim();
    if trimmed.contains(" from ") {
        return Ok(());
    }
    let provenance = location(
        &document.path,
        statement.start_byte(),
        statement.end_byte(),
        digest,
    )?;
    if trimmed.starts_with("export default") {
        exports
            .entry("default".to_owned())
            .or_default()
            .push(provenance);
        return Ok(());
    }
    if let Some(named) = trimmed
        .strip_prefix("export {")
        .and_then(|value| value.trim_end_matches(';').strip_suffix('}'))
    {
        for item in named
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            let words = item.split_whitespace().collect::<Vec<_>>();
            let exported = match words.as_slice() {
                [name] => *name,
                [_name, "as", alias] => *alias,
                _ => continue,
            };
            if is_identifier(exported) {
                exports
                    .entry(exported.to_owned())
                    .or_default()
                    .push(provenance.clone());
            }
        }
        return Ok(());
    }
    if let Some(name) = declared_export_name(trimmed) {
        exports.entry(name).or_default().push(provenance);
    }
    Ok(())
}

fn contains_dynamic_import(root: tree_sitter::Node<'_>, source: &str) -> bool {
    if root.kind() == "call_expression" {
        if let Some(text) = node_text(root, source) {
            let compact = text.trim_start();
            if compact.starts_with("import(") || compact.starts_with("import (") {
                return true;
            }
        }
    }
    let mut cursor = root.walk();
    root.named_children(&mut cursor)
        .any(|child| contains_dynamic_import(child, source))
}

fn declared_export_name(text: &str) -> Option<String> {
    let rest = text.strip_prefix("export ")?;
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    for keyword in ["function ", "class ", "const ", "let ", "var "] {
        if let Some(after) = rest.strip_prefix(keyword) {
            let name = after
                .split(|character: char| !is_identifier_continue(character))
                .next()?;
            return is_identifier(name).then(|| name.to_owned());
        }
    }
    None
}

fn split_static_import(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("import ")?.trim();
    let from_index = rest.rfind(" from ")?;
    let binding = rest.get(..from_index)?.trim();
    let source = rest.get(from_index + " from ".len()..)?.trim();
    let source = source.trim_end_matches(';').trim();
    Some((binding, unquote(source)?))
}

fn unquote(value: &str) -> Option<&str> {
    if value.len() < 2 {
        return None;
    }
    let bytes = value.as_bytes();
    if !matches!(bytes[0], b'\'' | b'"') || bytes[value.len() - 1] != bytes[0] {
        return None;
    }
    value.get(1..value.len() - 1)
}

fn resolve_explicit_local_import(
    importer: &NormalizedRepoPath,
    specifier: &str,
) -> Result<(Option<NormalizedRepoPath>, Option<LinkingDiagnosticReason>), LinkingError> {
    if !(specifier.starts_with("./") || specifier.starts_with("../"))
        || specifier.contains('\\')
        || specifier.contains('?')
        || specifier.contains('#')
        || !SUPPORTED_MODULE_EXTENSIONS
            .iter()
            .any(|extension| specifier.ends_with(extension))
    {
        return Ok((
            None,
            Some(LinkingDiagnosticReason::UnsupportedModuleSpecifier),
        ));
    }

    let mut components = importer
        .as_str()
        .split('/')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    components.pop();
    for component in specifier.split('/') {
        match component {
            "." | "" => {}
            ".." => {
                if components.pop().is_none() {
                    return Ok((
                        None,
                        Some(LinkingDiagnosticReason::UnsupportedModuleSpecifier),
                    ));
                }
            }
            other => components.push(other.to_owned()),
        }
    }
    if components.is_empty() {
        return Ok((
            None,
            Some(LinkingDiagnosticReason::UnsupportedModuleSpecifier),
        ));
    }
    let resolved = components.join("/");
    Ok((
        Some(NormalizedRepoPath::parse(
            &resolved,
            DEFAULT_MAX_REPO_PATH_BYTES,
        )?),
        None,
    ))
}

fn parse_tree(
    language: StructuralLanguage,
    source: &str,
    path: &NormalizedRepoPath,
) -> Result<tree_sitter::Tree, LinkingError> {
    let language: tree_sitter::Language = match language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|_| LinkingError::ParseFailed(path.clone()))?;
    parser
        .parse(source, None)
        .ok_or_else(|| LinkingError::ParseFailed(path.clone()))
}

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.start_byte()..node.end_byte())
}

fn location(
    path: &NormalizedRepoPath,
    start: usize,
    end: usize,
    digest: &str,
) -> Result<SourceLocation, LinkingError> {
    Ok(SourceLocation::new(
        path.clone(),
        start,
        end,
        digest.to_owned(),
    )?)
}

fn insert_link(
    links: &mut BTreeMap<String, CrossLayerLink>,
    link: CrossLayerLink,
    max_links: usize,
) -> Result<(), LinkingError> {
    let key = link.link_id().as_str().to_owned();
    if !links.contains_key(&key) && links.len() >= max_links {
        return Err(LinkingError::TooManyLinks {
            count: links.len().saturating_add(1),
            max: max_links,
        });
    }
    links.insert(key, link);
    Ok(())
}

fn push_diagnostic(
    diagnostics: &mut Vec<LinkingDiagnostic>,
    reason: LinkingDiagnosticReason,
    mut provenance: Vec<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<(), LinkingError> {
    if diagnostics.len() >= limits.max_diagnostics {
        return Err(LinkingError::TooManyDiagnostics {
            count: diagnostics.len().saturating_add(1),
            max: limits.max_diagnostics,
        });
    }
    provenance.sort();
    provenance.dedup();
    diagnostics.push(LinkingDiagnostic { reason, provenance });
    Ok(())
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !is_identifier_start(first) {
        return false;
    }
    chars.all(is_identifier_continue)
}

fn is_identifier_start(character: char) -> bool {
    character == '_' || character == '$' || character.is_ascii_alphabetic()
}

fn is_identifier_continue(character: char) -> bool {
    is_identifier_start(character) || character.is_ascii_digit()
}
