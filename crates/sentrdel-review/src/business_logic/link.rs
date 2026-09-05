//! Bounded local/inter-file semantic linking for canonical R3-T016.
//!
//! This module consumes already-validated R3 route observations and bounded source documents.
//! Target repository source remains data only: no module loader, package manager, target code,
//! provider code, filesystem resolution, network access, or repository configuration executes.
//! Local linking intentionally supports only explicit relative ESM paths with an explicit supported
//! extension and an exact provided target document. Package exports, tsconfig aliases, extension
//! guessing, index-file guessing, dynamic imports, namespace imports, and re-export traversal remain
//! visible coverage gaps rather than guessed identity.
//!
//! SCIP facts accepted here are downstream facts only. This module does not qualify SCIP producers
//! or artifacts; callers may pass `AdmittedScipReference` values only after the existing bounded SCIP
//! ingestion/producer-qualification boundary has admitted the source fact. Missing or ambiguous SCIP
//! coverage never becomes a clean fallback.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use sentrdel_schema::{canonical::content_id, coverage::CoverageState};

use super::model::{
    BusinessLogicLimits, ConfidenceBasis, CrossLayerLink, LinkBasis, ModelError, RouteObservation,
    SourceLocation, StableSemanticId,
};
use crate::{
    structural::{StructuralError, StructuralLanguage, StructuralRegistry},
    view::{DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_REPO_PATH_BYTES, NormalizedRepoPath, RepoViewError},
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
    MissingRouteCallback,
    UnsupportedModuleSpecifier,
    UnsupportedImportBinding,
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
        StableSemanticId::from_parts(
            "r3-scip-admission",
            &[&qualification_id, &artifact_digest, producer_basis.identity_key()],
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
    Ambiguous { provenance: Vec<SourceLocation> },
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
    TooManyDocuments { count: usize, max: usize },
    TooManyImportBindings { count: usize, max: usize },
    TooManyLinks { count: usize, max: usize },
    TooManyScipReferences { count: usize, max: usize },
    TooManyDiagnostics { count: usize, max: usize },
    DocumentTooLarge {
        path: NormalizedRepoPath,
        bytes: usize,
        max: usize,
    },
    DuplicateDocumentPath(NormalizedRepoPath),
    NonUtf8Document(NormalizedRepoPath),
    ParseFailed(NormalizedRepoPath),
    MissingScipProvenance,
    TooManyScipProvenance { count: usize, max: usize },
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
struct ExportBinding {
    provenance: SourceLocation,
}

struct ParsedDocument<'a> {
    source: &'a str,
    digest: String,
    tree: tree_sitter::Tree,
}

/// Build deterministic, bounded callback/import/SCIP links without performing path discovery or
/// semantic guessing.
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
    if documents.len() > MAX_LINK_DOCUMENTS {
        return Err(LinkingError::TooManyDocuments {
            count: documents.len(),
            max: MAX_LINK_DOCUMENTS,
        });
    }

    let validator = StructuralRegistry::new(&[])?;
    let mut document_by_path = BTreeMap::<String, &LinkDocument>::new();
    let mut parsed_by_path = BTreeMap::<String, ParsedDocument<'_>>::new();
    for document in documents {
        if document_by_path
            .insert(document.path.as_str().to_owned(), document)
            .is_some()
        {
            return Err(LinkingError::DuplicateDocumentPath(document.path.clone()));
        }
        validator.scan_language(document.language, &document.path, &document.source)?;
        let source = std::str::from_utf8(&document.source)
            .map_err(|_| LinkingError::NonUtf8Document(document.path.clone()))?;
        let digest = content_id("r3-link-source", &(document.path.as_str(), source))
            .map_err(ModelError::from)?;
        let tree = parse_tree(document.language, source, &document.path)?;
        parsed_by_path.insert(
            document.path.as_str().to_owned(),
            ParsedDocument {
                source,
                digest,
                tree,
            },
        );
    }

    let mut exports = BTreeMap::<String, BTreeMap<String, Vec<ExportBinding>>>::new();
    for document in documents {
        let parsed = parsed_by_path
            .get(document.path.as_str())
            .expect("parsed document exists for validated input");
        exports.insert(
            document.path.as_str().to_owned(),
            collect_exports(document, parsed, limits)?,
        );
    }

    let mut imports = BTreeMap::<String, Vec<ImportBinding>>::new();
    let mut import_count = 0usize;
    for document in documents {
        let parsed = parsed_by_path
            .get(document.path.as_str())
            .expect("parsed document exists for validated input");
        let observed = collect_imports(document, parsed, limits)?;
        import_count = import_count.saturating_add(observed.len());
        if import_count > MAX_LOCAL_IMPORT_BINDINGS {
            return Err(LinkingError::TooManyImportBindings {
                count: import_count,
                max: MAX_LOCAL_IMPORT_BINDINGS,
            });
        }
        imports.insert(document.path.as_str().to_owned(), observed);
    }

    let mut links = BTreeMap::<String, CrossLayerLink>::new();
    let mut diagnostics = Vec::<LinkingDiagnostic>::new();
    let mut local_partial = false;
    let mut local_candidates = 0usize;

    for route in routes {
        let route_provenance = route.provenance().to_vec();
        let callbacks = route.callback_chain();
        if callbacks.is_empty() {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::MissingRouteCallback,
                route_provenance,
                limits,
            )?;
            continue;
        }

        local_candidates = local_candidates.saturating_add(callbacks.len());
        let mut source_id = route.route_id().clone();
        for callback in callbacks {
            insert_link(
                &mut links,
                CrossLayerLink::new(
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
                )?,
            )?;
            source_id = callback.clone();
        }

        let (Some(handler_key), Some(route_location)) =
            (route.handler_semantic_key(), route.provenance().first())
        else {
            continue;
        };
        if !is_identifier(handler_key) {
            continue;
        }
        let Some(document_imports) = imports.get(route_location.path().as_str()) else {
            continue;
        };
        let matching = document_imports
            .iter()
            .filter(|binding| binding.local_name == handler_key)
            .collect::<Vec<_>>();
        if matching.is_empty() {
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
        if !document_by_path.contains_key(target_path.as_str()) {
            local_partial = true;
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::MissingTargetDocument,
                vec![binding.provenance.clone()],
                limits,
            )?;
            continue;
        }
        let target_exports = exports
            .get(target_path.as_str())
            .and_then(|by_name| by_name.get(&binding.imported_name));
        let Some(target_exports) = target_exports else {
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
            provenance.extend(
                target_exports
                    .iter()
                    .map(|export| export.provenance.clone()),
            );
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
        let mut provenance = route.provenance().to_vec();
        provenance.push(binding.provenance.clone());
        provenance.push(target_exports[0].provenance.clone());
        provenance.sort();
        provenance.dedup();
        insert_link(
            &mut links,
            CrossLayerLink::new(
                StableSemanticId::from_parts(
                    "r3-import-link",
                    &[
                        callbacks.last().expect("non-empty callback chain").as_str(),
                        target_symbol.as_str(),
                        target_path.as_str(),
                        &binding.imported_name,
                    ],
                    limits,
                )?,
                callbacks
                    .last()
                    .expect("non-empty callback chain")
                    .clone(),
                target_symbol,
                LOCAL_LINK_RELATION,
                LinkBasis::SupportedImportBinding,
                ConfidenceBasis::Extracted,
                provenance,
                limits,
            )?,
        )?;
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

    let semantic_state = match scip {
        ScipSemanticInput::Unavailable => {
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::ScipUnavailable,
                Vec::new(),
                limits,
            )?;
            CoverageState::Unavailable
        }
        ScipSemanticInput::Ambiguous { mut provenance } => {
            provenance.sort();
            provenance.dedup();
            push_diagnostic(
                &mut diagnostics,
                LinkingDiagnosticReason::ScipAmbiguous,
                provenance,
                limits,
            )?;
            CoverageState::Partial
        }
        ScipSemanticInput::Admitted {
            references,
            complete,
        } => {
            if references.len() > MAX_SCIP_REFERENCES {
                return Err(LinkingError::TooManyScipReferences {
                    count: references.len(),
                    max: MAX_SCIP_REFERENCES,
                });
            }
            let any_heuristic = references
                .iter()
                .any(|reference| reference.producer_basis == ScipProducerBasis::Heuristic);
            for reference in &references {
                insert_link(
                    &mut links,
                    CrossLayerLink::new(
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
                    )?,
                )?;
            }
            if !complete || references.is_empty() || any_heuristic {
                push_diagnostic(
                    &mut diagnostics,
                    LinkingDiagnosticReason::ScipIncomplete,
                    references
                        .iter()
                        .flat_map(|reference| reference.provenance.iter().cloned())
                        .collect(),
                    limits,
                )?;
                CoverageState::Partial
            } else {
                CoverageState::Covered
            }
        }
    };

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

fn insert_link(
    links: &mut BTreeMap<String, CrossLayerLink>,
    link: CrossLayerLink,
) -> Result<(), LinkingError> {
    let key = link.link_id().as_str().to_owned();
    if !links.contains_key(&key) && links.len() >= MAX_INTER_FILE_LINKS {
        return Err(LinkingError::TooManyLinks {
            count: links.len().saturating_add(1),
            max: MAX_INTER_FILE_LINKS,
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

fn collect_imports(
    document: &LinkDocument,
    parsed: &ParsedDocument<'_>,
    limits: BusinessLogicLimits,
) -> Result<Vec<ImportBinding>, LinkingError> {
    let mut imports = Vec::new();
    let root = parsed.tree.root_node();
    let mut cursor = root.walk();
    for statement in root.named_children(&mut cursor) {
        if statement.kind() != "import_statement" {
            continue;
        }
        let statement_text = node_text(statement, parsed.source).unwrap_or_default();
        if statement_text.trim_start().starts_with("import type ") {
            continue;
        }
        let source_node = statement
            .child_by_field_name("source")
            .or_else(|| find_direct_string_child(statement));
        let Some(source_node) = source_node else {
            continue;
        };
        let Some(specifier) = static_string(source_node, parsed.source) else {
            continue;
        };
        let (target_path, path_reason) = resolve_explicit_local_import(&document.path, &specifier)?;
        let provenance = location(
            &document.path,
            statement.start_byte(),
            statement.end_byte(),
            &parsed.digest,
        )?;

        let mut found_supported_binding = false;
        collect_named_import_specifiers(statement, parsed.source, |imported, local| {
            found_supported_binding = true;
            imports.push(ImportBinding {
                local_name: local.to_owned(),
                imported_name: imported.to_owned(),
                target_path: target_path.clone(),
                reason: path_reason,
                provenance: provenance.clone(),
            });
        });

        if let Some(default_local) = default_import_identifier(statement, parsed.source) {
            found_supported_binding = true;
            imports.push(ImportBinding {
                local_name: default_local.to_owned(),
                imported_name: "default".to_owned(),
                target_path: target_path.clone(),
                reason: path_reason,
                provenance: provenance.clone(),
            });
        }

        if !found_supported_binding && contains_namespace_import(statement) {
            let local = namespace_import_identifier(statement, parsed.source)
                .unwrap_or("<namespace>")
                .to_owned();
            imports.push(ImportBinding {
                local_name: local,
                imported_name: "*".to_owned(),
                target_path,
                reason: Some(LinkingDiagnosticReason::UnsupportedImportBinding),
                provenance,
            });
        }
    }
    if imports.len() > limits.max_path_candidates {
        return Err(LinkingError::TooManyImportBindings {
            count: imports.len(),
            max: limits.max_path_candidates,
        });
    }
    imports.sort_by(|left, right| {
        left.local_name
            .cmp(&right.local_name)
            .then_with(|| left.imported_name.cmp(&right.imported_name))
            .then_with(|| left.provenance.cmp(&right.provenance))
    });
    Ok(imports)
}

fn collect_exports(
    document: &LinkDocument,
    parsed: &ParsedDocument<'_>,
    limits: BusinessLogicLimits,
) -> Result<BTreeMap<String, Vec<ExportBinding>>, LinkingError> {
    let root = parsed.tree.root_node();
    let mut exports = BTreeMap::<String, Vec<ExportBinding>>::new();
    let mut cursor = root.walk();
    for statement in root.named_children(&mut cursor) {
        if statement.kind() != "export_statement" {
            continue;
        }
        if export_has_module_source(statement) {
            continue;
        }
        let statement_text = node_text(statement, parsed.source).unwrap_or_default();
        let provenance = location(
            &document.path,
            statement.start_byte(),
            statement.end_byte(),
            &parsed.digest,
        )?;
        if statement_text.trim_start().starts_with("export default") {
            exports
                .entry("default".to_owned())
                .or_default()
                .push(ExportBinding {
                    provenance: provenance.clone(),
                });
        }
        collect_export_names(statement, parsed.source, |name| {
            exports
                .entry(name.to_owned())
                .or_default()
                .push(ExportBinding {
                    provenance: provenance.clone(),
                });
        });
    }
    let count = exports.values().map(Vec::len).sum::<usize>();
    if count > limits.max_path_candidates {
        return Err(LinkingError::TooManyImportBindings {
            count,
            max: limits.max_path_candidates,
        });
    }
    Ok(exports)
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

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.start_byte()..node.end_byte())
}

fn static_string<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    let text = node_text(node, source)?;
    if text.len() < 2 {
        return None;
    }
    let bytes = text.as_bytes();
    let quote = bytes[0];
    if !matches!(quote, b'\'' | b'"') || bytes[text.len() - 1] != quote {
        return None;
    }
    text.get(1..text.len() - 1)
}

fn find_direct_string_child(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "string")
}

fn collect_named_import_specifiers<'a>(
    node: tree_sitter::Node<'_>,
    source: &'a str,
    mut callback: impl FnMut(&'a str, &'a str),
) {
    fn visit<'a>(
        node: tree_sitter::Node<'_>,
        source: &'a str,
        callback: &mut impl FnMut(&'a str, &'a str),
    ) {
        if node.kind() == "import_specifier" {
            if let Some(name) = node.child_by_field_name("name").and_then(|value| node_text(value, source)) {
                let local = node
                    .child_by_field_name("alias")
                    .and_then(|value| node_text(value, source))
                    .unwrap_or(name);
                if is_identifier(name) && is_identifier(local) {
                    callback(name, local);
                }
            }
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            visit(child, source, callback);
        }
    }
    visit(node, source, &mut callback);
}

fn default_import_identifier<'a>(
    import_statement: tree_sitter::Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    let clause = find_descendant_kind(import_statement, "import_clause")?;
    let mut cursor = clause.walk();
    for child in clause.named_children(&mut cursor) {
        if child.kind() == "identifier" {
            let name = node_text(child, source)?;
            if is_identifier(name) {
                return Some(name);
            }
        }
    }
    None
}

fn contains_namespace_import(node: tree_sitter::Node<'_>) -> bool {
    find_descendant_kind(node, "namespace_import").is_some()
}

fn namespace_import_identifier<'a>(
    node: tree_sitter::Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    let namespace = find_descendant_kind(node, "namespace_import")?;
    find_descendant_kind(namespace, "identifier").and_then(|value| node_text(value, source))
}

fn collect_export_names<'a>(
    export_statement: tree_sitter::Node<'_>,
    source: &'a str,
    mut callback: impl FnMut(&'a str),
) {
    fn visit<'a>(
        node: tree_sitter::Node<'_>,
        source: &'a str,
        callback: &mut impl FnMut(&'a str),
    ) {
        match node.kind() {
            "function_declaration" | "generator_function_declaration" | "class_declaration" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|value| node_text(value, source))
                    .filter(|name| is_identifier(name))
                {
                    callback(name);
                }
                return;
            }
            "variable_declarator" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|value| node_text(value, source))
                    .filter(|name| is_identifier(name))
                {
                    callback(name);
                }
                return;
            }
            "export_specifier" => {
                let exported = node
                    .child_by_field_name("alias")
                    .or_else(|| node.child_by_field_name("name"))
                    .and_then(|value| node_text(value, source));
                if let Some(exported) = exported.filter(|name| is_identifier(name)) {
                    callback(exported);
                }
                return;
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            visit(child, source, callback);
        }
    }
    visit(export_statement, source, &mut callback);
}

fn export_has_module_source(statement: tree_sitter::Node<'_>) -> bool {
    statement.child_by_field_name("source").is_some()
        || {
            let mut cursor = statement.walk();
            statement
                .named_children(&mut cursor)
                .any(|child| child.kind() == "string")
        }
}

fn find_descendant_kind<'tree>(
    node: tree_sitter::Node<'tree>,
    kind: &str,
) -> Option<tree_sitter::Node<'tree>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = find_descendant_kind(child, kind) {
            return Some(found);
        }
    }
    None
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|character| {
        character == '_' || character == '$' || character.is_ascii_alphanumeric()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentrdel_schema::coverage::CoverageState;

    fn path(value: &str) -> NormalizedRepoPath {
        NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).expect("normalized path")
    }

    fn id(namespace: &str, value: &str) -> StableSemanticId {
        StableSemanticId::from_parts(namespace, &[value], BusinessLogicLimits::default())
            .expect("stable semantic id")
    }

    fn location_for(value: &str) -> SourceLocation {
        SourceLocation::new(
            path(value),
            0,
            1,
            format!("sha256:{:064x}", 1),
        )
        .expect("source location")
    }

    fn route(importer: &str, handler: &str) -> RouteObservation {
        RouteObservation::new(
            id("route", importer),
            super::super::model::FrameworkFamily::Express,
            super::super::model::HttpMethod::Get,
            "/fixture",
            Some(handler.to_owned()),
            vec![id("callback", &format!("{importer}:{handler}"))],
            vec![location_for(importer)],
            CoverageState::Covered,
            BusinessLogicLimits::default(),
        )
        .expect("route")
    }

    fn document(value: &str, source: &str) -> LinkDocument {
        LinkDocument::new(
            path(value),
            StructuralLanguage::TypeScript,
            source.as_bytes().to_vec(),
        )
        .expect("link document")
    }

    #[test]
    fn explicit_named_import_links_final_callback_to_exact_export() {
        let routes = vec![route("src/routes.ts", "handler")];
        let documents = vec![
            document(
                "src/routes.ts",
                "import { handler } from './handlers.ts';\napp.get('/fixture', handler);",
            ),
            document(
                "src/handlers.ts",
                "export function handler(req, res) { return res.json({ ok: true }); }",
            ),
        ];
        let result = link_inter_file_semantics(
            &routes,
            &documents,
            ScipSemanticInput::Unavailable,
            BusinessLogicLimits::default(),
        )
        .expect("linking result");

        assert_eq!(result.coverage().local_state(), &CoverageState::Covered);
        assert_eq!(
            result.coverage().semantic_state(),
            &CoverageState::Unavailable
        );
        assert!(result.links().iter().any(|link| {
            link.basis() == LinkBasis::SupportedImportBinding
                && link.confidence_basis() == ConfidenceBasis::Extracted
                && link.relation() == LOCAL_LINK_RELATION
        }));
        assert!(result.links().iter().any(|link| {
            link.basis() == LinkBasis::SupportedCallbackChain
                && link.relation() == CALLBACK_CHAIN_RELATION
        }));
    }

    #[test]
    fn same_raw_handler_name_in_unrelated_file_does_not_create_false_join() {
        let routes = vec![route("src/routes.ts", "handler")];
        let documents = vec![
            document(
                "src/routes.ts",
                "function handler() {}\napp.get('/fixture', handler);",
            ),
            document("src/unrelated.ts", "export function handler() {}"),
        ];
        let result = link_inter_file_semantics(
            &routes,
            &documents,
            ScipSemanticInput::Unavailable,
            BusinessLogicLimits::default(),
        )
        .expect("linking result");
        assert!(!result
            .links()
            .iter()
            .any(|link| link.basis() == LinkBasis::SupportedImportBinding));
    }

    #[test]
    fn extensionless_local_import_is_partial_not_guessed() {
        let routes = vec![route("src/routes.ts", "handler")];
        let documents = vec![
            document(
                "src/routes.ts",
                "import { handler } from './handlers';\napp.get('/fixture', handler);",
            ),
            document("src/handlers.ts", "export function handler() {}"),
        ];
        let result = link_inter_file_semantics(
            &routes,
            &documents,
            ScipSemanticInput::Unavailable,
            BusinessLogicLimits::default(),
        )
        .expect("linking result");
        assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
        assert!(!result
            .links()
            .iter()
            .any(|link| link.basis() == LinkBasis::SupportedImportBinding));
        assert!(result.diagnostics().iter().any(|diagnostic| {
            diagnostic.reason() == LinkingDiagnosticReason::UnsupportedModuleSpecifier
        }));
    }

    #[test]
    fn parent_traversal_cannot_escape_repository_root() {
        let routes = vec![route("src/routes.ts", "handler")];
        let documents = vec![document(
            "src/routes.ts",
            "import { handler } from '../../outside.ts';\napp.get('/fixture', handler);",
        )];
        let result = link_inter_file_semantics(
            &routes,
            &documents,
            ScipSemanticInput::Unavailable,
            BusinessLogicLimits::default(),
        )
        .expect("linking result");
        assert_eq!(result.coverage().local_state(), &CoverageState::Partial);
        assert!(result.diagnostics().iter().any(|diagnostic| {
            diagnostic.reason() == LinkingDiagnosticReason::UnsupportedModuleSpecifier
        }));
    }

    #[test]
    fn admitted_compiler_backed_scip_reference_is_extracted() {
        let reference = AdmittedScipReference::new(
            id("source", "a"),
            id("target", "b"),
            "scip-qualified-tsc-1",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ScipProducerBasis::CompilerBacked,
            vec![location_for("src/routes.ts")],
            BusinessLogicLimits::default(),
        )
        .expect("admitted SCIP reference");
        let result = link_inter_file_semantics(
            &[],
            &[],
            ScipSemanticInput::Admitted {
                references: vec![reference],
                complete: true,
            },
            BusinessLogicLimits::default(),
        )
        .expect("linking result");
        assert_eq!(result.coverage().semantic_state(), &CoverageState::Covered);
        assert!(result.links().iter().any(|link| {
            link.basis() == LinkBasis::ScipReference
                && link.confidence_basis() == ConfidenceBasis::Extracted
        }));
    }

    #[test]
    fn heuristic_scip_reference_remains_inferred_and_partial() {
        let reference = AdmittedScipReference::new(
            id("source", "a"),
            id("target", "b"),
            "scip-qualified-heuristic-1",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ScipProducerBasis::Heuristic,
            vec![location_for("src/routes.ts")],
            BusinessLogicLimits::default(),
        )
        .expect("admitted SCIP reference");
        let result = link_inter_file_semantics(
            &[],
            &[],
            ScipSemanticInput::Admitted {
                references: vec![reference],
                complete: true,
            },
            BusinessLogicLimits::default(),
        )
        .expect("linking result");
        assert_eq!(result.coverage().semantic_state(), &CoverageState::Partial);
        assert!(result.links().iter().any(|link| {
            link.basis() == LinkBasis::ScipReference
                && link.confidence_basis() == ConfidenceBasis::Inferred
        }));
    }

    #[test]
    fn ambiguous_or_unavailable_scip_never_produces_clean_linking() {
        let ambiguous = link_inter_file_semantics(
            &[],
            &[],
            ScipSemanticInput::Ambiguous {
                provenance: vec![location_for("src/routes.ts")],
            },
            BusinessLogicLimits::default(),
        )
        .expect("ambiguous result");
        assert_eq!(ambiguous.coverage().semantic_state(), &CoverageState::Partial);
        assert!(!ambiguous
            .links()
            .iter()
            .any(|link| link.basis() == LinkBasis::ScipReference));

        let unavailable = link_inter_file_semantics(
            &[],
            &[],
            ScipSemanticInput::Unavailable,
            BusinessLogicLimits::default(),
        )
        .expect("unavailable result");
        assert_eq!(
            unavailable.coverage().semantic_state(),
            &CoverageState::Unavailable
        );
        assert!(!unavailable
            .links()
            .iter()
            .any(|link| link.basis() == LinkBasis::ScipReference));
    }

    #[test]
    fn authority_canaries_remain_false() {
        const { assert!(!R3_LINK_EXECUTES_TARGET_CODE) };
        const { assert!(!R3_LINK_PERFORMS_NETWORK_ACCESS) };
        const { assert!(!R3_LINK_QUALIFIES_SCIP_PRODUCERS) };
        const { assert!(!R3_LINK_CREATES_FINDINGS) };
    }
}