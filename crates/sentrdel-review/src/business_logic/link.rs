//! Bounded R3 inter-file semantic linking.
//!
//! This module links only validated R3 callback identities, statically proven
//! local ESM import bindings, and separately qualified SCIP reference facts.
//! Repository source remains data only. The linker performs no filesystem reads,
//! target execution, package resolution, index generation, network access, or
//! provider access. Missing or ambiguous semantics remain explicit coverage gaps.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use sentrdel_schema::{canonical::content_id, coverage::CoverageState};

use super::model::{
    BusinessLogicLimits, ConfidenceBasis, CrossLayerLink, FrameworkFamily, LinkBasis, ModelError,
    RouteObservation, SourceLocation, StableSemanticId,
};
use crate::{
    structural::{StructuralError, StructuralLanguage, StructuralRegistry},
    view::NormalizedRepoPath,
};

pub const REL_CALLBACK_PRECEDES: &str = "callback-precedes";
pub const REL_CALLBACK_IMPORT_BINDING: &str = "callback-import-binding";
pub const REL_SCIP_REFERENCE: &str = "scip-reference";
pub const INTER_FILE_LINKING_EXECUTES_TARGET: bool = false;
pub const INTER_FILE_LINKING_REQUIRES_SCIP: bool = false;
pub const LEXICAL_EQUALITY_PROVES_LINK_EQUIVALENCE: bool = false;
pub const SCIP_QUALIFICATION_IS_INFERRED_FROM_REPOSITORY: bool = false;

const MODULE_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx"];

#[derive(Clone, Debug)]
pub struct SourceModule<'a> {
    path: NormalizedRepoPath,
    language: StructuralLanguage,
    source: &'a [u8],
}

impl<'a> SourceModule<'a> {
    #[must_use]
    pub fn new(path: NormalizedRepoPath, language: StructuralLanguage, source: &'a [u8]) -> Self {
        Self {
            path,
            language,
            source,
        }
    }

    #[must_use]
    pub fn path(&self) -> &NormalizedRepoPath {
        &self.path
    }
}

/// A caller-qualified semantic reference originating from the canonical SCIP
/// ingestion boundary.
///
/// `qualification_id` is trusted caller metadata. It MUST come from the
/// separately qualified SCIP producer path and MUST NOT be inferred from
/// repository text, an indexer's self-description, or lexical symbol equality.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualifiedScipReference {
    source_semantic_id: StableSemanticId,
    target_semantic_id: StableSemanticId,
    qualification_id: String,
    confidence_basis: ConfidenceBasis,
    provenance: Vec<SourceLocation>,
}

impl QualifiedScipReference {
    pub fn new(
        source_semantic_id: StableSemanticId,
        target_semantic_id: StableSemanticId,
        qualification_id: impl Into<String>,
        confidence_basis: ConfidenceBasis,
        provenance: Vec<SourceLocation>,
        limits: BusinessLogicLimits,
    ) -> Result<Self, InterFileLinkError> {
        let limits = limits.validate()?;
        let qualification_id = qualification_id.into();
        if qualification_id.trim().is_empty()
            || qualification_id.len() > limits.max_id_part_bytes
            || qualification_id.chars().any(char::is_control)
        {
            return Err(InterFileLinkError::InvalidQualificationId);
        }
        if provenance.is_empty() {
            return Err(InterFileLinkError::EmptySemanticProvenance);
        }
        if provenance.len() > limits.max_provenance_per_record {
            return Err(InterFileLinkError::TooManySemanticProvenance {
                count: provenance.len(),
                maximum: limits.max_provenance_per_record,
            });
        }
        let provenance = provenance.into_iter().collect::<BTreeSet<_>>();
        if provenance.len() > limits.max_provenance_per_record {
            return Err(InterFileLinkError::TooManySemanticProvenance {
                count: provenance.len(),
                maximum: limits.max_provenance_per_record,
            });
        }
        Ok(Self {
            source_semantic_id,
            target_semantic_id,
            qualification_id,
            confidence_basis,
            provenance: provenance.into_iter().collect(),
        })
    }

    #[must_use]
    pub fn qualification_id(&self) -> &str {
        &self.qualification_id
    }
}

#[derive(Clone, Debug)]
pub enum SemanticIndexInput<'a> {
    /// No semantic index was supplied. This is always explicit UNAVAILABLE
    /// semantic-linking coverage, never a clean fallback.
    NotProvided,
    /// Canonical upstream SCIP coverage is a gap. Covered/Partial are invalid
    /// here because usable qualified references belong in `Qualified`.
    CoverageGap(CoverageState),
    /// Separately qualified SCIP references and their canonical coverage state.
    /// Only Covered or Partial are accepted.
    Qualified {
        references: &'a [QualifiedScipReference],
        coverage_state: CoverageState,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LinkingCoverageGapReason {
    MissingRouteSource,
    AmbiguousRouteSource,
    UnsupportedRouteFramework,
    TypeOnlyImportBinding,
    UnsupportedNamespaceImport,
    InvalidLocalImportSpecifier,
    UnresolvedLocalImport,
    AmbiguousLocalImport,
    SelfImport,
    AmbiguousImportBinding,
    SemanticIndexUnavailable,
    SemanticIndexCoverageGap,
    SemanticIndexPartial,
    SemanticIndexEmpty,
    SemanticIndexInferred,
    SemanticReferenceAmbiguous,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LinkingCoverageGap {
    reason: LinkingCoverageGapReason,
    provenance: Option<SourceLocation>,
}

impl LinkingCoverageGap {
    #[must_use]
    pub const fn reason(&self) -> LinkingCoverageGapReason {
        self.reason
    }

    #[must_use]
    pub fn provenance(&self) -> Option<&SourceLocation> {
        self.provenance.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterFileLinking {
    links: Vec<CrossLayerLink>,
    gaps: Vec<LinkingCoverageGap>,
    local_coverage: CoverageState,
    semantic_coverage: CoverageState,
    semantic_qualification_ids: Vec<String>,
}

impl InterFileLinking {
    #[must_use]
    pub fn links(&self) -> &[CrossLayerLink] {
        &self.links
    }

    #[must_use]
    pub fn gaps(&self) -> &[LinkingCoverageGap] {
        &self.gaps
    }

    #[must_use]
    pub fn local_coverage(&self) -> &CoverageState {
        &self.local_coverage
    }

    #[must_use]
    pub fn semantic_coverage(&self) -> &CoverageState {
        &self.semantic_coverage
    }

    #[must_use]
    pub fn semantic_qualification_ids(&self) -> &[String] {
        &self.semantic_qualification_ids
    }
}

#[derive(Debug)]
pub enum InterFileLinkError {
    Model(ModelError),
    Structural(StructuralError),
    ParseFailed(String),
    NonUtf8Source,
    DuplicateSourcePath(String),
    TooManySourceModules { count: usize, maximum: usize },
    TooManyImportBindings { count: usize, maximum: usize },
    TooManyLinks { count: usize, maximum: usize },
    TooManyGaps { count: usize, maximum: usize },
    TooManySemanticReferences { count: usize, maximum: usize },
    InvalidQualificationId,
    EmptySemanticProvenance,
    TooManySemanticProvenance { count: usize, maximum: usize },
    InvalidSemanticCoverageState,
}

impl fmt::Display for InterFileLinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Model(source) => write!(formatter, "inter-file link model failed: {source}"),
            Self::Structural(source) => {
                write!(
                    formatter,
                    "inter-file structural validation failed: {source}"
                )
            }
            Self::ParseFailed(message) => write!(formatter, "inter-file parse failed: {message}"),
            Self::NonUtf8Source => formatter.write_str("inter-file source is not UTF-8"),
            Self::DuplicateSourcePath(path) => {
                write!(formatter, "duplicate inter-file source path: {path}")
            }
            Self::TooManySourceModules { count, maximum } => write!(
                formatter,
                "inter-file source module count {count} exceeds cap {maximum}"
            ),
            Self::TooManyImportBindings { count, maximum } => write!(
                formatter,
                "inter-file import binding count {count} exceeds cap {maximum}"
            ),
            Self::TooManyLinks { count, maximum } => {
                write!(
                    formatter,
                    "inter-file link count {count} exceeds cap {maximum}"
                )
            }
            Self::TooManyGaps { count, maximum } => write!(
                formatter,
                "inter-file coverage gap count {count} exceeds cap {maximum}"
            ),
            Self::TooManySemanticReferences { count, maximum } => write!(
                formatter,
                "qualified semantic reference count {count} exceeds cap {maximum}"
            ),
            Self::InvalidQualificationId => formatter.write_str(
                "SCIP qualification id must be non-empty, bounded, and free of control characters",
            ),
            Self::EmptySemanticProvenance => {
                formatter.write_str("qualified SCIP reference requires explicit source provenance")
            }
            Self::TooManySemanticProvenance { count, maximum } => write!(
                formatter,
                "qualified SCIP provenance count {count} exceeds cap {maximum}"
            ),
            Self::InvalidSemanticCoverageState => formatter.write_str(
                "semantic index coverage state does not match the supplied semantic-index input",
            ),
        }
    }
}

impl Error for InterFileLinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Model(source) => Some(source),
            Self::Structural(source) => Some(source),
            _ => None,
        }
    }
}

impl From<ModelError> for InterFileLinkError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

impl From<StructuralError> for InterFileLinkError {
    fn from(value: StructuralError) -> Self {
        Self::Structural(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImportKind {
    Runtime,
    TypeOnly,
    Namespace,
}

#[derive(Clone, Debug)]
struct ImportBinding {
    local_name: String,
    imported_name: String,
    specifier: String,
    kind: ImportKind,
    provenance: SourceLocation,
}

#[derive(Clone, Debug)]
enum ImportResolution {
    Unique(NormalizedRepoPath),
    Invalid,
    Unresolved,
    Ambiguous,
    SelfImport,
}

pub fn link_inter_file(
    routes: &[RouteObservation],
    source_modules: &[SourceModule<'_>],
    semantic_index: SemanticIndexInput<'_>,
    limits: BusinessLogicLimits,
) -> Result<InterFileLinking, InterFileLinkError> {
    let limits = limits.validate()?;
    if source_modules.len() > limits.max_path_candidates {
        return Err(InterFileLinkError::TooManySourceModules {
            count: source_modules.len(),
            maximum: limits.max_path_candidates,
        });
    }

    let mut modules = BTreeMap::<String, &SourceModule<'_>>::new();
    let mut known_paths = BTreeMap::<String, NormalizedRepoPath>::new();
    for module in source_modules {
        let key = module.path.as_str().to_owned();
        if modules.insert(key.clone(), module).is_some() {
            return Err(InterFileLinkError::DuplicateSourcePath(key));
        }
        known_paths.insert(key, module.path.clone());
    }

    let mut links = BTreeMap::<String, CrossLayerLink>::new();
    let mut gaps = BTreeSet::<LinkingCoverageGap>::new();
    let mut import_cache = BTreeMap::<String, Vec<ImportBinding>>::new();
    let mut local_coverage = CoverageState::Covered;

    for route in routes {
        for pair in route.callback_chain().windows(2) {
            let link = make_link(
                pair[0].clone(),
                pair[1].clone(),
                REL_CALLBACK_PRECEDES,
                LinkBasis::SupportedCallbackChain,
                ConfidenceBasis::Extracted,
                route.provenance().to_vec(),
                limits,
            )?;
            insert_link(&mut links, link, limits)?;
        }

        if route.callback_chain().is_empty() {
            continue;
        }

        let route_paths = route
            .provenance()
            .iter()
            .map(|location| location.path().as_str())
            .collect::<BTreeSet<_>>();
        if route_paths.len() != 1 {
            local_coverage = CoverageState::Partial;
            add_gap(
                &mut gaps,
                LinkingCoverageGapReason::AmbiguousRouteSource,
                route.provenance().first().cloned(),
                limits,
            )?;
            continue;
        }
        let Some(route_path) = route_paths.first().copied() else {
            continue;
        };
        let Some(module) = modules.get(route_path).copied() else {
            local_coverage = CoverageState::Partial;
            add_gap(
                &mut gaps,
                LinkingCoverageGapReason::MissingRouteSource,
                route.provenance().first().cloned(),
                limits,
            )?;
            continue;
        };
        let Some(framework_key) = framework_identity_key(route.framework()) else {
            local_coverage = CoverageState::Partial;
            add_gap(
                &mut gaps,
                LinkingCoverageGapReason::UnsupportedRouteFramework,
                route.provenance().first().cloned(),
                limits,
            )?;
            continue;
        };

        if !import_cache.contains_key(route_path) {
            let observed = extract_local_imports(module, limits)?;
            import_cache.insert(route_path.to_owned(), observed);
        }
        let import_bindings = import_cache
            .get(route_path)
            .expect("route import cache inserted above");

        for namespace in import_bindings
            .iter()
            .filter(|binding| binding.kind == ImportKind::Namespace)
        {
            if route.handler_semantic_key().is_some_and(|handler| {
                handler
                    .strip_prefix(&namespace.local_name)
                    .is_some_and(|suffix| suffix.starts_with('.'))
            }) {
                local_coverage = CoverageState::Partial;
                add_gap(
                    &mut gaps,
                    LinkingCoverageGapReason::UnsupportedNamespaceImport,
                    Some(namespace.provenance.clone()),
                    limits,
                )?;
            }
        }

        for (index, callback_id) in route.callback_chain().iter().enumerate() {
            let mut matched = Vec::new();
            for binding in import_bindings {
                if binding.kind == ImportKind::Namespace {
                    continue;
                }
                let candidate = StableSemanticId::from_parts(
                    "r3-route-callback",
                    &[
                        framework_key,
                        route_path,
                        route.route_pattern(),
                        &index.to_string(),
                        &binding.local_name,
                    ],
                    limits,
                )?;
                if &candidate == callback_id {
                    matched.push(binding);
                }
            }

            if matched.len() > 1 {
                local_coverage = CoverageState::Partial;
                add_gap(
                    &mut gaps,
                    LinkingCoverageGapReason::AmbiguousImportBinding,
                    matched.first().map(|binding| binding.provenance.clone()),
                    limits,
                )?;
                continue;
            }
            let Some(binding) = matched.first().copied() else {
                continue;
            };
            if binding.kind == ImportKind::TypeOnly {
                local_coverage = CoverageState::Partial;
                add_gap(
                    &mut gaps,
                    LinkingCoverageGapReason::TypeOnlyImportBinding,
                    Some(binding.provenance.clone()),
                    limits,
                )?;
                continue;
            }

            match resolve_local_import(route_path, &binding.specifier, &known_paths) {
                ImportResolution::Unique(target_path) => {
                    let target_id = StableSemanticId::from_parts(
                        "r3-imported-symbol",
                        &[target_path.as_str(), &binding.imported_name],
                        limits,
                    )?;
                    let provenance = route
                        .provenance()
                        .iter()
                        .cloned()
                        .chain(std::iter::once(binding.provenance.clone()))
                        .collect();
                    let link = make_link(
                        callback_id.clone(),
                        target_id,
                        REL_CALLBACK_IMPORT_BINDING,
                        LinkBasis::SupportedImportBinding,
                        ConfidenceBasis::Extracted,
                        provenance,
                        limits,
                    )?;
                    insert_link(&mut links, link, limits)?;
                }
                ImportResolution::Invalid => {
                    local_coverage = CoverageState::Partial;
                    add_gap(
                        &mut gaps,
                        LinkingCoverageGapReason::InvalidLocalImportSpecifier,
                        Some(binding.provenance.clone()),
                        limits,
                    )?;
                }
                ImportResolution::Unresolved => {
                    local_coverage = CoverageState::Partial;
                    add_gap(
                        &mut gaps,
                        LinkingCoverageGapReason::UnresolvedLocalImport,
                        Some(binding.provenance.clone()),
                        limits,
                    )?;
                }
                ImportResolution::Ambiguous => {
                    local_coverage = CoverageState::Partial;
                    add_gap(
                        &mut gaps,
                        LinkingCoverageGapReason::AmbiguousLocalImport,
                        Some(binding.provenance.clone()),
                        limits,
                    )?;
                }
                ImportResolution::SelfImport => {
                    local_coverage = CoverageState::Partial;
                    add_gap(
                        &mut gaps,
                        LinkingCoverageGapReason::SelfImport,
                        Some(binding.provenance.clone()),
                        limits,
                    )?;
                }
            }
        }
    }

    let mut semantic_qualification_ids = BTreeSet::new();
    let semantic_coverage = match semantic_index {
        SemanticIndexInput::NotProvided => {
            add_gap(
                &mut gaps,
                LinkingCoverageGapReason::SemanticIndexUnavailable,
                None,
                limits,
            )?;
            CoverageState::Unavailable
        }
        SemanticIndexInput::CoverageGap(state) => {
            if matches!(state, CoverageState::Covered | CoverageState::Partial) {
                return Err(InterFileLinkError::InvalidSemanticCoverageState);
            }
            add_gap(
                &mut gaps,
                LinkingCoverageGapReason::SemanticIndexCoverageGap,
                None,
                limits,
            )?;
            state
        }
        SemanticIndexInput::Qualified {
            references,
            coverage_state,
        } => {
            if !matches!(
                coverage_state,
                CoverageState::Covered | CoverageState::Partial
            ) {
                return Err(InterFileLinkError::InvalidSemanticCoverageState);
            }
            if references.len() > limits.max_path_candidates {
                return Err(InterFileLinkError::TooManySemanticReferences {
                    count: references.len(),
                    maximum: limits.max_path_candidates,
                });
            }
            let mut state = coverage_state;
            if state == CoverageState::Partial {
                add_gap(
                    &mut gaps,
                    LinkingCoverageGapReason::SemanticIndexPartial,
                    None,
                    limits,
                )?;
            }
            if references.is_empty() && state == CoverageState::Covered {
                state = CoverageState::Partial;
                add_gap(
                    &mut gaps,
                    LinkingCoverageGapReason::SemanticIndexEmpty,
                    None,
                    limits,
                )?;
            }
            for reference in references {
                semantic_qualification_ids.insert(reference.qualification_id.clone());
                match reference.confidence_basis {
                    ConfidenceBasis::Extracted => {}
                    ConfidenceBasis::Inferred => {
                        state = CoverageState::Partial;
                        add_gap(
                            &mut gaps,
                            LinkingCoverageGapReason::SemanticIndexInferred,
                            reference.provenance.first().cloned(),
                            limits,
                        )?;
                    }
                    ConfidenceBasis::Ambiguous => {
                        state = CoverageState::Partial;
                        add_gap(
                            &mut gaps,
                            LinkingCoverageGapReason::SemanticReferenceAmbiguous,
                            reference.provenance.first().cloned(),
                            limits,
                        )?;
                    }
                }
                let link = make_link(
                    reference.source_semantic_id.clone(),
                    reference.target_semantic_id.clone(),
                    REL_SCIP_REFERENCE,
                    LinkBasis::ScipReference,
                    reference.confidence_basis,
                    reference.provenance.clone(),
                    limits,
                )?;
                insert_link(&mut links, link, limits)?;
            }
            state
        }
    };

    Ok(InterFileLinking {
        links: links.into_values().collect(),
        gaps: gaps.into_iter().collect(),
        local_coverage,
        semantic_coverage,
        semantic_qualification_ids: semantic_qualification_ids.into_iter().collect(),
    })
}

fn extract_local_imports(
    module: &SourceModule<'_>,
    limits: BusinessLogicLimits,
) -> Result<Vec<ImportBinding>, InterFileLinkError> {
    let validator = StructuralRegistry::new(&[])?;
    validator.scan_language(module.language, &module.path, module.source)?;
    let source =
        std::str::from_utf8(module.source).map_err(|_| InterFileLinkError::NonUtf8Source)?;
    let language: tree_sitter::Language = match module.language {
        StructuralLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        StructuralLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
    };
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| InterFileLinkError::ParseFailed(error.to_string()))?;
    let tree = parser.parse(source, None).ok_or_else(|| {
        InterFileLinkError::ParseFailed("inter-file parser returned no syntax tree".to_owned())
    })?;
    let digest = content_id("r3-link-source", &(module.path.as_str(), source))
        .map_err(ModelError::from)?;

    let mut imports = Vec::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "import_statement" {
            collect_import_statement(node, source, module, &digest, &mut imports, limits)?;
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    imports.sort_by(|left, right| {
        left.local_name
            .cmp(&right.local_name)
            .then_with(|| left.specifier.cmp(&right.specifier))
            .then_with(|| left.imported_name.cmp(&right.imported_name))
            .then_with(|| {
                left.provenance
                    .start_byte()
                    .cmp(&right.provenance.start_byte())
            })
    });
    imports.dedup_by(|left, right| {
        left.local_name == right.local_name
            && left.imported_name == right.imported_name
            && left.specifier == right.specifier
            && left.kind == right.kind
            && left.provenance == right.provenance
    });
    Ok(imports)
}

fn collect_import_statement(
    statement: tree_sitter::Node<'_>,
    source: &str,
    module: &SourceModule<'_>,
    digest: &str,
    imports: &mut Vec<ImportBinding>,
    limits: BusinessLogicLimits,
) -> Result<(), InterFileLinkError> {
    let Some(source_node) = statement.child_by_field_name("source") else {
        return Ok(());
    };
    let Some(specifier) = static_string(source_node, source) else {
        return Ok(());
    };
    if !specifier.starts_with('.') {
        return Ok(());
    }
    let statement_text = source
        .get(statement.byte_range())
        .unwrap_or_default()
        .trim();
    let all_type_only = statement_text.starts_with("import type ");
    let provenance = SourceLocation::new(
        module.path.clone(),
        statement.start_byte(),
        statement.end_byte(),
        digest.to_owned(),
    )?;

    let mut cursor = statement.walk();
    let clause = statement
        .named_children(&mut cursor)
        .find(|child| child.kind() == "import_clause");
    let Some(clause) = clause else {
        return Ok(());
    };

    let mut clause_cursor = clause.walk();
    for child in clause.named_children(&mut clause_cursor) {
        match child.kind() {
            "identifier" => push_import(
                imports,
                ImportBinding {
                    local_name: node_text(child, source).unwrap_or_default().to_owned(),
                    imported_name: "default".to_owned(),
                    specifier: specifier.clone(),
                    kind: if all_type_only {
                        ImportKind::TypeOnly
                    } else {
                        ImportKind::Runtime
                    },
                    provenance: provenance.clone(),
                },
                limits,
            )?,
            "namespace_import" => {
                if let Some(local) = first_identifier(child, source) {
                    push_import(
                        imports,
                        ImportBinding {
                            local_name: local.to_owned(),
                            imported_name: "*".to_owned(),
                            specifier: specifier.clone(),
                            kind: ImportKind::Namespace,
                            provenance: provenance.clone(),
                        },
                        limits,
                    )?;
                }
            }
            "named_imports" => {
                let mut named_cursor = child.walk();
                for specifier_node in child.named_children(&mut named_cursor) {
                    if specifier_node.kind() != "import_specifier" {
                        continue;
                    }
                    let text = source
                        .get(specifier_node.byte_range())
                        .unwrap_or_default()
                        .trim();
                    let specifier_type_only = all_type_only || text.starts_with("type ");
                    let mut spec_cursor = specifier_node.walk();
                    let parts: Vec<_> = specifier_node.named_children(&mut spec_cursor).collect();
                    let Some(imported_node) = parts.first().copied() else {
                        continue;
                    };
                    let Some(imported_name) = import_name(imported_node, source) else {
                        continue;
                    };
                    let local_name = parts
                        .get(1)
                        .and_then(|node| node_text(*node, source))
                        .unwrap_or(imported_name.as_str())
                        .to_owned();
                    push_import(
                        imports,
                        ImportBinding {
                            local_name,
                            imported_name,
                            specifier: specifier.clone(),
                            kind: if specifier_type_only {
                                ImportKind::TypeOnly
                            } else {
                                ImportKind::Runtime
                            },
                            provenance: provenance.clone(),
                        },
                        limits,
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn push_import(
    imports: &mut Vec<ImportBinding>,
    binding: ImportBinding,
    limits: BusinessLogicLimits,
) -> Result<(), InterFileLinkError> {
    let count = imports.len().saturating_add(1);
    if count > limits.max_path_candidates {
        return Err(InterFileLinkError::TooManyImportBindings {
            count,
            maximum: limits.max_path_candidates,
        });
    }
    if !binding.local_name.is_empty() {
        imports.push(binding);
    }
    Ok(())
}

fn resolve_local_import(
    source_path: &str,
    specifier: &str,
    known_paths: &BTreeMap<String, NormalizedRepoPath>,
) -> ImportResolution {
    let Some(joined) = normalize_relative_specifier(source_path, specifier) else {
        return ImportResolution::Invalid;
    };
    let mut candidates = BTreeSet::new();
    candidates.insert(joined.clone());
    if !has_module_extension(&joined) {
        for extension in MODULE_EXTENSIONS {
            candidates.insert(format!("{joined}.{extension}"));
            candidates.insert(format!("{joined}/index.{extension}"));
        }
    }
    let matched = candidates
        .into_iter()
        .filter_map(|candidate| known_paths.get(&candidate).cloned())
        .collect::<BTreeSet<_>>();
    match matched.len() {
        0 => ImportResolution::Unresolved,
        1 => {
            let target = matched.into_iter().next().expect("one matched import");
            if target.as_str() == source_path {
                ImportResolution::SelfImport
            } else {
                ImportResolution::Unique(target)
            }
        }
        _ => ImportResolution::Ambiguous,
    }
}

fn normalize_relative_specifier(source_path: &str, specifier: &str) -> Option<String> {
    if specifier.is_empty()
        || !specifier.starts_with('.')
        || specifier.starts_with('/')
        || specifier.contains('\\')
        || specifier.contains('?')
        || specifier.contains('#')
        || specifier.ends_with('/')
    {
        return None;
    }
    let mut components = source_path
        .split('/')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    components.pop()?;
    for component in specifier.split('/') {
        match component {
            "." => {}
            ".." => {
                components.pop()?;
            }
            "" => return None,
            value => {
                if value.chars().any(char::is_control) || value == "." || value == ".." {
                    return None;
                }
                components.push(value.to_owned());
            }
        }
    }
    if components.is_empty() {
        None
    } else {
        Some(components.join("/"))
    }
}

fn make_link(
    source: StableSemanticId,
    target: StableSemanticId,
    relation: &str,
    basis: LinkBasis,
    confidence_basis: ConfidenceBasis,
    provenance: Vec<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<CrossLayerLink, InterFileLinkError> {
    let link_id = StableSemanticId::from_parts(
        "r3-cross-layer-link",
        &[
            source.as_str(),
            target.as_str(),
            relation,
            link_basis_key(basis),
        ],
        limits,
    )?;
    Ok(CrossLayerLink::new(
        link_id,
        source,
        target,
        relation,
        basis,
        confidence_basis,
        provenance,
        limits,
    )?)
}

fn insert_link(
    links: &mut BTreeMap<String, CrossLayerLink>,
    link: CrossLayerLink,
    limits: BusinessLogicLimits,
) -> Result<(), InterFileLinkError> {
    let key = link.link_id().as_str().to_owned();
    if let Some(existing) = links.get(&key) {
        let provenance = existing
            .provenance()
            .iter()
            .cloned()
            .chain(link.provenance().iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let confidence =
            conservative_confidence(existing.confidence_basis(), link.confidence_basis());
        let merged = CrossLayerLink::new(
            existing.link_id().clone(),
            existing.source_semantic_id().clone(),
            existing.target_semantic_id().clone(),
            existing.relation(),
            existing.basis(),
            confidence,
            provenance,
            limits,
        )?;
        links.insert(key, merged);
        return Ok(());
    }
    if links.len() >= limits.max_path_candidates {
        return Err(InterFileLinkError::TooManyLinks {
            count: links.len().saturating_add(1),
            maximum: limits.max_path_candidates,
        });
    }
    links.insert(key, link);
    Ok(())
}

fn add_gap(
    gaps: &mut BTreeSet<LinkingCoverageGap>,
    reason: LinkingCoverageGapReason,
    provenance: Option<SourceLocation>,
    limits: BusinessLogicLimits,
) -> Result<(), InterFileLinkError> {
    let candidate = LinkingCoverageGap { reason, provenance };
    if !gaps.contains(&candidate) && gaps.len() >= limits.max_diagnostics {
        return Err(InterFileLinkError::TooManyGaps {
            count: gaps.len().saturating_add(1),
            maximum: limits.max_diagnostics,
        });
    }
    gaps.insert(candidate);
    Ok(())
}

const fn conservative_confidence(left: ConfidenceBasis, right: ConfidenceBasis) -> ConfidenceBasis {
    match (left, right) {
        (ConfidenceBasis::Ambiguous, _) | (_, ConfidenceBasis::Ambiguous) => {
            ConfidenceBasis::Ambiguous
        }
        (ConfidenceBasis::Inferred, _) | (_, ConfidenceBasis::Inferred) => {
            ConfidenceBasis::Inferred
        }
        _ => ConfidenceBasis::Extracted,
    }
}

const fn link_basis_key(basis: LinkBasis) -> &'static str {
    match basis {
        LinkBasis::SameHandlerStructural => "same-handler-structural",
        LinkBasis::SupportedCallbackChain => "supported-callback-chain",
        LinkBasis::SupportedImportBinding => "supported-import-binding",
        LinkBasis::ScipReference => "scip-reference",
        LinkBasis::ExplicitAdapterLink => "explicit-adapter-link",
        LinkBasis::Unknown => "unknown",
    }
}

const fn framework_identity_key(framework: FrameworkFamily) -> Option<&'static str> {
    match framework {
        FrameworkFamily::Express => Some("express"),
        FrameworkFamily::NextApp => Some("next-app"),
        FrameworkFamily::NextPagesApi => Some("next-pages-api"),
        FrameworkFamily::SupabaseEdge => Some("supabase-edge"),
        FrameworkFamily::OtherSupported => None,
    }
}

fn static_string(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    let raw = source.get(node.byte_range())?.trim();
    let inner = raw
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .or_else(|| {
            raw.strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
        })?;
    if inner.contains('\\') || inner.chars().any(char::is_control) {
        return None;
    }
    Some(inner.to_owned())
}

fn import_name(node: tree_sitter::Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return node_text(node, source).map(str::to_owned);
    }
    static_string(node, source)
}

fn first_identifier<'a>(node: tree_sitter::Node<'a>, source: &'a str) -> Option<&'a str> {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if current.kind() == "identifier" {
            return node_text(current, source);
        }
        let mut cursor = current.walk();
        let children: Vec<_> = current.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    None
}

fn node_text<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    source.get(node.byte_range())
}

fn has_module_extension(path: &str) -> bool {
    MODULE_EXTENSIONS
        .iter()
        .any(|extension| path.ends_with(&format!(".{extension}")))
}
