//! Deterministic Evidence correlation and canonical Finding reconciliation.
//!
//! Evidence remains immutable source material. This module groups compatible
//! observations by stable non-secret identity, retains every source Evidence ID,
//! records contradictions explicitly, and lets only runtime-owned reconciliation
//! policy plus `ReconcilerAuthority` mint canonical Findings.

use sentrdel_schema::SCHEMA_V1;
use sentrdel_schema::canonical::{CanonicalError, content_id};
use sentrdel_schema::evidence::{EpistemicClass, Evidence, EvidenceClaim};
use sentrdel_schema::finding::{
    EpistemicState, Finding, FindingError, ReconciledFindingDraft, ReconcilerAuthority, Severity,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const STABLE_ATTRIBUTE_KEYS: &[&str] = &[
    "sanitized_fingerprint",
    "rule_id",
    "advisory_id",
    "package_name",
    "package_version",
];

/// Runtime-owned semantics for one Evidence category. It deliberately does not
/// implement serialization, so repository/model/engine bytes cannot choose the
/// canonical Finding severity, title, category, or impact statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationRule {
    evidence_category: String,
    finding_category: String,
    title: String,
    impact_statement: String,
    severity: Severity,
}

impl ReconciliationRule {
    pub fn from_runtime(
        evidence_category: impl Into<String>,
        finding_category: impl Into<String>,
        title: impl Into<String>,
        impact_statement: impl Into<String>,
        severity: Severity,
    ) -> Result<Self, ReconcileError> {
        let rule = Self {
            evidence_category: evidence_category.into(),
            finding_category: finding_category.into(),
            title: title.into(),
            impact_statement: impact_statement.into(),
            severity,
        };
        if rule.evidence_category.trim().is_empty()
            || rule.finding_category.trim().is_empty()
            || rule.title.trim().is_empty()
            || rule.impact_statement.trim().is_empty()
        {
            return Err(ReconcileError::InvalidRuntimeRule);
        }
        Ok(rule)
    }

    #[must_use]
    pub fn evidence_category(&self) -> &str {
        &self.evidence_category
    }
}

#[derive(Debug)]
pub enum ReconcileError {
    InvalidRuntimeRule,
    EmptyEvidence,
    EmptyUpdatedAt,
    UnexpectedEvidenceCategory { expected: String, actual: String },
    NoSupportingEvidence,
    Canonical(CanonicalError),
    Finding(FindingError),
}

impl fmt::Display for ReconcileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRuntimeRule => formatter.write_str(
                "runtime reconciliation rule requires non-empty category, title, and impact fields",
            ),
            Self::EmptyEvidence => formatter.write_str("reconciliation requires Evidence input"),
            Self::EmptyUpdatedAt => formatter.write_str("updated_at must not be empty"),
            Self::UnexpectedEvidenceCategory { expected, actual } => write!(
                formatter,
                "evidence category {actual:?} does not match runtime rule category {expected:?}"
            ),
            Self::NoSupportingEvidence => formatter.write_str(
                "contradiction-only evidence cannot mint a canonical Finding without supporting evidence",
            ),
            Self::Canonical(error) => write!(formatter, "cannot derive correlation fingerprint: {error}"),
            Self::Finding(error) => write!(formatter, "cannot mint reconciled Finding: {error}"),
        }
    }
}

impl std::error::Error for ReconcileError {}

impl From<CanonicalError> for ReconcileError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

impl From<FindingError> for ReconcileError {
    fn from(value: FindingError) -> Self {
        Self::Finding(value)
    }
}

/// Reconcile one trusted runtime rule's Evidence into deterministic canonical
/// Findings. Input order never affects grouping, Evidence ordering, or Finding IDs.
pub fn reconcile_evidence(
    evidence: &[Evidence],
    rule: &ReconciliationRule,
    reconciler: &ReconcilerAuthority,
    updated_at: &str,
) -> Result<Vec<Finding>, ReconcileError> {
    if evidence.is_empty() {
        return Err(ReconcileError::EmptyEvidence);
    }
    if updated_at.trim().is_empty() {
        return Err(ReconcileError::EmptyUpdatedAt);
    }

    let mut groups: BTreeMap<String, Vec<&Evidence>> = BTreeMap::new();
    for item in evidence {
        if item.claim().category != rule.evidence_category {
            return Err(ReconcileError::UnexpectedEvidenceCategory {
                expected: rule.evidence_category.clone(),
                actual: item.claim().category.clone(),
            });
        }
        groups
            .entry(correlation_fingerprint(item.claim())?)
            .or_default()
            .push(item);
    }

    let mut findings = Vec::with_capacity(groups.len());
    for (fingerprint, mut grouped) in groups {
        grouped.sort_by(|left, right| left.evidence_id().cmp(right.evidence_id()));

        let supporting: Vec<_> = grouped
            .iter()
            .copied()
            .filter(|item| item.claim().epistemic_class != EpistemicClass::Contradiction)
            .collect();
        if supporting.is_empty() {
            return Err(ReconcileError::NoSupportingEvidence);
        }

        let evidence_ids: Vec<_> = grouped
            .iter()
            .map(|item| item.evidence_id().to_owned())
            .collect();
        let contradiction_ids: Vec<_> = grouped
            .iter()
            .filter(|item| item.claim().epistemic_class == EpistemicClass::Contradiction)
            .map(|item| item.evidence_id().to_owned())
            .collect();

        let epistemic_state = if !contradiction_ids.is_empty() {
            EpistemicState::Contested
        } else {
            let producers: BTreeSet<_> = supporting
                .iter()
                .map(|item| {
                    (
                        item.producer().id.as_str(),
                        item.producer().version.as_str(),
                        format!("{:?}", item.producer().kind),
                    )
                })
                .collect();
            if producers.len() >= 2 {
                EpistemicState::Corroborated
            } else {
                EpistemicState::Detected
            }
        };

        let primary_location = supporting
            .iter()
            .flat_map(|item| item.claim().locations.iter())
            .map(|location| location.repo_relative_path.clone())
            .min();
        let affected_subjects: BTreeSet<_> = supporting
            .iter()
            .flat_map(|item| item.claim().subjects.iter())
            .map(|subject| format!("{}:{}", subject.kind, subject.id))
            .collect();

        let draft = ReconciledFindingDraft {
            schema_version: SCHEMA_V1.to_owned(),
            fingerprint,
            title: rule.title.clone(),
            impact_statement: rule.impact_statement.clone(),
            category: rule.finding_category.clone(),
            severity: rule.severity.clone(),
            epistemic_state,
            evidence_ids,
            contradiction_ids,
            primary_location,
            affected_subjects: affected_subjects.into_iter().collect(),
            first_seen_commit: None,
            last_seen_commit: None,
            remediation: None,
            updated_at: updated_at.to_owned(),
        };
        findings.push(Finding::new_reconciled(draft, reconciler)?);
    }
    findings.sort_by(|left, right| left.finding_id().cmp(right.finding_id()));
    Ok(findings)
}

fn correlation_fingerprint(claim: &EvidenceClaim) -> Result<String, CanonicalError> {
    let mut subjects: Vec<_> = claim
        .subjects
        .iter()
        .map(|subject| format!("{}:{}", subject.kind, subject.id))
        .collect();
    subjects.sort();
    subjects.dedup();

    let mut locations: Vec<_> = claim
        .locations
        .iter()
        .map(|location| {
            json!({
                "path": location.repo_relative_path,
                "symbol": location.symbol,
            })
        })
        .collect();
    locations.sort_by_key(Value::to_string);
    locations.dedup();

    let stable_attributes: BTreeMap<_, _> = STABLE_ATTRIBUTE_KEYS
        .iter()
        .filter_map(|key| {
            claim
                .attributes
                .get(*key)
                .filter(|value| value.is_string())
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect();

    content_id(
        "evidence-correlation",
        &json!({
            "category": claim.category,
            "subjects": subjects,
            "locations": locations,
            "stable_attributes": stable_attributes,
        }),
    )
}
