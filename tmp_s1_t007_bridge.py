from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match in {path}, found {count}")
    file.write_text(text.replace(old, new, 1), encoding="utf-8")


model = "crates/sentrdel-review/src/regression/model.rs"
revision = "crates/sentrdel-review/src/regression/revision.rs"
tests = "crates/sentrdel-review/tests/s1_revision_validation.rs"

replace_once(
    model,
    "impl RevisionIdentity {\n    pub fn fixture(\n",
    """impl RevisionIdentity {
    /// Construct a non-fixture revision identity after the production revision
    /// boundary has validated and canonically derived its exact identity.
    pub(super) fn validated_production(
        role: RevisionRole,
        exact_identity: String,
        snapshot_input_digest: String,
        limits: RegressionLimits,
    ) -> Result<Self, RegressionModelError> {
        let limits = limits.validate()?;
        validate_text(&exact_identity, \"exact_identity\", limits)?;
        validate_text(&snapshot_input_digest, \"snapshot_input_digest\", limits)?;
        Ok(Self {
            role,
            exact_identity,
            snapshot_input_digest,
            fixture_only: false,
        })
    }

    pub fn fixture(
""",
)

replace_once(
    revision,
    "use crate::regression::S1_REGRESSION_CONTRACT_VERSION;\nuse crate::regression::model::{RegressionLimits, RegressionModelError, RevisionRole};\n",
    "use crate::regression::model::{\n    RegressionLimits, RegressionModelError, RevisionIdentity, RevisionPair, RevisionRole,\n};\n",
)
replace_once(
    revision,
    """pub struct ValidatedLocalRevision {
    role: RevisionRole,
    exact_identity: String,
    commit_id: String,
    root_tree_id: String,
    snapshot_input_digest: String,
}
""",
    """pub struct ValidatedLocalRevision {
    revision_identity: RevisionIdentity,
    commit_id: String,
    root_tree_id: String,
}
""",
)
replace_once(
    revision,
    """    pub const fn role(&self) -> RevisionRole {
        self.role
    }

    #[must_use]
    pub fn exact_identity(&self) -> &str {
        &self.exact_identity
    }
""",
    """    pub const fn role(&self) -> RevisionRole {
        self.revision_identity.role()
    }

    #[must_use]
    pub fn exact_identity(&self) -> &str {
        self.revision_identity.exact_identity()
    }

    #[must_use]
    pub fn revision_identity(&self) -> &RevisionIdentity {
        &self.revision_identity
    }
""",
)
replace_once(
    revision,
    """    pub fn snapshot_input_digest(&self) -> &str {
        &self.snapshot_input_digest
    }

    #[must_use]
    pub const fn is_fixture_only(&self) -> bool {
        false
    }
""",
    """    pub fn snapshot_input_digest(&self) -> &str {
        self.revision_identity.snapshot_input_digest()
    }

    #[must_use]
    pub const fn is_fixture_only(&self) -> bool {
        self.revision_identity.is_fixture_only()
    }
""",
)
replace_once(
    revision,
    """pub struct ValidatedRevisionPair {
    pair_id: String,
    trusted_base: ValidatedLocalRevision,
    candidate: ValidatedLocalRevision,
}
""",
    """pub struct ValidatedRevisionPair {
    revision_pair: RevisionPair,
    trusted_base: ValidatedLocalRevision,
    candidate: ValidatedLocalRevision,
}
""",
)
replace_once(
    revision,
    """    pub fn pair_id(&self) -> &str {
        &self.pair_id
    }

    #[must_use]
    pub fn trusted_base(&self) -> &ValidatedLocalRevision {
""",
    """    pub fn pair_id(&self) -> &str {
        self.revision_pair.pair_id()
    }

    #[must_use]
    pub fn revision_pair(&self) -> &RevisionPair {
        &self.revision_pair
    }

    #[must_use]
    pub fn trusted_base(&self) -> &ValidatedLocalRevision {
""",
)
replace_once(
    revision,
    """pub enum RevisionValidationError {
    Limits(RegressionModelError),
""",
    """pub enum RevisionValidationError {
    Limits(RegressionModelError),
    ModelContract(RegressionModelError),
""",
)
replace_once(
    revision,
    """            Self::Limits(error) => write!(formatter, \"invalid S1 revision limits: {error}\"),
""",
    """            Self::Limits(error) => write!(formatter, \"invalid S1 revision limits: {error}\"),
            Self::ModelContract(error) => {
                write!(formatter, \"S1 revision contract construction failed: {error}\")
            }
""",
)
replace_once(
    revision,
    """            Self::Limits(error) => Some(error),
            Self::Canonical(error) => Some(error),
""",
    """            Self::Limits(error) | Self::ModelContract(error) => Some(error),
            Self::Canonical(error) => Some(error),
""",
)
replace_once(
    revision,
    """    let pair_id = content_id(
        \"s1-revision-pair\",
        &(
            S1_REGRESSION_CONTRACT_VERSION,
            trusted_base.exact_identity.as_str(),
            candidate.exact_identity.as_str(),
        ),
    )?;

    Ok(ValidatedRevisionPair {
        pair_id,
        trusted_base,
        candidate,
    })
""",
    """    let revision_pair = RevisionPair::new(
        trusted_base.revision_identity().clone(),
        candidate.revision_identity().clone(),
    )
    .map_err(RevisionValidationError::ModelContract)?;

    Ok(ValidatedRevisionPair {
        revision_pair,
        trusted_base,
        candidate,
    })
""",
)
replace_once(
    revision,
    """    Ok(ValidatedLocalRevision {
        role,
        exact_identity,
        commit_id: resolved_id,
        root_tree_id,
        snapshot_input_digest,
    })
""",
    """    let revision_identity = RevisionIdentity::validated_production(
        role,
        exact_identity,
        snapshot_input_digest,
        limits,
    )
    .map_err(RevisionValidationError::ModelContract)?;

    Ok(ValidatedLocalRevision {
        revision_identity,
        commit_id: resolved_id,
        root_tree_id,
    })
""",
)

replace_once(
    tests,
    "use sentrdel_review::regression::model::{RegressionLimits, RevisionRole};\n",
    """use sentrdel_review::regression::model::{
    ProducerContractIdentity, RegressionLimits, RevisionPair, RevisionRole,
    SemanticSnapshotContract,
};
""",
)
replace_once(
    tests,
    """    assert!(!first.trusted_base().is_fixture_only());
    assert!(!first.candidate().is_fixture_only());

    let reversed = validate_local_revision_pair(
""",
    """    assert!(!first.trusted_base().is_fixture_only());
    assert!(!first.candidate().is_fixture_only());

    let canonical_pair = RevisionPair::new(
        first.trusted_base().revision_identity().clone(),
        first.candidate().revision_identity().clone(),
    )
    .expect(\"validated production revisions must construct the frozen pair contract\");
    assert_eq!(first.revision_pair(), &canonical_pair);
    assert_eq!(first.pair_id(), canonical_pair.pair_id());

    let producer = ProducerContractIdentity::new(
        \"r3-business-logic\",
        \"1\",
        \"config:stable\",
        \"BUSINESS_LOGIC\",
        \"r3-contract\",
        limits,
    )
    .expect(\"producer contract fixture must be valid\");
    let base_snapshot = SemanticSnapshotContract::new(
        first.trusted_base().revision_identity().clone(),
        \"canonical-schema-v1\",
        vec![producer],
        vec![\"config:stable\".to_owned()],
        limits,
    )
    .expect(\"validated production identity must bind directly into a semantic snapshot\");
    assert_eq!(base_snapshot.revision(), canonical_pair.trusted_base());
    assert!(!base_snapshot.revision().is_fixture_only());

    let reversed = validate_local_revision_pair(
""",
)

print("S1-T007 contract bridge patch applied")
