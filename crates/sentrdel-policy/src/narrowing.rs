//! Monotonic composition and repository-local policy narrowing for Spec 001 T024.
//!
//! Repository policy is untrusted project input. It may make an already trusted/base policy result
//! stricter, but it may not widen that result or disable the evidence-log boundary. Rust kernel
//! invariants remain separate and are still applied by the crate's enforcement boundary.

use std::{error::Error, fmt};

use crate::{Verdict, compose_verdicts};

/// Why a repository-local policy/config cannot be admitted as a monotonic narrowing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepositoryNarrowingError {
    /// Repository-local configuration attempted to disable mandatory evidence logging.
    EvidenceLoggingDisabled,
    /// The trusted/base policy result was unavailable, so narrowing cannot be proven.
    IndeterminateBasePolicy,
    /// Repository policy evaluation was unavailable, so narrowing cannot be proven.
    IndeterminateRepositoryPolicy,
    /// The repository result is less restrictive than the trusted/base policy result.
    PermissionWidening { base: Verdict, repository: Verdict },
}

impl fmt::Display for RepositoryNarrowingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EvidenceLoggingDisabled => {
                write!(
                    formatter,
                    "repository policy cannot disable evidence logging"
                )
            }
            Self::IndeterminateBasePolicy => write!(
                formatter,
                "repository narrowing cannot be proven from an UNDECIDABLE base policy"
            ),
            Self::IndeterminateRepositoryPolicy => write!(
                formatter,
                "repository narrowing cannot be proven from an UNDECIDABLE repository policy"
            ),
            Self::PermissionWidening { base, repository } => write!(
                formatter,
                "repository policy attempts to widen {base:?} to {repository:?}"
            ),
        }
    }
}

impl Error for RepositoryNarrowingError {}

/// Validate one repository-local policy/config result against an already trusted/base result.
///
/// Ordered verdicts use the frozen `ALLOW < ASK < DENY` lattice. Equality is valid; a repository
/// may also move upward to a stricter verdict. A move downward is rejected as widening.
/// `UNDECIDABLE` deliberately has no lattice rank, so it cannot be used as proof that a repository
/// configuration is a valid narrowing. Evidence logging is a Rust-owned invariant of repository
/// policy admission and cannot be disabled by project-local configuration.
pub fn validate_repository_narrowing(
    base: Verdict,
    repository: Verdict,
    evidence_logging_enabled: bool,
) -> Result<(), RepositoryNarrowingError> {
    if !evidence_logging_enabled {
        return Err(RepositoryNarrowingError::EvidenceLoggingDisabled);
    }

    let base_rank = ordered_rank(base).ok_or(RepositoryNarrowingError::IndeterminateBasePolicy)?;
    let repository_rank =
        ordered_rank(repository).ok_or(RepositoryNarrowingError::IndeterminateRepositoryPolicy)?;

    if repository_rank < base_rank {
        return Err(RepositoryNarrowingError::PermissionWidening { base, repository });
    }

    Ok(())
}

/// Compose trusted/base and optional repository candidates without permitting a downgrade.
///
/// This function is runtime composition, not repository-config admission. It intentionally retains
/// `UNDECIDABLE` when either participating policy is unavailable (unless an absorbing `DENY` is
/// present), so evaluation failure never turns into implicit `ALLOW`. The Rust kernel floor is
/// applied later by `resolve_for_enforcement` and cannot be weakened by this function.
#[must_use = "layered policy composition must be resolved by the Rust enforcement boundary"]
pub fn compose_base_and_repository(base: Verdict, repository: Option<Verdict>) -> Verdict {
    match repository {
        Some(repository) => compose_verdicts([base, repository]),
        None => base,
    }
}

const fn ordered_rank(verdict: Verdict) -> Option<u8> {
    match verdict {
        Verdict::Allow => Some(0),
        Verdict::Ask => Some(1),
        Verdict::Deny => Some(2),
        Verdict::Undecidable => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{UndecidableResolution, kernel::KernelIntegrityState, resolve_for_enforcement};

    fn for_each_verdict_sequence(max_len: usize, mut assertion: impl FnMut(&[Verdict])) {
        const VERDICTS: [Verdict; 4] = [
            Verdict::Allow,
            Verdict::Ask,
            Verdict::Deny,
            Verdict::Undecidable,
        ];

        for len in 0..=max_len {
            let cases = VERDICTS.len().pow(len as u32);
            for encoded in 0..cases {
                let mut value = encoded;
                let mut sequence = Vec::with_capacity(len);
                for _ in 0..len {
                    sequence.push(VERDICTS[value % VERDICTS.len()]);
                    value /= VERDICTS.len();
                }
                assertion(&sequence);
            }
        }
    }

    fn healthy_kernel_state() -> KernelIntegrityState {
        KernelIntegrityState::for_test(true, true, true, true)
    }

    #[test]
    fn equal_or_stricter_repository_verdict_is_valid_narrowing() {
        let accepted = [
            (Verdict::Allow, Verdict::Allow),
            (Verdict::Allow, Verdict::Ask),
            (Verdict::Allow, Verdict::Deny),
            (Verdict::Ask, Verdict::Ask),
            (Verdict::Ask, Verdict::Deny),
            (Verdict::Deny, Verdict::Deny),
        ];

        for (base, repository) in accepted {
            assert_eq!(
                validate_repository_narrowing(base, repository, true),
                Ok(())
            );
        }
    }

    #[test]
    fn repository_cannot_widen_trusted_policy() {
        let rejected = [
            (Verdict::Ask, Verdict::Allow),
            (Verdict::Deny, Verdict::Allow),
            (Verdict::Deny, Verdict::Ask),
        ];

        for (base, repository) in rejected {
            assert_eq!(
                validate_repository_narrowing(base, repository, true),
                Err(RepositoryNarrowingError::PermissionWidening { base, repository })
            );
        }
    }

    #[test]
    fn repository_cannot_disable_evidence_logging() {
        for base in [Verdict::Allow, Verdict::Ask, Verdict::Deny] {
            assert_eq!(
                validate_repository_narrowing(base, Verdict::Deny, false),
                Err(RepositoryNarrowingError::EvidenceLoggingDisabled)
            );
        }
    }

    #[test]
    fn undecidable_cannot_masquerade_as_proven_narrowing() {
        assert_eq!(
            validate_repository_narrowing(Verdict::Undecidable, Verdict::Deny, true),
            Err(RepositoryNarrowingError::IndeterminateBasePolicy)
        );
        assert_eq!(
            validate_repository_narrowing(Verdict::Allow, Verdict::Undecidable, true),
            Err(RepositoryNarrowingError::IndeterminateRepositoryPolicy)
        );
    }

    #[test]
    fn runtime_composition_never_lets_repository_weaken_base() {
        assert_eq!(
            compose_base_and_repository(Verdict::Deny, Some(Verdict::Allow)),
            Verdict::Deny
        );
        assert_eq!(
            compose_base_and_repository(Verdict::Ask, Some(Verdict::Allow)),
            Verdict::Ask
        );
        assert_eq!(
            compose_base_and_repository(Verdict::Allow, Some(Verdict::Deny)),
            Verdict::Deny
        );
    }

    #[test]
    fn runtime_repository_failure_is_never_implicit_allow() {
        assert_eq!(
            compose_base_and_repository(Verdict::Allow, Some(Verdict::Undecidable)),
            Verdict::Undecidable
        );
        assert_eq!(
            compose_base_and_repository(Verdict::Ask, Some(Verdict::Undecidable)),
            Verdict::Undecidable
        );
        assert_eq!(
            compose_base_and_repository(Verdict::Deny, Some(Verdict::Undecidable)),
            Verdict::Deny
        );
    }

    #[test]
    fn absent_repository_policy_preserves_base_without_inventing_authority() {
        for base in [
            Verdict::Allow,
            Verdict::Ask,
            Verdict::Deny,
            Verdict::Undecidable,
        ] {
            assert_eq!(compose_base_and_repository(base, None), base);
        }
    }

    #[test]
    fn t025_all_policy_orderings_preserve_deny_and_failure_semantics() {
        for_each_verdict_sequence(5, |sequence| {
            let composed = compose_verdicts(sequence.iter().copied());
            let has_deny = sequence.contains(&Verdict::Deny);
            let has_failure = sequence.contains(&Verdict::Undecidable);

            if has_deny {
                assert_eq!(
                    composed,
                    Verdict::Deny,
                    "DENY must remain absorbing for ordering {sequence:?}"
                );
            } else if has_failure || sequence.is_empty() {
                assert_eq!(
                    composed,
                    Verdict::Undecidable,
                    "policy failure or missing policy must remain explicit for ordering {sequence:?}"
                );
            }
        });
    }

    #[test]
    fn t025_policy_failure_never_resolves_to_silent_allow() {
        for_each_verdict_sequence(5, |sequence| {
            if !sequence.contains(&Verdict::Undecidable) || sequence.contains(&Verdict::Deny) {
                return;
            }

            let candidate = compose_verdicts(sequence.iter().copied());
            assert_eq!(candidate, Verdict::Undecidable);
            assert_eq!(
                resolve_for_enforcement(
                    healthy_kernel_state(),
                    candidate,
                    UndecidableResolution::Ask,
                )
                .verdict(),
                Verdict::Ask,
                "interactive fail-closed resolution must never ALLOW ordering {sequence:?}"
            );
            assert_eq!(
                resolve_for_enforcement(
                    healthy_kernel_state(),
                    candidate,
                    UndecidableResolution::Deny,
                )
                .verdict(),
                Verdict::Deny,
                "hard fail-closed resolution must never ALLOW ordering {sequence:?}"
            );
        });
    }

    #[test]
    fn t025_every_kernel_violation_is_absorbing_across_policy_orderings() {
        for mask in 0_u8..16 {
            if mask == 0b1111 {
                continue;
            }

            let state = KernelIntegrityState::for_test(
                mask & 0b0001 != 0,
                mask & 0b0010 != 0,
                mask & 0b0100 != 0,
                mask & 0b1000 != 0,
            );

            for_each_verdict_sequence(4, |sequence| {
                let candidate = compose_verdicts(sequence.iter().copied());
                for resolution in [UndecidableResolution::Ask, UndecidableResolution::Deny] {
                    let decision = resolve_for_enforcement(state, candidate, resolution);
                    assert_eq!(
                        decision.verdict(),
                        Verdict::Deny,
                        "kernel violation mask {mask:04b} was downgraded by ordering {sequence:?} with {resolution:?}"
                    );
                    assert!(
                        decision.kernel().is_deny(),
                        "kernel violation mask {mask:04b} must retain a DENY kernel decision"
                    );
                }
            });
        }
    }
}
