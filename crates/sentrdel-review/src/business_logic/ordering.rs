//! Deterministic bounded ordering helpers for R3 semantic collections.
//!
//! These public helpers use the same normalization boundary enforced by the
//! validated IR constructors. They do not provide an alternate unchecked path.

use super::model::{self, BusinessLogicLimits, ModelError, StableSemanticId};

pub fn normalize_semantic_ids(
    values: Vec<StableSemanticId>,
    limits: BusinessLogicLimits,
) -> Result<Vec<StableSemanticId>, ModelError> {
    model::normalize_semantic_ids(values, limits)
}

pub fn normalize_bounded_strings(
    values: Vec<String>,
    limits: BusinessLogicLimits,
) -> Result<Vec<String>, ModelError> {
    model::normalize_bounded_strings(values, "ordering_strings", limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> StableSemanticId {
        StableSemanticId::from_parts("r3.ordering", &[value], BusinessLogicLimits::default())
            .expect("stable id")
    }

    #[test]
    fn semantic_ids_are_stable_across_input_order_and_duplicates() {
        let limits = BusinessLogicLimits::default();
        let first = normalize_semantic_ids(vec![id("b"), id("a"), id("b")], limits).unwrap();
        let second = normalize_semantic_ids(vec![id("a"), id("b")], limits).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
    }

    #[test]
    fn string_sets_are_sorted_deduplicated_and_bounded() {
        let limits = BusinessLogicLimits::default();
        assert_eq!(
            normalize_bounded_strings(
                vec![
                    "role:z".to_owned(),
                    "role:a".to_owned(),
                    "role:z".to_owned(),
                ],
                limits,
            )
            .unwrap(),
            vec!["role:a".to_owned(), "role:z".to_owned()]
        );

        let too_many = BusinessLogicLimits {
            max_related_ids: 1,
            ..limits
        };
        assert!(matches!(
            normalize_bounded_strings(vec!["a".to_owned(), "b".to_owned()], too_many),
            Err(ModelError::TooManyCollectionItems { .. })
        ));
    }
}
