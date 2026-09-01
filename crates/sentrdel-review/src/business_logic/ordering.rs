//! Deterministic bounded ordering helpers for R3 semantic collections.
//!
//! Producers may observe equivalent facts in parser/traversal order. Before
//! identities or persistent semantic output depend on those collections, R3
//! normalizes them into stable order and removes duplicate semantic identities.

use super::model::{BusinessLogicLimits, ModelError, StableSemanticId};

pub fn normalize_semantic_ids(
    mut values: Vec<StableSemanticId>,
    limits: BusinessLogicLimits,
) -> Result<Vec<StableSemanticId>, ModelError> {
    let limits = limits.validate()?;
    if values.len() > limits.max_related_ids {
        return Err(ModelError::TooManyRelatedIds {
            count: values.len(),
            max: limits.max_related_ids,
        });
    }
    values.sort();
    values.dedup();
    Ok(values)
}

pub fn normalize_bounded_strings(
    mut values: Vec<String>,
    limits: BusinessLogicLimits,
) -> Result<Vec<String>, ModelError> {
    let limits = limits.validate()?;
    if values.len() > limits.max_related_ids {
        return Err(ModelError::TooManyRelatedIds {
            count: values.len(),
            max: limits.max_related_ids,
        });
    }

    for (index, value) in values.iter().enumerate() {
        if value.trim().is_empty() {
            return Err(ModelError::EmptyIdentityPart { index });
        }
        if value.len() > limits.max_id_part_bytes {
            return Err(ModelError::IdentityPartTooLarge {
                index,
                bytes: value.len(),
                max: limits.max_id_part_bytes,
            });
        }
    }

    values.sort();
    values.dedup();
    Ok(values)
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
            Err(ModelError::TooManyRelatedIds { .. })
        ));
    }
}
