#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    return text.replace(old, new, 1)


path = Path("crates/sentrdel-review/src/regression/support.rs")
text = path.read_text(encoding="utf-8")

text = replace_once(
    text,
    "    EvidenceRefTooLarge {\n        side: &'static str,\n        bytes: usize,\n        max: usize,\n    },\n    UnknownEvidenceRef {",
    "    EvidenceRefTooLarge {\n        side: &'static str,\n        bytes: usize,\n        max: usize,\n    },\n    ProvenanceFieldTooLarge {\n        side: &'static str,\n        field: &'static str,\n        bytes: usize,\n        max: usize,\n    },\n    UnknownEvidenceRef {",
    "error variant",
)

text = replace_once(
    text,
    "            Self::EvidenceRefTooLarge { side, bytes, max } => write!(\n                formatter,\n                \"{side} evidence reference size {bytes} exceeds configured maximum {max}\"\n            ),\n            Self::UnknownEvidenceRef { side, evidence_ref } => write!(",
    "            Self::EvidenceRefTooLarge { side, bytes, max } => write!(\n                formatter,\n                \"{side} evidence reference size {bytes} exceeds configured maximum {max}\"\n            ),\n            Self::ProvenanceFieldTooLarge {\n                side,\n                field,\n                bytes,\n                max,\n            } => write!(\n                formatter,\n                \"{side} provenance {field} size {bytes} exceeds configured maximum {max}\"\n            ),\n            Self::UnknownEvidenceRef { side, evidence_ref } => write!(",
    "display variant",
)

text = replace_once(
    text,
    "            | Self::EmptyEvidenceRef { .. }\n            | Self::EvidenceRefTooLarge { .. }\n            | Self::UnknownEvidenceRef { .. }",
    "            | Self::EmptyEvidenceRef { .. }\n            | Self::EvidenceRefTooLarge { .. }\n            | Self::ProvenanceFieldTooLarge { .. }\n            | Self::UnknownEvidenceRef { .. }",
    "error source variant",
)

text = replace_once(
    text,
    "    let mut normalized_provenance = BTreeSet::new();\n    for location in provenance {\n        account_input_bytes(\n            total_input_bytes,\n            location.path().as_str().len(),\n            limits.max_total_input_bytes,\n        )?;\n        account_input_bytes(\n            total_input_bytes,\n            location.content_digest().len(),\n            limits.max_total_input_bytes,\n        )?;",
    "    let mut normalized_provenance = BTreeSet::new();\n    for location in provenance {\n        let path = location.path().as_str();\n        let content_digest = location.content_digest();\n        validate_provenance_text(side, \"path\", path, limits.max_text_bytes)?;\n        validate_provenance_text(\n            side,\n            \"content_digest\",\n            content_digest,\n            limits.max_text_bytes,\n        )?;\n        account_input_bytes(\n            total_input_bytes,\n            path.len(),\n            limits.max_total_input_bytes,\n        )?;\n        account_input_bytes(\n            total_input_bytes,\n            content_digest.len(),\n            limits.max_total_input_bytes,\n        )?;",
    "provenance per-field validation",
)

text = replace_once(
    text,
    "fn provenance_ref(\n    side: &'static str,\n    location: &SourceLocation,\n) -> Result<String, BilateralSupportError> {",
    "fn validate_provenance_text(\n    side: &'static str,\n    field: &'static str,\n    value: &str,\n    max: usize,\n) -> Result<(), BilateralSupportError> {\n    if value.len() > max {\n        return Err(BilateralSupportError::ProvenanceFieldTooLarge {\n            side,\n            field,\n            bytes: value.len(),\n            max,\n        });\n    }\n    Ok(())\n}\n\nfn provenance_ref(\n    side: &'static str,\n    location: &SourceLocation,\n) -> Result<String, BilateralSupportError> {",
    "validation helper",
)

marker = "    #[test]\n    fn provenance_identity_is_stable_and_side_label_is_not_identity_material() {"
new_test = r'''    #[test]
    fn provenance_text_limits_are_enforced_per_field_with_inclusive_boundary() {
        let path_too_large = location("abcde", 0, "d");
        let path_known = known_provenance("TRUSTED_BASE", std::slice::from_ref(&path_too_large));
        let no_evidence = BTreeSet::new();
        let limits = RegressionLimits {
            max_text_bytes: 4,
            ..RegressionLimits::default()
        };
        let mut path_total = 0;
        let path_error = normalize_side_support(
            "TRUSTED_BASE",
            vec![],
            &[path_too_large],
            &no_evidence,
            &path_known,
            limits,
            &mut path_total,
        )
        .expect_err("oversized provenance path must fail");
        assert!(matches!(
            path_error,
            BilateralSupportError::ProvenanceFieldTooLarge {
                side: "TRUSTED_BASE",
                field: "path",
                bytes: 5,
                max: 4,
            }
        ));

        let digest_too_large = location("a", 0, "12345");
        let digest_known = known_provenance("CANDIDATE", std::slice::from_ref(&digest_too_large));
        let mut digest_total = 0;
        let digest_error = normalize_side_support(
            "CANDIDATE",
            vec![],
            &[digest_too_large],
            &no_evidence,
            &digest_known,
            limits,
            &mut digest_total,
        )
        .expect_err("oversized provenance digest must fail");
        assert!(matches!(
            digest_error,
            BilateralSupportError::ProvenanceFieldTooLarge {
                side: "CANDIDATE",
                field: "content_digest",
                bytes: 5,
                max: 4,
            }
        ));

        let at_boundary = location("abcd", 0, "1234");
        let boundary_known = known_provenance("TRUSTED_BASE", std::slice::from_ref(&at_boundary));
        let mut boundary_total = 0;
        let boundary = normalize_side_support(
            "TRUSTED_BASE",
            vec![],
            &[at_boundary],
            &no_evidence,
            &boundary_known,
            limits,
            &mut boundary_total,
        )
        .expect("provenance fields exactly at max_text_bytes must remain valid");
        assert_eq!(boundary.provenance_refs().len(), 1);
    }

'''
if text.count(marker) != 1:
    raise SystemExit(f"test insertion marker: expected one match, got {text.count(marker)}")
text = text.replace(marker, new_test + marker, 1)

path.write_text(text, encoding="utf-8")
