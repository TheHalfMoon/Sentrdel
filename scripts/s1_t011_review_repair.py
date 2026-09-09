from pathlib import Path

path = Path("crates/sentrdel-review/src/regression/support.rs")
text = path.read_text()


def replace_once(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    text = text.replace(old, new, 1)


replace_once(
    "    EvidenceRefTooLarge {\n        side: &'static str,\n        bytes: usize,\n        max: usize,\n    },\n    UnknownEvidenceRef {",
    "    EvidenceRefTooLarge {\n        side: &'static str,\n        bytes: usize,\n        max: usize,\n    },\n    ProvenanceFieldTooLarge {\n        side: &'static str,\n        field: &'static str,\n        bytes: usize,\n        max: usize,\n    },\n    UnknownEvidenceRef {",
    "error variant",
)

replace_once(
    "            Self::EvidenceRefTooLarge { side, bytes, max } => write!(\n                formatter,\n                \"{side} evidence reference size {bytes} exceeds configured maximum {max}\"\n            ),\n            Self::UnknownEvidenceRef { side, evidence_ref } => write!(",
    "            Self::EvidenceRefTooLarge { side, bytes, max } => write!(\n                formatter,\n                \"{side} evidence reference size {bytes} exceeds configured maximum {max}\"\n            ),\n            Self::ProvenanceFieldTooLarge {\n                side,\n                field,\n                bytes,\n                max,\n            } => write!(\n                formatter,\n                \"{side} {field} size {bytes} exceeds configured maximum {max}\"\n            ),\n            Self::UnknownEvidenceRef { side, evidence_ref } => write!(",
    "display variant",
)

replace_once(
    "            | Self::EmptyEvidenceRef { .. }\n            | Self::EvidenceRefTooLarge { .. }\n            | Self::UnknownEvidenceRef { .. }",
    "            | Self::EmptyEvidenceRef { .. }\n            | Self::EvidenceRefTooLarge { .. }\n            | Self::ProvenanceFieldTooLarge { .. }\n            | Self::UnknownEvidenceRef { .. }",
    "error source variant",
)

replace_once(
    "    let mut normalized_provenance = BTreeSet::new();\n    for location in provenance {\n        account_input_bytes(\n            total_input_bytes,\n            location.path().as_str().len(),\n            limits.max_total_input_bytes,\n        )?;\n        account_input_bytes(\n            total_input_bytes,\n            location.content_digest().len(),\n            limits.max_total_input_bytes,\n        )?;",
    "    let mut normalized_provenance = BTreeSet::new();\n    for location in provenance {\n        let path_bytes = location.path().as_str().len();\n        if path_bytes > limits.max_text_bytes {\n            return Err(BilateralSupportError::ProvenanceFieldTooLarge {\n                side,\n                field: \"provenance path\",\n                bytes: path_bytes,\n                max: limits.max_text_bytes,\n            });\n        }\n        let digest_bytes = location.content_digest().len();\n        if digest_bytes > limits.max_text_bytes {\n            return Err(BilateralSupportError::ProvenanceFieldTooLarge {\n                side,\n                field: \"provenance content digest\",\n                bytes: digest_bytes,\n                max: limits.max_text_bytes,\n            });\n        }\n        account_input_bytes(\n            total_input_bytes,\n            path_bytes,\n            limits.max_total_input_bytes,\n        )?;\n        account_input_bytes(\n            total_input_bytes,\n            digest_bytes,\n            limits.max_total_input_bytes,\n        )?;",
    "provenance bounds",
)

marker = "    #[test]\n    fn provenance_identity_is_stable_and_side_label_is_not_identity_material() {"
tests = '''    #[test]
    fn provenance_path_and_digest_respect_text_bounds() {
        let path_location = location("abcde", 0, "x");
        let path_known = known_provenance("TRUSTED_BASE", std::slice::from_ref(&path_location));
        let limits = RegressionLimits {
            max_text_bytes: 4,
            ..RegressionLimits::default()
        };
        let mut path_total = 0;
        let path_error = normalize_side_support(
            "TRUSTED_BASE",
            vec![],
            &[path_location],
            &BTreeSet::new(),
            &path_known,
            limits,
            &mut path_total,
        )
        .expect_err("oversized provenance path must fail");
        assert!(matches!(
            path_error,
            BilateralSupportError::ProvenanceFieldTooLarge {
                side: "TRUSTED_BASE",
                field: "provenance path",
                bytes: 5,
                max: 4,
            }
        ));

        let digest_location = location("a", 0, "12345");
        let digest_known = known_provenance("CANDIDATE", std::slice::from_ref(&digest_location));
        let mut digest_total = 0;
        let digest_error = normalize_side_support(
            "CANDIDATE",
            vec![],
            &[digest_location],
            &BTreeSet::new(),
            &digest_known,
            limits,
            &mut digest_total,
        )
        .expect_err("oversized provenance digest must fail");
        assert!(matches!(
            digest_error,
            BilateralSupportError::ProvenanceFieldTooLarge {
                side: "CANDIDATE",
                field: "provenance content digest",
                bytes: 5,
                max: 4,
            }
        ));
    }

'''
if text.count(marker) != 1:
    raise SystemExit("test insertion marker mismatch")
text = text.replace(marker, tests + marker, 1)
path.write_text(text)
