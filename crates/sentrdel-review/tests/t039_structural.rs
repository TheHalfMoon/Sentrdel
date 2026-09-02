use sentrdel_review::structural::{
    MAX_STRUCTURAL_DOCUMENT_BYTES, StructuralError, StructuralLanguage, StructuralRegistry,
    StructuralRule,
};
use sentrdel_review::view::NormalizedRepoPath;

const EVAL_RULE: StructuralRule =
    StructuralRule::new("js.eval-call", StructuralLanguage::JavaScript, "eval($ARG)");
const TS_EVAL_RULE: StructuralRule =
    StructuralRule::new("ts.eval-call", StructuralLanguage::TypeScript, "eval($ARG)");

fn path() -> NormalizedRepoPath {
    NormalizedRepoPath::parse("src/app.js", 128).unwrap()
}

fn typescript_path() -> NormalizedRepoPath {
    NormalizedRepoPath::parse("src/app.ts", 128).unwrap()
}

#[test]
fn structural_registry_matches_sentrdel_owned_pattern_and_preserves_location() {
    let registry = StructuralRegistry::new(&[EVAL_RULE]).unwrap();
    let source = b"const value = eval(userInput);\n";
    let matches = registry.scan(&path(), source).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_id, "js.eval-call");
    assert_eq!(matches[0].language, StructuralLanguage::JavaScript);
    assert_eq!(matches[0].path.as_str(), "src/app.js");
    assert_eq!(&source[matches[0].byte_range.clone()], b"eval(userInput)");
}

#[test]
fn typescript_scan_uses_qualified_grammar_and_filters_other_language_rules() {
    let registry = StructuralRegistry::new(&[EVAL_RULE, TS_EVAL_RULE]).unwrap();
    let source = b"const value: string = eval(userInput);\n";
    let matches = registry
        .scan_language(StructuralLanguage::TypeScript, &typescript_path(), source)
        .unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_id, "ts.eval-call");
    assert_eq!(matches[0].language, StructuralLanguage::TypeScript);
    assert_eq!(matches[0].path.as_str(), "src/app.ts");
    assert_eq!(&source[matches[0].byte_range.clone()], b"eval(userInput)");
}

#[test]
fn default_scan_remains_javascript_only() {
    let registry = StructuralRegistry::new(&[TS_EVAL_RULE, EVAL_RULE]).unwrap();
    let source = b"const value = eval(userInput);\n";
    let matches = registry.scan(&path(), source).unwrap();

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_id, "js.eval-call");
    assert_eq!(matches[0].language, StructuralLanguage::JavaScript);
}

#[test]
fn non_matching_source_is_empty_without_claiming_a_finding() {
    let registry = StructuralRegistry::new(&[EVAL_RULE]).unwrap();
    let matches = registry
        .scan(&path(), b"const value = JSON.parse(userInput);\n")
        .unwrap();
    assert!(matches.is_empty());
}

#[test]
fn malformed_source_and_non_utf8_source_fail_closed() {
    let registry = StructuralRegistry::new(&[EVAL_RULE]).unwrap();
    assert!(matches!(
        registry.scan(&path(), b"function broken( {"),
        Err(StructuralError::MalformedSyntax)
    ));
    assert!(matches!(
        registry.scan(&path(), &[0xff, 0xfe, 0xfd]),
        Err(StructuralError::NonUtf8Source)
    ));
}

#[test]
fn malformed_typescript_source_fails_closed() {
    let registry = StructuralRegistry::new(&[TS_EVAL_RULE]).unwrap();
    assert!(matches!(
        registry.scan_language(
            StructuralLanguage::TypeScript,
            &typescript_path(),
            b"const value: string = {"
        ),
        Err(StructuralError::MalformedSyntax)
    ));
}

#[test]
fn oversized_documents_and_invalid_rule_registries_fail_closed() {
    let registry = StructuralRegistry::new(&[EVAL_RULE]).unwrap();
    let oversized = vec![b'x'; MAX_STRUCTURAL_DOCUMENT_BYTES + 1];
    assert!(matches!(
        registry.scan(&path(), &oversized),
        Err(StructuralError::DocumentTooLarge { .. })
    ));

    let duplicate = StructuralRegistry::new(&[EVAL_RULE, EVAL_RULE]);
    assert!(matches!(
        duplicate,
        Err(StructuralError::DuplicateRuleId("js.eval-call"))
    ));

    let invalid_id = StructuralRule::new("JS Eval", StructuralLanguage::JavaScript, "eval($ARG)");
    assert!(matches!(
        StructuralRegistry::new(&[invalid_id]),
        Err(StructuralError::InvalidRuleId("JS Eval"))
    ));

    let empty_pattern =
        StructuralRule::new("js.empty-pattern", StructuralLanguage::JavaScript, "   ");
    assert!(matches!(
        StructuralRegistry::new(&[empty_pattern]),
        Err(StructuralError::EmptyPattern("js.empty-pattern"))
    ));
}

#[test]
fn replay_and_rule_input_order_are_deterministic() {
    const CALL_RULE: StructuralRule = StructuralRule::new(
        "js.console-call",
        StructuralLanguage::JavaScript,
        "console.log($ARG)",
    );
    let first = StructuralRegistry::new(&[EVAL_RULE, CALL_RULE]).unwrap();
    let second = StructuralRegistry::new(&[CALL_RULE, EVAL_RULE]).unwrap();
    let source = b"console.log(eval(value));\neval(other);\n";

    let a = first.scan(&path(), source).unwrap();
    let b = second.scan(&path(), source).unwrap();
    assert_eq!(a, b);
    assert_eq!(a, first.scan(&path(), source).unwrap());
}

#[test]
fn typescript_replay_and_rule_input_order_are_deterministic() {
    const TS_CONSOLE_RULE: StructuralRule = StructuralRule::new(
        "ts.console-call",
        StructuralLanguage::TypeScript,
        "console.log($ARG)",
    );
    let first = StructuralRegistry::new(&[TS_EVAL_RULE, TS_CONSOLE_RULE]).unwrap();
    let second = StructuralRegistry::new(&[TS_CONSOLE_RULE, TS_EVAL_RULE]).unwrap();
    let source = b"const value: string = eval(input);\nconsole.log(value);\n";

    let a = first
        .scan_language(StructuralLanguage::TypeScript, &typescript_path(), source)
        .unwrap();
    let b = second
        .scan_language(StructuralLanguage::TypeScript, &typescript_path(), source)
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(
        a,
        first
            .scan_language(StructuralLanguage::TypeScript, &typescript_path(), source)
            .unwrap()
    );
}
