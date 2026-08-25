//! Bounded Regorus integration for repository/external policy candidates.
//!
//! This module deliberately exposes neither raw Regorus engines nor arbitrary query evaluation.
//! Rust kernel invariants remain outside Rego. A repository policy can only produce a candidate
//! verdict that must still pass through the Rust-owned enforcement boundary.

use std::{
    error::Error,
    fmt,
    num::{NonZeroU32, NonZeroUsize},
    time::Duration,
};

use regorus::utils::limits::ExecutionTimerConfig;
use regorus::{Engine, PolicyLengthConfig};

use crate::Verdict;

/// Maximum accepted Rego source size for one R1 policy module.
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
/// Maximum accepted number of lines for one R1 policy module.
pub const MAX_POLICY_LINES: usize = 2_000;
/// Maximum accepted byte width of one policy source line.
pub const MAX_POLICY_COLUMN_BYTES: usize = 4_096;
/// Maximum accepted JSON bytes for static policy data.
pub const MAX_DATA_BYTES: usize = 256 * 1024;
/// Maximum accepted JSON bytes for one action input.
pub const MAX_INPUT_BYTES: usize = 256 * 1024;
/// Maximum JSON object/array nesting accepted before any JSON parser runs.
pub const MAX_JSON_DEPTH: usize = 32;
/// Maximum validated entrypoint length.
pub const MAX_ENTRYPOINT_BYTES: usize = 256;
/// Engine-specific wall-clock evaluation budget for one policy candidate.
pub const EVALUATION_TIMEOUT: Duration = Duration::from_millis(250);
/// Work-unit interval between Regorus execution-timer checks.
pub const EVALUATION_TIMER_CHECK_INTERVAL: u32 = 64;

const POLICY_PATH: &str = "sentrdel-policy.rego";
const ALLOWED_BUILTIN_CALLS: &[&str] = &["contains", "count", "endswith", "startswith"];

/// Installation-time errors. Invalid policy is never admitted into the runtime policy set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegoPolicyError {
    /// Policy source exceeded the Sentrdel byte cap.
    PolicyTooLarge,
    /// Policy source exceeded the Sentrdel line-count cap.
    TooManyPolicyLines,
    /// At least one policy source line exceeded the Sentrdel column cap.
    PolicyColumnTooLong,
    /// Static data exceeded the Sentrdel byte cap.
    DataTooLarge,
    /// Static data exceeded the Sentrdel JSON-depth cap.
    DataTooDeep,
    /// Static data was not valid JSON.
    MalformedData,
    /// Static data must be a JSON object.
    DataMustBeObject,
    /// Entrypoint was not a bounded `data.<package>.<rule>` path.
    InvalidEntrypoint,
    /// Policy attempted an import outside the deliberately supported R1 subset.
    UnsupportedImport,
    /// Policy used a language feature deliberately excluded from the R1 subset.
    UnsupportedKeyword(&'static str),
    /// Executable policy code used non-ASCII bytes that the bounded lexer will not normalize.
    NonAsciiCode,
    /// Policy called a builtin or helper function outside the tested allowlist.
    UnsupportedCall(String),
    /// Regorus rejected the policy/data while loading.
    EngineLoadRejected,
    /// Regorus could not compile the fixed entrypoint.
    EntrypointCompileRejected,
}

impl fmt::Display for RegoPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyTooLarge => write!(formatter, "policy source exceeds the byte limit"),
            Self::TooManyPolicyLines => write!(formatter, "policy source exceeds the line limit"),
            Self::PolicyColumnTooLong => write!(formatter, "policy source exceeds the column limit"),
            Self::DataTooLarge => write!(formatter, "policy data exceeds the byte limit"),
            Self::DataTooDeep => write!(formatter, "policy data exceeds the JSON depth limit"),
            Self::MalformedData => write!(formatter, "policy data is malformed JSON"),
            Self::DataMustBeObject => write!(formatter, "policy data must be a JSON object"),
            Self::InvalidEntrypoint => write!(formatter, "policy entrypoint is invalid"),
            Self::UnsupportedImport => {
                write!(formatter, "policy import is outside the supported subset")
            }
            Self::UnsupportedKeyword(keyword) => {
                write!(
                    formatter,
                    "policy keyword `{keyword}` is outside the supported subset"
                )
            }
            Self::NonAsciiCode => write!(
                formatter,
                "non-ASCII executable policy code is outside the supported subset"
            ),
            Self::UnsupportedCall(call) => {
                write!(
                    formatter,
                    "policy call `{call}` is outside the supported allowlist"
                )
            }
            Self::EngineLoadRejected => write!(formatter, "policy engine rejected policy or data"),
            Self::EntrypointCompileRejected => {
                write!(formatter, "policy engine rejected the fixed entrypoint")
            }
        }
    }
}

impl Error for RegoPolicyError {}

/// Runtime failure category retained without storing raw policy/input values or engine error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegoFailure {
    /// Action input exceeded the byte cap.
    InputTooLarge,
    /// Action input exceeded the JSON-depth cap.
    InputTooDeep,
    /// Action input was not valid JSON.
    MalformedInput,
    /// Action input was not a JSON object.
    InputMustBeObject,
    /// Regorus rejected or timed out while evaluating the fixed rule.
    EvaluationFailed,
    /// The fixed rule returned something other than `allow`, `ask`, or `deny`.
    InvalidOutput,
}

/// Candidate verdict returned by the bounded repository-policy evaluator.
///
/// Failures are represented as `UNDECIDABLE` by construction. Callers cannot accidentally turn an
/// engine/parser failure into `ALLOW` by using `Result::unwrap_or_default` or a similar fallback.
#[must_use = "repository-policy evaluation must be composed and resolved by the Rust enforcement boundary"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegoEvaluation {
    verdict: Verdict,
    failure: Option<RegoFailure>,
}

impl RegoEvaluation {
    /// Return the repository/external policy candidate verdict.
    pub const fn verdict(self) -> Verdict {
        self.verdict
    }

    /// Return the bounded failure category, if evaluation did not produce a valid candidate.
    pub const fn failure(self) -> Option<RegoFailure> {
        self.failure
    }

    const fn undecidable(failure: RegoFailure) -> Self {
        Self {
            verdict: Verdict::Undecidable,
            failure: Some(failure),
        }
    }

    const fn decided(verdict: Verdict) -> Self {
        Self {
            verdict,
            failure: None,
        }
    }
}

/// Loaded, bounded policy with a fixed prevalidated entrypoint.
///
/// Policy parsing, static-data loading, and entrypoint compilation occur once in [`Self::compile`].
/// Per-action evaluation clones the already prepared engine, sets one bounded input document, and
/// evaluates only the fixed rule. The engine-specific execution timer remains active on the clone.
#[derive(Debug)]
pub struct BoundedRegoPolicy {
    engine: Engine,
    entrypoint: String,
    // Kept as proof that the fixed entrypoint compiled successfully before installation. Hot-path
    // evaluation uses the prepared Engine because Regorus 0.11.0 does not carry an engine-specific
    // ExecutionTimerConfig into CompiledPolicy::eval_with_input.
    _compiled: regorus::CompiledPolicy,
}

impl BoundedRegoPolicy {
    /// Validate and load one bounded Rego v1 policy with optional static JSON data.
    pub fn compile(
        policy_source: &str,
        entrypoint: &str,
        data_json: Option<&str>,
    ) -> Result<Self, RegoPolicyError> {
        validate_policy_source(policy_source)?;
        validate_entrypoint(entrypoint)?;

        if let Some(data) = data_json {
            validate_json_object(data, MAX_DATA_BYTES).map_err(map_data_boundary_error)?;
        }

        let mut engine = Engine::new();
        engine.set_rego_v0(false);
        engine.set_strict_builtin_errors(true);
        engine.set_policy_length_config(PolicyLengthConfig {
            max_col: NonZeroU32::new(MAX_POLICY_COLUMN_BYTES as u32)
                .expect("T023 policy column cap is non-zero"),
            max_file_bytes: NonZeroUsize::new(MAX_POLICY_BYTES)
                .expect("T023 policy byte cap is non-zero"),
            max_lines: NonZeroUsize::new(MAX_POLICY_LINES)
                .expect("T023 policy line cap is non-zero"),
        });
        engine.set_execution_timer_config(ExecutionTimerConfig {
            limit: EVALUATION_TIMEOUT,
            check_interval: NonZeroU32::new(EVALUATION_TIMER_CHECK_INTERVAL)
                .expect("T023 timer check interval is non-zero"),
        });

        engine
            .add_policy(POLICY_PATH.to_owned(), policy_source.to_owned())
            .map_err(|_| RegoPolicyError::EngineLoadRejected)?;

        if let Some(data) = data_json {
            engine
                .add_data_json(data)
                .map_err(|_| RegoPolicyError::EngineLoadRejected)?;
        }

        let compiled_entrypoint: regorus::Rc<str> = entrypoint.into();
        let compiled = engine
            .compile_with_entrypoint(&compiled_entrypoint)
            .map_err(|_| RegoPolicyError::EntrypointCompileRejected)?;

        Ok(Self {
            engine,
            entrypoint: entrypoint.to_owned(),
            _compiled: compiled,
        })
    }

    /// Evaluate one bounded JSON object and return a fail-closed candidate verdict.
    pub fn evaluate_json(&self, input_json: &str) -> RegoEvaluation {
        if let Err(error) = validate_json_object(input_json, MAX_INPUT_BYTES) {
            return RegoEvaluation::undecidable(map_input_boundary_error(error));
        }

        let mut engine = self.engine.clone();
        if engine.set_input_json(input_json).is_err() {
            return RegoEvaluation::undecidable(RegoFailure::EvaluationFailed);
        }

        let value = match engine.eval_rule(self.entrypoint.clone()) {
            Ok(value) => value,
            Err(_) => return RegoEvaluation::undecidable(RegoFailure::EvaluationFailed),
        };
        let output = match value.as_string() {
            Ok(output) => output.as_ref(),
            Err(_) => return RegoEvaluation::undecidable(RegoFailure::InvalidOutput),
        };

        match output {
            "allow" => RegoEvaluation::decided(Verdict::Allow),
            "ask" => RegoEvaluation::decided(Verdict::Ask),
            "deny" => RegoEvaluation::decided(Verdict::Deny),
            _ => RegoEvaluation::undecidable(RegoFailure::InvalidOutput),
        }
    }

    /// Return the exact fixed rule path bound at installation time.
    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonBoundaryError {
    TooLarge,
    TooDeep,
    Malformed,
    NotObject,
}

fn map_data_boundary_error(error: JsonBoundaryError) -> RegoPolicyError {
    match error {
        JsonBoundaryError::TooLarge => RegoPolicyError::DataTooLarge,
        JsonBoundaryError::TooDeep => RegoPolicyError::DataTooDeep,
        JsonBoundaryError::Malformed => RegoPolicyError::MalformedData,
        JsonBoundaryError::NotObject => RegoPolicyError::DataMustBeObject,
    }
}

fn map_input_boundary_error(error: JsonBoundaryError) -> RegoFailure {
    match error {
        JsonBoundaryError::TooLarge => RegoFailure::InputTooLarge,
        JsonBoundaryError::TooDeep => RegoFailure::InputTooDeep,
        JsonBoundaryError::Malformed => RegoFailure::MalformedInput,
        JsonBoundaryError::NotObject => RegoFailure::InputMustBeObject,
    }
}

fn validate_json_object(raw: &str, max_bytes: usize) -> Result<(), JsonBoundaryError> {
    if raw.len() > max_bytes {
        return Err(JsonBoundaryError::TooLarge);
    }
    if exceeds_json_depth(raw, MAX_JSON_DEPTH) {
        return Err(JsonBoundaryError::TooDeep);
    }

    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| JsonBoundaryError::Malformed)?;
    if !value.is_object() {
        return Err(JsonBoundaryError::NotObject);
    }
    Ok(())
}

fn exceeds_json_depth(raw: &str, max_depth: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for byte in raw.bytes() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > max_depth {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    false
}

fn validate_entrypoint(entrypoint: &str) -> Result<(), RegoPolicyError> {
    if entrypoint.is_empty() || entrypoint.len() > MAX_ENTRYPOINT_BYTES {
        return Err(RegoPolicyError::InvalidEntrypoint);
    }

    let parts = entrypoint.split('.').collect::<Vec<_>>();
    if parts.len() < 3 || parts.first().copied() != Some("data") {
        return Err(RegoPolicyError::InvalidEntrypoint);
    }
    if parts.iter().any(|part| !is_identifier(part)) {
        return Err(RegoPolicyError::InvalidEntrypoint);
    }
    Ok(())
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !is_identifier_start(first) {
        return false;
    }
    bytes.all(is_identifier_continue)
}

fn validate_policy_source(source: &str) -> Result<(), RegoPolicyError> {
    if source.len() > MAX_POLICY_BYTES {
        return Err(RegoPolicyError::PolicyTooLarge);
    }

    let mut line_count = 0usize;
    for line in source.lines() {
        line_count += 1;
        if line.len() > MAX_POLICY_COLUMN_BYTES {
            return Err(RegoPolicyError::PolicyColumnTooLong);
        }
    }
    if line_count > MAX_POLICY_LINES {
        return Err(RegoPolicyError::TooManyPolicyLines);
    }

    let masked = mask_literals_and_comments(source)?;
    validate_imports(&masked)?;

    for (token, error_name) in [
        ("with", "with"),
        ("__target__", "__target__"),
        (";", "semicolon"),
    ] {
        let present = if token == ";" {
            masked.contains(token)
        } else {
            contains_identifier_token(&masked, token)
        };
        if present {
            return Err(RegoPolicyError::UnsupportedKeyword(error_name));
        }
    }

    for call in function_calls(&masked) {
        if !ALLOWED_BUILTIN_CALLS.contains(&call.as_str()) {
            return Err(RegoPolicyError::UnsupportedCall(call));
        }
    }

    Ok(())
}

fn validate_imports(masked: &str) -> Result<(), RegoPolicyError> {
    for line in masked.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("import") else {
            continue;
        };
        if rest.is_empty() || !rest.as_bytes()[0].is_ascii_whitespace() {
            continue;
        }
        if rest.trim() != "rego.v1" {
            return Err(RegoPolicyError::UnsupportedImport);
        }
    }
    Ok(())
}

fn mask_literals_and_comments(source: &str) -> Result<String, RegoPolicyError> {
    #[derive(Clone, Copy)]
    enum Mode {
        Code,
        Quoted,
        Raw,
        Comment,
    }

    let mut mode = Mode::Code;
    let mut escaped = false;
    let mut masked = String::with_capacity(source.len());

    for byte in source.bytes() {
        match mode {
            Mode::Code => match byte {
                b'#' => {
                    mode = Mode::Comment;
                    masked.push(' ');
                }
                b'"' => {
                    mode = Mode::Quoted;
                    escaped = false;
                    masked.push(' ');
                }
                b'`' => {
                    mode = Mode::Raw;
                    masked.push(' ');
                }
                b'\n' => masked.push('\n'),
                byte if byte.is_ascii() => masked.push(byte as char),
                _ => return Err(RegoPolicyError::NonAsciiCode),
            },
            Mode::Quoted => {
                masked.push(if byte == b'\n' { '\n' } else { ' ' });
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    mode = Mode::Code;
                }
            }
            Mode::Raw => {
                masked.push(if byte == b'\n' { '\n' } else { ' ' });
                if byte == b'`' {
                    mode = Mode::Code;
                }
            }
            Mode::Comment => {
                if byte == b'\n' {
                    masked.push('\n');
                    mode = Mode::Code;
                } else {
                    masked.push(' ');
                }
            }
        }
    }

    Ok(masked)
}

fn contains_identifier_token(source: &str, wanted: &str) -> bool {
    identifier_tokens(source).any(|token| token == wanted)
}

fn identifier_tokens(source: &str) -> impl Iterator<Item = &str> {
    source
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
}

fn function_calls(source: &str) -> Vec<String> {
    let bytes = source.as_bytes();
    let mut calls = Vec::new();
    let mut index = 0usize;

    while index < bytes.len() {
        if !is_identifier_start(bytes[index]) {
            index += 1;
            continue;
        }

        let start = index;
        index += 1;
        while index < bytes.len()
            && (is_identifier_continue(bytes[index]) || bytes[index] == b'.')
        {
            index += 1;
        }
        let end = index;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'(' {
            let token = &source[start..end];
            if !token.ends_with('.') {
                calls.push(token.to_owned());
            }
        }
    }

    calls
}

const fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

const fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRYPOINT: &str = "data.sentrdel.t023.decision";
    const SIMPLE_POLICY: &str = r#"
package sentrdel.t023
import rego.v1

default decision := "ask"
decision := "allow" if input.action == "read"
decision := "deny" if input.action == "delete"
"#;

    #[test]
    fn bounded_policy_returns_only_explicit_candidate_strings() {
        let policy = BoundedRegoPolicy::compile(SIMPLE_POLICY, ENTRYPOINT, None)
            .expect("valid bounded policy");

        assert_eq!(
            policy.evaluate_json(r#"{"action":"read"}"#),
            RegoEvaluation::decided(Verdict::Allow)
        );
        assert_eq!(
            policy.evaluate_json(r#"{"action":"delete"}"#),
            RegoEvaluation::decided(Verdict::Deny)
        );
        assert_eq!(
            policy.evaluate_json(r#"{"action":"other"}"#),
            RegoEvaluation::decided(Verdict::Ask)
        );
    }

    #[test]
    fn tested_allowlist_builtin_is_accepted() {
        let source = r#"
package sentrdel.t023
import rego.v1

decision := "allow" if count(input.items) > 0
default decision := "deny"
"#;
        let policy = BoundedRegoPolicy::compile(source, ENTRYPOINT, None)
            .expect("count is in the T023 builtin allowlist");
        assert_eq!(
            policy.evaluate_json(r#"{"items":["x"]}"#).verdict(),
            Verdict::Allow
        );
    }

    #[test]
    fn disallowed_capability_calls_are_rejected_before_engine_load() {
        for call in ["http.send", "net.lookup_ip_addr", "time.now_ns", "print"] {
            let source = format!(
                "package sentrdel.t023\nimport rego.v1\ndecision := {call}({{}})\n"
            );
            assert_eq!(
                BoundedRegoPolicy::compile(&source, ENTRYPOINT, None)
                    .expect_err("unqualified call must be rejected"),
                RegoPolicyError::UnsupportedCall(call.to_owned())
            );
        }
    }

    #[test]
    fn imports_with_targets_and_semicolons_are_rejected() {
        assert_eq!(
            BoundedRegoPolicy::compile(
                "package sentrdel.t023\nimport data.external\ndecision := \"allow\"\n",
                ENTRYPOINT,
                None,
            )
            .expect_err("repository data import is outside the subset"),
            RegoPolicyError::UnsupportedImport
        );
        assert_eq!(
            BoundedRegoPolicy::compile(
                "package sentrdel.t023\nimport rego.v1\ndecision := input.x with input.x as true\n",
                ENTRYPOINT,
                None,
            )
            .expect_err("with is deliberately excluded"),
            RegoPolicyError::UnsupportedKeyword("with")
        );
        assert_eq!(
            BoundedRegoPolicy::compile(
                "package sentrdel.t023\nimport rego.v1\n__target__ := `target.example`\ndecision := \"allow\"\n",
                ENTRYPOINT,
                None,
            )
            .expect_err("targets are deliberately excluded"),
            RegoPolicyError::UnsupportedKeyword("__target__")
        );
        assert_eq!(
            BoundedRegoPolicy::compile(
                "package sentrdel.t023; import data.external\ndecision := \"allow\"\n",
                ENTRYPOINT,
                None,
            )
            .expect_err("statement compaction must not evade import validation"),
            RegoPolicyError::UnsupportedKeyword("semicolon")
        );
    }

    #[test]
    fn non_ascii_code_is_rejected_but_literals_and_comments_remain_valid() {
        assert_eq!(
            BoundedRegoPolicy::compile(
                "package sentrdel.t023\nimport rego.v1\ndécision := \"allow\"\n",
                ENTRYPOINT,
                None,
            )
            .expect_err("non-ASCII executable identifiers must fail closed"),
            RegoPolicyError::NonAsciiCode
        );

        let source = r#"
package sentrdel.t023
import rego.v1
# Unicode in a comment: أهلاً

decision := "allow" if input.note == "مرحباً"
default decision := "deny"
"#;
        BoundedRegoPolicy::compile(source, ENTRYPOINT, None)
            .expect("Unicode data inside comments/literals is not executable code");
    }

    #[test]
    fn comments_and_literals_cannot_fake_disallowed_calls() {
        let source = r#"
package sentrdel.t023
import rego.v1
# http.send({}) and with are comments, not capabilities.
decision := "allow" if input.note == "print(\"x\") with http.send({})"
default decision := "deny"
"#;
        BoundedRegoPolicy::compile(source, ENTRYPOINT, None)
            .expect("masked literals/comments must not create false capability matches");
    }

    #[test]
    fn invalid_entrypoint_is_rejected_before_installation() {
        for entrypoint in ["decision", "data.onlypackage", "data.bad-name.rule", "input.x.y"] {
            assert_eq!(
                BoundedRegoPolicy::compile(SIMPLE_POLICY, entrypoint, None)
                    .expect_err("invalid entrypoint must fail"),
                RegoPolicyError::InvalidEntrypoint
            );
        }
        assert_eq!(
            BoundedRegoPolicy::compile(SIMPLE_POLICY, "data.sentrdel.t023.missing", None)
                .expect_err("missing fixed entrypoint must fail compilation"),
            RegoPolicyError::EntrypointCompileRejected
        );
    }

    #[test]
    fn policy_length_limits_fail_before_engine_load() {
        let oversized = "#".repeat(MAX_POLICY_BYTES + 1);
        assert_eq!(
            BoundedRegoPolicy::compile(&oversized, ENTRYPOINT, None)
                .expect_err("oversized source must fail"),
            RegoPolicyError::PolicyTooLarge
        );

        let too_many_lines = "#\n".repeat(MAX_POLICY_LINES + 1);
        assert_eq!(
            BoundedRegoPolicy::compile(&too_many_lines, ENTRYPOINT, None)
                .expect_err("too many lines must fail"),
            RegoPolicyError::TooManyPolicyLines
        );

        let long_column = format!(
            "package sentrdel.t023\n#{}\n",
            "x".repeat(MAX_POLICY_COLUMN_BYTES)
        );
        assert_eq!(
            BoundedRegoPolicy::compile(&long_column, ENTRYPOINT, None)
                .expect_err("long source line must fail"),
            RegoPolicyError::PolicyColumnTooLong
        );
    }

    #[test]
    fn deep_or_oversized_runtime_input_is_undecidable_not_allow() {
        let policy = BoundedRegoPolicy::compile(SIMPLE_POLICY, ENTRYPOINT, None)
            .expect("valid bounded policy");

        let mut deep = String::new();
        for _ in 0..MAX_JSON_DEPTH {
            deep.push_str("{\"x\":");
        }
        deep.push_str("{}");
        for _ in 0..MAX_JSON_DEPTH {
            deep.push('}');
        }
        assert_eq!(
            policy.evaluate_json(&deep),
            RegoEvaluation::undecidable(RegoFailure::InputTooDeep)
        );

        let oversized = format!("{{\"x\":\"{}\"}}", "x".repeat(MAX_INPUT_BYTES));
        assert_eq!(
            policy.evaluate_json(&oversized),
            RegoEvaluation::undecidable(RegoFailure::InputTooLarge)
        );
    }

    #[test]
    fn malformed_or_non_object_input_is_undecidable() {
        let policy = BoundedRegoPolicy::compile(SIMPLE_POLICY, ENTRYPOINT, None)
            .expect("valid bounded policy");
        assert_eq!(
            policy.evaluate_json("{"),
            RegoEvaluation::undecidable(RegoFailure::MalformedInput)
        );
        assert_eq!(
            policy.evaluate_json("[]"),
            RegoEvaluation::undecidable(RegoFailure::InputMustBeObject)
        );
    }

    #[test]
    fn deep_static_data_fails_before_regorus_parser() {
        let mut deep = String::new();
        for _ in 0..MAX_JSON_DEPTH {
            deep.push_str("{\"x\":");
        }
        deep.push_str("{}");
        for _ in 0..MAX_JSON_DEPTH {
            deep.push('}');
        }
        assert_eq!(
            BoundedRegoPolicy::compile(SIMPLE_POLICY, ENTRYPOINT, Some(&deep))
                .expect_err("deep static data must fail before Regorus"),
            RegoPolicyError::DataTooDeep
        );
    }

    #[test]
    fn invalid_rule_output_is_undecidable() {
        let source = "package sentrdel.t023\nimport rego.v1\ndecision := true\n";
        let policy = BoundedRegoPolicy::compile(source, ENTRYPOINT, None)
            .expect("boolean output policy still compiles");
        assert_eq!(
            policy.evaluate_json("{}"),
            RegoEvaluation::undecidable(RegoFailure::InvalidOutput)
        );
    }

    #[test]
    fn engine_evaluation_error_is_undecidable() {
        let source = r#"
package sentrdel.t023
import rego.v1

decision := "allow" if 1 / input.divisor > 0
default decision := "deny"
"#;
        let policy = BoundedRegoPolicy::compile(source, ENTRYPOINT, None)
            .expect("policy should compile");
        let result = policy.evaluate_json(r#"{"divisor":0}"#);
        assert_eq!(result.verdict(), Verdict::Undecidable);
        assert_eq!(result.failure(), Some(RegoFailure::EvaluationFailed));
    }

    #[test]
    fn json_depth_scanner_ignores_delimiters_inside_strings() {
        let value = r#"{"x":"[[[[{{{{","y":{"z":1}}}"#;
        assert!(!exceeds_json_depth(value, 2));
    }
}
