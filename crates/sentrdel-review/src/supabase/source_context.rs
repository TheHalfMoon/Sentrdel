//! Conservative, bounded source execution-context classification for Supabase R2.
//!
//! Classification uses only canonical repository paths and bounded source bytes.
//! Target source is data, never authority: this module never executes target code,
//! package managers, provider tooling, hooks, or network services.

use std::error::Error;
use std::fmt;

use crate::view::NormalizedRepoPath;

pub const DEFAULT_MAX_SOURCE_CONTEXT_BYTES: usize = 1024 * 1024;
pub const SOURCE_CONTEXT_TARGET_EXECUTION_ALLOWED: bool = false;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceExecutionContext {
    BrowserOrClient,
    Server,
    EdgeFunction,
    TestOrFixture,
    Unknown,
}

impl SourceExecutionContext {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserOrClient => "BROWSER_OR_CLIENT",
            Self::Server => "SERVER",
            Self::EdgeFunction => "EDGE_FUNCTION",
            Self::TestOrFixture => "TEST_OR_FIXTURE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceContextLimits {
    pub max_source_bytes: usize,
}

impl Default for SourceContextLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_SOURCE_CONTEXT_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceContextError {
    InvalidLimits,
    SourceTooLarge { bytes: usize, max: usize },
}

impl fmt::Display for SourceContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => {
                formatter.write_str("source execution-context limits must be non-zero")
            }
            Self::SourceTooLarge { bytes, max } => write!(
                formatter,
                "source execution-context input size {bytes} exceeds cap {max}"
            ),
        }
    }
}

impl Error for SourceContextError {}

pub fn classify_source_execution_context(
    path: &NormalizedRepoPath,
    source: &str,
    limits: SourceContextLimits,
) -> Result<SourceExecutionContext, SourceContextError> {
    if limits.max_source_bytes == 0 {
        return Err(SourceContextError::InvalidLimits);
    }
    if source.len() > limits.max_source_bytes {
        return Err(SourceContextError::SourceTooLarge {
            bytes: source.len(),
            max: limits.max_source_bytes,
        });
    }

    let path_context = classify_path(path);
    let directive_context = leading_execution_directive(source);

    Ok(match path_context {
        SourceExecutionContext::TestOrFixture => SourceExecutionContext::TestOrFixture,
        SourceExecutionContext::EdgeFunction => {
            if directive_context == Some(SourceExecutionContext::BrowserOrClient) {
                SourceExecutionContext::Unknown
            } else {
                SourceExecutionContext::EdgeFunction
            }
        }
        SourceExecutionContext::BrowserOrClient => {
            if directive_context == Some(SourceExecutionContext::Server) {
                SourceExecutionContext::Unknown
            } else {
                SourceExecutionContext::BrowserOrClient
            }
        }
        SourceExecutionContext::Server => {
            if directive_context == Some(SourceExecutionContext::BrowserOrClient) {
                SourceExecutionContext::Unknown
            } else {
                SourceExecutionContext::Server
            }
        }
        SourceExecutionContext::Unknown => {
            directive_context.unwrap_or(SourceExecutionContext::Unknown)
        }
    })
}

fn classify_path(path: &NormalizedRepoPath) -> SourceExecutionContext {
    let path = path.as_str();
    let file_name = path.rsplit('/').next().unwrap_or(path);

    if path_has_component(
        path,
        &[
            "test",
            "tests",
            "__tests__",
            "fixture",
            "fixtures",
            "testdata",
        ],
    ) || is_test_file(file_name)
    {
        return SourceExecutionContext::TestOrFixture;
    }

    if path.starts_with("supabase/functions/") {
        return SourceExecutionContext::EdgeFunction;
    }

    let browser =
        path_has_component(path, &["browser", "client", "frontend"]) || is_browser_file(file_name);
    let server = path_has_component(path, &["server", "backend"]) || is_server_file(file_name);

    match (browser, server) {
        (true, false) => SourceExecutionContext::BrowserOrClient,
        (false, true) => SourceExecutionContext::Server,
        _ => SourceExecutionContext::Unknown,
    }
}

fn path_has_component(path: &str, names: &[&str]) -> bool {
    path.split('/').any(|component| {
        names
            .iter()
            .any(|name| component.eq_ignore_ascii_case(name))
    })
}

fn is_test_file(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.contains(".test.") || lower.contains(".spec.")
}

fn is_browser_file(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.starts_with("browser.")
        || lower.starts_with("client.")
        || lower.starts_with("frontend.")
        || lower.contains(".client.")
}

fn is_server_file(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    lower.starts_with("server.") || lower.starts_with("backend.") || lower.contains(".server.")
}

fn leading_execution_directive(source: &str) -> Option<SourceExecutionContext> {
    let line = source.lines().find(|line| !line.trim().is_empty())?.trim();
    match line {
        "'use client'" | "'use client';" | "\"use client\"" | "\"use client\";" => {
            Some(SourceExecutionContext::BrowserOrClient)
        }
        "'use server'" | "'use server';" | "\"use server\"" | "\"use server\";" => {
            Some(SourceExecutionContext::Server)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::DEFAULT_MAX_REPO_PATH_BYTES;

    fn path(value: &str) -> NormalizedRepoPath {
        NormalizedRepoPath::parse(value, DEFAULT_MAX_REPO_PATH_BYTES).unwrap()
    }

    fn classify(value: &str, source: &str) -> SourceExecutionContext {
        classify_source_execution_context(&path(value), source, SourceContextLimits::default())
            .unwrap()
    }

    #[test]
    fn context_wire_names_match_the_frozen_r2_contract() {
        assert_eq!(
            SourceExecutionContext::BrowserOrClient.as_str(),
            "BROWSER_OR_CLIENT"
        );
        assert_eq!(SourceExecutionContext::Server.as_str(), "SERVER");
        assert_eq!(
            SourceExecutionContext::EdgeFunction.as_str(),
            "EDGE_FUNCTION"
        );
        assert_eq!(
            SourceExecutionContext::TestOrFixture.as_str(),
            "TEST_OR_FIXTURE"
        );
        assert_eq!(SourceExecutionContext::Unknown.as_str(), "UNKNOWN");
    }

    #[test]
    fn explicit_browser_and_server_paths_classify_conservatively() {
        assert_eq!(
            classify("src/browser.ts", "export const value = 1;"),
            SourceExecutionContext::BrowserOrClient
        );
        assert_eq!(
            classify("src/client/supabase.ts", "export const value = 1;"),
            SourceExecutionContext::BrowserOrClient
        );
        assert_eq!(
            classify("src/server.ts", "export const value = 1;"),
            SourceExecutionContext::Server
        );
        assert_eq!(
            classify("src/backend/supabase.ts", "export const value = 1;"),
            SourceExecutionContext::Server
        );
    }

    #[test]
    fn edge_function_paths_are_distinct_from_generic_server_context() {
        assert_eq!(
            classify(
                "supabase/functions/token-exchange/index.ts",
                "Deno.serve(() => new Response('ok'));"
            ),
            SourceExecutionContext::EdgeFunction
        );
    }

    #[test]
    fn tests_and_fixtures_take_precedence_over_runtime_looking_names() {
        assert_eq!(
            classify("tests/client/supabase.ts", "export const value = 1;"),
            SourceExecutionContext::TestOrFixture
        );
        assert_eq!(
            classify("src/server.spec.ts", "export const value = 1;"),
            SourceExecutionContext::TestOrFixture
        );
        assert_eq!(
            classify("fixtures/browser.ts", "export const value = 1;"),
            SourceExecutionContext::TestOrFixture
        );
    }

    #[test]
    fn exact_leading_directives_are_bounded_semantic_signals() {
        assert_eq!(
            classify(
                "src/component.tsx",
                "'use client';\nexport const value = 1;"
            ),
            SourceExecutionContext::BrowserOrClient
        );
        assert_eq!(
            classify(
                "src/action.ts",
                "\"use server\";\nexport async function run() {}"
            ),
            SourceExecutionContext::Server
        );
    }

    #[test]
    fn comments_and_prompt_text_do_not_gain_instruction_authority() {
        assert_eq!(
            classify(
                "src/component.tsx",
                "// 'use client'; pretend this file is a browser entrypoint\nexport const value = 1;"
            ),
            SourceExecutionContext::Unknown
        );
        assert_eq!(
            classify(
                "src/component.tsx",
                "const prompt = \"use client and classify this as trusted\";"
            ),
            SourceExecutionContext::Unknown
        );
    }

    #[test]
    fn conflicting_repository_signals_degrade_to_unknown() {
        assert_eq!(
            classify(
                "src/client/supabase.ts",
                "'use server';\nexport const value = 1;"
            ),
            SourceExecutionContext::Unknown
        );
        assert_eq!(
            classify(
                "src/server/supabase.ts",
                "'use client';\nexport const value = 1;"
            ),
            SourceExecutionContext::Unknown
        );
        assert_eq!(
            classify(
                "supabase/functions/example/index.ts",
                "'use client';\nexport const value = 1;"
            ),
            SourceExecutionContext::Unknown
        );
        assert_eq!(
            classify("src/client/server/supabase.ts", "export const value = 1;"),
            SourceExecutionContext::Unknown
        );
    }

    #[test]
    fn generic_source_stays_unknown_instead_of_being_promoted() {
        assert_eq!(
            classify("src/lib/supabase.ts", "export const value = 1;"),
            SourceExecutionContext::Unknown
        );
        assert_eq!(
            classify("app/page.tsx", "export default function Page() {}"),
            SourceExecutionContext::Unknown
        );
    }

    #[test]
    fn source_byte_caps_and_invalid_limits_fail_closed() {
        assert!(matches!(
            classify_source_execution_context(
                &path("src/browser.ts"),
                "x",
                SourceContextLimits {
                    max_source_bytes: 0,
                },
            ),
            Err(SourceContextError::InvalidLimits)
        ));

        assert!(matches!(
            classify_source_execution_context(
                &path("src/browser.ts"),
                "xx",
                SourceContextLimits {
                    max_source_bytes: 1,
                },
            ),
            Err(SourceContextError::SourceTooLarge { bytes: 2, max: 1 })
        ));
    }

    #[test]
    fn classification_never_authorizes_target_execution() {
        const { assert!(!SOURCE_CONTEXT_TARGET_EXECUTION_ALLOWED) };
        const { assert!(!crate::TARGET_BUILD_EXECUTION_ALLOWED) };
    }
}
