//! Bounded SQL lexical scanning for the Supabase R2 static provider.
//!
//! SQL is untrusted repository text. This scanner only identifies lexical
//! tokens and deterministic statement boundaries. It never executes SQL and it
//! deliberately leaves statement semantics to later R2 tasks.

use std::error::Error;
use std::fmt;

pub const DEFAULT_MAX_SQL_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_SQL_STATEMENTS: usize = 4_096;
pub const DEFAULT_MAX_SQL_TOKENS: usize = 262_144;
pub const DEFAULT_MAX_SQL_NESTING: usize = 128;
pub const DEFAULT_MAX_SQL_DIAGNOSTICS: usize = 128;
pub const DEFAULT_MAX_DOLLAR_TAG_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlScanLimits {
    pub max_bytes: usize,
    pub max_statements: usize,
    pub max_tokens: usize,
    pub max_nesting: usize,
    pub max_diagnostics: usize,
    pub max_dollar_tag_bytes: usize,
}

impl Default for SqlScanLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_SQL_BYTES,
            max_statements: DEFAULT_MAX_SQL_STATEMENTS,
            max_tokens: DEFAULT_MAX_SQL_TOKENS,
            max_nesting: DEFAULT_MAX_SQL_NESTING,
            max_diagnostics: DEFAULT_MAX_SQL_DIAGNOSTICS,
            max_dollar_tag_bytes: DEFAULT_MAX_DOLLAR_TAG_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlTokenKind {
    Word,
    StringLiteral,
    QuotedIdentifier,
    DollarQuoted,
    Symbol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlToken {
    pub kind: SqlTokenKind,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlStatementSpan {
    pub start_byte: usize,
    pub end_byte: usize,
    pub token_start: usize,
    pub token_end: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlDiagnosticKind {
    UnexpectedClosingParenthesis,
    UnclosedParenthesis,
    UnterminatedSingleQuote,
    UnterminatedQuotedIdentifier,
    UnterminatedDollarQuote,
    UnterminatedBlockComment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlDiagnostic {
    pub kind: SqlDiagnosticKind,
    pub byte_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlScan {
    pub statements: Vec<SqlStatementSpan>,
    pub tokens: Vec<SqlToken>,
    pub diagnostics: Vec<SqlDiagnostic>,
}

impl SqlScan {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.diagnostics.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlScanError {
    InvalidLimits,
    InputTooLarge { size: usize, max: usize },
    TooManyStatements { max: usize },
    TooManyTokens { max: usize },
    NestingLimitExceeded { max: usize, byte_offset: usize },
    TooManyDiagnostics { max: usize },
    DollarTagTooLarge { max: usize, byte_offset: usize },
}

impl fmt::Display for SqlScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("SQL scan limits must be non-zero"),
            Self::InputTooLarge { size, max } => {
                write!(formatter, "SQL input is {size} bytes and exceeds cap {max}")
            }
            Self::TooManyStatements { max } => {
                write!(formatter, "SQL statement count exceeds cap {max}")
            }
            Self::TooManyTokens { max } => write!(formatter, "SQL token count exceeds cap {max}"),
            Self::NestingLimitExceeded { max, byte_offset } => write!(
                formatter,
                "SQL nesting exceeds cap {max} at byte offset {byte_offset}"
            ),
            Self::TooManyDiagnostics { max } => {
                write!(formatter, "SQL diagnostic count exceeds cap {max}")
            }
            Self::DollarTagTooLarge { max, byte_offset } => write!(
                formatter,
                "SQL dollar-quote tag exceeds cap {max} at byte offset {byte_offset}"
            ),
        }
    }
}

impl Error for SqlScanError {}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LexState {
    Normal,
    SingleQuote { start: usize },
    QuotedIdentifier { start: usize },
    DollarQuote { start: usize, delimiter: Vec<u8> },
    LineComment,
    BlockComment { start: usize, depth: usize },
}

pub fn scan_sql(input: &str, limits: SqlScanLimits) -> Result<SqlScan, SqlScanError> {
    validate_limits(limits)?;
    if input.len() > limits.max_bytes {
        return Err(SqlScanError::InputTooLarge {
            size: input.len(),
            max: limits.max_bytes,
        });
    }

    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut statements = Vec::new();
    let mut diagnostics = Vec::new();
    let mut state = LexState::Normal;
    let mut paren_depth = 0_usize;
    let mut paren_open_offset = None;
    let mut word_start = None;
    let mut statement_start = 0_usize;
    let mut statement_token_start = 0_usize;
    let mut has_statement_content = false;
    let mut index = 0_usize;

    while index < bytes.len() {
        match &mut state {
            LexState::Normal => {
                if bytes[index].is_ascii_whitespace() {
                    finish_word(&mut tokens, &mut word_start, index);
                    index += 1;
                    continue;
                }

                if starts_with(bytes, index, b"--") {
                    finish_word(&mut tokens, &mut word_start, index);
                    state = LexState::LineComment;
                    index += 2;
                    continue;
                }

                if starts_with(bytes, index, b"/*") {
                    finish_word(&mut tokens, &mut word_start, index);
                    bump_nesting(1, limits, index)?;
                    state = LexState::BlockComment {
                        start: index,
                        depth: 1,
                    };
                    index += 2;
                    continue;
                }

                match bytes[index] {
                    b'\'' => {
                        finish_word(&mut tokens, &mut word_start, index);
                        bump_token(&tokens, limits)?;
                        has_statement_content = true;
                        state = LexState::SingleQuote { start: index };
                        index += 1;
                    }
                    b'"' => {
                        finish_word(&mut tokens, &mut word_start, index);
                        bump_token(&tokens, limits)?;
                        has_statement_content = true;
                        state = LexState::QuotedIdentifier { start: index };
                        index += 1;
                    }
                    b'$' => {
                        if let Some(delimiter) =
                            dollar_delimiter(bytes, index, limits.max_dollar_tag_bytes)?
                        {
                            finish_word(&mut tokens, &mut word_start, index);
                            bump_token(&tokens, limits)?;
                            has_statement_content = true;
                            let delimiter = delimiter.to_vec();
                            index += delimiter.len();
                            state = LexState::DollarQuote {
                                start: index - delimiter.len(),
                                delimiter,
                            };
                        } else {
                            start_word(
                                &tokens,
                                &mut word_start,
                                index,
                                &mut has_statement_content,
                                limits,
                            )?;
                            index += 1;
                        }
                    }
                    b'(' => {
                        finish_word(&mut tokens, &mut word_start, index);
                        push_symbol(&mut tokens, index, limits)?;
                        has_statement_content = true;
                        paren_depth = paren_depth.saturating_add(1);
                        bump_nesting(paren_depth, limits, index)?;
                        paren_open_offset.get_or_insert(index);
                        index += 1;
                    }
                    b')' => {
                        finish_word(&mut tokens, &mut word_start, index);
                        push_symbol(&mut tokens, index, limits)?;
                        has_statement_content = true;
                        if paren_depth == 0 {
                            push_diagnostic(
                                &mut diagnostics,
                                SqlDiagnosticKind::UnexpectedClosingParenthesis,
                                index,
                                limits,
                            )?;
                        } else {
                            paren_depth -= 1;
                            if paren_depth == 0 {
                                paren_open_offset = None;
                            }
                        }
                        index += 1;
                    }
                    b';' if paren_depth == 0 => {
                        finish_word(&mut tokens, &mut word_start, index);
                        if has_statement_content {
                            push_statement(
                                &mut statements,
                                input,
                                statement_start,
                                index,
                                statement_token_start,
                                tokens.len(),
                                limits,
                            )?;
                        }
                        statement_start = index + 1;
                        statement_token_start = tokens.len();
                        has_statement_content = false;
                        index += 1;
                    }
                    byte if is_symbol(byte) => {
                        finish_word(&mut tokens, &mut word_start, index);
                        push_symbol(&mut tokens, index, limits)?;
                        has_statement_content = true;
                        index += 1;
                    }
                    _ => {
                        start_word(
                            &tokens,
                            &mut word_start,
                            index,
                            &mut has_statement_content,
                            limits,
                        )?;
                        index += 1;
                    }
                }
            }
            LexState::SingleQuote { start } => {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    index += 2;
                } else if bytes[index] == b'\'' {
                    if index + 1 < bytes.len() && bytes[index + 1] == b'\'' {
                        index += 2;
                    } else {
                        tokens.push(SqlToken {
                            kind: SqlTokenKind::StringLiteral,
                            start_byte: *start,
                            end_byte: index + 1,
                        });
                        state = LexState::Normal;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            LexState::QuotedIdentifier { start } => {
                if bytes[index] == b'"' {
                    if index + 1 < bytes.len() && bytes[index + 1] == b'"' {
                        index += 2;
                    } else {
                        tokens.push(SqlToken {
                            kind: SqlTokenKind::QuotedIdentifier,
                            start_byte: *start,
                            end_byte: index + 1,
                        });
                        state = LexState::Normal;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            LexState::DollarQuote { start, delimiter } => {
                if starts_with(bytes, index, delimiter) {
                    tokens.push(SqlToken {
                        kind: SqlTokenKind::DollarQuoted,
                        start_byte: *start,
                        end_byte: index + delimiter.len(),
                    });
                    index += delimiter.len();
                    state = LexState::Normal;
                } else {
                    index += 1;
                }
            }
            LexState::LineComment => {
                if bytes[index] == b'\n' {
                    state = LexState::Normal;
                }
                index += 1;
            }
            LexState::BlockComment { start: _, depth } => {
                if starts_with(bytes, index, b"/*") {
                    *depth = depth.saturating_add(1);
                    bump_nesting(*depth, limits, index)?;
                    index += 2;
                } else if starts_with(bytes, index, b"*/") {
                    *depth -= 1;
                    index += 2;
                    if *depth == 0 {
                        state = LexState::Normal;
                    }
                } else {
                    index += 1;
                }
            }
        }
    }

    finish_word(&mut tokens, &mut word_start, bytes.len());
    match state {
        LexState::Normal | LexState::LineComment => {}
        LexState::SingleQuote { start } => {
            push_diagnostic(
                &mut diagnostics,
                SqlDiagnosticKind::UnterminatedSingleQuote,
                start,
                limits,
            )?;
            tokens.push(SqlToken {
                kind: SqlTokenKind::StringLiteral,
                start_byte: start,
                end_byte: bytes.len(),
            });
        }
        LexState::QuotedIdentifier { start } => {
            push_diagnostic(
                &mut diagnostics,
                SqlDiagnosticKind::UnterminatedQuotedIdentifier,
                start,
                limits,
            )?;
            tokens.push(SqlToken {
                kind: SqlTokenKind::QuotedIdentifier,
                start_byte: start,
                end_byte: bytes.len(),
            });
        }
        LexState::DollarQuote { start, .. } => {
            push_diagnostic(
                &mut diagnostics,
                SqlDiagnosticKind::UnterminatedDollarQuote,
                start,
                limits,
            )?;
            tokens.push(SqlToken {
                kind: SqlTokenKind::DollarQuoted,
                start_byte: start,
                end_byte: bytes.len(),
            });
        }
        LexState::BlockComment { start, .. } => {
            push_diagnostic(
                &mut diagnostics,
                SqlDiagnosticKind::UnterminatedBlockComment,
                start,
                limits,
            )?;
        }
    }

    if paren_depth > 0 {
        push_diagnostic(
            &mut diagnostics,
            SqlDiagnosticKind::UnclosedParenthesis,
            paren_open_offset.unwrap_or(bytes.len()),
            limits,
        )?;
    }

    if has_statement_content {
        push_statement(
            &mut statements,
            input,
            statement_start,
            bytes.len(),
            statement_token_start,
            tokens.len(),
            limits,
        )?;
    }

    Ok(SqlScan {
        statements,
        tokens,
        diagnostics,
    })
}

fn validate_limits(limits: SqlScanLimits) -> Result<(), SqlScanError> {
    if limits.max_bytes == 0
        || limits.max_statements == 0
        || limits.max_tokens == 0
        || limits.max_nesting == 0
        || limits.max_diagnostics == 0
        || limits.max_dollar_tag_bytes == 0
    {
        return Err(SqlScanError::InvalidLimits);
    }
    Ok(())
}

fn start_word(
    tokens: &[SqlToken],
    word_start: &mut Option<usize>,
    index: usize,
    has_statement_content: &mut bool,
    limits: SqlScanLimits,
) -> Result<(), SqlScanError> {
    if word_start.is_none() {
        bump_token(tokens, limits)?;
        *word_start = Some(index);
        *has_statement_content = true;
    }
    Ok(())
}

fn finish_word(tokens: &mut Vec<SqlToken>, word_start: &mut Option<usize>, end: usize) {
    if let Some(start) = word_start.take() {
        tokens.push(SqlToken {
            kind: SqlTokenKind::Word,
            start_byte: start,
            end_byte: end,
        });
    }
}

fn push_symbol(
    tokens: &mut Vec<SqlToken>,
    index: usize,
    limits: SqlScanLimits,
) -> Result<(), SqlScanError> {
    bump_token(tokens, limits)?;
    tokens.push(SqlToken {
        kind: SqlTokenKind::Symbol,
        start_byte: index,
        end_byte: index + 1,
    });
    Ok(())
}

fn bump_token(tokens: &[SqlToken], limits: SqlScanLimits) -> Result<(), SqlScanError> {
    if tokens.len() >= limits.max_tokens {
        return Err(SqlScanError::TooManyTokens {
            max: limits.max_tokens,
        });
    }
    Ok(())
}

fn bump_nesting(depth: usize, limits: SqlScanLimits, offset: usize) -> Result<(), SqlScanError> {
    if depth > limits.max_nesting {
        return Err(SqlScanError::NestingLimitExceeded {
            max: limits.max_nesting,
            byte_offset: offset,
        });
    }
    Ok(())
}

fn push_diagnostic(
    diagnostics: &mut Vec<SqlDiagnostic>,
    kind: SqlDiagnosticKind,
    byte_offset: usize,
    limits: SqlScanLimits,
) -> Result<(), SqlScanError> {
    if diagnostics.len() >= limits.max_diagnostics {
        return Err(SqlScanError::TooManyDiagnostics {
            max: limits.max_diagnostics,
        });
    }
    diagnostics.push(SqlDiagnostic { kind, byte_offset });
    Ok(())
}

fn push_statement(
    statements: &mut Vec<SqlStatementSpan>,
    input: &str,
    start: usize,
    end: usize,
    token_start: usize,
    token_end: usize,
    limits: SqlScanLimits,
) -> Result<(), SqlScanError> {
    if statements.len() >= limits.max_statements {
        return Err(SqlScanError::TooManyStatements {
            max: limits.max_statements,
        });
    }
    let (start_byte, end_byte) = trim_ascii_whitespace(input.as_bytes(), start, end);
    statements.push(SqlStatementSpan {
        start_byte,
        end_byte,
        token_start,
        token_end,
    });
    Ok(())
}

fn trim_ascii_whitespace(bytes: &[u8], mut start: usize, mut end: usize) -> (usize, usize) {
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    (start, end)
}

fn is_symbol(byte: u8) -> bool {
    matches!(
        byte,
        b',' | b'.'
            | b'='
            | b'+'
            | b'-'
            | b'*'
            | b'/'
            | b'%'
            | b'<'
            | b'>'
            | b':'
            | b'['
            | b']'
            | b'{'
            | b'}'
    )
}

fn starts_with(bytes: &[u8], index: usize, needle: &[u8]) -> bool {
    bytes.get(index..index.saturating_add(needle.len())) == Some(needle)
}

fn dollar_delimiter(
    bytes: &[u8],
    start: usize,
    max_tag_bytes: usize,
) -> Result<Option<&[u8]>, SqlScanError> {
    if bytes.get(start) != Some(&b'$') {
        return Ok(None);
    }
    if bytes.get(start + 1) == Some(&b'$') {
        return Ok(bytes.get(start..start + 2));
    }

    let Some(first) = bytes.get(start + 1).copied() else {
        return Ok(None);
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Ok(None);
    }

    let mut index = start + 1;
    while let Some(byte) = bytes.get(index).copied() {
        if byte == b'$' {
            return Ok(bytes.get(start..=index));
        }
        if !(byte.is_ascii_alphanumeric() || byte == b'_') {
            return Ok(None);
        }
        if index - (start + 1) >= max_tag_bytes {
            return Err(SqlScanError::DollarTagTooLarge {
                max: max_tag_bytes,
                byte_offset: start,
            });
        }
        index += 1;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement_text<'a>(input: &'a str, statement: &SqlStatementSpan) -> &'a str {
        &input[statement.start_byte..statement.end_byte]
    }

    #[test]
    fn splitter_ignores_semicolons_inside_all_supported_lexical_containers() {
        let input = "select ';' as value; -- comment ;\nselect $$begin; perform 1; end$$; select \"semi;colon\";";
        let scan = scan_sql(input, SqlScanLimits::default()).unwrap();

        assert!(scan.is_clean());
        assert_eq!(scan.statements.len(), 3);
        assert_eq!(
            statement_text(input, &scan.statements[0]),
            "select ';' as value"
        );
        assert!(statement_text(input, &scan.statements[1]).contains("begin; perform 1; end"));
        assert_eq!(
            statement_text(input, &scan.statements[2]),
            "select \"semi;colon\""
        );
    }

    #[test]
    fn nested_block_comments_are_bounded_and_do_not_create_statements() {
        let input = "/* outer ; /* inner ; */ still outer */ select 1;";
        let scan = scan_sql(input, SqlScanLimits::default()).unwrap();
        assert!(scan.is_clean());
        assert_eq!(scan.statements.len(), 1);
        assert!(statement_text(input, &scan.statements[0]).ends_with("select 1"));
    }

    #[test]
    fn malformed_lexical_state_is_explicitly_diagnostic_not_clean() {
        for (input, expected) in [
            (
                "select 'unterminated",
                SqlDiagnosticKind::UnterminatedSingleQuote,
            ),
            (
                "select \"unterminated",
                SqlDiagnosticKind::UnterminatedQuotedIdentifier,
            ),
            (
                "select $$unterminated",
                SqlDiagnosticKind::UnterminatedDollarQuote,
            ),
            (
                "select 1 /* unterminated",
                SqlDiagnosticKind::UnterminatedBlockComment,
            ),
            ("select (1", SqlDiagnosticKind::UnclosedParenthesis),
        ] {
            let scan = scan_sql(input, SqlScanLimits::default()).unwrap();
            assert!(!scan.is_clean());
            assert!(scan.diagnostics.iter().any(|value| value.kind == expected));
        }
    }

    #[test]
    fn resource_caps_fail_closed() {
        let defaults = SqlScanLimits::default();
        assert!(matches!(
            scan_sql(
                "select 1",
                SqlScanLimits {
                    max_bytes: 0,
                    ..defaults
                }
            ),
            Err(SqlScanError::InvalidLimits)
        ));
        assert!(matches!(
            scan_sql(
                "select 1",
                SqlScanLimits {
                    max_bytes: 4,
                    ..defaults
                }
            ),
            Err(SqlScanError::InputTooLarge { .. })
        ));
        assert!(matches!(
            scan_sql(
                "select 1; select 2;",
                SqlScanLimits {
                    max_statements: 1,
                    ..defaults
                }
            ),
            Err(SqlScanError::TooManyStatements { max: 1 })
        ));
        assert!(matches!(
            scan_sql(
                "select a + b",
                SqlScanLimits {
                    max_tokens: 2,
                    ..defaults
                }
            ),
            Err(SqlScanError::TooManyTokens { max: 2 })
        ));
        assert!(matches!(
            scan_sql(
                "select (((1)))",
                SqlScanLimits {
                    max_nesting: 2,
                    ..defaults
                }
            ),
            Err(SqlScanError::NestingLimitExceeded { max: 2, .. })
        ));
        assert!(matches!(
            scan_sql(
                "))",
                SqlScanLimits {
                    max_diagnostics: 1,
                    ..defaults
                }
            ),
            Err(SqlScanError::TooManyDiagnostics { max: 1 })
        ));
    }

    #[test]
    fn dollar_quote_tag_scan_is_separately_bounded() {
        let result = scan_sql(
            "$abcdefghijkl$body$abcdefghijkl$;",
            SqlScanLimits {
                max_dollar_tag_bytes: 4,
                ..SqlScanLimits::default()
            },
        );
        assert!(matches!(
            result,
            Err(SqlScanError::DollarTagTooLarge { max: 4, .. })
        ));
    }

    #[test]
    fn replay_is_deterministic_and_execution_remains_forbidden() {
        let input = "create table public.items(id bigint); alter table public.items enable row level security;";
        let first = scan_sql(input, SqlScanLimits::default()).unwrap();
        let second = scan_sql(input, SqlScanLimits::default()).unwrap();
        assert_eq!(first, second);
        const { assert!(!super::super::SUPABASE_MIGRATION_EXECUTION_ALLOWED) };
        const { assert!(!crate::TARGET_BUILD_EXECUTION_ALLOWED) };
    }
}
