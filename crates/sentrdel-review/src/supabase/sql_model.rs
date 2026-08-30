//! Supported SQL statement model for the Supabase R2 static provider.
//!
//! This module consumes the bounded lexical scan produced by `supabase::sql` and
//! reduces only the security-relevant statement shapes authorized by the R2
//! contract. It never executes SQL and deliberately leaves unsupported
//! security-relevant syntax visible for later coverage handling.

use super::sql::{
    SqlDiagnostic, SqlScanError, SqlScanLimits, SqlStatementSpan, SqlToken, SqlTokenKind, scan_sql,
};

pub const DEFAULT_MAX_SQL_MODEL_LIST_ITEMS: usize = 128;
pub const DEFAULT_MAX_SQL_OBJECT_PARTS: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlParseCoverage {
    Supported,
    IgnoredSafeScope,
    UnsupportedSecurityRelevant,
    MalformedOrBoundedRejection,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SqlObjectName {
    pub parts: Vec<String>,
}

impl SqlObjectName {
    #[must_use]
    pub fn normalized(&self) -> String {
        self.parts.join(".")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlPolicyCommand {
    All,
    Select,
    Insert,
    Update,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlFunctionSecurityMode {
    Unspecified,
    Invoker,
    Definer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlSearchPathAttribute {
    Unspecified,
    PinnedEmpty,
    PinnedExplicit(Vec<String>),
    MutableOrDefault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlGrantObjectKind {
    Relation,
    Table,
    Function,
    Schema,
    Sequence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SupportedSqlStatement {
    CreateSchema {
        schema: SqlObjectName,
    },
    CreateTable {
        relation: SqlObjectName,
    },
    AlterTableRls {
        relation: SqlObjectName,
        enabled: bool,
    },
    CreatePolicy {
        policy: String,
        relation: SqlObjectName,
        command: SqlPolicyCommand,
        roles: Vec<String>,
        has_using: bool,
        has_with_check: bool,
    },
    AlterPolicy {
        policy: String,
        relation: SqlObjectName,
        roles: Option<Vec<String>>,
        has_using: bool,
        has_with_check: bool,
    },
    DropPolicy {
        policy: String,
        relation: SqlObjectName,
    },
    Grant {
        privileges: Vec<String>,
        object_kind: SqlGrantObjectKind,
        objects: Vec<SqlObjectName>,
        roles: Vec<String>,
    },
    Revoke {
        privileges: Vec<String>,
        object_kind: SqlGrantObjectKind,
        objects: Vec<SqlObjectName>,
        roles: Vec<String>,
    },
    CreateFunction {
        function: SqlObjectName,
        security_mode: SqlFunctionSecurityMode,
        search_path: SqlSearchPathAttribute,
    },
    AlterFunction {
        function: SqlObjectName,
        security_mode: SqlFunctionSecurityMode,
        search_path: SqlSearchPathAttribute,
    },
    DropFunction {
        function: SqlObjectName,
    },
    CreateView {
        view: SqlObjectName,
        security_invoker: Option<bool>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlStatementModel {
    pub statement_index: usize,
    pub span: SqlStatementSpan,
    pub coverage: SqlParseCoverage,
    pub supported: Option<SupportedSqlStatement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlModelScan {
    pub statements: Vec<SqlStatementModel>,
    pub diagnostics: Vec<SqlDiagnostic>,
}

pub fn parse_sql_model(input: &str, limits: SqlScanLimits) -> Result<SqlModelScan, SqlScanError> {
    let scan = scan_sql(input, limits)?;
    let malformed = !scan.diagnostics.is_empty();
    let statements = scan
        .statements
        .iter()
        .enumerate()
        .map(|(statement_index, span)| {
            let tokens = scan
                .tokens
                .get(span.token_start..span.token_end)
                .unwrap_or_default();
            let (coverage, supported) = if malformed {
                (SqlParseCoverage::MalformedOrBoundedRejection, None)
            } else {
                parse_statement(input, tokens)
            };
            SqlStatementModel {
                statement_index,
                span: span.clone(),
                coverage,
                supported,
            }
        })
        .collect();

    Ok(SqlModelScan {
        statements,
        diagnostics: scan.diagnostics,
    })
}

fn parse_statement(
    input: &str,
    tokens: &[SqlToken],
) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    let mut cursor = Cursor::new(input, tokens);
    match cursor.peek_keyword().as_deref() {
        Some("CREATE") => parse_create(&mut cursor),
        Some("ALTER") => parse_alter(&mut cursor),
        Some("DROP") => parse_drop(&mut cursor),
        Some("GRANT") => parse_grant_revoke(&mut cursor, false),
        Some("REVOKE") => parse_grant_revoke(&mut cursor, true),
        Some("DO" | "CALL" | "EXECUTE" | "PREPARE" | "SET" | "RESET") => unsupported(),
        _ => ignored(),
    }
}

fn parse_create(cursor: &mut Cursor<'_>) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    cursor.consume_keyword("CREATE");
    let or_replace = if cursor.consume_keyword("OR") {
        if !cursor.consume_keyword("REPLACE") {
            return unsupported();
        }
        true
    } else {
        false
    };

    if cursor.consume_keyword("SCHEMA") {
        if or_replace {
            return unsupported();
        }
        cursor.consume_sequence(&["IF", "NOT", "EXISTS"]);
        return supported_from(
            cursor
                .parse_object_name()
                .map(|schema| SupportedSqlStatement::CreateSchema { schema }),
        );
    }
    if cursor.consume_keyword("TABLE") {
        if or_replace {
            return unsupported();
        }
        cursor.consume_sequence(&["IF", "NOT", "EXISTS"]);
        return supported_from(
            cursor
                .parse_object_name()
                .map(|relation| SupportedSqlStatement::CreateTable { relation }),
        );
    }
    if cursor.consume_keyword("POLICY") {
        if or_replace {
            return unsupported();
        }
        return parse_create_policy(cursor);
    }
    if cursor.consume_keyword("FUNCTION") {
        return parse_function(cursor, false);
    }
    if cursor.consume_keyword("VIEW") {
        let Some(view) = cursor.parse_object_name() else {
            return unsupported();
        };
        let security_invoker = cursor.find_boolean_assignment("SECURITY_INVOKER");
        return supported(SupportedSqlStatement::CreateView {
            view,
            security_invoker,
        });
    }

    if matches!(
        cursor.peek_keyword().as_deref(),
        Some("MATERIALIZED" | "TEMP" | "TEMPORARY" | "UNLOGGED" | "TRIGGER" | "ROLE" | "EXTENSION")
    ) {
        unsupported()
    } else {
        ignored()
    }
}

fn parse_alter(cursor: &mut Cursor<'_>) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    cursor.consume_keyword("ALTER");
    if cursor.consume_keyword("TABLE") {
        cursor.consume_sequence(&["IF", "EXISTS"]);
        let Some(relation) = cursor.parse_object_name() else {
            return unsupported();
        };
        let enabled = if cursor.consume_sequence(&["ENABLE", "ROW", "LEVEL", "SECURITY"]) {
            Some(true)
        } else if cursor.consume_sequence(&["DISABLE", "ROW", "LEVEL", "SECURITY"]) {
            Some(false)
        } else {
            None
        };
        if let Some(enabled) = enabled {
            return supported(SupportedSqlStatement::AlterTableRls { relation, enabled });
        }
        if cursor.contains_sequence(&["ROW", "LEVEL", "SECURITY"])
            || cursor.contains_keyword("POLICY")
        {
            return unsupported();
        }
        return ignored();
    }
    if cursor.consume_keyword("POLICY") {
        return parse_alter_policy(cursor);
    }
    if cursor.consume_keyword("FUNCTION") {
        return parse_function(cursor, true);
    }
    if matches!(
        cursor.peek_keyword().as_deref(),
        Some("DEFAULT" | "ROLE" | "SCHEMA" | "VIEW")
    ) {
        unsupported()
    } else {
        ignored()
    }
}

fn parse_drop(cursor: &mut Cursor<'_>) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    cursor.consume_keyword("DROP");
    if cursor.consume_keyword("POLICY") {
        cursor.consume_sequence(&["IF", "EXISTS"]);
        let Some(policy) = cursor.parse_identifier() else {
            return unsupported();
        };
        if !cursor.consume_keyword("ON") {
            return unsupported();
        }
        let Some(relation) = cursor.parse_object_name() else {
            return unsupported();
        };
        if !cursor.is_at_end() {
            return unsupported();
        }
        return supported(SupportedSqlStatement::DropPolicy { policy, relation });
    }
    if cursor.consume_keyword("FUNCTION") {
        cursor.consume_sequence(&["IF", "EXISTS"]);
        let Some(function) = cursor.parse_object_name() else {
            return unsupported();
        };
        if !cursor.consume_empty_function_signature() || !cursor.is_at_end() {
            return unsupported();
        }
        return supported(SupportedSqlStatement::DropFunction { function });
    }
    if matches!(
        cursor.peek_keyword().as_deref(),
        Some("TABLE" | "VIEW" | "SCHEMA" | "OWNED" | "ROLE" | "TRIGGER" | "EXTENSION")
    ) {
        unsupported()
    } else {
        ignored()
    }
}

fn parse_create_policy(
    cursor: &mut Cursor<'_>,
) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    let Some((policy, relation)) = parse_policy_identity(cursor) else {
        return unsupported();
    };

    if cursor.consume_keyword("AS") {
        if cursor.consume_keyword("RESTRICTIVE") {
            return unsupported();
        }
        if !cursor.consume_keyword("PERMISSIVE") {
            return unsupported();
        }
    }

    let command = if cursor.consume_keyword("FOR") {
        if cursor.consume_keyword("ALL") {
            SqlPolicyCommand::All
        } else if cursor.consume_keyword("SELECT") {
            SqlPolicyCommand::Select
        } else if cursor.consume_keyword("INSERT") {
            SqlPolicyCommand::Insert
        } else if cursor.consume_keyword("UPDATE") {
            SqlPolicyCommand::Update
        } else if cursor.consume_keyword("DELETE") {
            SqlPolicyCommand::Delete
        } else {
            return unsupported();
        }
    } else {
        SqlPolicyCommand::All
    };

    let roles = if cursor.consume_keyword("TO") {
        let Some(roles) = cursor.role_list_until(&["USING", "WITH"]) else {
            return unsupported();
        };
        if roles.is_empty() {
            return unsupported();
        }
        roles
    } else {
        vec!["public".to_owned()]
    };

    let has_using = if cursor.consume_keyword("USING") {
        if !cursor.consume_nonempty_parenthesized() {
            return unsupported();
        }
        true
    } else {
        false
    };
    let has_with_check = if cursor.consume_sequence(&["WITH", "CHECK"]) {
        if !cursor.consume_nonempty_parenthesized() {
            return unsupported();
        }
        true
    } else {
        false
    };
    if !cursor.is_at_end() {
        return unsupported();
    }

    supported(SupportedSqlStatement::CreatePolicy {
        policy,
        relation,
        command,
        roles,
        has_using,
        has_with_check,
    })
}

fn parse_alter_policy(
    cursor: &mut Cursor<'_>,
) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    let Some((policy, relation)) = parse_policy_identity(cursor) else {
        return unsupported();
    };
    if cursor.consume_keyword("RENAME")
        || cursor.contains_keyword("AS")
        || cursor.contains_keyword("FOR")
    {
        return unsupported();
    }

    let roles = if cursor.consume_keyword("TO") {
        let Some(roles) = cursor.role_list_until(&["USING", "WITH"]) else {
            return unsupported();
        };
        if roles.is_empty() {
            return unsupported();
        }
        Some(roles)
    } else {
        None
    };

    let has_using = if cursor.consume_keyword("USING") {
        if !cursor.consume_nonempty_parenthesized() {
            return unsupported();
        }
        true
    } else {
        false
    };
    let has_with_check = if cursor.consume_sequence(&["WITH", "CHECK"]) {
        if !cursor.consume_nonempty_parenthesized() {
            return unsupported();
        }
        true
    } else {
        false
    };
    if roles.is_none() && !has_using && !has_with_check {
        return unsupported();
    }
    if !cursor.is_at_end() {
        return unsupported();
    }

    supported(SupportedSqlStatement::AlterPolicy {
        policy,
        relation,
        roles,
        has_using,
        has_with_check,
    })
}

fn parse_policy_identity(cursor: &mut Cursor<'_>) -> Option<(String, SqlObjectName)> {
    let policy = cursor.parse_identifier()?;
    cursor.consume_keyword("ON").then_some(())?;
    let relation = cursor.parse_object_name()?;
    Some((policy, relation))
}

fn parse_function(
    cursor: &mut Cursor<'_>,
    alter: bool,
) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    let Some(function) = cursor.parse_object_name() else {
        return unsupported();
    };
    if !cursor.consume_empty_function_signature() {
        return unsupported();
    }
    if alter
        && (cursor.contains_keyword("RENAME")
            || cursor.contains_keyword("OWNER")
            || cursor.contains_sequence(&["SET", "SCHEMA"]))
    {
        return unsupported();
    }

    let security_mode = if cursor.contains_sequence(&["SECURITY", "DEFINER"]) {
        SqlFunctionSecurityMode::Definer
    } else if cursor.contains_sequence(&["SECURITY", "INVOKER"]) {
        SqlFunctionSecurityMode::Invoker
    } else {
        SqlFunctionSecurityMode::Unspecified
    };
    let search_path = cursor.search_path_attribute();

    if alter {
        supported(SupportedSqlStatement::AlterFunction {
            function,
            security_mode,
            search_path,
        })
    } else {
        supported(SupportedSqlStatement::CreateFunction {
            function,
            security_mode,
            search_path,
        })
    }
}

fn parse_grant_revoke(
    cursor: &mut Cursor<'_>,
    revoke: bool,
) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    cursor.consume_keyword(if revoke { "REVOKE" } else { "GRANT" });
    if revoke
        && (cursor.peek_keyword().as_deref() == Some("GRANT")
            || cursor.peek_keyword().as_deref() == Some("ADMIN"))
    {
        return unsupported();
    }

    let Some(privileges) = cursor.keyword_list_until("ON") else {
        return unsupported();
    };
    if privileges.is_empty() || !cursor.consume_keyword("ON") {
        return unsupported();
    }

    let object_kind = if cursor.consume_keyword("TABLE") {
        SqlGrantObjectKind::Table
    } else if cursor.consume_keyword("FUNCTION") {
        SqlGrantObjectKind::Function
    } else if cursor.consume_keyword("SCHEMA") {
        SqlGrantObjectKind::Schema
    } else if cursor.consume_keyword("SEQUENCE") {
        SqlGrantObjectKind::Sequence
    } else {
        SqlGrantObjectKind::Relation
    };

    let marker = if revoke { "FROM" } else { "TO" };
    let Some(objects) =
        cursor.object_list_until(marker, object_kind == SqlGrantObjectKind::Function)
    else {
        return unsupported();
    };
    if objects.is_empty() || !cursor.consume_keyword(marker) {
        return unsupported();
    }

    let Some(roles) = cursor.role_list_until(&["CASCADE", "RESTRICT", "GRANTED", "WITH"])
    else {
        return unsupported();
    };
    if roles.is_empty() || !cursor.is_at_end() {
        return unsupported();
    }

    if revoke {
        supported(SupportedSqlStatement::Revoke {
            privileges,
            object_kind,
            objects,
            roles,
        })
    } else {
        supported(SupportedSqlStatement::Grant {
            privileges,
            object_kind,
            objects,
            roles,
        })
    }
}

fn supported(
    statement: SupportedSqlStatement,
) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    (SqlParseCoverage::Supported, Some(statement))
}

fn supported_from(
    statement: Option<SupportedSqlStatement>,
) -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    statement.map_or_else(unsupported, supported)
}

fn unsupported() -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    (SqlParseCoverage::UnsupportedSecurityRelevant, None)
}

fn ignored() -> (SqlParseCoverage, Option<SupportedSqlStatement>) {
    (SqlParseCoverage::IgnoredSafeScope, None)
}

struct Cursor<'a> {
    input: &'a str,
    tokens: &'a [SqlToken],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(input: &'a str, tokens: &'a [SqlToken]) -> Self {
        Self {
            input,
            tokens,
            position: 0,
        }
    }

    fn is_at_end(&self) -> bool {
        self.position == self.tokens.len()
    }

    fn peek_keyword(&self) -> Option<String> {
        self.tokens
            .get(self.position)
            .and_then(|token| keyword(self.input, token))
    }

    fn consume_keyword(&mut self, expected: &str) -> bool {
        if self.peek_keyword().as_deref() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn consume_sequence(&mut self, expected: &[&str]) -> bool {
        let start = self.position;
        for value in expected {
            if !self.consume_keyword(value) {
                self.position = start;
                return false;
            }
        }
        true
    }

    fn consume_symbol(&mut self, expected: &str) -> bool {
        let Some(token) = self.tokens.get(self.position) else {
            return false;
        };
        if token.kind == SqlTokenKind::Symbol && token_text(self.input, token) == expected {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn consume_empty_function_signature(&mut self) -> bool {
        let start = self.position;
        if self.consume_symbol("(") && self.consume_symbol(")") {
            true
        } else {
            self.position = start;
            false
        }
    }

    fn consume_nonempty_parenthesized(&mut self) -> bool {
        let start = self.position;
        if !self.consume_symbol("(") {
            return false;
        }
        let mut depth = 1_usize;
        let mut has_expression_token = false;
        while self.position < self.tokens.len() {
            let token = &self.tokens[self.position];
            if token.kind == SqlTokenKind::Symbol {
                match token_text(self.input, token) {
                    "(" => {
                        depth = depth.saturating_add(1);
                        self.position += 1;
                    }
                    ")" => {
                        depth -= 1;
                        self.position += 1;
                        if depth == 0 {
                            return has_expression_token;
                        }
                    }
                    _ => {
                        has_expression_token = true;
                        self.position += 1;
                    }
                }
            } else {
                has_expression_token = true;
                self.position += 1;
            }
        }
        self.position = start;
        false
    }

    fn parse_identifier(&mut self) -> Option<String> {
        let value = normalized_identifier(self.input, self.tokens.get(self.position)?)?;
        self.position += 1;
        Some(value)
    }

    fn parse_role_identifier(&mut self) -> Option<String> {
        let token = self.tokens.get(self.position)?;
        if token.kind == SqlTokenKind::Word
            && matches!(
                keyword(self.input, token).as_deref(),
                Some("CURRENT_ROLE" | "CURRENT_USER" | "SESSION_USER")
            )
        {
            return None;
        }
        let value = normalized_identifier(self.input, token)?;
        self.position += 1;
        if token.kind == SqlTokenKind::QuotedIdentifier && value == "public" {
            Some("\"public\"".to_owned())
        } else {
            Some(value)
        }
    }

    fn parse_object_name(&mut self) -> Option<SqlObjectName> {
        let mut parts = vec![self.parse_identifier()?];
        while self.consume_symbol(".") {
            if parts.len() >= DEFAULT_MAX_SQL_OBJECT_PARTS {
                return None;
            }
            parts.push(self.parse_identifier()?);
        }
        Some(SqlObjectName { parts })
    }

    fn contains_keyword(&self, expected: &str) -> bool {
        self.tokens[self.position..]
            .iter()
            .any(|token| keyword(self.input, token).as_deref() == Some(expected))
    }

    fn contains_sequence(&self, expected: &[&str]) -> bool {
        self.tokens[self.position..]
            .windows(expected.len())
            .any(|window| {
                window
                    .iter()
                    .zip(expected)
                    .all(|(token, value)| keyword(self.input, token).as_deref() == Some(*value))
            })
    }

    fn identifier_list_until(&mut self, stop_words: &[&str]) -> Option<Vec<String>> {
        if self.position >= self.tokens.len()
            || self
                .peek_keyword()
                .is_some_and(|value| stop_words.contains(&value.as_str()))
        {
            return None;
        }

        let mut values = Vec::new();
        loop {
            if values.len() >= DEFAULT_MAX_SQL_MODEL_LIST_ITEMS {
                return None;
            }
            values.push(self.parse_identifier()?);

            if self.position >= self.tokens.len()
                || self
                    .peek_keyword()
                    .is_some_and(|value| stop_words.contains(&value.as_str()))
            {
                break;
            }
            if !self.consume_symbol(",") {
                return None;
            }
            if self.position >= self.tokens.len()
                || self
                    .peek_keyword()
                    .is_some_and(|value| stop_words.contains(&value.as_str()))
            {
                return None;
            }
        }
        Some(values)
    }

    fn role_list_until(&mut self, stop_words: &[&str]) -> Option<Vec<String>> {
        if self.position >= self.tokens.len()
            || self
                .peek_keyword()
                .is_some_and(|value| stop_words.contains(&value.as_str()))
        {
            return None;
        }

        let mut values = Vec::new();
        loop {
            if values.len() >= DEFAULT_MAX_SQL_MODEL_LIST_ITEMS {
                return None;
            }
            values.push(self.parse_role_identifier()?);

            if self.position >= self.tokens.len()
                || self
                    .peek_keyword()
                    .is_some_and(|value| stop_words.contains(&value.as_str()))
            {
                break;
            }
            if !self.consume_symbol(",") {
                return None;
            }
            if self.position >= self.tokens.len()
                || self
                    .peek_keyword()
                    .is_some_and(|value| stop_words.contains(&value.as_str()))
            {
                return None;
            }
        }
        Some(values)
    }

    fn keyword_list_until(&mut self, marker: &str) -> Option<Vec<String>> {
        let mut values = Vec::new();
        while self.position < self.tokens.len() && self.peek_keyword().as_deref() != Some(marker) {
            if self.consume_symbol(",") {
                continue;
            }
            let value = self.peek_keyword()?;
            self.position += 1;
            if value == "PRIVILEGES" && values.last().is_some_and(|last| last == "ALL") {
                continue;
            }
            if values.len() >= DEFAULT_MAX_SQL_MODEL_LIST_ITEMS {
                return None;
            }
            values.push(value);
        }
        (self.position < self.tokens.len()).then_some(values)
    }

    fn object_list_until(
        &mut self,
        marker: &str,
        require_empty_function_signature: bool,
    ) -> Option<Vec<SqlObjectName>> {
        let mut values = Vec::new();
        while self.position < self.tokens.len() && self.peek_keyword().as_deref() != Some(marker) {
            if values.len() >= DEFAULT_MAX_SQL_MODEL_LIST_ITEMS {
                return None;
            }
            let object = self.parse_object_name()?;
            if require_empty_function_signature && !self.consume_empty_function_signature() {
                return None;
            }
            values.push(object);
            if self.peek_keyword().as_deref() == Some(marker) {
                break;
            }
            if !self.consume_symbol(",") {
                return None;
            }
        }
        Some(values)
    }

    fn find_boolean_assignment(&self, name: &str) -> Option<bool> {
        let remaining = &self.tokens[self.position..];
        let index = remaining
            .iter()
            .position(|token| keyword(self.input, token).as_deref() == Some(name))?;
        let mut value_index = index + 1;
        if remaining.get(value_index).is_some_and(|token| {
            token.kind == SqlTokenKind::Symbol && token_text(self.input, token) == "="
        }) {
            value_index += 1;
        }
        match remaining
            .get(value_index)
            .and_then(|token| keyword(self.input, token))?
            .as_str()
        {
            "TRUE" | "ON" => Some(true),
            "FALSE" | "OFF" => Some(false),
            _ => None,
        }
    }

    fn search_path_attribute(&self) -> SqlSearchPathAttribute {
        let remaining = &self.tokens[self.position..];
        for (index, token) in remaining.iter().enumerate() {
            let Some(value) = keyword(self.input, token) else {
                continue;
            };
            if value == "RESET"
                && remaining
                    .get(index + 1)
                    .and_then(|token| keyword(self.input, token))
                    .as_deref()
                    == Some("SEARCH_PATH")
            {
                return SqlSearchPathAttribute::MutableOrDefault;
            }
            if value != "SET"
                || remaining
                    .get(index + 1)
                    .and_then(|token| keyword(self.input, token))
                    .as_deref()
                    != Some("SEARCH_PATH")
            {
                continue;
            }

            let mut value_index = index + 2;
            if remaining.get(value_index).is_some_and(|token| {
                (token.kind == SqlTokenKind::Symbol && token_text(self.input, token) == "=")
                    || keyword(self.input, token).as_deref() == Some("TO")
            }) {
                value_index += 1;
            }
            if remaining
                .get(value_index)
                .and_then(|token| keyword(self.input, token))
                .as_deref()
                == Some("FROM")
                && remaining
                    .get(value_index + 1)
                    .and_then(|token| keyword(self.input, token))
                    .as_deref()
                    == Some("CURRENT")
            {
                return SqlSearchPathAttribute::MutableOrDefault;
            }

            let mut values = Vec::new();
            for token in &remaining[value_index..] {
                if keyword(self.input, token).is_some_and(|keyword| {
                    matches!(
                        keyword.as_str(),
                        "LANGUAGE" | "SECURITY" | "AS" | "SET" | "RESET" | "COST" | "ROWS"
                    )
                }) {
                    break;
                }
                if token.kind == SqlTokenKind::Symbol && token_text(self.input, token) == "," {
                    continue;
                }
                let Some(value) = normalized_search_path_value(self.input, token) else {
                    break;
                };
                if value.is_empty() {
                    return SqlSearchPathAttribute::PinnedEmpty;
                }
                if value.eq_ignore_ascii_case("default") || value == "$user" {
                    return SqlSearchPathAttribute::MutableOrDefault;
                }
                if values.len() >= DEFAULT_MAX_SQL_MODEL_LIST_ITEMS {
                    return SqlSearchPathAttribute::MutableOrDefault;
                }
                values.push(value);
            }
            return if values.is_empty() {
                SqlSearchPathAttribute::MutableOrDefault
            } else {
                SqlSearchPathAttribute::PinnedExplicit(values)
            };
        }
        SqlSearchPathAttribute::Unspecified
    }
}

fn token_text<'a>(input: &'a str, token: &SqlToken) -> &'a str {
    input
        .get(token.start_byte..token.end_byte)
        .unwrap_or_default()
}

fn keyword(input: &str, token: &SqlToken) -> Option<String> {
    (token.kind == SqlTokenKind::Word).then(|| token_text(input, token).to_ascii_uppercase())
}

fn normalized_identifier(input: &str, token: &SqlToken) -> Option<String> {
    let text = token_text(input, token);
    match token.kind {
        SqlTokenKind::Word => Some(text.to_ascii_lowercase()),
        SqlTokenKind::QuotedIdentifier => text
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .map(|value| value.replace("\"\"", "\"")),
        _ => None,
    }
}

fn normalized_search_path_value(input: &str, token: &SqlToken) -> Option<String> {
    match token.kind {
        SqlTokenKind::Word | SqlTokenKind::QuotedIdentifier => normalized_identifier(input, token),
        SqlTokenKind::StringLiteral => token_text(input, token)
            .strip_prefix('\'')
            .and_then(|value| value.strip_suffix('\''))
            .map(|value| value.replace("''", "'")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supported_statements(input: &str) -> Vec<SupportedSqlStatement> {
        parse_sql_model(input, SqlScanLimits::default())
            .unwrap()
            .statements
            .into_iter()
            .map(|statement| {
                assert_eq!(statement.coverage, SqlParseCoverage::Supported);
                statement.supported.unwrap()
            })
            .collect()
    }

    fn unsupported_statements(input: &str) -> Vec<SqlStatementModel> {
        let statements = parse_sql_model(input, SqlScanLimits::default())
            .unwrap()
            .statements;
        assert!(statements.iter().all(|statement| {
            statement.coverage == SqlParseCoverage::UnsupportedSecurityRelevant
                && statement.supported.is_none()
        }));
        statements
    }

    #[test]
    fn models_schema_table_and_rls_state_changes() {
        let statements = supported_statements(
            "create schema private; create table public.accounts(id bigint); alter table public.accounts enable row level security; alter table public.accounts disable row level security;",
        );
        assert_eq!(statements.len(), 4);
        assert!(matches!(
            &statements[0],
            SupportedSqlStatement::CreateSchema { schema } if schema.normalized() == "private"
        ));
        assert!(matches!(
            &statements[1],
            SupportedSqlStatement::CreateTable { relation } if relation.normalized() == "public.accounts"
        ));
        assert!(matches!(
            &statements[2],
            SupportedSqlStatement::AlterTableRls { relation, enabled: true }
                if relation.normalized() == "public.accounts"
        ));
        assert!(matches!(
            &statements[3],
            SupportedSqlStatement::AlterTableRls { relation, enabled: false }
                if relation.normalized() == "public.accounts"
        ));
    }

    #[test]
    fn models_policy_scope_roles_defaults_and_expression_presence() {
        let statements = supported_statements(
            "create policy \"Account read\" on public.accounts for select to anon, authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid()); alter policy \"Account read\" on public.accounts to authenticated using (true); create policy public_default on public.accounts using (true); alter policy public_default on public.accounts using (owner_id = auth.uid());",
        );
        assert!(matches!(
            &statements[0],
            SupportedSqlStatement::CreatePolicy {
                policy,
                relation,
                command: SqlPolicyCommand::Select,
                roles,
                has_using: true,
                has_with_check: true,
            } if policy == "Account read"
                && relation.normalized() == "public.accounts"
                && roles == &vec!["anon".to_owned(), "authenticated".to_owned()]
        ));
        assert!(matches!(
            &statements[1],
            SupportedSqlStatement::AlterPolicy {
                policy,
                relation,
                roles: Some(roles),
                has_using: true,
                has_with_check: false,
            } if policy == "Account read"
                && relation.normalized() == "public.accounts"
                && roles == &vec!["authenticated".to_owned()]
        ));
        assert!(matches!(
            &statements[2],
            SupportedSqlStatement::CreatePolicy { roles, .. }
                if roles == &vec!["public".to_owned()]
        ));
        assert!(matches!(
            &statements[3],
            SupportedSqlStatement::AlterPolicy { roles: None, .. }
        ));
    }

    #[test]
    fn canonical_drop_policy_remains_supported() {
        let statements = supported_statements(
            "drop policy account_read on public.accounts; drop policy if exists account_write on public.accounts;",
        );
        assert_eq!(statements.len(), 2);
        assert!(statements.iter().all(|statement| matches!(
            statement,
            SupportedSqlStatement::DropPolicy { relation, .. }
                if relation.normalized() == "public.accounts"
        )));
    }

    #[test]
    fn drop_policy_trailing_semantics_fail_closed() {
        let statements = unsupported_statements(
            "drop policy account_read on public.accounts cascade; drop policy account_write on public.accounts frobulate; drop policy account_delete on public.accounts,;",
        );
        assert_eq!(statements.len(), 3);
    }

    #[test]
    fn malformed_policy_clause_markers_fail_closed() {
        let statements = unsupported_statements(
            "create policy bare_using on public.accounts using; create policy empty_using on public.accounts using (); create policy bad_with on public.accounts with nope; alter policy bare_alter on public.accounts using; alter policy empty_check on public.accounts with check (); alter policy no_change on public.accounts;",
        );
        assert_eq!(statements.len(), 6);
    }

    #[test]
    fn opaque_nested_policy_expressions_remain_supported() {
        let statements = supported_statements(
            "create policy nested on public.accounts to authenticated using ((owner_id = auth.uid()) and (active = true)) with check ((owner_id = auth.uid())); alter policy nested on public.accounts using ((owner_id = auth.uid()));",
        );
        assert_eq!(statements.len(), 2);
        assert!(matches!(
            &statements[0],
            SupportedSqlStatement::CreatePolicy {
                has_using: true,
                has_with_check: true,
                ..
            }
        ));
        assert!(matches!(
            &statements[1],
            SupportedSqlStatement::AlterPolicy {
                has_using: true,
                has_with_check: false,
                ..
            }
        ));
    }

    #[test]
    fn malformed_role_lists_fail_closed() {
        let statements = unsupported_statements(
            "create policy missing_comma on public.accounts to anon authenticated using (true); create policy leading_comma on public.accounts to , anon using (true); alter policy trailing_comma on public.accounts to authenticated, using (true); grant select on table public.accounts to anon authenticated;",
        );
        assert_eq!(statements.len(), 4);
    }

    #[test]
    fn quoted_public_role_remains_distinct_from_public_pseudo_role() {
        let statements = supported_statements(
            "create policy all_roles on public.accounts to public using (true); create policy named_public on public.accounts to \"public\" using (true); grant select on table public.accounts to public; grant select on table public.accounts to \"public\";",
        );
        assert_eq!(statements.len(), 4);
        assert!(matches!(
            &statements[0],
            SupportedSqlStatement::CreatePolicy { roles, .. }
                if roles == &vec!["public".to_owned()]
        ));
        assert!(matches!(
            &statements[1],
            SupportedSqlStatement::CreatePolicy { roles, .. }
                if roles == &vec!["\"public\"".to_owned()]
        ));
        assert!(matches!(
            &statements[2],
            SupportedSqlStatement::Grant { roles, .. }
                if roles == &vec!["public".to_owned()]
        ));
        assert!(matches!(
            &statements[3],
            SupportedSqlStatement::Grant { roles, .. }
                if roles == &vec!["\"public\"".to_owned()]
        ));
    }

    #[test]
    fn dynamic_role_specifications_fail_closed_but_quoted_names_remain_supported() {
        let unsupported = unsupported_statements(
            "create policy current_user_policy on public.accounts to current_user using (true); grant select on table public.accounts to current_role; revoke select on table public.accounts from session_user;",
        );
        assert_eq!(unsupported.len(), 3);

        let supported = supported_statements(
            "create policy named_current_user on public.accounts to \"current_user\" using (true); grant select on table public.accounts to \"current_role\";",
        );
        assert!(matches!(
            &supported[0],
            SupportedSqlStatement::CreatePolicy { roles, .. }
                if roles == &vec!["current_user".to_owned()]
        ));
        assert!(matches!(
            &supported[1],
            SupportedSqlStatement::Grant { roles, .. }
                if roles == &vec!["current_role".to_owned()]
        ));
    }

    #[test]
    fn models_grant_and_revoke_without_collapsing_rls() {
        let statements = supported_statements(
            "grant select, insert on table public.accounts to anon, authenticated; revoke insert on table public.accounts from anon;",
        );
        assert!(matches!(
            &statements[0],
            SupportedSqlStatement::Grant {
                privileges,
                object_kind: SqlGrantObjectKind::Table,
                objects,
                roles,
            } if privileges == &vec!["SELECT".to_owned(), "INSERT".to_owned()]
                && objects[0].normalized() == "public.accounts"
                && roles == &vec!["anon".to_owned(), "authenticated".to_owned()]
        ));
        assert!(matches!(
            &statements[1],
            SupportedSqlStatement::Revoke { privileges, roles, .. }
                if privileges == &vec!["INSERT".to_owned()]
                    && roles == &vec!["anon".to_owned()]
        ));
    }

    #[test]
    fn models_canonical_empty_signature_function_grants() {
        let statements = supported_statements(
            "revoke all on function private.current_account_id() from public; grant execute on function private.current_account_id() to authenticated;",
        );
        assert!(matches!(
            &statements[0],
            SupportedSqlStatement::Revoke {
                object_kind: SqlGrantObjectKind::Function,
                objects,
                roles,
                ..
            } if objects[0].normalized() == "private.current_account_id"
                && roles == &vec!["public".to_owned()]
        ));
        assert!(matches!(
            &statements[1],
            SupportedSqlStatement::Grant {
                privileges,
                object_kind: SqlGrantObjectKind::Function,
                objects,
                roles,
            } if privileges == &vec!["EXECUTE".to_owned()]
                && objects[0].normalized() == "private.current_account_id"
                && roles == &vec!["authenticated".to_owned()]
        ));
    }

    #[test]
    fn models_function_authority_and_search_path_attributes() {
        let statements = supported_statements(
            "create function private.lookup_role() returns text language sql security definer set search_path = '' as $$ select 'admin' $$; alter function private.lookup_role() security invoker set search_path = pg_catalog, private; drop function private.lookup_role();",
        );
        assert!(matches!(
            &statements[0],
            SupportedSqlStatement::CreateFunction {
                function,
                security_mode: SqlFunctionSecurityMode::Definer,
                search_path: SqlSearchPathAttribute::PinnedEmpty,
            } if function.normalized() == "private.lookup_role"
        ));
        assert!(matches!(
            &statements[1],
            SupportedSqlStatement::AlterFunction {
                security_mode: SqlFunctionSecurityMode::Invoker,
                search_path: SqlSearchPathAttribute::PinnedExplicit(values),
                ..
            } if values == &vec!["pg_catalog".to_owned(), "private".to_owned()]
        ));
        assert!(matches!(
            &statements[2],
            SupportedSqlStatement::DropFunction { function }
                if function.normalized() == "private.lookup_role"
        ));
    }

    #[test]
    fn dynamic_search_path_is_not_recorded_as_pinned() {
        let statements = supported_statements(
            "create function private.from_current() returns void language sql security definer set search_path from current as $$ select 1 $$; create function private.default_path() returns void language sql security definer set search_path = default as $$ select 1 $$; create function private.user_path() returns void language sql security definer set search_path = '$user', public as $$ select 1 $$;",
        );
        assert!(statements.iter().all(|statement| matches!(
            statement,
            SupportedSqlStatement::CreateFunction {
                search_path: SqlSearchPathAttribute::MutableOrDefault,
                ..
            }
        )));
    }

    #[test]
    fn models_minimal_view_security_invoker_attribute() {
        let statements = supported_statements(
            "create view public.safe_accounts with (security_invoker = true) as select id from private.accounts;",
        );
        assert!(matches!(
            &statements[0],
            SupportedSqlStatement::CreateView {
                view,
                security_invoker: Some(true),
            } if view.normalized() == "public.safe_accounts"
        ));
    }

    #[test]
    fn unsupported_security_syntax_never_becomes_clean_supported_state() {
        let statements = unsupported_statements(
            "alter table public.accounts force row level security; do $$ begin execute 'grant all'; end $$; drop table public.accounts; create policy restrictive_policy on public.accounts as restrictive using (true);",
        );
        assert_eq!(statements.len(), 4);
    }

    #[test]
    fn overloaded_functions_and_grant_option_semantics_fail_closed() {
        let statements = unsupported_statements(
            "create function public.lookup(value uuid) returns uuid language sql as $$ select value $$; grant execute on function public.lookup(uuid) to anon; grant execute on function public.lookup() to anon with grant option; revoke grant option for execute on function public.lookup() from anon;",
        );
        assert_eq!(statements.len(), 4);
    }

    #[test]
    fn malformed_lexical_input_is_explicitly_non_clean() {
        let scan = parse_sql_model(
            "create policy broken on public.accounts using ('unterminated",
            SqlScanLimits::default(),
        )
        .unwrap();
        assert!(!scan.diagnostics.is_empty());
        assert!(scan.statements.iter().all(|statement| {
            statement.coverage == SqlParseCoverage::MalformedOrBoundedRejection
                && statement.supported.is_none()
        }));
    }

    #[test]
    fn ordinary_query_scope_is_ignored_not_upgraded_to_security_state() {
        let scan =
            parse_sql_model("select * from public.accounts;", SqlScanLimits::default()).unwrap();
        assert_eq!(scan.statements.len(), 1);
        assert_eq!(
            scan.statements[0].coverage,
            SqlParseCoverage::IgnoredSafeScope
        );
        assert!(scan.statements[0].supported.is_none());
    }
}
