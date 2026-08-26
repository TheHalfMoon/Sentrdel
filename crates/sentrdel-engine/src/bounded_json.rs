//! Allocation-bounded JSON structural preflight for T028 external-engine results.
//!
//! This parser intentionally does not construct a JSON value tree. It validates
//! enough JSON grammar to walk the document and rejects structural amplification
//! before serde materializes untrusted collections. Full dialect semantics are
//! still validated by serde and the adapter after this preflight succeeds.

pub(crate) const MAX_JSON_DEPTH: usize = 64;
pub(crate) const MAX_JSON_NODES: usize = 1_000_000;
pub(crate) const MAX_JSON_STRING_BYTES: usize = 64 * 1024;
pub(crate) const MAX_ATTRIBUTE_VALUE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_ATTRIBUTE_VALUE_DEPTH: usize = 16;
pub(crate) const MAX_ATTRIBUTE_VALUE_NODES: usize = 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedJsonDialect {
    Native,
    Sarif,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedJsonError {
    Malformed,
    TooManyRuns { count: usize, max: usize },
    TooManyItems { count: usize, max: usize },
    TooManyLocations { count: usize, max: usize },
    TooManySubjects { count: usize, max: usize },
    TooManyAttributes { count: usize, max: usize },
    StringTooLarge { bytes: usize, max: usize },
    NestingTooDeep { depth: usize, max: usize },
    StructureTooComplex { nodes: usize, max: usize },
    AttributeValueTooLarge { bytes: usize, max: usize },
    AttributeValueTooDeep { depth: usize, max: usize },
    AttributeValueTooComplex { nodes: usize, max: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Context {
    RootNative,
    NativeEvidenceArray,
    NativeEvidenceItem,
    NativeSubjectsArray,
    NativeLocationsArray,
    NativeAttributes,
    AttributeValue,
    RootSarif,
    SarifRunsArray,
    SarifRun,
    SarifResultsArray,
    SarifResult,
    SarifLocationsArray,
    Generic,
}

pub(crate) fn preflight_json(
    raw: &[u8],
    dialect: BoundedJsonDialect,
    max_items: usize,
    max_runs: usize,
    max_locations: usize,
    max_subjects: usize,
    max_attributes: usize,
) -> Result<(), BoundedJsonError> {
    if std::str::from_utf8(raw).is_err() {
        return Err(BoundedJsonError::Malformed);
    }
    let root = match dialect {
        BoundedJsonDialect::Native => Context::RootNative,
        BoundedJsonDialect::Sarif => Context::RootSarif,
    };
    let mut parser = Parser {
        raw,
        position: 0,
        nodes: 0,
        sarif_items: 0,
        max_items,
        max_runs,
        max_locations,
        max_subjects,
        max_attributes,
    };
    parser.parse_value(root, 0, None)?;
    parser.skip_whitespace();
    if parser.position != raw.len() {
        return Err(BoundedJsonError::Malformed);
    }
    Ok(())
}

struct Parser<'a> {
    raw: &'a [u8],
    position: usize,
    nodes: usize,
    sarif_items: usize,
    max_items: usize,
    max_runs: usize,
    max_locations: usize,
    max_subjects: usize,
    max_attributes: usize,
}

impl Parser<'_> {
    fn parse_value(
        &mut self,
        context: Context,
        depth: usize,
        local_depth_limit: Option<usize>,
    ) -> Result<(), BoundedJsonError> {
        self.skip_whitespace();
        self.bump_node()?;
        self.check_depth(depth, local_depth_limit)?;
        match context {
            Context::NativeEvidenceArray
            | Context::NativeSubjectsArray
            | Context::NativeLocationsArray
            | Context::SarifRunsArray
            | Context::SarifResultsArray
            | Context::SarifLocationsArray => {
                if self.peek() != Some(b'[') {
                    return Err(BoundedJsonError::Malformed);
                }
                self.parse_array(context, depth, local_depth_limit)
            }
            Context::NativeAttributes => {
                if self.peek() != Some(b'{') {
                    return Err(BoundedJsonError::Malformed);
                }
                self.parse_object(context, depth, local_depth_limit)
            }
            _ => match self.peek().ok_or(BoundedJsonError::Malformed)? {
                b'{' => self.parse_object(context, depth, local_depth_limit),
                b'[' => self.parse_array(Context::Generic, depth, local_depth_limit),
                b'"' => self.skip_string(),
                b't' => self.parse_literal(b"true"),
                b'f' => self.parse_literal(b"false"),
                b'n' => self.parse_literal(b"null"),
                b'-' | b'0'..=b'9' => self.parse_number(),
                _ => Err(BoundedJsonError::Malformed),
            },
        }
    }

    fn parse_object(
        &mut self,
        context: Context,
        depth: usize,
        local_depth_limit: Option<usize>,
    ) -> Result<(), BoundedJsonError> {
        self.expect(b'{')?;
        self.skip_whitespace();
        if self.consume(b'}') {
            return Ok(());
        }
        let mut entries = 0usize;
        loop {
            self.skip_whitespace();
            let key = self.parse_structural_key()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            entries = entries
                .checked_add(1)
                .ok_or(BoundedJsonError::StructureTooComplex {
                    nodes: usize::MAX,
                    max: MAX_JSON_NODES,
                })?;
            if context == Context::NativeAttributes && entries > self.max_attributes {
                return Err(BoundedJsonError::TooManyAttributes {
                    count: entries,
                    max: self.max_attributes,
                });
            }

            let child = child_context(context, &key);
            if child == Context::AttributeValue {
                self.parse_attribute_value(depth + 1)?;
            } else {
                self.parse_value(child, depth + 1, local_depth_limit)?;
            }

            self.skip_whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    fn parse_array(
        &mut self,
        context: Context,
        depth: usize,
        local_depth_limit: Option<usize>,
    ) -> Result<(), BoundedJsonError> {
        self.expect(b'[')?;
        self.skip_whitespace();
        if self.consume(b']') {
            return Ok(());
        }
        let mut count = 0usize;
        loop {
            count = count
                .checked_add(1)
                .ok_or(BoundedJsonError::StructureTooComplex {
                    nodes: usize::MAX,
                    max: MAX_JSON_NODES,
                })?;
            let element_context = match context {
                Context::NativeEvidenceArray => {
                    if count > self.max_items {
                        return Err(BoundedJsonError::TooManyItems {
                            count,
                            max: self.max_items,
                        });
                    }
                    Context::NativeEvidenceItem
                }
                Context::NativeSubjectsArray => {
                    if count > self.max_subjects {
                        return Err(BoundedJsonError::TooManySubjects {
                            count,
                            max: self.max_subjects,
                        });
                    }
                    Context::Generic
                }
                Context::NativeLocationsArray | Context::SarifLocationsArray => {
                    if count > self.max_locations {
                        return Err(BoundedJsonError::TooManyLocations {
                            count,
                            max: self.max_locations,
                        });
                    }
                    Context::Generic
                }
                Context::SarifRunsArray => {
                    if count > self.max_runs {
                        return Err(BoundedJsonError::TooManyRuns {
                            count,
                            max: self.max_runs,
                        });
                    }
                    Context::SarifRun
                }
                Context::SarifResultsArray => {
                    self.sarif_items =
                        self.sarif_items
                            .checked_add(1)
                            .ok_or(BoundedJsonError::TooManyItems {
                                count: usize::MAX,
                                max: self.max_items,
                            })?;
                    if self.sarif_items > self.max_items {
                        return Err(BoundedJsonError::TooManyItems {
                            count: self.sarif_items,
                            max: self.max_items,
                        });
                    }
                    Context::SarifResult
                }
                _ => Context::Generic,
            };
            self.parse_value(element_context, depth + 1, local_depth_limit)?;
            self.skip_whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            self.expect(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_attribute_value(&mut self, depth: usize) -> Result<(), BoundedJsonError> {
        self.skip_whitespace();
        let start = self.position;
        let nodes_before = self.nodes;
        let depth_limit = depth.saturating_add(MAX_ATTRIBUTE_VALUE_DEPTH);
        self.parse_value(Context::Generic, depth, Some(depth_limit))?;
        let bytes = self.position.saturating_sub(start);
        if bytes > MAX_ATTRIBUTE_VALUE_BYTES {
            return Err(BoundedJsonError::AttributeValueTooLarge {
                bytes,
                max: MAX_ATTRIBUTE_VALUE_BYTES,
            });
        }
        let nodes = self.nodes.saturating_sub(nodes_before);
        if nodes > MAX_ATTRIBUTE_VALUE_NODES {
            return Err(BoundedJsonError::AttributeValueTooComplex {
                nodes,
                max: MAX_ATTRIBUTE_VALUE_NODES,
            });
        }
        Ok(())
    }

    fn parse_structural_key(&mut self) -> Result<String, BoundedJsonError> {
        self.expect(b'"')?;
        let start = self.position;
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    let end = self.position;
                    self.position += 1;
                    let bytes = end.saturating_sub(start);
                    if bytes > 4 * 1024 {
                        return Err(BoundedJsonError::StringTooLarge {
                            bytes,
                            max: 4 * 1024,
                        });
                    }
                    return std::str::from_utf8(&self.raw[start..end])
                        .map(str::to_owned)
                        .map_err(|_| BoundedJsonError::Malformed);
                }
                0x00..=0x1f | b'\\' => {
                    // Reject escaped object keys so an attacker cannot alias a bounded
                    // structural key (for example `res\u0075lts`) around the preflight.
                    return Err(BoundedJsonError::Malformed);
                }
                _ => self.position += 1,
            }
        }
        Err(BoundedJsonError::Malformed)
    }

    fn skip_string(&mut self) -> Result<(), BoundedJsonError> {
        self.expect(b'"')?;
        let start = self.position;
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    let bytes = self.position.saturating_sub(start);
                    self.position += 1;
                    if bytes > MAX_JSON_STRING_BYTES {
                        return Err(BoundedJsonError::StringTooLarge {
                            bytes,
                            max: MAX_JSON_STRING_BYTES,
                        });
                    }
                    return Ok(());
                }
                0x00..=0x1f => return Err(BoundedJsonError::Malformed),
                b'\\' => {
                    self.position += 1;
                    match self.peek().ok_or(BoundedJsonError::Malformed)? {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            self.position += 1;
                        }
                        b'u' => {
                            self.position += 1;
                            for _ in 0..4 {
                                if !self.peek().is_some_and(|value| value.is_ascii_hexdigit()) {
                                    return Err(BoundedJsonError::Malformed);
                                }
                                self.position += 1;
                            }
                        }
                        _ => return Err(BoundedJsonError::Malformed),
                    }
                }
                _ => self.position += 1,
            }
        }
        Err(BoundedJsonError::Malformed)
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), BoundedJsonError> {
        let end = self
            .position
            .checked_add(literal.len())
            .ok_or(BoundedJsonError::Malformed)?;
        if self.raw.get(self.position..end) != Some(literal) {
            return Err(BoundedJsonError::Malformed);
        }
        self.position = end;
        Ok(())
    }

    fn parse_number(&mut self) -> Result<(), BoundedJsonError> {
        if self.consume(b'-') && self.peek().is_none() {
            return Err(BoundedJsonError::Malformed);
        }
        match self.peek().ok_or(BoundedJsonError::Malformed)? {
            b'0' => {
                self.position += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(BoundedJsonError::Malformed);
                }
            }
            b'1'..=b'9' => {
                self.position += 1;
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.position += 1;
                }
            }
            _ => return Err(BoundedJsonError::Malformed),
        }
        if self.consume(b'.') {
            let start = self.position;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
            if self.position == start {
                return Err(BoundedJsonError::Malformed);
            }
        }
        if self.peek().is_some_and(|byte| matches!(byte, b'e' | b'E')) {
            self.position += 1;
            if self.peek().is_some_and(|byte| matches!(byte, b'+' | b'-')) {
                self.position += 1;
            }
            let start = self.position;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
            if self.position == start {
                return Err(BoundedJsonError::Malformed);
            }
        }
        Ok(())
    }

    fn bump_node(&mut self) -> Result<(), BoundedJsonError> {
        self.nodes = self
            .nodes
            .checked_add(1)
            .ok_or(BoundedJsonError::StructureTooComplex {
                nodes: usize::MAX,
                max: MAX_JSON_NODES,
            })?;
        if self.nodes > MAX_JSON_NODES {
            return Err(BoundedJsonError::StructureTooComplex {
                nodes: self.nodes,
                max: MAX_JSON_NODES,
            });
        }
        Ok(())
    }

    fn check_depth(
        &self,
        depth: usize,
        local_depth_limit: Option<usize>,
    ) -> Result<(), BoundedJsonError> {
        if depth > MAX_JSON_DEPTH {
            return Err(BoundedJsonError::NestingTooDeep {
                depth,
                max: MAX_JSON_DEPTH,
            });
        }
        if let Some(limit) = local_depth_limit
            && depth > limit
        {
            return Err(BoundedJsonError::AttributeValueTooDeep { depth, max: limit });
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), BoundedJsonError> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(BoundedJsonError::Malformed)
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.raw.get(self.position).copied()
    }
}

fn child_context(parent: Context, key: &str) -> Context {
    match (parent, key) {
        (Context::RootNative, "evidence") => Context::NativeEvidenceArray,
        (Context::NativeEvidenceItem, "subjects") => Context::NativeSubjectsArray,
        (Context::NativeEvidenceItem, "locations") => Context::NativeLocationsArray,
        (Context::NativeEvidenceItem, "attributes") => Context::NativeAttributes,
        (Context::NativeAttributes, _) => Context::AttributeValue,
        (Context::RootSarif, "runs") => Context::SarifRunsArray,
        (Context::SarifRun, "results") => Context::SarifResultsArray,
        (Context::SarifResult, "locations") => Context::SarifLocationsArray,
        _ => Context::Generic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_item_count_stops_before_materialization() {
        let mut raw = String::from(r#"{"schema_version":"1","evidence":["#);
        for index in 0..4 {
            if index != 0 {
                raw.push(',');
            }
            raw.push_str("{}");
        }
        raw.push_str("]}");
        assert_eq!(
            preflight_json(raw.as_bytes(), BoundedJsonDialect::Native, 3, 4, 4, 4, 4),
            Err(BoundedJsonError::TooManyItems { count: 4, max: 3 })
        );
    }

    #[test]
    fn sarif_result_count_is_global_across_runs() {
        let raw = br#"{"version":"2.1.0","runs":[{"results":[{},{}]},{"results":[{},{}]}]}"#;
        assert_eq!(
            preflight_json(raw, BoundedJsonDialect::Sarif, 3, 4, 4, 4, 4),
            Err(BoundedJsonError::TooManyItems { count: 4, max: 3 })
        );
    }

    #[test]
    fn attribute_depth_is_bounded() {
        let mut nested = String::new();
        for _ in 0..=MAX_ATTRIBUTE_VALUE_DEPTH {
            nested.push('[');
        }
        nested.push('0');
        for _ in 0..=MAX_ATTRIBUTE_VALUE_DEPTH {
            nested.push(']');
        }
        let raw =
            format!(r#"{{"schema_version":"1","evidence":[{{"attributes":{{"x":{nested}}}}}]}}"#);
        assert!(matches!(
            preflight_json(raw.as_bytes(), BoundedJsonDialect::Native, 4, 4, 4, 4, 4),
            Err(BoundedJsonError::AttributeValueTooDeep { .. })
        ));
    }

    #[test]
    fn escaped_structural_keys_fail_closed() {
        let raw = br#"{"schema_version":"1","evi\u0064ence":[]}"#;
        assert_eq!(
            preflight_json(raw, BoundedJsonDialect::Native, 4, 4, 4, 4, 4),
            Err(BoundedJsonError::Malformed)
        );
    }
}
