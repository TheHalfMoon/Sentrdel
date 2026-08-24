use std::{collections::BTreeMap, error::Error, fmt};

use rusqlite::{OptionalExtension, TransactionBehavior, params};
use sentrdel_schema::{
    SCHEMA_V1,
    asel::{
        Actor, AgentSecurityEvent, AgentSecurityEventRecord, AselValidationError, EventKind,
        SessionIntegrity, SessionVerification,
    },
    canonical::{CanonicalError, canonical_json_bytes, content_id},
    policy::{PolicyDecisionClaim, PolicyDecisionRecord},
};
use serde::Serialize;

use crate::{PersistentSink, RedactionError, Store};

pub type AselStoreResult<T> = Result<T, AselStoreError>;

#[derive(Debug)]
pub enum AselStoreError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Canonical(CanonicalError),
    Validation(AselValidationError),
    Redaction(RedactionError),
    SequenceOutOfRange {
        sequence: u64,
    },
    SequenceMismatch {
        session_id: String,
        expected: u64,
        found: u64,
    },
    PreviousHashMismatch {
        session_id: String,
        sequence: u64,
    },
    AppendConflict {
        session_id: String,
        sequence: u64,
    },
    CorruptStoredEvent {
        session_id: String,
        sequence: u64,
        detail: &'static str,
    },
    EventCountOutOfRange,
}

impl fmt::Display for AselStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(formatter, "SQLite ASEL-store error: {error}"),
            Self::Json(error) => write!(formatter, "stored ASEL JSON is invalid: {error}"),
            Self::Canonical(error) => write!(formatter, "ASEL canonicalization failed: {error}"),
            Self::Validation(error) => write!(formatter, "ASEL event validation failed: {error}"),
            Self::Redaction(error) => {
                write!(formatter, "ASEL persistence redaction failed: {error}")
            }
            Self::SequenceOutOfRange { sequence } => write!(
                formatter,
                "ASEL sequence {sequence} cannot be represented by SQLite INTEGER"
            ),
            Self::SequenceMismatch {
                session_id,
                expected,
                found,
            } => write!(
                formatter,
                "ASEL session {session_id:?} expected sequence {expected} but received {found}"
            ),
            Self::PreviousHashMismatch {
                session_id,
                sequence,
            } => write!(
                formatter,
                "ASEL session {session_id:?} sequence {sequence} does not link to the current head"
            ),
            Self::AppendConflict {
                session_id,
                sequence,
            } => write!(
                formatter,
                "ASEL session {session_id:?} sequence {sequence} already exists with different canonical bytes"
            ),
            Self::CorruptStoredEvent {
                session_id,
                sequence,
                detail,
            } => write!(
                formatter,
                "stored ASEL session {session_id:?} sequence {sequence} failed integrity validation: {detail}"
            ),
            Self::EventCountOutOfRange => {
                write!(formatter, "ASEL event count cannot be represented as u64")
            }
        }
    }
}

impl Error for AselStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Canonical(error) => Some(error),
            Self::Validation(error) => Some(error),
            Self::Redaction(error) => Some(error),
            Self::SequenceOutOfRange { .. }
            | Self::SequenceMismatch { .. }
            | Self::PreviousHashMismatch { .. }
            | Self::AppendConflict { .. }
            | Self::CorruptStoredEvent { .. }
            | Self::EventCountOutOfRange => None,
        }
    }
}

impl From<rusqlite::Error> for AselStoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for AselStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<CanonicalError> for AselStoreError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<AselValidationError> for AselStoreError {
    fn from(error: AselValidationError) -> Self {
        Self::Validation(error)
    }
}

impl From<RedactionError> for AselStoreError {
    fn from(error: RedactionError) -> Self {
        Self::Redaction(error)
    }
}

#[derive(Debug)]
struct StoredAselRow {
    session_id: String,
    sequence: i64,
    event_hash: String,
    previous_event_hash: Option<String>,
    canonical_json: Vec<u8>,
}

impl Store {
    /// Append one already-sealed ASEL event to the exact current session head.
    ///
    /// The append is atomic under an IMMEDIATE SQLite transaction. An exact
    /// byte-identical replay of an already stored event is idempotent and returns
    /// `false`; gaps, forks, conflicting replays, and wrong previous hashes fail.
    pub fn append_asel_event(&mut self, event: &AgentSecurityEvent) -> AselStoreResult<bool> {
        if !event.verify_hash()? {
            return Err(AselStoreError::CorruptStoredEvent {
                session_id: event.session_id().to_owned(),
                sequence: event.sequence(),
                detail: "sealed event hash does not match its canonical draft",
            });
        }

        let record = event.to_record();
        let canonical = canonical_json_bytes(&record)?;
        self.require_persistable(PersistentSink::Sqlite, &canonical)?;
        let sequence = sqlite_sequence(event.sequence())?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        let existing: Option<(String, Vec<u8>)> = transaction
            .query_row(
                "SELECT event_hash, canonical_json FROM sentrdel_asel_events WHERE session_id = ?1 AND sequence = ?2",
                params![event.session_id(), sequence],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_hash, existing_bytes)) = existing {
            if existing_hash == event.event_hash() && existing_bytes == canonical {
                transaction.commit()?;
                return Ok(false);
            }
            return Err(AselStoreError::AppendConflict {
                session_id: event.session_id().to_owned(),
                sequence: event.sequence(),
            });
        }

        let tail: Option<(i64, String)> = transaction
            .query_row(
                "SELECT sequence, event_hash FROM sentrdel_asel_events WHERE session_id = ?1 ORDER BY sequence DESC LIMIT 1",
                params![event.session_id()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let expected_sequence = match tail.as_ref() {
            None => 0,
            Some((last_sequence, _)) => last_sequence
                .checked_add(1)
                .ok_or(AselStoreError::EventCountOutOfRange)?,
        };
        if sequence != expected_sequence {
            return Err(AselStoreError::SequenceMismatch {
                session_id: event.session_id().to_owned(),
                expected: u64::try_from(expected_sequence)
                    .map_err(|_| AselStoreError::EventCountOutOfRange)?,
                found: event.sequence(),
            });
        }

        let expected_previous = tail.as_ref().map(|(_, hash)| hash.as_str());
        if event.previous_event_hash() != expected_previous {
            return Err(AselStoreError::PreviousHashMismatch {
                session_id: event.session_id().to_owned(),
                sequence: event.sequence(),
            });
        }

        let inserted = transaction.execute(
            "INSERT INTO sentrdel_asel_events(session_id, sequence, event_hash, previous_event_hash, canonical_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                record.session_id,
                sequence,
                record.event_hash,
                record.previous_event_hash,
                canonical
            ],
        )?;
        if inserted != 1 {
            return Err(AselStoreError::CorruptStoredEvent {
                session_id: event.session_id().to_owned(),
                sequence: event.sequence(),
                detail: "append did not create exactly one ASEL row",
            });
        }

        transaction.commit()?;
        Ok(true)
    }

    /// Return one persisted wire record after canonical-byte, row-identity, and
    /// event-hash checks. The record remains untrusted with respect to embedded
    /// policy authority; callers must separately rebind policy decisions.
    pub fn get_asel_event_record(
        &self,
        session_id: &str,
        sequence: u64,
    ) -> AselStoreResult<Option<AgentSecurityEventRecord>> {
        let sqlite_sequence = sqlite_sequence(sequence)?;
        let row: Option<StoredAselRow> = self
            .connection
            .query_row(
                "SELECT session_id, sequence, event_hash, previous_event_hash, canonical_json FROM sentrdel_asel_events WHERE session_id = ?1 AND sequence = ?2",
                params![session_id, sqlite_sequence],
                stored_row,
            )
            .optional()?;
        row.map(|row| validate_stored_row(&row, session_id, sequence))
            .transpose()
    }

    /// Count locally available events for one session. Count alone is not an
    /// integrity or trust claim; use `verify_asel_session` for chain validation.
    pub fn asel_event_count(&self, session_id: &str) -> AselStoreResult<u64> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM sentrdel_asel_events WHERE session_id = ?1",
            params![session_id],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| AselStoreError::EventCountOutOfRange)
    }

    /// Return the locally available tail hash. This is not a trusted checkpoint
    /// and must not be presented as tamper-proof provenance.
    pub fn asel_session_head(&self, session_id: &str) -> AselStoreResult<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT event_hash FROM sentrdel_asel_events WHERE session_id = ?1 ORDER BY sequence DESC LIMIT 1",
                params![session_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Verify the complete locally available session chain.
    ///
    /// `NoTrustedHead` means the available chain is internally consistent only.
    /// `ValidRelativeToProvidedHead` is returned only when the caller supplies an
    /// expected checkpoint that exactly matches the verified local tail. This API
    /// does not authenticate embedded policy decisions; their authority binding
    /// remains a separate schema-layer operation.
    pub fn verify_asel_session(
        &self,
        session_id: &str,
        trusted_head: Option<&str>,
    ) -> AselStoreResult<SessionVerification> {
        let mut statement = self.connection.prepare(
            "SELECT session_id, sequence, event_hash, previous_event_hash, canonical_json FROM sentrdel_asel_events WHERE session_id = ?1 ORDER BY sequence ASC",
        )?;
        let rows = statement.query_map(params![session_id], stored_row)?;
        let stored: Vec<StoredAselRow> = rows.collect::<Result<_, _>>()?;

        if stored.is_empty() {
            return Ok(SessionVerification {
                integrity: SessionIntegrity::EmptySession,
                event_count: 0,
                session_id: None,
                computed_head: None,
            });
        }

        let event_count =
            u64::try_from(stored.len()).map_err(|_| AselStoreError::EventCountOutOfRange)?;
        let available_head = stored.last().map(|row| row.event_hash.clone());
        let mut expected_previous: Option<String> = None;

        for (index, row) in stored.iter().enumerate() {
            let expected_sequence =
                u64::try_from(index).map_err(|_| AselStoreError::EventCountOutOfRange)?;
            let row_sequence = match u64::try_from(row.sequence) {
                Ok(sequence) => sequence,
                Err(_) => {
                    return Ok(session_verification(
                        SessionIntegrity::SequenceGap,
                        event_count,
                        session_id,
                        available_head,
                    ));
                }
            };
            let record = decode_canonical_record(row, session_id, row_sequence)?;

            if row.session_id != session_id || record.session_id != session_id {
                return Ok(session_verification(
                    SessionIntegrity::SessionMismatch,
                    event_count,
                    session_id,
                    available_head,
                ));
            }
            if row_sequence != expected_sequence || record.sequence != row_sequence {
                return Ok(session_verification(
                    SessionIntegrity::SequenceGap,
                    event_count,
                    session_id,
                    available_head,
                ));
            }
            if record.event_hash != row.event_hash
                || record_content_hash(&record)? != record.event_hash
            {
                return Ok(session_verification(
                    SessionIntegrity::HashMismatch,
                    event_count,
                    session_id,
                    available_head,
                ));
            }
            if record.previous_event_hash != row.previous_event_hash
                || record.previous_event_hash.as_deref() != expected_previous.as_deref()
            {
                return Ok(session_verification(
                    SessionIntegrity::PreviousHashMismatch,
                    event_count,
                    session_id,
                    available_head,
                ));
            }

            expected_previous = Some(record.event_hash);
        }

        let integrity = match (trusted_head, available_head.as_deref()) {
            (Some(expected), Some(actual)) if expected == actual => {
                SessionIntegrity::ValidRelativeToProvidedHead
            }
            (Some(_), Some(_)) => SessionIntegrity::TrustedHeadMismatch,
            (None, Some(_)) => SessionIntegrity::NoTrustedHead,
            _ => SessionIntegrity::EmptySession,
        };

        Ok(SessionVerification {
            integrity,
            event_count,
            session_id: Some(session_id.to_owned()),
            computed_head: available_head,
        })
    }
}

fn sqlite_sequence(sequence: u64) -> AselStoreResult<i64> {
    i64::try_from(sequence).map_err(|_| AselStoreError::SequenceOutOfRange { sequence })
}

fn stored_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAselRow> {
    Ok(StoredAselRow {
        session_id: row.get(0)?,
        sequence: row.get(1)?,
        event_hash: row.get(2)?,
        previous_event_hash: row.get(3)?,
        canonical_json: row.get(4)?,
    })
}

fn validate_stored_row(
    row: &StoredAselRow,
    expected_session_id: &str,
    expected_sequence: u64,
) -> AselStoreResult<AgentSecurityEventRecord> {
    let row_sequence =
        u64::try_from(row.sequence).map_err(|_| AselStoreError::CorruptStoredEvent {
            session_id: expected_session_id.to_owned(),
            sequence: expected_sequence,
            detail: "row sequence is negative or out of range",
        })?;
    let record = decode_canonical_record(row, expected_session_id, expected_sequence)?;
    if row.session_id != expected_session_id
        || record.session_id != expected_session_id
        || row_sequence != expected_sequence
        || record.sequence != expected_sequence
    {
        return Err(AselStoreError::CorruptStoredEvent {
            session_id: expected_session_id.to_owned(),
            sequence: expected_sequence,
            detail: "row key does not match canonical event identity",
        });
    }
    if record.event_hash != row.event_hash || record_content_hash(&record)? != record.event_hash {
        return Err(AselStoreError::CorruptStoredEvent {
            session_id: expected_session_id.to_owned(),
            sequence: expected_sequence,
            detail: "event hash does not match canonical event content",
        });
    }
    if record.previous_event_hash != row.previous_event_hash {
        return Err(AselStoreError::CorruptStoredEvent {
            session_id: expected_session_id.to_owned(),
            sequence: expected_sequence,
            detail: "row previous hash does not match canonical event content",
        });
    }
    validate_record_shape(&record, expected_session_id, expected_sequence)?;
    Ok(record)
}

fn decode_canonical_record(
    row: &StoredAselRow,
    session_id: &str,
    sequence: u64,
) -> AselStoreResult<AgentSecurityEventRecord> {
    let record: AgentSecurityEventRecord = serde_json::from_slice(&row.canonical_json)?;
    let recanonical = canonical_json_bytes(&record)?;
    if recanonical != row.canonical_json {
        return Err(AselStoreError::CorruptStoredEvent {
            session_id: session_id.to_owned(),
            sequence,
            detail: "stored bytes are not canonical for AgentSecurityEventRecord",
        });
    }
    validate_record_shape(&record, session_id, sequence)?;
    Ok(record)
}

fn validate_record_shape(
    record: &AgentSecurityEventRecord,
    session_id: &str,
    sequence: u64,
) -> AselStoreResult<()> {
    let invalid = record.schema_version != SCHEMA_V1
        || record.session_id.trim().is_empty()
        || record.actor.id.trim().is_empty()
        || (record.sequence == 0 && record.previous_event_hash.is_some())
        || (record.sequence > 0 && record.previous_event_hash.is_none());
    if invalid {
        return Err(AselStoreError::CorruptStoredEvent {
            session_id: session_id.to_owned(),
            sequence,
            detail: "canonical event violates the R1 ASEL structural contract",
        });
    }
    Ok(())
}

fn session_verification(
    integrity: SessionIntegrity,
    event_count: u64,
    session_id: &str,
    computed_head: Option<String>,
) -> SessionVerification {
    SessionVerification {
        integrity,
        event_count,
        session_id: Some(session_id.to_owned()),
        computed_head,
    }
}

#[derive(Serialize)]
struct StoredPolicyDecisionHashView<'a> {
    decision_id: &'a str,
    authority_id: &'a str,
    authority_configuration_digest: &'a str,
    #[serde(flatten)]
    claim: &'a PolicyDecisionClaim,
}

impl<'a> From<&'a PolicyDecisionRecord> for StoredPolicyDecisionHashView<'a> {
    fn from(record: &'a PolicyDecisionRecord) -> Self {
        Self {
            decision_id: &record.decision_id,
            authority_id: &record.authority_id,
            authority_configuration_digest: &record.authority_configuration_digest,
            claim: &record.claim,
        }
    }
}

#[derive(Serialize)]
struct StoredEventHashView<'a> {
    schema_version: &'a str,
    session_id: &'a str,
    sequence: u64,
    timestamp: &'a str,
    actor: &'a Actor,
    kind: &'a EventKind,
    intent_digest: &'a Option<String>,
    target: &'a BTreeMap<String, String>,
    params_digest: &'a Option<String>,
    result_digest: &'a Option<String>,
    policy_decision: Option<StoredPolicyDecisionHashView<'a>>,
    provenance: &'a BTreeMap<String, String>,
    previous_event_hash: &'a Option<String>,
}

fn record_content_hash(record: &AgentSecurityEventRecord) -> Result<String, CanonicalError> {
    content_id(
        "asel-event",
        &StoredEventHashView {
            schema_version: &record.schema_version,
            session_id: &record.session_id,
            sequence: record.sequence,
            timestamp: &record.timestamp,
            actor: &record.actor,
            kind: &record.kind,
            intent_digest: &record.intent_digest,
            target: &record.target,
            params_digest: &record.params_digest,
            result_digest: &record.result_digest,
            policy_decision: record
                .policy_decision
                .as_ref()
                .map(StoredPolicyDecisionHashView::from),
            provenance: &record.provenance,
            previous_event_hash: &record.previous_event_hash,
        },
    )
}
