use serde::{Deserialize, Serialize};

/// An idempotency record that prevents duplicate command execution.
///
/// # Rules
/// - Same `command_id` + same `command_hash` → return existing result
/// - Same `command_id` + different `command_hash` → reject as `IdempotencyConflict`
/// - Client timeout never authorizes re-execution
/// - Replay via another server must produce same result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    /// Unique command identifier (supplied by the client).
    pub command_id: String,
    /// Hash of the command payload (for detecting replay with different payloads).
    pub command_hash: String,
    /// Hash of the result produced by executing this command.
    pub result_hash: String,
    /// Sequence number of the journal entry that committed this command.
    pub committed_sequence: u64,
    /// Hash of the resulting state root after applying the command.
    pub resulting_state_root: String,
}

impl IdempotencyRecord {
    /// Creates a new idempotency record.
    pub fn new(
        command_id: impl Into<String>,
        command_hash: impl Into<String>,
        result_hash: impl Into<String>,
        committed_sequence: u64,
        resulting_state_root: impl Into<String>,
    ) -> Self {
        Self {
            command_id: command_id.into(),
            command_hash: command_hash.into(),
            result_hash: result_hash.into(),
            committed_sequence,
            resulting_state_root: resulting_state_root.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_idempotency_record() {
        let rec = IdempotencyRecord::new(
            "cmd-1",
            "hash-abc",
            "result-xyz",
            42,
            "root-123",
        );
        assert_eq!(rec.command_id, "cmd-1");
        assert_eq!(rec.command_hash, "hash-abc");
        assert_eq!(rec.result_hash, "result-xyz");
        assert_eq!(rec.committed_sequence, 42);
        assert_eq!(rec.resulting_state_root, "root-123");
    }

    #[test]
    fn idempotency_record_serde_roundtrip() {
        let rec = IdempotencyRecord::new(
            "cmd-1",
            "hash-abc",
            "result-xyz",
            1,
            "root-123",
        );
        let json = serde_json::to_string(&rec).unwrap();
        let deserialized: IdempotencyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, deserialized);
    }
}
