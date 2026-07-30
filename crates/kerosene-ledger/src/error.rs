use crate::account::StandardAccount;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LedgerError {
    #[error("unbalanced entry: debits {debits_sum} != credits {credits_sum}")]
    UnbalancedEntry { debits_sum: u128, credits_sum: u128 },

    #[error("entry must have at least one debit and one credit")]
    EmptyEntry,

    #[error("negative balance for {account:?}: {balance}")]
    NegativeBalance {
        account: StandardAccount,
        balance: i128,
    },

    #[error("duplicate sequence: {0}")]
    DuplicateSequence(u64),

    #[error("sequence gap: expected {expected}, got {got}")]
    SequenceGap { expected: u64, got: u64 },

    #[error("account not found: {0:?}")]
    AccountNotFound(StandardAccount),

    #[error("invalid hash: {0}")]
    InvalidHash(String),

    #[error("invariant violation: {0}")]
    InvariantViolation(String),

    #[error("reserved {reserved} exceeds available {available}")]
    ReservedExceedsAvailable { reserved: u64, available: u64 },

    #[error("pending outgoing {outgoing} exceeds internal available {available}")]
    PendingOutgoingExceedsAvailable { outgoing: u64, available: u64 },

    #[error("state version regression: previous {prev}, current {current}")]
    StateVersionRegression { prev: u64, current: u64 },

    #[error("balance overflow for account {account:?}")]
    BalanceOverflow { account: StandardAccount },

    #[error("duplicate entry id: {0}")]
    DuplicateEntryId(String),

    // -----------------------------------------------------------------------
    // Wave 2 — Optimistic versioning, atomic reservations, durable idempotency
    // -----------------------------------------------------------------------
    #[error("version conflict: account {account} expected version {expected}, current {current}")]
    VersionConflict {
        account: String,
        expected: u64,
        current: u64,
    },

    #[error("insufficient funds: account {account} has {available}, needs {needed}")]
    InsufficientFunds {
        account: String,
        available: u64,
        needed: u64,
    },

    #[error("idempotency conflict: command {command_id} with different hash")]
    IdempotencyConflict { command_id: String },

    #[error("reservation not found: {0}")]
    ReservationNotFound(String),

    #[error("reservation already consumed: {0}")]
    ReservationAlreadyConsumed(String),

    #[error("reservation expired: {0}")]
    ReservationExpired(String),

    #[error("atomic transfer failed: {0}")]
    AtomicTransferFailed(String),

    // -----------------------------------------------------------------------
    // Wave 3 — Deterministic state machine, state roots, certificates
    // -----------------------------------------------------------------------
    #[error("unknown command type: {0}")]
    UnknownCommand(String),

    #[error("invalid state transition: {0}")]
    InvalidStateTransition(String),

    #[error("snapshot not found at sequence {0}")]
    SnapshotNotFound(u64),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("state root mismatch: expected {expected}, got {got}")]
    StateRootMismatch { expected: String, got: String },

    // -----------------------------------------------------------------------
    // Wave 4 — Ordered replication, sync status, node recovery & membership
    // -----------------------------------------------------------------------
    #[error("sync not healthy: {0}")]
    SyncNotHealthy(String),

    #[error("node {node_id} is not a voter (role: {role:?})")]
    NotAVoter {
        node_id: String,
        role: crate::membership::NodeRole,
    },

    #[error("cannot vote: {}", .reasons.join(", "))]
    CannotVote { reasons: Vec<String> },

    #[error("node not found: {0}")]
    NodeNotFound(String),

    #[error("invalid role transition: from {from:?} to {to:?}")]
    InvalidRoleTransition {
        from: crate::membership::NodeRole,
        to: crate::membership::NodeRole,
    },

    // -----------------------------------------------------------------------
    // Wave 5 — UTXOs, chain observer, RBF, reorganizations
    // -----------------------------------------------------------------------
    #[error("utxo not found: {txid}:{vout}")]
    UtxoNotFound { txid: String, vout: u32 },

    #[error("invalid utxo transition: from {from:?} to {to:?}")]
    InvalidUtxoTransition {
        from: crate::chain::OnchainState,
        to: crate::chain::OnchainState,
    },

    #[error("utxo already reserved by {reserved_by}")]
    UtxoAlreadyReserved { reserved_by: String },

    #[error("utxo not reserved")]
    UtxoNotReserved,

    #[error("invalid utxo data: {0}")]
    InvalidUtxoData(String),

    // -----------------------------------------------------------------------
    // Wave 6 — Settlement authorization, PSBT binding, vault validation
    // -----------------------------------------------------------------------
    #[error("authorization expired at {expires_at}, current time {now}")]
    AuthorizationExpired { expires_at: u64, now: u64 },

    #[error("authorization invalid: {0}")]
    AuthorizationInvalid(String),

    #[error("PSBT hash mismatch: expected {expected}, got {got}")]
    PsbtMismatch { expected: String, got: String },

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("withdrawal not found: {0}")]
    WithdrawalNotFound(String),

    // -----------------------------------------------------------------------
    // Wave 7 — Reconciliation, metrics, production gates
    // -----------------------------------------------------------------------
    #[error("gate blocked: {reason}")]
    GateBlocked { reason: String },
}
