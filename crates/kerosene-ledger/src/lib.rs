pub mod account;
pub mod account_state;
pub mod balance;
pub mod certificate;
pub mod chain;
pub mod command;
pub mod double_entry;
pub mod error;
pub mod gates;
pub mod idempotency;
pub mod in_memory;
pub mod invariants;
pub mod membership;
pub mod metrics;
pub mod nonce;
pub mod observer;
pub mod persistent;
pub mod reconciliation;
pub mod replication;
pub mod reservation;
pub mod settlement;
pub mod snapshot;
pub mod state_machine;
pub mod state_root;
pub mod traits;
pub mod utxo_store;
pub mod wallet;
pub mod withdrawal;

pub use account::{AccountClass, StandardAccount};
pub use account_state::AccountState;
pub use balance::AccountBalanceState;
pub use certificate::{CertifiedSnapshot, Checkpoint, NodeSignature, QuorumCertificate};
pub use chain::{
    apply_rbf_replacement, compute_utxo_root, ChainObservationType, DetectUtxoPayload, Observation,
    OnchainState, OutPoint, ReorgHandler, ReorgPayload, UtxoEntry, UtxoSet, UtxoTransitionGate,
};
pub use command::{BalanceCommand, BalanceOperation, InternalTransferCommand};
pub use double_entry::{
    AccountBalance, InMemoryLedger, JournalEntry, JournalReceipt, LedgerPort, Posting,
};
pub use error::LedgerError;
pub use gates::{DegradedMode, GateResult, ProductionGates};
pub use idempotency::IdempotencyRecord;
pub use in_memory::{
    InMemoryIdempotencyStore, InMemoryReservationStore, InMemoryVersionedAccountStore,
};
pub use membership::{
    validate_role_transition, AdmissionFlow, InMemoryMembershipStore, MembershipGate,
    MembershipStore, NodeMembership, NodeRole, VotingGate,
};
pub use metrics::{BasicMetricsCollector, LedgerMetrics, MetricsCollector};
pub use observer::ChainObserverPort;
pub use reconciliation::{
    ReconciliationEngine, ReconciliationInputs, ReconciliationReport, ReconciliationStatus,
};
pub use replication::{
    can_vote, execute_catch_up, recover_divergence, CatchUpPlan, CatchUpStrategy, DivergenceReport,
    DivergenceResult, ReplicationStatus, SyncManager, SyncStatus, DIVERGENCE_CHECK_INTERVAL,
    MAX_REPLAY_COMMANDS,
};
pub use reservation::{Reservation, ReservationState};
pub use snapshot::{InMemorySnapshotStore, SnapshotStore};
pub use state_machine::{
    ConsensusProfile, DeterministicStateMachine, LedgerCommand, LedgerCommandType, LedgerState,
    MembershipView, StateMachine, StateTransitionReceipt,
};
pub use state_root::compute_state_root;
pub use traits::{IdempotencyStore, ReservationStore, VersionedAccountStore};
pub use utxo_store::{InMemoryUtxoStore, UtxoStore};
pub use wallet::{BalanceView, WalletControl};

// Persistent sled-backed stores (production-ready)
pub use persistent::{
    SledIdempotencyStore, SledLedgerDb, SledMembershipStore, SledNonceChecker,
    SledReservationStore, SledSnapshotStore, SledUtxoStore, SledVersionedAccountStore,
    SledWithdrawalStore,
};

// Wave 6 — Settlement authorization, PSBT binding, withdrawal lifecycle
pub use nonce::{InMemoryNonceChecker, NonceChecker};
pub use settlement::{
    NonceChecker as SyncNonceChecker, PsbtCommitment, SettlementAuthorization, SettlementPolicy,
    SettlementValidator, VaultAuthorizationVerifier, VaultVerificationError,
};
pub use withdrawal::{
    InMemoryWithdrawalStore, WithdrawalRecord, WithdrawalStatus, WithdrawalStore,
};

#[cfg(test)]
mod tests;
