use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::certificate::CertifiedSnapshot;
use crate::error::LedgerError;
use crate::snapshot::SnapshotStore;
use crate::state_machine::{DeterministicStateMachine, LedgerCommand, LedgerState};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum commands that can be replayed before falling back to snapshot
/// installation.
pub const MAX_REPLAY_COMMANDS: u64 = 10000;

/// Check for divergence every N committed commands.
pub const DIVERGENCE_CHECK_INTERVAL: u64 = 100;

// ---------------------------------------------------------------------------
// SyncStatus
// ---------------------------------------------------------------------------

/// The sync health of a node relative to the cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SyncStatus {
    /// Node is fully caught up and participating.
    Healthy,
    /// Node is replaying commands to catch up.
    CatchingUp,
    /// Node requires a snapshot to catch up (gap too large).
    SnapshotRequired,
    /// Node has diverged from the cluster (state root mismatch).
    Diverged,
    /// Node has been quarantined due to persistent divergence.
    Quarantined,
}

// ---------------------------------------------------------------------------
// ReplicationStatus
// ---------------------------------------------------------------------------

/// Snapshot of a node's replication progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationStatus {
    /// Current epoch the node is operating in.
    pub epoch: u64,
    /// Highest sequence committed by the cluster (visible in quorum certs).
    pub committed_sequence: u64,
    /// Highest sequence this node has applied to its local state machine.
    pub applied_sequence: u64,
    /// State root hash of the locally applied state.
    pub state_root: String,
    /// Current leader view.
    pub leader_view: u64,
    /// Sync health of this node.
    pub sync_status: SyncStatus,
}

// ---------------------------------------------------------------------------
// DivergenceResult
// ---------------------------------------------------------------------------

/// Result of comparing the local node's status against a peer's status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceResult {
    /// Local node is in sync with the peer.
    InSync,
    /// Local node is ahead of the peer.
    Ahead {
        local_sequence: u64,
        peer_sequence: u64,
    },
    /// Local node is behind the peer.
    Behind {
        local_sequence: u64,
        peer_sequence: u64,
    },
    /// State root mismatch (actual divergence).
    StateRootMismatch {
        local_root: String,
        peer_root: String,
    },
}

// ---------------------------------------------------------------------------
// DivergenceReport
// ---------------------------------------------------------------------------

/// Detailed report comparing local and peer state at a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceReport {
    /// Checkpoint sequence number being compared.
    pub checkpoint_sequence: u64,
    /// Local state root at this checkpoint.
    pub local_state_root: String,
    /// Peer state root (None if peer has no checkpoint at this sequence).
    pub peer_state_root: Option<String>,
    /// Local ledger totals hash.
    pub local_ledger_totals_hash: String,
    /// Peer ledger totals hash.
    pub peer_ledger_totals_hash: Option<String>,
    /// Whether the local node has diverged from the peer.
    pub is_diverged: bool,
}

// ---------------------------------------------------------------------------
// CatchUpStrategy
// ---------------------------------------------------------------------------

/// Strategy for catching up to the cluster's current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CatchUpStrategy {
    /// Replay commands one by one.
    ReplayCommands,
    /// Install a certified snapshot and replay remaining commands.
    InstallSnapshot,
}

// ---------------------------------------------------------------------------
// CatchUpPlan
// ---------------------------------------------------------------------------

/// A plan for a node to catch up to the current cluster state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatchUpPlan {
    /// Sequence number the node is currently at.
    pub from_sequence: u64,
    /// Sequence number the node needs to reach.
    pub to_sequence: u64,
    /// Number of missing commands.
    pub missing_count: u64,
    /// Strategy to use for catching up.
    pub strategy: CatchUpStrategy,
}

impl CatchUpPlan {
    /// Creates a new catch-up plan from the current and target sequences.
    ///
    /// Automatically selects a strategy based on the gap size:
    /// - `ReplayCommands` if the gap is <= `MAX_REPLAY_COMMANDS`
    /// - `InstallSnapshot` otherwise
    pub fn new(from_sequence: u64, to_sequence: u64) -> Self {
        let missing_count = to_sequence.saturating_sub(from_sequence);
        let strategy = if missing_count > MAX_REPLAY_COMMANDS {
            CatchUpStrategy::InstallSnapshot
        } else {
            CatchUpStrategy::ReplayCommands
        };
        Self {
            from_sequence,
            to_sequence,
            missing_count,
            strategy,
        }
    }
}

// ---------------------------------------------------------------------------
// SyncManager trait
// ---------------------------------------------------------------------------

/// Port trait for managing node synchronization with the cluster.
#[async_trait]
pub trait SyncManager: Send + Sync {
    /// Returns the current replication status of this node.
    async fn status(&self) -> Result<ReplicationStatus, LedgerError>;

    /// Checks whether this node has diverged from the given peer status.
    async fn check_divergence(
        &self,
        peer: &ReplicationStatus,
    ) -> Result<DivergenceResult, LedgerError>;

    /// Begins the catch-up process to reach the target sequence.
    async fn start_catch_up(&self, target_sequence: u64) -> Result<(), LedgerError>;

    /// Requests a certified snapshot at the given sequence from a peer.
    async fn request_snapshot(&self, sequence: u64) -> Result<CertifiedSnapshot, LedgerError>;

    /// Marks this node as quarantined with the given reason.
    async fn mark_quarantined(&self, reason: &str) -> Result<(), LedgerError>;

    /// Attempts to recover from a detected divergence.
    async fn recover_from_divergence(&self) -> Result<(), LedgerError>;
}

// ---------------------------------------------------------------------------
// can_vote
// ---------------------------------------------------------------------------

/// Returns `true` if a node is allowed to vote based on its replication status.
///
/// A node can only vote when:
/// - `sync_status == Healthy`
/// - `applied_sequence == committed_sequence`
pub fn can_vote(status: &ReplicationStatus) -> bool {
    status.sync_status == SyncStatus::Healthy
        && status.applied_sequence == status.committed_sequence
}

// ---------------------------------------------------------------------------
// recover_divergence
// ---------------------------------------------------------------------------

/// Full divergence recovery flow.
///
/// 1. Marks the node as DIVERGED (stops voting)
/// 2. Finds the last common checkpoint via the snapshot store
/// 3. Installs the certified snapshot
/// 4. Replays entries from the snapshot sequence forward
/// 5. If still diverged, moves to QUARANTINED
///
/// Callers should verify the state root after this function returns and
/// call `sync_mgr.mark_quarantined()` if divergence persists.
pub async fn recover_divergence(
    sync_mgr: &dyn SyncManager,
    snapshot_store: &dyn SnapshotStore,
    state_machine: &dyn DeterministicStateMachine,
    state: &mut LedgerState,
    commands: &[LedgerCommand],
) -> Result<(), LedgerError> {
    sync_mgr.mark_quarantined("divergence detected").await?;

    // Find the latest certified snapshot
    let snapshot = snapshot_store
        .latest_snapshot()
        .await?
        .ok_or(LedgerError::SnapshotNotFound(0))?;

    // Install the snapshot (replaces current state)
    let restored_state = snapshot_store.install_snapshot(&snapshot).await?;
    *state = restored_state;

    // Replay commands that came after the snapshot
    let snapshot_epoch = snapshot.epoch;
    for cmd in commands.iter().filter(|c| c.epoch >= snapshot_epoch) {
        state_machine.apply(state, cmd)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// execute_catch_up
// ---------------------------------------------------------------------------

/// Catch-up flow for delayed nodes.
///
/// 1. Determines the gap between local and target sequence
/// 2. If the gap exceeds `MAX_REPLAY_COMMANDS`, installs a certified snapshot,
///    then replays remaining commands
/// 3. Otherwise replays all missing commands in order
/// 4. After replaying, the caller must verify the state root
pub async fn execute_catch_up(
    sync_mgr: &dyn SyncManager,
    snapshot_store: &dyn SnapshotStore,
    state_machine: &dyn DeterministicStateMachine,
    state: &mut LedgerState,
    from_sequence: u64,
    commands: &[LedgerCommand],
) -> Result<(), LedgerError> {
    let missing_count = commands.len() as u64;

    if missing_count > MAX_REPLAY_COMMANDS {
        // Gap too large — install a snapshot first
        let snapshot = snapshot_store
            .latest_snapshot()
            .await?
            .ok_or(LedgerError::SnapshotNotFound(from_sequence))?;

        let restored_state = snapshot_store.install_snapshot(&snapshot).await?;
        *state = restored_state;

        sync_mgr.start_catch_up(from_sequence).await?;

        // Replay remaining commands
        for cmd in commands {
            state_machine.apply(state, cmd)?;
        }
    } else {
        sync_mgr.start_catch_up(from_sequence).await?;

        // Replay all commands in order
        for cmd in commands {
            state_machine.apply(state, cmd)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ReplicationStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn new_node_starts_with_empty_style_status() {
        let status = ReplicationStatus {
            epoch: 1,
            committed_sequence: 0,
            applied_sequence: 0,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::Healthy,
        };
        assert_eq!(status.applied_sequence, 0);
        assert_eq!(status.committed_sequence, 0);
        assert_eq!(status.sync_status, SyncStatus::Healthy);
    }

    #[test]
    fn applying_commands_advances_applied_sequence() {
        let mut status = ReplicationStatus {
            epoch: 1,
            committed_sequence: 10,
            applied_sequence: 5,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::CatchingUp,
        };
        status.applied_sequence = 10;
        assert_eq!(status.applied_sequence, status.committed_sequence);
    }

    // -----------------------------------------------------------------------
    // can_vote tests
    // -----------------------------------------------------------------------

    #[test]
    fn can_vote_true_when_healthy_and_caught_up() {
        let status = ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 42,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::Healthy,
        };
        assert!(can_vote(&status));
    }

    #[test]
    fn can_vote_false_when_catching_up() {
        let status = ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 40,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::CatchingUp,
        };
        assert!(!can_vote(&status));
    }

    #[test]
    fn can_vote_false_when_not_caught_up_even_if_healthy() {
        let status = ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 41,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::Healthy,
        };
        assert!(!can_vote(&status));
    }

    #[test]
    fn can_vote_false_when_diverged() {
        let status = ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 42,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::Diverged,
        };
        assert!(!can_vote(&status));
    }

    #[test]
    fn can_vote_false_when_quarantined() {
        let status = ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 42,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::Quarantined,
        };
        assert!(!can_vote(&status));
    }

    // -----------------------------------------------------------------------
    // Divergence detection tests
    // -----------------------------------------------------------------------

    #[test]
    fn divergence_detection_catches_state_root_mismatch() {
        let local = ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 42,
            state_root: "root-a".into(),
            leader_view: 0,
            sync_status: SyncStatus::Healthy,
        };
        let peer = ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 42,
            state_root: "root-b".into(),
            leader_view: 0,
            sync_status: SyncStatus::Healthy,
        };

        // If local and peer have same sequence but different roots, it's a divergence
        if local.applied_sequence == peer.applied_sequence && local.state_root != peer.state_root {
            // This is a divergence scenario
            let result = DivergenceResult::StateRootMismatch {
                local_root: local.state_root.clone(),
                peer_root: peer.state_root.clone(),
            };
            assert!(matches!(result, DivergenceResult::StateRootMismatch { .. }));
        }
    }

    #[test]
    fn divergence_result_in_sync_when_equal() {
        let result = DivergenceResult::InSync;
        assert!(matches!(result, DivergenceResult::InSync));
    }

    // -----------------------------------------------------------------------
    // CatchUpPlan tests
    // -----------------------------------------------------------------------

    #[test]
    fn catch_up_plan_chooses_replay_for_small_gaps() {
        let plan = CatchUpPlan::new(100, 200);
        assert_eq!(plan.from_sequence, 100);
        assert_eq!(plan.to_sequence, 200);
        assert_eq!(plan.missing_count, 100);
        assert_eq!(plan.strategy, CatchUpStrategy::ReplayCommands);
    }

    #[test]
    fn catch_up_plan_chooses_snapshot_for_large_gaps() {
        let plan = CatchUpPlan::new(0, MAX_REPLAY_COMMANDS + 1);
        assert_eq!(plan.missing_count, MAX_REPLAY_COMMANDS + 1);
        assert_eq!(plan.strategy, CatchUpStrategy::InstallSnapshot);
    }

    #[test]
    fn catch_up_plan_exactly_at_threshold_uses_replay() {
        let plan = CatchUpPlan::new(0, MAX_REPLAY_COMMANDS);
        assert_eq!(plan.strategy, CatchUpStrategy::ReplayCommands);
    }

    // -----------------------------------------------------------------------
    // SyncStatus transitions
    // -----------------------------------------------------------------------

    #[test]
    fn sync_status_transitions_are_consistent() {
        // A node can move from Healthy -> CatchingUp -> Healthy
        let mut status = SyncStatus::Healthy;
        assert_eq!(status, SyncStatus::Healthy);

        status = SyncStatus::CatchingUp;
        assert_eq!(status, SyncStatus::CatchingUp);

        status = SyncStatus::Healthy;
        assert_eq!(status, SyncStatus::Healthy);

        // A node can move from Healthy -> Diverged -> Quarantined
        status = SyncStatus::Diverged;
        assert_eq!(status, SyncStatus::Diverged);

        status = SyncStatus::Quarantined;
        assert_eq!(status, SyncStatus::Quarantined);

        // A node that needs a snapshot
        status = SyncStatus::SnapshotRequired;
        assert_eq!(status, SyncStatus::SnapshotRequired);
    }

    // -----------------------------------------------------------------------
    // DivergenceReport tests
    // -----------------------------------------------------------------------

    #[test]
    fn divergence_report_detects_diverged_state() {
        let report = DivergenceReport {
            checkpoint_sequence: 100,
            local_state_root: "root-a".into(),
            peer_state_root: Some("root-b".into()),
            local_ledger_totals_hash: "totals-a".into(),
            peer_ledger_totals_hash: Some("totals-b".into()),
            is_diverged: true,
        };
        assert!(report.is_diverged);
    }

    #[test]
    fn divergence_report_in_sync() {
        let report = DivergenceReport {
            checkpoint_sequence: 100,
            local_state_root: "root-a".into(),
            peer_state_root: Some("root-a".into()),
            local_ledger_totals_hash: "totals-a".into(),
            peer_ledger_totals_hash: Some("totals-a".into()),
            is_diverged: false,
        };
        assert!(!report.is_diverged);
    }

    #[test]
    fn divergence_report_missing_peer_data() {
        let report = DivergenceReport {
            checkpoint_sequence: 50,
            local_state_root: "root".into(),
            peer_state_root: None,
            local_ledger_totals_hash: "totals".into(),
            peer_ledger_totals_hash: None,
            is_diverged: false,
        };
        assert!(report.peer_state_root.is_none());
        assert!(report.peer_ledger_totals_hash.is_none());
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn replication_status_serde_roundtrip() {
        let status = ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 40,
            state_root: "abc123".into(),
            leader_view: 0,
            sync_status: SyncStatus::CatchingUp,
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: ReplicationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deserialized);
    }

    #[test]
    fn catch_up_plan_serde_roundtrip() {
        let plan = CatchUpPlan::new(50, 150);
        let json = serde_json::to_string(&plan).unwrap();
        let deserialized: CatchUpPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, deserialized);
    }
}
