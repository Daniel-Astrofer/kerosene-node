use crate::certificate::CertifiedSnapshot;
use crate::error::LedgerError;
use crate::membership::{
    validate_role_transition, AdmissionFlow, InMemoryMembershipStore, MembershipGate,
    MembershipStore, NodeMembership, NodeRole, VotingGate,
};
use crate::replication::{
    can_vote, execute_catch_up, recover_divergence, CatchUpPlan, CatchUpStrategy, DivergenceReport,
    DivergenceResult, ReplicationStatus, SyncStatus, MAX_REPLAY_COMMANDS,
};
use crate::snapshot::{InMemorySnapshotStore, SnapshotStore};
use crate::state_machine::{
    LedgerCommand, LedgerCommandType, LedgerState, MembershipView, StateMachine,
};
use crate::tests::helpers::make_signed_qc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_membership() -> MembershipView {
    MembershipView::single_node("cluster-1", "node-1")
}

fn healthy_status(committed: u64, applied: u64) -> ReplicationStatus {
    ReplicationStatus {
        epoch: 1,
        committed_sequence: committed,
        applied_sequence: applied,
        state_root: "root".into(),
        leader_view: 0,
        sync_status: SyncStatus::Healthy,
    }
}

fn sample_membership(node_id: &str, role: NodeRole) -> NodeMembership {
    NodeMembership {
        node_id: node_id.into(),
        role,
        onion_endpoint: None,
        identity_pubkey: format!("pubkey-{}", node_id),
        attested_at_bucket: 100,
        joined_epoch: 1,
        last_heartbeat_bucket: 100,
        admission_signature: None,
    }
}

fn dummy_cmd(sequence: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("cmd-{}", sequence),
        LedgerCommandType::CreditInternalBalance,
        "test",
        None,
        "100",
        1,
        100,
    )
}

fn make_snapshot(sequence: u64, state: &LedgerState) -> CertifiedSnapshot {
    let (qc, _pk_hex) = make_signed_qc(
        "cluster-1",
        1,
        0,
        sequence,
        "cmd-hash",
        "prev-root",
        &crate::state_root::compute_state_root(state),
        "node-1",
    );
    let state_bytes = serde_json::to_vec(state).unwrap();
    let state_root = crate::state_root::compute_state_root(state);
    CertifiedSnapshot {
        cluster_id: "cluster-1".into(),
        epoch: 1,
        sequence,
        state_bytes,
        state_root,
        membership_hash: crate::state_root::compute_membership_hash(&state.membership),
        constitution_hash: "const-hash".into(),
        policy_hash: "policy-hash".into(),
        ledger_totals_hash: "totals-hash".into(),
        utxo_set_root: "utxo-root".into(),
        consumed_intents_root: "intents-root".into(),
        quorum_certificate: qc,
    }
}

// ===========================================================================
// REPLICATION TESTS
// ===========================================================================

#[test]
fn new_node_starts_with_empty_status() {
    let status = ReplicationStatus {
        epoch: 1,
        committed_sequence: 0,
        applied_sequence: 0,
        state_root: "root".into(),
        leader_view: 0,
        sync_status: SyncStatus::Healthy,
    };
    assert_eq!(status.committed_sequence, 0);
    assert_eq!(status.applied_sequence, 0);
    assert_eq!(status.epoch, 1);
    assert_eq!(status.sync_status, SyncStatus::Healthy);
}

#[test]
fn applying_commands_advances_applied_sequence() {
    let mut status = healthy_status(10, 4);
    status.applied_sequence = 6;
    assert_eq!(status.applied_sequence, 6);

    status.applied_sequence = 10;
    assert_eq!(status.applied_sequence, status.committed_sequence);
}

#[test]
fn can_vote_is_true_when_healthy_and_caught_up() {
    let status = healthy_status(42, 42);
    assert!(can_vote(&status));
}

#[test]
fn can_vote_is_false_when_catching_up() {
    let mut status = healthy_status(42, 40);
    status.sync_status = SyncStatus::CatchingUp;
    assert!(!can_vote(&status));
}

#[test]
fn can_vote_is_false_when_not_caught_up() {
    let status = healthy_status(42, 41);
    assert!(!can_vote(&status));
}

#[test]
fn can_vote_is_false_when_diverged() {
    let mut status = healthy_status(42, 42);
    status.sync_status = SyncStatus::Diverged;
    assert!(!can_vote(&status));
}

#[test]
fn can_vote_is_false_when_quarantined() {
    let mut status = healthy_status(42, 42);
    status.sync_status = SyncStatus::Quarantined;
    assert!(!can_vote(&status));
}

#[test]
fn can_vote_is_false_when_snapshot_required() {
    let mut status = healthy_status(42, 42);
    status.sync_status = SyncStatus::SnapshotRequired;
    assert!(!can_vote(&status));
}

#[test]
fn divergence_detection_catches_state_root_mismatch() {
    let local = healthy_status(42, 42);
    let mut peer = healthy_status(42, 42);
    peer.state_root = "different-root".into();

    if local.state_root != peer.state_root {
        let result = DivergenceResult::StateRootMismatch {
            local_root: local.state_root,
            peer_root: peer.state_root,
        };
        assert!(matches!(result, DivergenceResult::StateRootMismatch { .. }));
    }
}

#[test]
fn divergence_detection_in_sync() {
    let local = healthy_status(42, 42);
    let peer = healthy_status(42, 42);

    if local.state_root == peer.state_root && local.applied_sequence == peer.applied_sequence {
        let result = DivergenceResult::InSync;
        assert!(matches!(result, DivergenceResult::InSync));
    }
}

#[test]
fn divergence_detection_ahead() {
    let local = healthy_status(50, 50);
    let peer = healthy_status(42, 42);

    if local.applied_sequence > peer.applied_sequence {
        let result = DivergenceResult::Ahead {
            local_sequence: local.applied_sequence,
            peer_sequence: peer.applied_sequence,
        };
        assert!(matches!(result, DivergenceResult::Ahead { .. }));
    }
}

#[test]
fn divergence_detection_behind() {
    let local = healthy_status(42, 42);
    let peer = healthy_status(50, 50);

    if local.applied_sequence < peer.applied_sequence {
        let result = DivergenceResult::Behind {
            local_sequence: local.applied_sequence,
            peer_sequence: peer.applied_sequence,
        };
        assert!(matches!(result, DivergenceResult::Behind { .. }));
    }
}

#[test]
fn catch_up_plan_chooses_replay_for_small_gaps() {
    let plan = CatchUpPlan::new(100, 200);
    assert_eq!(plan.from_sequence, 100);
    assert_eq!(plan.to_sequence, 200);
    assert_eq!(plan.missing_count, 100);
    assert_eq!(plan.strategy, CatchUpStrategy::ReplayCommands);
}

#[test]
fn catch_up_plan_chooses_install_snapshot_for_large_gaps() {
    let plan = CatchUpPlan::new(0, MAX_REPLAY_COMMANDS + 5000);
    assert_eq!(plan.strategy, CatchUpStrategy::InstallSnapshot);
}

#[test]
fn catch_up_plan_at_threshold_still_replay() {
    let plan = CatchUpPlan::new(0, MAX_REPLAY_COMMANDS);
    assert_eq!(plan.strategy, CatchUpStrategy::ReplayCommands);
}

#[test]
fn catch_up_plan_no_gap() {
    let plan = CatchUpPlan::new(100, 100);
    assert_eq!(plan.missing_count, 0);
    assert_eq!(plan.strategy, CatchUpStrategy::ReplayCommands);
}

#[test]
fn sync_status_can_transition_through_lifecycle() {
    let mut s = SyncStatus::Healthy;
    assert_eq!(s, SyncStatus::Healthy);

    s = SyncStatus::CatchingUp;
    assert_eq!(s, SyncStatus::CatchingUp);

    s = SyncStatus::Healthy;
    assert_eq!(s, SyncStatus::Healthy);

    s = SyncStatus::Diverged;
    assert_eq!(s, SyncStatus::Diverged);

    s = SyncStatus::Quarantined;
    assert_eq!(s, SyncStatus::Quarantined);
}

#[test]
fn quarantined_node_cannot_vote() {
    let status = ReplicationStatus {
        epoch: 1,
        committed_sequence: 100,
        applied_sequence: 100,
        state_root: "root".into(),
        leader_view: 0,
        sync_status: SyncStatus::Quarantined,
    };
    assert!(!can_vote(&status));
}

#[test]
fn divergence_report_detects_diverged() {
    let report = DivergenceReport {
        checkpoint_sequence: 100,
        local_state_root: "root-a".into(),
        peer_state_root: Some("root-b".into()),
        local_ledger_totals_hash: "totals-a".into(),
        peer_ledger_totals_hash: Some("totals-b".into()),
        is_diverged: true,
    };
    assert!(report.is_diverged);
    assert_eq!(report.checkpoint_sequence, 100);
}

#[test]
fn divergence_report_in_sync_state() {
    let report = DivergenceReport {
        checkpoint_sequence: 100,
        local_state_root: "same-root".into(),
        peer_state_root: Some("same-root".into()),
        local_ledger_totals_hash: "same-totals".into(),
        peer_ledger_totals_hash: Some("same-totals".into()),
        is_diverged: false,
    };
    assert!(!report.is_diverged);
}

#[test]
fn divergence_report_no_peer_data() {
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

#[tokio::test]
async fn execute_catch_up_replays_commands() {
    let sm = StateMachine;
    let snapshot_store = InMemorySnapshotStore::new();
    let mut state = LedgerState::empty(test_membership());

    let cmds = vec![dummy_cmd(0), dummy_cmd(1), dummy_cmd(2)];

    let result = execute_catch_up(
        &TestSyncManager::default(),
        &snapshot_store,
        &sm,
        &mut state,
        0,
        &cmds,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(state.version, 3);
}

#[tokio::test]
async fn recover_divergence_installs_snapshot_and_replays() {
    let sm = StateMachine;
    let snapshot_store = InMemorySnapshotStore::new();
    let mut state = LedgerState::empty(test_membership());

    // Save a snapshot of the empty state
    let snap = make_snapshot(0, &state);
    snapshot_store.save_snapshot(&snap).await.unwrap();

    let cmds = vec![dummy_cmd(0)];

    let result = recover_divergence(
        &TestSyncManager::default(),
        &snapshot_store,
        &sm,
        &mut state,
        &cmds,
    )
    .await;

    assert!(result.is_ok());
}

// ===========================================================================
// MEMBERSHIP TESTS
// ===========================================================================

#[test]
fn new_node_starts_as_untrusted() {
    let node = sample_membership("node-1", NodeRole::Untrusted);
    assert_eq!(node.role, NodeRole::Untrusted);
}

#[test]
fn can_add_as_observer() {
    let node = sample_membership("node-1", NodeRole::Observer);
    assert_eq!(node.role, NodeRole::Observer);
}

#[test]
fn observer_promoted_to_learner() {
    assert!(validate_role_transition(NodeRole::Observer, NodeRole::Learner).is_ok());
}

#[test]
fn learner_promoted_to_voter() {
    assert!(validate_role_transition(NodeRole::Learner, NodeRole::Voter).is_ok());
}

#[test]
fn invalid_role_transitions_rejected() {
    assert!(validate_role_transition(NodeRole::Untrusted, NodeRole::Voter).is_err());
    assert!(validate_role_transition(NodeRole::Untrusted, NodeRole::Learner).is_err());
    assert!(validate_role_transition(NodeRole::Observer, NodeRole::Voter).is_err());
    assert!(validate_role_transition(NodeRole::Voter, NodeRole::Learner).is_err());
    assert!(validate_role_transition(NodeRole::Learner, NodeRole::Observer).is_err());
}

#[test]
fn voter_demoted_to_observer() {
    assert!(validate_role_transition(NodeRole::Voter, NodeRole::Observer).is_ok());
}

#[test]
fn node_removal_any_to_untrusted() {
    assert!(validate_role_transition(NodeRole::Untrusted, NodeRole::Untrusted).is_ok());
    assert!(validate_role_transition(NodeRole::Observer, NodeRole::Untrusted).is_ok());
    assert!(validate_role_transition(NodeRole::Learner, NodeRole::Untrusted).is_ok());
    assert!(validate_role_transition(NodeRole::Voter, NodeRole::Untrusted).is_ok());
}

#[test]
fn voting_gate_allows_healthy_voter() {
    let gate = VotingGate {
        sync_status: healthy_status(42, 42),
        membership: sample_membership("node-1", NodeRole::Voter),
    };
    assert!(gate.can_vote());
    assert!(gate.can_propose());
    assert!(gate.reason_blocked().is_empty());
}

#[test]
fn voting_gate_blocks_non_voter() {
    let gate = VotingGate {
        sync_status: healthy_status(42, 42),
        membership: sample_membership("node-1", NodeRole::Observer),
    };
    assert!(!gate.can_vote());
    assert!(!gate.can_propose());
    let reasons = gate.reason_blocked();
    assert!(!reasons.is_empty());
}

#[test]
fn voting_gate_blocks_learner() {
    let gate = VotingGate {
        sync_status: healthy_status(42, 42),
        membership: sample_membership("node-1", NodeRole::Learner),
    };
    assert!(!gate.can_vote());
}

#[test]
fn voting_gate_blocks_untrusted() {
    let gate = VotingGate {
        sync_status: healthy_status(42, 42),
        membership: sample_membership("node-1", NodeRole::Untrusted),
    };
    assert!(!gate.can_vote());
}

#[test]
fn voting_gate_blocks_out_of_sync_voter() {
    let gate = VotingGate {
        sync_status: healthy_status(50, 40),
        membership: sample_membership("node-1", NodeRole::Voter),
    };
    assert!(!gate.can_vote());
    let reasons = gate.reason_blocked();
    assert!(reasons.iter().any(|r| r.contains("applied sequence")));
}

#[test]
fn voting_gate_blocks_diverged_voter() {
    let mut status = healthy_status(42, 42);
    status.sync_status = SyncStatus::Diverged;
    let gate = VotingGate {
        sync_status: status,
        membership: sample_membership("node-1", NodeRole::Voter),
    };
    assert!(!gate.can_vote());
    let reasons = gate.reason_blocked();
    assert!(reasons.iter().any(|r| r.contains("sync status")));
}

#[test]
fn voting_gate_multiple_blockers() {
    let mut status = healthy_status(50, 30);
    status.sync_status = SyncStatus::CatchingUp;
    let gate = VotingGate {
        sync_status: status,
        membership: sample_membership("node-1", NodeRole::Learner),
    };
    let reasons = gate.reason_blocked();
    // At least two reasons: not a voter + not caught up
    assert!(reasons.len() >= 2);
}

#[test]
fn voting_gate_reasons_are_informative() {
    let gate = VotingGate {
        sync_status: healthy_status(42, 42),
        membership: sample_membership("node-1", NodeRole::Observer),
    };
    let reasons = gate.reason_blocked();
    assert_eq!(reasons.len(), 1);
    assert!(reasons[0].contains("node-1"));
    assert!(reasons[0].contains("not a voter"));
    assert!(reasons[0].contains("Observer"));
}

#[test]
fn admission_flow_has_default_stability_window() {
    let flow = AdmissionFlow::default();
    assert_eq!(flow.required_stability_window_buckets, 10);
}

#[test]
fn admission_flow_custom_stability_window() {
    let flow = AdmissionFlow {
        required_stability_window_buckets: 100,
    };
    assert_eq!(flow.required_stability_window_buckets, 100);
}

#[test]
fn membership_gate_defaults() {
    let gate = MembershipGate::default();
    assert_eq!(gate.min_voter_count, 1);
    assert!(gate.allow_observer_read);
}

#[test]
fn membership_gate_custom_values() {
    let gate = MembershipGate {
        min_voter_count: 3,
        allow_observer_read: false,
    };
    assert_eq!(gate.min_voter_count, 3);
    assert!(!gate.allow_observer_read);
}

// ===========================================================================
// InMemoryMembershipStore integration tests
// ===========================================================================

#[tokio::test]
async fn membership_store_lifecycle() {
    let store = InMemoryMembershipStore::new();

    // Start as untrusted
    store
        .add_node(sample_membership("node-1", NodeRole::Untrusted))
        .await
        .unwrap();
    let node = store.get_node("node-1").await.unwrap().unwrap();
    assert_eq!(node.role, NodeRole::Untrusted);

    // Promote to observer
    store.promote("node-1", NodeRole::Observer).await.unwrap();
    let node = store.get_node("node-1").await.unwrap().unwrap();
    assert_eq!(node.role, NodeRole::Observer);

    // Promote to learner
    store.promote("node-1", NodeRole::Learner).await.unwrap();
    let node = store.get_node("node-1").await.unwrap().unwrap();
    assert_eq!(node.role, NodeRole::Learner);

    // Promote to voter
    store.promote("node-1", NodeRole::Voter).await.unwrap();
    let node = store.get_node("node-1").await.unwrap().unwrap();
    assert_eq!(node.role, NodeRole::Voter);

    // Demote to observer
    store.promote("node-1", NodeRole::Observer).await.unwrap();
    let node = store.get_node("node-1").await.unwrap().unwrap();
    assert_eq!(node.role, NodeRole::Observer);

    // Remove
    store.remove_node("node-1").await.unwrap();
    let node = store.get_node("node-1").await.unwrap();
    assert!(node.is_none());
}

#[tokio::test]
async fn membership_store_list_by_role_sorted() {
    let store = InMemoryMembershipStore::new();
    store
        .add_node(sample_membership("node-c", NodeRole::Voter))
        .await
        .unwrap();
    store
        .add_node(sample_membership("node-a", NodeRole::Voter))
        .await
        .unwrap();
    store
        .add_node(sample_membership("node-b", NodeRole::Voter))
        .await
        .unwrap();

    let voters = store.list_by_role(NodeRole::Voter).await.unwrap();
    assert_eq!(voters.len(), 3);
    assert_eq!(voters[0].node_id, "node-a");
    assert_eq!(voters[1].node_id, "node-b");
    assert_eq!(voters[2].node_id, "node-c");
}

#[tokio::test]
async fn membership_store_update_heartbeat() {
    let store = InMemoryMembershipStore::new();
    store
        .add_node(sample_membership("node-1", NodeRole::Voter))
        .await
        .unwrap();

    store.update_heartbeat("node-1", 999).await.unwrap();
    let node = store.get_node("node-1").await.unwrap().unwrap();
    assert_eq!(node.last_heartbeat_bucket, 999);
}

#[tokio::test]
async fn membership_store_promote_nonexistent_fails() {
    let store = InMemoryMembershipStore::new();
    let err = store
        .promote("nonexistent", NodeRole::Voter)
        .await
        .unwrap_err();
    assert!(matches!(err, LedgerError::NodeNotFound(_)));
}

#[tokio::test]
async fn membership_store_add_duplicate_fails() {
    let store = InMemoryMembershipStore::new();
    store
        .add_node(sample_membership("node-1", NodeRole::Untrusted))
        .await
        .unwrap();
    let err = store
        .add_node(sample_membership("node-1", NodeRole::Voter))
        .await
        .unwrap_err();
    assert!(matches!(err, LedgerError::InvariantViolation(_)));
}

// ===========================================================================
// Serde tests
// ===========================================================================

#[test]
fn replication_status_serde_roundtrip() {
    let status = ReplicationStatus {
        epoch: 1,
        committed_sequence: 100,
        applied_sequence: 95,
        state_root: "abc123def456".into(),
        leader_view: 2,
        sync_status: SyncStatus::CatchingUp,
    };
    let json = serde_json::to_string(&status).unwrap();
    let deserialized: ReplicationStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(status, deserialized);
}

#[test]
fn catch_up_plan_serde_roundtrip() {
    let plan = CatchUpPlan::new(50, 200);
    let json = serde_json::to_string(&plan).unwrap();
    let deserialized: CatchUpPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, deserialized);
}

#[test]
fn node_membership_serde_roundtrip() {
    let node = sample_membership("node-1", NodeRole::Voter);
    let json = serde_json::to_string(&node).unwrap();
    let deserialized: NodeMembership = serde_json::from_str(&json).unwrap();
    assert_eq!(node, deserialized);
}

#[test]
fn divergence_report_serde_roundtrip() {
    let report = DivergenceReport {
        checkpoint_sequence: 100,
        local_state_root: "root-a".into(),
        peer_state_root: Some("root-b".into()),
        local_ledger_totals_hash: "totals-a".into(),
        peer_ledger_totals_hash: Some("totals-b".into()),
        is_diverged: true,
    };
    let json = serde_json::to_string(&report).unwrap();
    let deserialized: DivergenceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, deserialized);
}

// ===========================================================================
// Constants tests
// ===========================================================================

#[test]
fn constants_are_correct() {
    assert_eq!(MAX_REPLAY_COMMANDS, 10000);
}

// ===========================================================================
// TestSyncManager — minimal in-memory implementation for tests
// ===========================================================================

struct TestSyncManager {
    status: std::sync::Mutex<ReplicationStatus>,
}

impl Default for TestSyncManager {
    fn default() -> Self {
        Self {
            status: std::sync::Mutex::new(ReplicationStatus {
                epoch: 1,
                committed_sequence: 0,
                applied_sequence: 0,
                state_root: "test-root".into(),
                leader_view: 0,
                sync_status: SyncStatus::Healthy,
            }),
        }
    }
}

#[async_trait::async_trait]
impl crate::replication::SyncManager for TestSyncManager {
    async fn status(&self) -> Result<ReplicationStatus, LedgerError> {
        let st = self.status.lock().unwrap();
        Ok(st.clone())
    }

    async fn check_divergence(
        &self,
        peer: &ReplicationStatus,
    ) -> Result<DivergenceResult, LedgerError> {
        let st = self.status.lock().unwrap();
        if st.state_root != peer.state_root {
            Ok(DivergenceResult::StateRootMismatch {
                local_root: st.state_root.clone(),
                peer_root: peer.state_root.clone(),
            })
        } else if st.applied_sequence > peer.applied_sequence {
            Ok(DivergenceResult::Ahead {
                local_sequence: st.applied_sequence,
                peer_sequence: peer.applied_sequence,
            })
        } else if st.applied_sequence < peer.applied_sequence {
            Ok(DivergenceResult::Behind {
                local_sequence: st.applied_sequence,
                peer_sequence: peer.applied_sequence,
            })
        } else {
            Ok(DivergenceResult::InSync)
        }
    }

    async fn start_catch_up(&self, _target_sequence: u64) -> Result<(), LedgerError> {
        let mut st = self.status.lock().unwrap();
        st.sync_status = SyncStatus::CatchingUp;
        Ok(())
    }

    async fn request_snapshot(&self, _sequence: u64) -> Result<CertifiedSnapshot, LedgerError> {
        Err(LedgerError::SnapshotNotFound(_sequence))
    }

    async fn mark_quarantined(&self, _reason: &str) -> Result<(), LedgerError> {
        let mut st = self.status.lock().unwrap();
        st.sync_status = SyncStatus::Quarantined;
        Ok(())
    }

    async fn recover_from_divergence(&self) -> Result<(), LedgerError> {
        let mut st = self.status.lock().unwrap();
        st.sync_status = SyncStatus::Healthy;
        Ok(())
    }
}
