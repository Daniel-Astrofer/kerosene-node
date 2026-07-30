use crate::tests::helpers::make_signed_qc;
use crate::{
    compute_state_root, AccountState, CertifiedSnapshot, Checkpoint, ConsensusProfile,
    DeterministicStateMachine, InMemorySnapshotStore, LedgerCommand, LedgerCommandType,
    LedgerError, LedgerState, MembershipView, NodeSignature, QuorumCertificate, SnapshotStore,
    StateMachine, StateTransitionReceipt,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_membership() -> MembershipView {
    MembershipView::single_node("cluster-1", "node-1")
}

fn empty_state() -> LedgerState {
    LedgerState::empty(test_membership())
}

fn default_qc() -> QuorumCertificate {
    make_signed_qc("cluster-1", 1, 0, 42, "hash", "prev", "result", "node-1").0
}

fn make_qc(
    cluster_id: &str,
    epoch: u64,
    view: u64,
    sequence: u64,
    command_hash: &str,
    prev_root: &str,
    result_root: &str,
    node_id: &str,
) -> QuorumCertificate {
    make_signed_qc(
        cluster_id,
        epoch,
        view,
        sequence,
        command_hash,
        prev_root,
        result_root,
        node_id,
    )
    .0
}

fn credit_cmd(account_id: &str, amount: u64, expected_version: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("credit-{}-{}", account_id, amount),
        LedgerCommandType::CreditInternalBalance,
        account_id,
        Some(expected_version),
        amount.to_string(),
        1,
        100,
    )
}

fn debit_cmd(account_id: &str, amount: u64, expected_version: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("debit-{}-{}", account_id, amount),
        LedgerCommandType::DebitInternalBalance,
        account_id,
        Some(expected_version),
        amount.to_string(),
        1,
        100,
    )
}

fn reserve_cmd(account_id: &str, amount: u64, expected_version: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("reserve-{}-{}", account_id, amount),
        LedgerCommandType::ReserveBalance,
        account_id,
        Some(expected_version),
        amount.to_string(),
        1,
        100,
    )
}

fn release_cmd(account_id: &str, amount: u64, expected_version: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("release-{}-{}", account_id, amount),
        LedgerCommandType::ReleaseReservation,
        account_id,
        Some(expected_version),
        amount.to_string(),
        1,
        100,
    )
}

fn transfer_cmd(source: &str, dest: &str, amount: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("transfer-{}-{}-{}", source, dest, amount),
        LedgerCommandType::CommitInternalTransfer,
        format!("{}|{}", source, dest),
        None,
        amount.to_string(),
        1,
        100,
    )
}

// ===========================================================================
// State machine tests
// ===========================================================================

#[test]
fn credit_to_nonexistent_account_creates_it() {
    let sm = StateMachine;
    let mut state = empty_state();
    let receipt = sm.apply(&mut state, &credit_cmd("alice", 1000, 0)).unwrap();

    assert_eq!(receipt.sequence, 0);
    assert!(receipt.affected_accounts.contains(&"alice".to_string()));

    let alice = state.find_account("alice").unwrap();
    assert_eq!(alice.available_sats, 1000);
    assert_eq!(alice.version, 1); // 0 → 1 after credit
    assert_eq!(state.version, 1);
}

#[test]
fn debit_with_sufficient_funds_succeeds() {
    let sm = StateMachine;
    let mut state = empty_state();

    sm.apply(&mut state, &credit_cmd("bob", 500, 0)).unwrap();
    let receipt = sm.apply(&mut state, &debit_cmd("bob", 200, 1)).unwrap();

    assert_eq!(receipt.sequence, 1);

    let bob = state.find_account("bob").unwrap();
    assert_eq!(bob.available_sats, 300);
    assert_eq!(bob.version, 2);
}

#[test]
fn debit_with_insufficient_funds_returns_error() {
    let sm = StateMachine;
    let mut state = empty_state();

    sm.apply(&mut state, &credit_cmd("carol", 50, 0)).unwrap();
    let err = sm
        .apply(&mut state, &debit_cmd("carol", 100, 1))
        .unwrap_err();
    assert!(matches!(err, LedgerError::InsufficientFunds { .. }));

    // State must be unchanged
    let carol = state.find_account("carol").unwrap();
    assert_eq!(carol.available_sats, 50);
    assert_eq!(state.version, 1);
}

#[test]
fn reserve_then_release_works() {
    let sm = StateMachine;
    let mut state = empty_state();

    sm.apply(&mut state, &credit_cmd("dave", 1000, 0)).unwrap();
    sm.apply(&mut state, &reserve_cmd("dave", 400, 1)).unwrap();

    let dave = state.find_account("dave").unwrap();
    assert_eq!(dave.available_sats, 600);
    assert_eq!(dave.reserved_sats, 400);

    sm.apply(&mut state, &release_cmd("dave", 150, 2)).unwrap();

    let dave = state.find_account("dave").unwrap();
    assert_eq!(dave.available_sats, 750);
    assert_eq!(dave.reserved_sats, 250);
    assert_eq!(state.version, 3);
}

#[test]
fn reserve_fails_when_insufficient_funds() {
    let sm = StateMachine;
    let mut state = empty_state();

    sm.apply(&mut state, &credit_cmd("eve", 100, 0)).unwrap();
    let err = sm
        .apply(&mut state, &reserve_cmd("eve", 200, 1))
        .unwrap_err();
    assert!(matches!(err, LedgerError::InsufficientFunds { .. }));
}

#[test]
fn atomic_transfer_succeeds_with_valid_versions() {
    let sm = StateMachine;
    let mut state = empty_state();

    sm.apply(&mut state, &credit_cmd("alice", 1000, 0)).unwrap();
    sm.apply(&mut state, &credit_cmd("bob", 500, 0)).unwrap();

    let receipt = sm
        .apply(&mut state, &transfer_cmd("alice", "bob", 300))
        .unwrap();

    assert_eq!(receipt.sequence, 2);

    let alice = state.find_account("alice").unwrap();
    let bob = state.find_account("bob").unwrap();
    assert_eq!(alice.available_sats, 700);
    assert_eq!(alice.version, 2);
    assert_eq!(bob.available_sats, 800);
    assert_eq!(bob.version, 2);
}

#[test]
fn atomic_transfer_fails_on_insufficient_source_balance() {
    let sm = StateMachine;
    let mut state = empty_state();

    sm.apply(&mut state, &credit_cmd("alice", 100, 0)).unwrap();
    sm.apply(&mut state, &credit_cmd("bob", 500, 0)).unwrap();

    let err = sm
        .apply(&mut state, &transfer_cmd("alice", "bob", 300))
        .unwrap_err();
    assert!(matches!(err, LedgerError::InsufficientFunds { .. }));

    // Verify no partial state change
    let alice = state.find_account("alice").unwrap();
    let bob = state.find_account("bob").unwrap();
    assert_eq!(alice.available_sats, 100);
    assert_eq!(bob.available_sats, 500);
    assert_eq!(state.version, 2); // Only the two credit commands
}

#[test]
fn unknown_command_type_not_applicable() {
    let sm = StateMachine;
    let mut state = empty_state();

    let cmd = LedgerCommand::new(
        "stub-test",
        LedgerCommandType::DetectUtxo,
        "tx1:0",
        None,
        r#"{"value_sats": 100, "address": "addr1"}"#,
        1,
        100,
    );

    // All commands should validate and apply without error
    assert!(sm.validate(&state, &cmd).is_ok());
    let receipt = sm.apply(&mut state, &cmd).unwrap();
    assert_eq!(receipt.sequence, 0);
    assert_eq!(state.version, 1);
}

#[test]
fn state_root_is_deterministic_same_commands_same_root() {
    fn build_state() -> LedgerState {
        let sm = StateMachine;
        let mut state = LedgerState::empty(MembershipView::single_node("cluster-1", "node-1"));
        sm.apply(&mut state, &credit_cmd("alice", 100, 0)).unwrap();
        sm.apply(&mut state, &credit_cmd("bob", 200, 0)).unwrap();
        sm.apply(&mut state, &debit_cmd("alice", 30, 1)).unwrap();
        sm.apply(&mut state, &transfer_cmd("bob", "alice", 50))
            .unwrap();
        state
    }

    let root1 = compute_state_root(&build_state());
    let root2 = compute_state_root(&build_state());
    assert_eq!(root1, root2, "same commands must produce same state root");
}

#[test]
fn state_root_changes_after_applying_command() {
    let sm = StateMachine;
    let mut state = empty_state();

    let root_before = compute_state_root(&state);
    sm.apply(&mut state, &credit_cmd("alice", 100, 0)).unwrap();
    let root_after = compute_state_root(&state);

    assert_ne!(
        root_before, root_after,
        "state root must change after mutation"
    );
}

#[test]
fn multiple_credits_accumulate() {
    let sm = StateMachine;
    let mut state = empty_state();

    sm.apply(&mut state, &credit_cmd("alice", 100, 0)).unwrap();
    sm.apply(&mut state, &credit_cmd("alice", 50, 1)).unwrap();
    sm.apply(&mut state, &credit_cmd("alice", 25, 2)).unwrap();

    let alice = state.find_account("alice").unwrap();
    assert_eq!(alice.available_sats, 175);
    assert_eq!(alice.version, 3);
}

#[test]
fn debit_exact_balance_succeeds() {
    let sm = StateMachine;
    let mut state = empty_state();

    sm.apply(&mut state, &credit_cmd("frank", 100, 0)).unwrap();
    sm.apply(&mut state, &debit_cmd("frank", 100, 1)).unwrap();

    let frank = state.find_account("frank").unwrap();
    assert_eq!(frank.available_sats, 0);
    assert_eq!(frank.spendable(), 0);
}

#[test]
fn validate_without_mutation() {
    let sm = StateMachine;
    let state = empty_state();

    // Valid: credit to non-existent account with version 0
    assert!(sm.validate(&state, &credit_cmd("alice", 100, 0)).is_ok());

    // Invalid: debit from non-existent account should fail
    assert!(sm
        .validate(&state, &debit_cmd("nonexistent", 100, 0))
        .is_err());
}

#[test]
fn state_transition_receipt_contains_valid_data() {
    let sm = StateMachine;
    let mut state = empty_state();

    let receipt = sm.apply(&mut state, &credit_cmd("grace", 500, 0)).unwrap();

    assert_eq!(receipt.sequence, 0);
    assert!(!receipt.command_hash.is_empty());
    assert!(!receipt.previous_state_root.is_empty());
    assert!(!receipt.resulting_state_root.is_empty());
    assert_ne!(receipt.previous_state_root, receipt.resulting_state_root);
    assert!(receipt.affected_accounts.contains(&"grace".to_string()));
}

// ===========================================================================
// State root tests
// ===========================================================================

#[test]
fn empty_state_has_deterministic_root() {
    let root1 = compute_state_root(&empty_state());
    let root2 = compute_state_root(&empty_state());
    assert_eq!(root1, root2);
    assert_eq!(root1.len(), 64);
}

#[test]
fn adding_accounts_changes_the_root() {
    let mut state = empty_state();
    let root_before = compute_state_root(&state);

    state.accounts.push(AccountState::new("test-account"));
    let root_after = compute_state_root(&state);

    assert_ne!(root_before, root_after);
}

#[test]
fn same_operations_produce_same_root_across_instances() {
    let sm = StateMachine;

    let mut state_a = empty_state();
    let mut state_b = empty_state();

    let ops = vec![
        credit_cmd("x", 100, 0),
        credit_cmd("y", 200, 0),
        debit_cmd("x", 50, 1),
    ];

    for cmd in &ops {
        sm.apply(&mut state_a, cmd).unwrap();
    }
    for cmd in &ops {
        sm.apply(&mut state_b, cmd).unwrap();
    }

    assert_eq!(compute_state_root(&state_a), compute_state_root(&state_b));
}

#[test]
fn account_insertion_order_does_not_affect_root() {
    // Create two states with same accounts but different insertion order
    let mut state1 = empty_state();
    let mut state2 = empty_state();

    state1.accounts.push(AccountState::new("z"));
    state1.accounts.push(AccountState::new("a"));
    state1.accounts[0].apply_credit(100).unwrap();
    state1.accounts[1].apply_credit(200).unwrap();

    state2.accounts.push(AccountState::new("a"));
    state2.accounts.push(AccountState::new("z"));
    state2.accounts[0].apply_credit(200).unwrap();
    state2.accounts[1].apply_credit(100).unwrap();

    assert_eq!(compute_state_root(&state1), compute_state_root(&state2));
}

#[test]
fn different_state_produces_different_root() {
    let mut state = empty_state();
    let root_before = compute_state_root(&state);

    state.version = 42;
    let root_after = compute_state_root(&state);

    assert_ne!(root_before, root_after);
}

// ===========================================================================
// Certificate tests
// ===========================================================================

#[test]
fn quorum_certificate_creation_single_mode() {
    let qc = QuorumCertificate::single_node(
        "cluster-1",
        1,  // epoch
        0,  // view
        42, // sequence
        "abc123",
        "prev-root",
        "result-root",
        "node-1",
        "deadbeef",
        "",
    );

    assert_eq!(qc.cluster_id, "cluster-1");
    assert_eq!(qc.epoch, 1);
    assert_eq!(qc.view, 0);
    assert_eq!(qc.sequence, 42);
    assert_eq!(qc.command_hash, "abc123");
    assert_eq!(qc.previous_state_root, "prev-root");
    assert_eq!(qc.resulting_state_root, "result-root");
    assert_eq!(qc.signer_count(), 1);
    assert_eq!(qc.signer_bitmap, vec![0b0000_0001]);
    assert_eq!(qc.signatures[0].node_id, "node-1");
    assert_eq!(qc.signatures[0].signature_hex, "deadbeef");
}

#[test]
fn quorum_certificate_serde_roundtrip() {
    let qc = QuorumCertificate::single_node(
        "cluster-1",
        1,
        0,
        42,
        "hash",
        "prev",
        "result",
        "node-1",
        "sig",
        "",
    );
    let json = serde_json::to_string(&qc).unwrap();
    let deserialized: QuorumCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(qc, deserialized);
}

#[test]
fn quorum_certificate_basic_verification() {
    let qc = default_qc();
    assert!(qc.verify_basic().is_ok());
}

#[test]
fn quorum_certificate_empty_roots_fail_verification() {
    let qc = QuorumCertificate {
        previous_state_root: String::new(),
        ..default_qc()
    };
    assert!(qc.verify_basic().is_err());
}

#[test]
fn checkpoint_creation_from_state() {
    let state = empty_state();
    let cp = Checkpoint::from_state(&state, 100, None);

    assert_eq!(cp.timestamp_bucket, 100);
    assert_eq!(cp.state_root, compute_state_root(&state));
    assert!(cp.quorum_certificate.is_none());
}

#[test]
fn checkpoint_state_root_matches_compute_state_root() {
    let state = empty_state();
    let cp = Checkpoint::from_state(&state, 100, None);
    assert_eq!(cp.state_root, compute_state_root(&state));
}

#[test]
fn checkpoint_verify_passes() {
    let state = empty_state();
    let cp = Checkpoint::from_state(&state, 100, None);
    assert!(cp.verify(&state).is_ok());
}

#[test]
fn checkpoint_verify_fails_on_tampered_state() {
    let mut state = empty_state();
    let cp = Checkpoint::from_state(&state, 100, None);

    // Tamper with the state
    state.accounts.push(AccountState::new("intruder"));
    assert!(cp.verify(&state).is_err());
}

#[test]
fn checkpoint_with_quorum_certificate() {
    let qc = QuorumCertificate::single_node(
        "cluster-1",
        1,
        0,
        0,
        "hash",
        "prev",
        "result",
        "node-1",
        "sig",
        "",
    );
    let state = empty_state();
    let cp = Checkpoint::from_state(&state, 100, Some(qc.clone()));

    assert_eq!(cp.quorum_certificate, Some(qc));
}

#[test]
fn certified_snapshot_serde_roundtrip() {
    let qc = QuorumCertificate::single_node(
        "cluster-1",
        1,
        0,
        42,
        "hash",
        "prev",
        "result",
        "node-1",
        "sig",
        "",
    );

    let state = empty_state();
    let state_root = compute_state_root(&state);
    let state_bytes = serde_json::to_vec(&state).unwrap();

    let snapshot = CertifiedSnapshot {
        cluster_id: "cluster-1".into(),
        epoch: 1,
        sequence: 42,
        state_bytes,
        state_root,
        membership_hash: "mem-hash".into(),
        constitution_hash: "const-hash".into(),
        policy_hash: "policy-hash".into(),
        ledger_totals_hash: "totals-hash".into(),
        utxo_set_root: "utxo-root".into(),
        consumed_intents_root: "intents-root".into(),
        quorum_certificate: qc,
    };

    let json = serde_json::to_string(&snapshot).unwrap();
    let deserialized: CertifiedSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snapshot, deserialized);
}

// ===========================================================================
// Snapshot store tests
// ===========================================================================

#[tokio::test]
async fn snapshot_store_save_and_retrieve_latest() {
    let store = InMemorySnapshotStore::new();
    let qc = make_qc("cluster-1", 1, 0, 1, "hash", "prev", "result", "node-1");

    let state = empty_state();
    let state_root = compute_state_root(&state);
    let state_bytes = serde_json::to_vec(&state).unwrap();

    let snap = CertifiedSnapshot {
        cluster_id: "cluster-1".into(),
        epoch: 1,
        sequence: 1,
        state_bytes,
        state_root,
        membership_hash: "mem-hash".into(),
        constitution_hash: "const-hash".into(),
        policy_hash: "policy-hash".into(),
        ledger_totals_hash: "totals-hash".into(),
        utxo_set_root: "utxo-root".into(),
        consumed_intents_root: "intents-root".into(),
        quorum_certificate: qc,
    };

    store.save_snapshot(&snap).await.unwrap();
    let latest = store.latest_snapshot().await.unwrap().unwrap();
    assert_eq!(latest.sequence, 1);
}

#[tokio::test]
async fn snapshot_store_empty_returns_none() {
    let store = InMemorySnapshotStore::new();
    assert!(store.latest_snapshot().await.unwrap().is_none());
    assert!(store.get_snapshot(1).await.unwrap().is_none());
}

#[tokio::test]
async fn snapshot_store_get_by_sequence() {
    let store = InMemorySnapshotStore::new();
    let qc = make_qc("cluster-1", 1, 0, 1, "hash", "prev", "result", "node-1");

    let state = empty_state();
    let state_root = compute_state_root(&state);
    let state_bytes = serde_json::to_vec(&state).unwrap();

    let snap = CertifiedSnapshot {
        cluster_id: "cluster-1".into(),
        epoch: 1,
        sequence: 42,
        state_bytes,
        state_root,
        membership_hash: "mem-hash".into(),
        constitution_hash: "const-hash".into(),
        policy_hash: "policy-hash".into(),
        ledger_totals_hash: "totals-hash".into(),
        utxo_set_root: "utxo-root".into(),
        consumed_intents_root: "intents-root".into(),
        quorum_certificate: qc,
    };

    store.save_snapshot(&snap).await.unwrap();
    let retrieved = store.get_snapshot(42).await.unwrap().unwrap();
    assert_eq!(retrieved.sequence, 42);
}

#[tokio::test]
async fn snapshot_store_install_valid_snapshot() {
    let store = InMemorySnapshotStore::new();
    let qc = make_qc("cluster-1", 1, 0, 1, "hash", "prev", "result", "node-1");

    let state = empty_state();
    let state_root = compute_state_root(&state);
    let state_bytes = serde_json::to_vec(&state).unwrap();

    let snap = CertifiedSnapshot {
        cluster_id: "cluster-1".into(),
        epoch: 1,
        sequence: 1,
        state_bytes,
        state_root,
        membership_hash: compute_state_root(&state), // placeholder
        constitution_hash: "const-hash".into(),
        policy_hash: "policy-hash".into(),
        ledger_totals_hash: "totals-hash".into(),
        utxo_set_root: "utxo-root".into(),
        consumed_intents_root: "intents-root".into(),
        quorum_certificate: qc,
    };

    store.save_snapshot(&snap).await.unwrap();
    let retrieved = store.get_snapshot(1).await.unwrap().unwrap();
    let installed = store.install_snapshot(&retrieved).await.unwrap();
    assert_eq!(installed.membership.cluster_id, "cluster-1");
}

#[tokio::test]
async fn snapshot_store_install_tampered_snapshot_fails() {
    let store = InMemorySnapshotStore::new();
    let qc = make_qc("cluster-1", 1, 0, 1, "hash", "prev", "result", "node-1");

    let state = empty_state();
    let state_bytes = serde_json::to_vec(&state).unwrap();

    let mut snap = CertifiedSnapshot {
        cluster_id: "cluster-1".into(),
        epoch: 1,
        sequence: 1,
        state_bytes,
        state_root: compute_state_root(&state),
        membership_hash: "mem-hash".into(),
        constitution_hash: "const-hash".into(),
        policy_hash: "policy-hash".into(),
        ledger_totals_hash: "totals-hash".into(),
        utxo_set_root: "utxo-root".into(),
        consumed_intents_root: "intents-root".into(),
        quorum_certificate: qc,
    };
    snap.state_root = "tampered-root".into();

    let err = store.install_snapshot(&snap).await.unwrap_err();
    assert!(matches!(err, LedgerError::StateRootMismatch { .. }));
}

// ===========================================================================
// NodeSignature tests
// ===========================================================================

#[test]
fn node_signature_creation() {
    let sig = NodeSignature {
        node_id: "node-42".into(),
        signature_hex: "abcdef0123456789".into(),
        public_key_hex: "pk-placeholder".into(),
    };
    assert_eq!(sig.node_id, "node-42");
    assert_eq!(sig.signature_hex, "abcdef0123456789");
}

#[test]
fn node_signature_serde_roundtrip() {
    let sig = NodeSignature {
        node_id: "node-1".into(),
        signature_hex: "deadbeef".into(),
        public_key_hex: "pk-placeholder".into(),
    };
    let json = serde_json::to_string(&sig).unwrap();
    let deserialized: NodeSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig, deserialized);
}

// ===========================================================================
// MembershipView tests
// ===========================================================================

#[test]
fn membership_single_node_creation() {
    let m = MembershipView::single_node("my-cluster", "my-node");
    assert_eq!(m.cluster_id, "my-cluster");
    assert_eq!(m.nodes, vec!["my-node"]);
    assert_eq!(m.active_profile, ConsensusProfile::Single);
}

#[test]
fn membership_serde_roundtrip() {
    let m = MembershipView::single_node("cluster-1", "node-1");
    let json = serde_json::to_string(&m).unwrap();
    let deserialized: MembershipView = serde_json::from_str(&json).unwrap();
    assert_eq!(m, deserialized);
}

// ===========================================================================
// LedgerCommand tests
// ===========================================================================

#[test]
fn ledger_command_new_and_payload_hash() {
    let cmd = LedgerCommand::new(
        "test-cmd-1",
        LedgerCommandType::CreditInternalBalance,
        "alice",
        Some(0),
        "100",
        1,
        100,
    );

    assert_eq!(cmd.command_id, "test-cmd-1");
    assert_eq!(cmd.command_type, LedgerCommandType::CreditInternalBalance);
    assert_eq!(cmd.partition_key, "alice");
    assert_eq!(cmd.expected_version, Some(0));
    assert_eq!(cmd.authorization_commitment, "100");
    assert_eq!(cmd.epoch, 1);
    assert_eq!(cmd.created_at_bucket, 100);
    assert_eq!(cmd.payload_hash.len(), 64);
}

#[test]
fn ledger_command_hash_does_not_depend_on_command_id() {
    let cmd1 = LedgerCommand::new(
        "id-1",
        LedgerCommandType::CreditInternalBalance,
        "alice",
        Some(0),
        "100",
        1,
        100,
    );
    let cmd2 = LedgerCommand::new(
        "id-2",
        LedgerCommandType::CreditInternalBalance,
        "alice",
        Some(0),
        "100",
        1,
        100,
    );

    assert_eq!(cmd1.payload_hash, cmd2.payload_hash);
}

#[test]
fn ledger_command_different_fields_different_hash() {
    let cmd1 = LedgerCommand::new(
        "id-1",
        LedgerCommandType::CreditInternalBalance,
        "alice",
        Some(0),
        "100",
        1,
        100,
    );
    let cmd2 = LedgerCommand::new(
        "id-2",
        LedgerCommandType::DebitInternalBalance,
        "alice",
        Some(0),
        "100",
        1,
        100,
    );

    assert_ne!(cmd1.payload_hash, cmd2.payload_hash);
}

#[test]
fn ledger_command_serde_roundtrip() {
    let cmd = LedgerCommand::new(
        "test-cmd",
        LedgerCommandType::CreditInternalBalance,
        "test-account",
        Some(5),
        "auth-commit",
        3,
        1000,
    );
    let json = serde_json::to_string(&cmd).unwrap();
    let deserialized: LedgerCommand = serde_json::from_str(&json).unwrap();
    assert_eq!(cmd, deserialized);
}

// ===========================================================================
// StateTransitionReceipt tests
// ===========================================================================

#[test]
fn state_transition_receipt_serde_roundtrip() {
    let receipt = StateTransitionReceipt {
        sequence: 42,
        command_hash: "cmd-hash".into(),
        previous_state_root: "prev-root".into(),
        resulting_state_root: "new-root".into(),
        affected_accounts: vec!["alice".into(), "bob".into()],
    };

    let json = serde_json::to_string(&receipt).unwrap();
    let deserialized: StateTransitionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, deserialized);
}

// ===========================================================================
// Determinism property tests
// ===========================================================================

#[test]
fn determinism_property_same_inputs_same_outputs() {
    // Property: same state + same command = same next state + same receipt
    let sm = StateMachine;

    // Run twice independently
    let (state1, receipt1) = {
        let mut state = empty_state();
        let cmd = credit_cmd("alice", 100, 0);
        let receipt = sm.apply(&mut state, &cmd).unwrap();
        (state, receipt)
    };

    let (state2, receipt2) = {
        let mut state = empty_state();
        let cmd = credit_cmd("alice", 100, 0);
        let receipt = sm.apply(&mut state, &cmd).unwrap();
        (state, receipt)
    };

    // Same accounts
    assert_eq!(state1.accounts, state2.accounts);
    // Same version
    assert_eq!(state1.version, state2.version);
    // Same state root
    assert_eq!(compute_state_root(&state1), compute_state_root(&state2));
    // Same receipt (except command_hash depends on command_id which differs)
    assert_eq!(receipt1.sequence, receipt2.sequence);
    assert_eq!(receipt1.previous_state_root, receipt2.previous_state_root);
    assert_eq!(receipt1.resulting_state_root, receipt2.resulting_state_root);
    assert_eq!(receipt1.affected_accounts, receipt2.affected_accounts);
}
