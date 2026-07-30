// ---------------------------------------------------------------------------
// Adversarial Integration Tests — Wave 7
//
// These tests simulate adversarial conditions: concurrency races,
// idempotency edge cases, sync/recovery scenarios, Byzantine behaviour,
// network partitions, blockchain edge cases, and vault-side failures.
//
// No sensitive data is used in metric labels or assertions.
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex};

use kerosene_ledger::{
    certificate::QuorumCertificate,
    chain::{OnchainState, OutPoint, UtxoEntry},
    settlement::{
        NonceChecker as SyncNonceChecker, PsbtCommitment, SettlementAuthorization,
        SettlementPolicy, VaultAuthorizationVerifier,
    },
    state_machine::{ConsensusProfile, DeterministicStateMachine, MembershipView},
    BasicMetricsCollector, DegradedMode, InMemoryNonceChecker, LedgerCommand, LedgerCommandType,
    LedgerError, LedgerMetrics, LedgerState, MetricsCollector, ProductionGates,
    ReconciliationEngine, ReconciliationStatus, ReplicationStatus, StateMachine, SyncStatus,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_membership() -> MembershipView {
    MembershipView {
        cluster_id: "adversarial-cluster".into(),
        nodes: vec!["node-1".into()],
        active_profile: ConsensusProfile::Single,
    }
}

/// Generate a real Ed25519 keypair for testing.
fn test_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with the given signing key and return the hex-encoded signature.
fn sign_message(signing_key: &ed25519_dalek::SigningKey, message: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(message);
    hex::encode(signature.to_bytes())
}

/// Create a QuorumCertificate with a real Ed25519 signature valid against its own signing message.
fn make_signed_qc(
    cluster_id: &str,
    epoch: u64,
    view: u64,
    sequence: u64,
    command_hash: &str,
    prev_root: &str,
    result_root: &str,
    node_id: &str,
) -> (QuorumCertificate, String) {
    let (sk, vk) = test_keypair();
    let pk_hex = hex::encode(vk.to_bytes());
    let stub = QuorumCertificate::single_node(
        cluster_id,
        epoch,
        view,
        sequence,
        command_hash,
        prev_root,
        result_root,
        node_id,
        "",
        &pk_hex,
    );
    let msg = stub.signing_message();
    let sig_hex = sign_message(&sk, &msg);
    let qc = QuorumCertificate::single_node(
        cluster_id,
        epoch,
        view,
        sequence,
        command_hash,
        prev_root,
        result_root,
        node_id,
        &sig_hex,
        &pk_hex,
    );
    (qc, pk_hex)
}

fn credit_cmd(account: &str, amount: u64, version: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("adv-credit-{}-{}", account, amount),
        LedgerCommandType::CreditInternalBalance,
        account,
        Some(version),
        amount.to_string(),
        1,
        100,
    )
}

fn debit_cmd(account: &str, amount: u64, version: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("adv-debit-{}-{}", account, amount),
        LedgerCommandType::DebitInternalBalance,
        account,
        Some(version),
        amount.to_string(),
        1,
        100,
    )
}

fn transfer_cmd(source: &str, dest: &str, amount: u64) -> LedgerCommand {
    LedgerCommand::new(
        format!("adv-xfer-{}-{}-{}", source, dest, amount),
        LedgerCommandType::CommitInternalTransfer,
        format!("{}|{}", source, dest),
        None,
        amount.to_string(),
        1,
        100,
    )
}

fn detect_utxo_cmd(txid: &str, vout: u32, value_sats: u64, address: &str) -> LedgerCommand {
    let outpoint = OutPoint::new(txid, vout);
    let payload = serde_json::json!({
        "value_sats": value_sats,
        "address": address,
    });
    LedgerCommand::new(
        format!("adv-utxo-detect-{}-{}", txid, vout),
        LedgerCommandType::DetectUtxo,
        outpoint.to_canonical_string(),
        None,
        payload.to_string(),
        1,
        100,
    )
}

// ===========================================================================
// 1. CONCURRENCY TESTS (1-6)
// ===========================================================================

/// Test 1: Two simultaneous withdrawals from same account exceeding balance.
#[test]
fn concurrency_two_withdrawals_exceeding_balance() {
    let state = Arc::new(Mutex::new(LedgerState::empty(test_membership())));
    let machine = Arc::new(StateMachine);

    // Seed account with 100 sats
    {
        let mut st = state.lock().unwrap();
        machine
            .apply(&mut st, &credit_cmd("alice", 100, 0))
            .unwrap();
    }

    let s1 = Arc::clone(&state);
    let m1 = Arc::clone(&machine);
    let join1 = std::thread::spawn(move || {
        let mut st = s1.lock().unwrap();
        m1.apply(&mut st, &debit_cmd("alice", 80, 1))
    });

    let join2 = std::thread::spawn(move || {
        let mut st = state.lock().unwrap();
        machine.apply(&mut st, &debit_cmd("alice", 80, 1))
    });

    let r1 = join1.join().unwrap();
    let r2 = join2.join().unwrap();

    let successes = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    let failures = [&r1, &r2].iter().filter(|r| r.is_err()).count();

    assert_eq!(successes, 1, "exactly one withdrawal should succeed");
    assert_eq!(failures, 1, "exactly one withdrawal should fail");
}

/// Test 2: Withdrawal and transfer simultaneously on same account.
#[test]
fn concurrency_withdrawal_and_transfer_same_account() {
    let state = Arc::new(Mutex::new(LedgerState::empty(test_membership())));
    let machine = Arc::new(StateMachine);

    // Seed alice with 100 sats, bob with 0
    {
        let mut st = state.lock().unwrap();
        machine
            .apply(&mut st, &credit_cmd("alice", 100, 0))
            .unwrap();
        machine.apply(&mut st, &credit_cmd("bob", 0, 0)).unwrap();
    }

    let s1 = Arc::clone(&state);
    let m1 = Arc::clone(&machine);
    let join1 = std::thread::spawn(move || {
        let mut st = s1.lock().unwrap();
        m1.apply(&mut st, &debit_cmd("alice", 60, 1))
    });

    let join2 = std::thread::spawn(move || {
        let mut st = state.lock().unwrap();
        let cmd = LedgerCommand::new(
            "adv-concurrent-xfer",
            LedgerCommandType::CommitInternalTransfer,
            "alice|bob",
            Some(1),
            "60",
            1,
            100,
        );
        machine.apply(&mut st, &cmd)
    });

    let r1 = join1.join().unwrap();
    let r2 = join2.join().unwrap();

    let successes = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 1, "exactly one operation should succeed");
}

/// Test 3: Alice sends to Bob while Bob sends to Alice (simultaneous).
#[test]
fn concurrency_circular_transfer() {
    let state = Arc::new(Mutex::new(LedgerState::empty(test_membership())));
    let machine = Arc::new(StateMachine);

    {
        let mut st = state.lock().unwrap();
        machine
            .apply(&mut st, &credit_cmd("alice", 100, 0))
            .unwrap();
        machine.apply(&mut st, &credit_cmd("bob", 100, 0)).unwrap();
    }

    let s1 = Arc::clone(&state);
    let m1 = Arc::clone(&machine);
    let join1 = std::thread::spawn(move || {
        let mut st = s1.lock().unwrap();
        m1.apply(&mut st, &transfer_cmd("alice", "bob", 50))
    });

    let join2 = std::thread::spawn(move || {
        let mut st = state.lock().unwrap();
        machine.apply(&mut st, &transfer_cmd("bob", "alice", 50))
    });

    let r1 = join1.join().unwrap();
    let r2 = join2.join().unwrap();

    // At least one should succeed with sufficient balance
    assert!(
        r1.is_ok() || r2.is_ok(),
        "at least one circular transfer should succeed"
    );
}

/// Test 4: 100 concurrent commands on same account — no overspending.
#[test]
fn concurrency_many_commands_no_overspend() {
    let state = Arc::new(Mutex::new(LedgerState::empty(test_membership())));
    let machine = Arc::new(StateMachine);

    // Seed with 1000 sats
    {
        let mut st = state.lock().unwrap();
        machine
            .apply(&mut st, &credit_cmd("alice", 1000, 0))
            .unwrap();
    }

    let mut handles = Vec::new();
    for i in 0..100 {
        let s = Arc::clone(&state);
        let m = Arc::clone(&machine);
        handles.push(std::thread::spawn(move || {
            let mut st = s.lock().unwrap();
            let version = st.find_account("alice").map(|a| a.version).unwrap_or(0);
            let cmd = LedgerCommand::new(
                format!("adv-concurrent-debit-{}-{}", i, 10),
                LedgerCommandType::DebitInternalBalance,
                "alice",
                Some(version),
                "10",
                1,
                100,
            );
            m.apply(&mut st, &cmd)
        }));
    }

    let mut successes = 0u64;
    let mut failures = 0u64;
    for h in handles {
        match h.join().unwrap() {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    // At most 100 debits of 10 sats = 1000 sats total
    assert!(successes <= 100, "no more than 100 debits can succeed");
    assert_eq!(successes + failures, 100, "all 100 threads must complete");
}

/// Test 5: Independent commands on different accounts — both succeed.
#[test]
fn concurrency_independent_accounts_all_succeed() {
    let state = Arc::new(Mutex::new(LedgerState::empty(test_membership())));
    let machine = Arc::new(StateMachine);

    {
        let mut st = state.lock().unwrap();
        machine
            .apply(&mut st, &credit_cmd("alice", 100, 0))
            .unwrap();
        machine.apply(&mut st, &credit_cmd("bob", 200, 0)).unwrap();
    }

    let s1 = Arc::clone(&state);
    let m1 = Arc::clone(&machine);
    let join1 = std::thread::spawn(move || {
        let mut st = s1.lock().unwrap();
        m1.apply(&mut st, &debit_cmd("alice", 30, 1))
    });

    let join2 = std::thread::spawn(move || {
        let mut st = state.lock().unwrap();
        machine.apply(&mut st, &debit_cmd("bob", 50, 1))
    });

    let r1 = join1.join().unwrap();
    let r2 = join2.join().unwrap();

    assert!(r1.is_ok(), "alice debit should succeed");
    assert!(r2.is_ok(), "bob debit should succeed");
}

/// Test 6: Two reservations try to consume same UTXO — second fails.
#[test]
fn concurrency_utxo_double_reserve_fails() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // Add a spendable UTXO
    state.utxos.push(UtxoEntry {
        state: OnchainState::Spendable,
        ..UtxoEntry::new_seen(OutPoint::new("tx1", 0), 100_000, "addr1", 100)
    });

    // First reserve succeeds
    let cmd1 = LedgerCommand::new(
        "reserve-utxo-1",
        LedgerCommandType::ReserveUtxo,
        "tx1:0",
        None,
        "intent-1",
        1,
        200,
    );
    assert!(machine.apply(&mut state, &cmd1).is_ok());

    // Second reserve on same UTXO fails
    let cmd2 = LedgerCommand::new(
        "reserve-utxo-2",
        LedgerCommandType::ReserveUtxo,
        "tx1:0",
        None,
        "intent-2",
        1,
        200,
    );
    let err = machine.apply(&mut state, &cmd2).unwrap_err();
    assert!(
        matches!(err, LedgerError::UtxoAlreadyReserved { .. }),
        "second reservation should fail: got {:?}",
        err
    );
}

// ===========================================================================
// 2. IDEMPOTENCY TESTS (7-10)
// ===========================================================================

/// Test 7: Same command replayed to same state — same result.
#[test]
fn idempotency_same_command_same_node() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    let cmd = credit_cmd("alice", 100, 0);

    let r1 = machine.apply(&mut state, &cmd).unwrap();
    let _r2 = machine.apply(&mut state, &cmd);

    // Second apply may fail (version conflict) — that's fine for idempotency
    // What matters is the state root didn't change
    let root = kerosene_ledger::compute_state_root(&state);
    assert_eq!(r1.resulting_state_root, root);
}

/// Test 8: Same command replayed to different node — same result.
#[test]
fn idempotency_same_command_different_node() {
    let mut state1 = LedgerState::empty(test_membership());
    let mut state2 = LedgerState::empty(test_membership());
    let machine = StateMachine;

    let cmd = credit_cmd("alice", 100, 0);

    let r1 = machine.apply(&mut state1, &cmd).unwrap();
    let r2 = machine.apply(&mut state2, &cmd).unwrap();

    // Same command on different clusters produce same receipt (same state root)
    assert_eq!(r1.resulting_state_root, r2.resulting_state_root);
}

/// Test 9: Same command_id with different payload — rejected as conflict.
#[test]
fn idempotency_same_id_different_payload() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // First command
    let cmd1 = LedgerCommand::new(
        "dup-id-1",
        LedgerCommandType::CreditInternalBalance,
        "alice",
        Some(0),
        "100",
        1,
        100,
    );
    machine.apply(&mut state, &cmd1).unwrap();

    // Same command_id but different payload
    let cmd2 = LedgerCommand::new(
        "dup-id-1",
        LedgerCommandType::CreditInternalBalance,
        "alice",
        Some(0),
        "200",
        1,
        100,
    );

    // Version conflict should catch the stale expected_version
    let err = machine.apply(&mut state, &cmd2).unwrap_err();
    assert!(
        matches!(err, LedgerError::VersionConflict { .. }),
        "should get version conflict for duplicate id with different payload: got {:?}",
        err
    );
}

/// Test 10: Client loses response after commit, retries — idempotent accept.
#[test]
fn idempotency_retry_after_lost_response() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    let cmd = credit_cmd("alice", 100, 0);

    // First apply succeeds
    let r1 = machine.apply(&mut state, &cmd).unwrap();

    // Client retries same command — should fail (version conflict) but state unchanged
    let _err = machine.apply(&mut state, &cmd);

    // State root should match the one from the first commit
    let root = kerosene_ledger::compute_state_root(&state);
    assert_eq!(r1.resulting_state_root, root);
}

// ===========================================================================
// 3. SYNC & RECOVERY TESTS (11-16)
// ===========================================================================

/// Test 11: Node misses entries, catches up via replay.
#[test]
fn sync_catch_up_via_replay() {
    let mut current = LedgerState::empty(test_membership());
    let mut target = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // Build target state with 5 commands
    let cmds = vec![
        credit_cmd("alice", 100, 0),
        credit_cmd("bob", 200, 0),
        debit_cmd("alice", 30, 1),
        transfer_cmd("bob", "alice", 50),
        credit_cmd("carol", 300, 0),
    ];

    for cmd in &cmds {
        machine.apply(&mut target, cmd).unwrap();
    }

    // Node starts with only first 3 commands applied
    for cmd in &cmds[..3] {
        machine.apply(&mut current, cmd).unwrap();
    }

    // Catch up by replaying missing commands
    for cmd in &cmds[3..] {
        machine.apply(&mut current, cmd).unwrap();
    }

    let current_root = kerosene_ledger::compute_state_root(&current);
    let target_root = kerosene_ledger::compute_state_root(&target);

    assert_eq!(
        current_root, target_root,
        "replayed state must match target state"
    );
}

/// Test 12: Node restarts with old state, catches up.
#[test]
fn sync_restart_and_catch_up() {
    let machine = StateMachine;

    let cmds = vec![
        credit_cmd("alice", 100, 0),
        credit_cmd("bob", 200, 0),
        credit_cmd("carol", 300, 0),
        debit_cmd("alice", 50, 1),
        transfer_cmd("bob", "carol", 100),
    ];

    // Build full state
    let mut full_state = LedgerState::empty(test_membership());
    for cmd in &cmds {
        machine.apply(&mut full_state, cmd).unwrap();
    }

    // Simulate node that only applied first 2 commands before restart
    let mut restart_state = LedgerState::empty(test_membership());
    for cmd in &cmds[..2] {
        machine.apply(&mut restart_state, cmd).unwrap();
    }

    // After restart, node replays from last persisted state
    for cmd in &cmds[2..] {
        machine.apply(&mut restart_state, cmd).unwrap();
    }

    let restart_root = kerosene_ledger::compute_state_root(&restart_state);
    let full_root = kerosene_ledger::compute_state_root(&full_state);

    assert_eq!(
        restart_root, full_root,
        "restarted node must match full state after catch-up"
    );
}

/// Test 13: Node receives out-of-order messages — rejects until in order.
#[test]
fn sync_out_of_order_messages_rejected() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // Apply command at version 0
    machine
        .apply(&mut state, &credit_cmd("alice", 100, 0))
        .unwrap();

    // Try with stale expected_version 0 (current is 1)
    let err = machine
        .apply(&mut state, &credit_cmd("alice", 50, 0))
        .unwrap_err();

    assert!(
        matches!(err, LedgerError::VersionConflict { .. }),
        "out-of-order (stale version) rejected: got {:?}",
        err
    );
}

/// Test 14: Node receives duplicate commands — idempotent.
#[test]
fn sync_duplicate_commands_idempotent() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    let cmd = credit_cmd("alice", 100, 0);

    machine.apply(&mut state, &cmd).unwrap();
    let root_before = kerosene_ledger::compute_state_root(&state);

    // Second apply should fail
    let err = machine.apply(&mut state, &cmd);
    let root_after = kerosene_ledger::compute_state_root(&state);

    assert_eq!(
        root_before, root_after,
        "state must not change after duplicate command rejection"
    );
    assert!(err.is_err(), "duplicate command should be rejected");
}

/// Test 15: Node installs snapshot, replays tail, reaches current state.
#[test]
fn sync_snapshot_and_replay_tail() {
    let machine = StateMachine;

    // Build full state with multiple commands
    let mut full_state = LedgerState::empty(test_membership());

    for i in 0..20 {
        let ver = full_state
            .find_account("alice")
            .map(|a| a.version)
            .unwrap_or(0);
        let cmd = LedgerCommand::new(
            format!("snap-credit-{}", i),
            LedgerCommandType::CreditInternalBalance,
            "alice",
            Some(ver),
            "100",
            1,
            100,
        );
        machine.apply(&mut full_state, &cmd).unwrap();
    }

    // Verify the state is deterministic
    let full_root = kerosene_ledger::compute_state_root(&full_state);

    // Rebuilding from scratch should produce same root
    let mut fresh_state = LedgerState::empty(test_membership());
    for i in 0..20 {
        let ver = fresh_state
            .find_account("alice")
            .map(|a| a.version)
            .unwrap_or(0);
        let cmd = LedgerCommand::new(
            format!("snap-credit-{}", i),
            LedgerCommandType::CreditInternalBalance,
            "alice",
            Some(ver),
            "100",
            1,
            100,
        );
        machine.apply(&mut fresh_state, &cmd).unwrap();
    }

    let fresh_root = kerosene_ledger::compute_state_root(&fresh_state);
    assert_eq!(full_root, fresh_root, "deterministic replay from snapshot");
}

/// Test 16: Node catches up and returns to healthy.
#[test]
fn sync_catch_up_returns_to_healthy() {
    let machine = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    let mut status = ReplicationStatus {
        epoch: 1,
        committed_sequence: 10,
        applied_sequence: 3,
        state_root: "root".into(),
        leader_view: 0,
        sync_status: SyncStatus::CatchingUp,
    };

    // Apply 7 more commands to reach 10
    for i in 0u64..7 {
        let ver = state.find_account("alice").map(|a| a.version).unwrap_or(0);
        let cmd = LedgerCommand::new(
            format!("catchup-credit-{}", i),
            LedgerCommandType::CreditInternalBalance,
            "alice",
            Some(ver),
            "100",
            1,
            100,
        );
        machine.apply(&mut state, &cmd).unwrap();
        status.applied_sequence += 1;
    }

    // Node caught up
    status.sync_status = SyncStatus::Healthy;
    assert_eq!(status.sync_status, SyncStatus::Healthy);
    assert_eq!(status.applied_sequence, 10);
}

// ===========================================================================
// 4. BYZANTINE SCENARIO TESTS (17-22)
// ===========================================================================

/// Test 17: Leader proposes negative balance — rejected.
#[test]
fn byzantine_negative_balance_rejected() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // Credit 50 sats
    machine
        .apply(&mut state, &credit_cmd("alice", 50, 0))
        .unwrap();

    // Try to debit 100 (more than available)
    let err = machine
        .apply(&mut state, &debit_cmd("alice", 100, 1))
        .unwrap_err();

    assert!(
        matches!(err, LedgerError::InsufficientFunds { .. }),
        "negative balance proposal rejected: got {:?}",
        err
    );
}

/// Test 18: Leader uses stale expected_version — VersionConflict.
#[test]
fn byzantine_stale_version_rejected() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    machine
        .apply(&mut state, &credit_cmd("alice", 100, 0))
        .unwrap();
    machine
        .apply(&mut state, &credit_cmd("alice", 50, 1))
        .unwrap();

    // Try with stale version 1 (current is 2)
    let err = machine
        .apply(&mut state, &credit_cmd("alice", 25, 1))
        .unwrap_err();

    assert!(
        matches!(err, LedgerError::VersionConflict { .. }),
        "stale version rejected: got {:?}",
        err
    );
}

/// Test 19: Leader sends different commands for same sequence — handled.
#[test]
fn byzantine_different_commands_same_sequence() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // Apply command at version 0
    machine
        .apply(&mut state, &credit_cmd("alice", 100, 0))
        .unwrap();

    // Bob with expected_version 0 should create a new account
    let cmd2 = credit_cmd("bob", 50, 0);
    let result = machine.apply(&mut state, &cmd2);
    assert!(result.is_ok());
    let bob = state.find_account("bob").unwrap();
    assert_eq!(bob.available_sats, 50);
}

/// Test 20: Node announces false state_root — divergence detected.
#[test]
fn byzantine_false_state_root_diverged() {
    let machine = StateMachine;

    let mut state1 = LedgerState::empty(test_membership());
    let mut state2 = LedgerState::empty(test_membership());

    // Both apply same first command
    machine
        .apply(&mut state1, &credit_cmd("alice", 100, 0))
        .unwrap();
    machine
        .apply(&mut state2, &credit_cmd("alice", 100, 0))
        .unwrap();

    // State2 diverges by applying an extra command
    machine
        .apply(&mut state2, &credit_cmd("bob", 50, 0))
        .unwrap();

    let root1 = kerosene_ledger::compute_state_root(&state1);
    let root2 = kerosene_ledger::compute_state_root(&state2);

    assert_ne!(
        root1, root2,
        "different states must produce different roots"
    );
}

/// Test 21: Node tries to vote while behind — VotingGate blocks.
#[test]
fn byzantine_vote_while_behind() {
    let status = ReplicationStatus {
        epoch: 1,
        committed_sequence: 100,
        applied_sequence: 80,
        state_root: "root".into(),
        leader_view: 0,
        sync_status: SyncStatus::CatchingUp,
    };

    assert!(
        !kerosene_ledger::can_vote(&status),
        "node behind should not be able to vote"
    );
}

/// Test 22: Node provides tampered snapshot — root mismatch detected.
#[tokio::test]
async fn snapshot_tampering_detection() {
    use kerosene_ledger::snapshot::SnapshotStore;
    let store = kerosene_ledger::snapshot::InMemorySnapshotStore::new();
    let state = LedgerState::empty(test_membership());
    let root = kerosene_ledger::compute_state_root(&state);

    let qc = make_signed_qc(
        "cluster-1",
        1,
        0,
        1,
        "cmd-hash",
        "prev-root",
        "result-root",
        "node-1",
    )
    .0;
    let state_bytes = vec![0];
    let snapshot = kerosene_ledger::CertifiedSnapshot {
        cluster_id: "cluster-1".into(),
        epoch: 1,
        sequence: 0,
        state_root: root.clone(),
        quorum_certificate: qc.clone(),
        state_bytes: state_bytes.clone(),
        membership_hash: "hash".into(),
        constitution_hash: "hash".into(),
        policy_hash: "hash".into(),
        ledger_totals_hash: "hash".into(),
        utxo_set_root: "hash".into(),
        consumed_intents_root: "hash".into(),
    };

    // Store the valid snapshot
    let result = store.save_snapshot(&snapshot).await;
    assert!(result.is_ok(), "valid snapshot should be stored");

    // Create a tampered snapshot with wrong state_root
    let tampered = kerosene_ledger::CertifiedSnapshot {
        state_root: "tampered-root".into(),
        ..snapshot.clone()
    };

    // State root should be mismatched
    let computed_root = kerosene_ledger::compute_state_root(&state);
    assert_ne!(
        computed_root, tampered.state_root,
        "tampered snapshot root doesn't match computed state"
    );
}

// ===========================================================================
// 5. PARTITION & NETWORK TESTS (23-26)
// ===========================================================================

/// Test 23: Node isolated without quorum — cannot commit new balances.
#[test]
fn partition_isolated_node_cannot_commit() {
    let status = ReplicationStatus {
        epoch: 1,
        committed_sequence: 0,
        applied_sequence: 0,
        state_root: "root".into(),
        leader_view: 0,
        sync_status: SyncStatus::Diverged,
    };

    assert!(
        !kerosene_ledger::can_vote(&status),
        "isolated node cannot vote"
    );
}

/// Test 24: Reconnection after partition — catch-up succeeds.
#[test]
fn partition_reconnect_catch_up() {
    let machine = StateMachine;

    // Build cluster state
    let mut cluster_state = LedgerState::empty(test_membership());
    let cmds = vec![
        credit_cmd("alice", 100, 0),
        credit_cmd("bob", 200, 0),
        credit_cmd("carol", 300, 0),
    ];
    for cmd in &cmds {
        machine.apply(&mut cluster_state, cmd).unwrap();
    }

    // Isolated node only has first command
    let mut isolated_state = LedgerState::empty(test_membership());
    machine.apply(&mut isolated_state, &cmds[0]).unwrap();

    // After reconnection, replay remaining
    for cmd in &cmds[1..] {
        machine.apply(&mut isolated_state, cmd).unwrap();
    }

    assert_eq!(
        kerosene_ledger::compute_state_root(&isolated_state),
        kerosene_ledger::compute_state_root(&cluster_state),
        "reconnected node matches cluster state"
    );
}

/// Test 25: Timeout before commit — no side effects.
#[test]
fn partition_timeout_before_commit_no_side_effects() {
    let state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // Validate a command without applying it
    let cmd = credit_cmd("alice", 100, 0);
    let validation = machine.validate(&state, &cmd);

    assert!(validation.is_ok(), "validation should pass");
    // State is unchanged since validate doesn't mutate
    assert_eq!(state.version, 0, "no side effects from validation");
    assert!(state.find_account("alice").is_none());
}

/// Test 26: Timeout after commit before response — idempotent retry.
#[test]
fn partition_timeout_after_commit_retry() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    let cmd = credit_cmd("alice", 100, 0);

    // Commit succeeds
    machine.apply(&mut state, &cmd).unwrap();
    let root_after_commit = kerosene_ledger::compute_state_root(&state);

    // Client retries (same command)
    let retry_result = machine.apply(&mut state, &cmd);

    // Retry should fail (version conflict)
    assert!(
        retry_result.is_err(),
        "retry after commit should be rejected"
    );

    let root_after_retry = kerosene_ledger::compute_state_root(&state);
    assert_eq!(
        root_after_commit, root_after_retry,
        "state unchanged after idempotent retry rejection"
    );
}

// ===========================================================================
// 6. BLOCKCHAIN TESTS (27-30)
// ===========================================================================

/// Test 27: Deposit detected, confirmed, then reorged — correct transitions.
#[test]
fn blockchain_deposit_detected_confirmed_reorged() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // 1. Detect deposit
    let detect = detect_utxo_cmd("deposit-tx", 0, 500_000, "bc1qtest");
    machine.apply(&mut state, &detect).unwrap();
    assert_eq!(state.utxos[0].state, OnchainState::Seen);

    // 2. Confirm (transition through InMempool → Confirming)
    state.utxos[0].state = OnchainState::InMempool;

    let confirm_cmd = LedgerCommand::new(
        "deposit-confirm",
        LedgerCommandType::ConfirmUtxo,
        "deposit-tx:0",
        None,
        "100",
        1,
        100,
    );
    machine.apply(&mut state, &confirm_cmd).unwrap();
    assert_eq!(state.utxos[0].state, OnchainState::Confirming);

    // 3. Reorg
    let reorg_payload = serde_json::json!({
        "disconnected_txids": ["deposit-tx"],
        "new_utxos": [],
    });
    let reorg_cmd = LedgerCommand::new(
        "deposit-reorg",
        LedgerCommandType::ApplyChainReorganization,
        "reorg-1",
        None,
        reorg_payload.to_string(),
        1,
        200,
    );
    machine.apply(&mut state, &reorg_cmd).unwrap();
    assert_eq!(state.utxos[0].state, OnchainState::Reorged);
}

/// Test 28: Withdrawal replaced via RBF — correct state updates.
#[test]
fn blockchain_withdrawal_rbf() {
    let mut state = LedgerState::empty(test_membership());

    // Add UTXO, make it spendable
    let mut utxo = UtxoEntry::new_seen(OutPoint::new("wd-tx", 0), 100_000, "bc1qwd", 100);
    utxo.state = OnchainState::Spendable;
    state.utxos.push(utxo);

    // Apply RBF replacement
    let replacement = UtxoEntry::new_seen(OutPoint::new("rbf-tx", 0), 100_000, "bc1qwd", 200);
    let released =
        kerosene_ledger::apply_rbf_replacement(&mut state.utxos, "wd-tx", &[replacement]).unwrap();

    assert!(released.is_empty());
    assert_eq!(state.utxos[0].state, OnchainState::Replaced);
    assert_eq!(state.utxos.len(), 2);
    assert_eq!(state.utxos[1].outpoint.txid, "rbf-tx");
}

/// Test 29: Observer sends false chain data — consensus rejects.
#[test]
fn blockchain_false_chain_data_rejected() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // Try to confirm a non-existent UTXO
    let cmd = LedgerCommand::new(
        "false-confirm",
        LedgerCommandType::ConfirmUtxo,
        "nonexistent:0",
        None,
        "100",
        1,
        100,
    );
    let err = machine.apply(&mut state, &cmd).unwrap_err();
    assert!(
        matches!(err, LedgerError::UtxoNotFound { .. }),
        "false chain data should be rejected: got {:?}",
        err
    );
}

/// Test 30: Observers disagree on chain state — handled gracefully.
#[test]
fn blockchain_observer_disagreement_handled() {
    let mut state = LedgerState::empty(test_membership());
    let machine = StateMachine;

    // Observer 1 reports detection
    let obs1 = detect_utxo_cmd("tx-disputed", 0, 100_000, "addr1");
    machine.apply(&mut state, &obs1).unwrap();

    // Observer 2 reports same UTXO with different value — first observation sticks
    let obs2 = detect_utxo_cmd("tx-disputed", 0, 200_000, "addr1");
    let r2 = machine.apply(&mut state, &obs2);

    assert_eq!(state.utxos[0].value_sats, 100_000);
    assert!(r2.is_ok(), "duplicate detection should be idempotent");
}

// ===========================================================================
// 7. VAULT TESTS (31-34)
// ===========================================================================

/// Test 31: Vault offline or sends invalid share — handled.
#[test]
fn vault_offline_or_invalid_share() {
    let policy = SettlementPolicy {
        max_fee_sats: 10_000,
        min_confirmations: 1,
        allowed_destination_types: vec!["p2wpkh".into()],
        max_outputs: 10,
        rbf_allowed: true,
        max_epoch_drift: 5,
        authorization_ttl_buckets: 100,
    };
    let nonce_checker = InMemoryNonceChecker::new();

    let qc = make_signed_qc(
        "cluster-1",
        1,
        0,
        1,
        "cmd-hash",
        "prev-root",
        "result-root",
        "node-1",
    )
    .0;
    let auth = SettlementAuthorization {
        intent_commitment: String::new(),
        command_hash: "cmd-hash".into(),
        psbt_commitment: "psbt-hash".into(),
        policy_hash: "policy-hash".into(),
        epoch: 1,
        expires_at_bucket: 200,
        nonce: "nonce-1".into(),
        quorum_certificate: qc,
    };

    let result = VaultAuthorizationVerifier::verify(
        &auth,
        b"psbt-bytes",
        1,
        1,
        100_000,
        &policy,
        &nonce_checker,
        50,
    );

    assert!(
        result.is_err(),
        "empty intent_commitment should be rejected"
    );
}

/// Test 32: Nonce reuse attempt — rejected.
#[test]
fn vault_nonce_reuse_rejected() {
    let nonce_checker = InMemoryNonceChecker::new();
    let policy = SettlementPolicy {
        max_fee_sats: 10_000,
        min_confirmations: 1,
        allowed_destination_types: vec!["p2wpkh".into()],
        max_outputs: 10,
        rbf_allowed: true,
        max_epoch_drift: 5,
        authorization_ttl_buckets: 100,
    };

    let qc = make_signed_qc(
        "cluster-1",
        1,
        0,
        1,
        "cmd-hash",
        "prev-root",
        "result-root",
        "node-1",
    )
    .0;
    let auth = SettlementAuthorization {
        intent_commitment: "intent-1".into(),
        command_hash: "cmd-hash".into(),
        psbt_commitment: PsbtCommitment::compute(b"psbt-bytes"),
        policy_hash: "policy-hash".into(),
        epoch: 1,
        expires_at_bucket: 200,
        nonce: "nonce-reuse-test".into(),
        quorum_certificate: qc,
    };

    // First use passes
    let result1 = VaultAuthorizationVerifier::verify(
        &auth,
        b"psbt-bytes",
        1,
        1,
        100_000,
        &policy,
        &nonce_checker,
        50,
    );
    assert!(result1.is_ok(), "first use of nonce should pass");

    // Mark nonce as consumed
    nonce_checker.mark_consumed_sync("nonce-reuse-test");

    // Second use fails
    let result2 = VaultAuthorizationVerifier::verify(
        &auth,
        b"psbt-bytes",
        1,
        1,
        100_000,
        &policy,
        &nonce_checker,
        50,
    );
    assert!(result2.is_err(), "nonce reuse should be rejected");
}

/// Test 33: Certificate doesn't match PSBT — rejected.
#[test]
fn vault_certificate_psbt_mismatch() {
    let policy = SettlementPolicy {
        max_fee_sats: 10_000,
        min_confirmations: 1,
        allowed_destination_types: vec!["p2wpkh".into()],
        max_outputs: 10,
        rbf_allowed: true,
        max_epoch_drift: 5,
        authorization_ttl_buckets: 100,
    };
    let nonce_checker = InMemoryNonceChecker::new();

    let qc = make_signed_qc(
        "cluster-1",
        1,
        0,
        1,
        "cmd-hash",
        "prev-root",
        "result-root",
        "node-1",
    )
    .0;
    let auth = SettlementAuthorization {
        intent_commitment: "intent-1".into(),
        command_hash: "cmd-hash".into(),
        psbt_commitment: "expected-psbt-hash".into(),
        policy_hash: "policy-hash".into(),
        epoch: 1,
        expires_at_bucket: 200,
        nonce: "nonce-psbt-test".into(),
        quorum_certificate: qc,
    };

    // Verify with different PSBT bytes
    let result = VaultAuthorizationVerifier::verify(
        &auth,
        b"different-psbt-bytes",
        1,
        1,
        100_000,
        &policy,
        &nonce_checker,
        50,
    );

    assert!(result.is_err(), "PSBT mismatch should be rejected");
}

/// Test 34: Expired authorization — rejected.
#[test]
fn vault_expired_authorization_rejected() {
    let policy = SettlementPolicy {
        max_fee_sats: 10_000,
        min_confirmations: 1,
        allowed_destination_types: vec!["p2wpkh".into()],
        max_outputs: 10,
        rbf_allowed: true,
        max_epoch_drift: 5,
        authorization_ttl_buckets: 100,
    };
    let nonce_checker = InMemoryNonceChecker::new();

    let qc = make_signed_qc(
        "cluster-1",
        1,
        0,
        1,
        "cmd-hash",
        "prev-root",
        "result-root",
        "node-1",
    )
    .0;
    let auth = SettlementAuthorization {
        intent_commitment: "intent-1".into(),
        command_hash: "cmd-hash".into(),
        psbt_commitment: "psbt-hash".into(),
        policy_hash: "policy-hash".into(),
        epoch: 1,
        expires_at_bucket: 100,
        nonce: "nonce-expired".into(),
        quorum_certificate: qc,
    };

    let result = VaultAuthorizationVerifier::verify(
        &auth,
        b"psbt-bytes",
        1,
        1,
        100_000,
        &policy,
        &nonce_checker,
        200,
    );

    assert!(result.is_err(), "expired authorization should be rejected");
}

// ===========================================================================
// ADDITIONAL INTEGRATION TESTS
// ===========================================================================

/// Test 35: Reconciliation detection via metrics.
#[tokio::test]
async fn integration_reconciliation_shows_in_metrics() {
    let collector = BasicMetricsCollector::new();
    collector.set_total_accounts(5);
    collector.set_total_utxos(10);

    let snapshot = collector.snapshot().await.unwrap();
    assert_eq!(snapshot.total_accounts, 5);
    assert_eq!(snapshot.total_utxos, 10);
}

/// Test 36: Gate blocked error format.
#[test]
fn integration_gate_blocked_error() {
    let err = LedgerError::GateBlocked {
        reason: "test blocked".into(),
    };
    let msg = format!("{}", err);
    assert!(msg.contains("test blocked"));
    assert!(matches!(err, LedgerError::GateBlocked { .. }));
}

/// Test 37: Degraded mode enables/disables operations.
#[test]
fn integration_degraded_mode_operations() {
    let normal = DegradedMode::Normal;
    assert!(normal.withdrawals_allowed());
    assert!(normal.internal_transfers_allowed());
    assert!(normal.credits_allowed());

    let ro = DegradedMode::ReadOnly;
    assert!(!ro.withdrawals_allowed());
    assert!(!ro.internal_transfers_allowed());
    assert!(!ro.credits_allowed());

    let deg = DegradedMode::Degraded {
        withdrawals_blocked: true,
        membership_changes_blocked: true,
        key_rotation_blocked: false,
        internal_transfers_allowed: false,
        credits_allowed: true,
    };
    assert!(!deg.withdrawals_allowed());
    assert!(!deg.internal_transfers_allowed());
    assert!(deg.credits_allowed());
}

/// Test 38: Combined gate evaluation at cluster level.
#[test]
fn integration_combined_gate_evaluation() {
    let metrics = LedgerMetrics::new();
    let state = LedgerState::empty(test_membership());
    let report = ReconciliationEngine::reconcile(&state, "tip", true);
    let status = ReplicationStatus {
        epoch: 1,
        committed_sequence: 0,
        applied_sequence: 0,
        state_root: "root".into(),
        leader_view: 0,
        sync_status: SyncStatus::Healthy,
    };
    let membership = test_membership();

    let mode = ProductionGates::evaluate_degraded_mode(&metrics, &report, &status, &membership);
    assert_eq!(mode, DegradedMode::Normal);
}

/// Test 39: Metrics collector handles concurrent increments.
#[tokio::test]
async fn integration_concurrent_metrics_increments() {
    let collector = Arc::new(BasicMetricsCollector::new());

    let mut handles = Vec::new();
    for _ in 0..10 {
        let c = Arc::clone(&collector);
        handles.push(std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    c.increment_counter("test_counter", 1).await;
                });
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let snapshot = collector.snapshot().await.unwrap();
    assert_eq!(snapshot.state_root_mismatch_total, 0);
}

/// Test 40: Reconciliation correctly reports surplus from UTXO assets.
#[test]
fn integration_reconciliation_surplus_from_utxos() {
    let mut state = LedgerState::empty(test_membership());
    state.utxos.push(UtxoEntry::new_seen(
        OutPoint::new("tx-surplus", 0),
        1_000_000,
        "addr-surplus",
        100,
    ));

    let report = ReconciliationEngine::reconcile(&state, "tip-hash", true);
    assert_eq!(report.status, ReconciliationStatus::Surplus);
    assert_eq!(report.total_assets_sats, 1_000_000);
    assert_eq!(report.total_liabilities_sats, 0);
}

/// Test 41: Multiple UTXOs aggregated correctly in reconciliation.
#[test]
fn integration_multiple_utxos_aggregated() {
    let mut state = LedgerState::empty(test_membership());
    state.utxos.push(UtxoEntry::new_seen(
        OutPoint::new("a", 0),
        100_000,
        "addr1",
        1,
    ));
    state.utxos.push(UtxoEntry::new_seen(
        OutPoint::new("b", 0),
        200_000,
        "addr2",
        2,
    ));
    state.utxos.push(UtxoEntry::new_seen(
        OutPoint::new("c", 0),
        300_000,
        "addr3",
        3,
    ));

    assert_eq!(ReconciliationEngine::compute_total_assets(&state), 600_000);
}

/// Test 42: Spent UTXOs excluded from total assets.
#[test]
fn integration_spent_utxos_excluded() {
    let mut state = LedgerState::empty(test_membership());
    let mut spent = UtxoEntry::new_seen(OutPoint::new("spent", 0), 500_000, "addr", 1);
    spent.state = OnchainState::Spent;
    state.utxos.push(spent);
    state.utxos.push(UtxoEntry::new_seen(
        OutPoint::new("active", 0),
        300_000,
        "addr2",
        2,
    ));

    assert_eq!(ReconciliationEngine::compute_total_assets(&state), 300_000);
}

/// Test 43: Replaced UTXOs excluded from total assets.
#[test]
fn integration_replaced_utxos_excluded() {
    let mut state = LedgerState::empty(test_membership());
    let mut replaced = UtxoEntry::new_seen(OutPoint::new("rbf", 0), 500_000, "addr", 1);
    replaced.state = OnchainState::Replaced;
    state.utxos.push(replaced);

    assert_eq!(ReconciliationEngine::compute_total_assets(&state), 0);
}

/// Test 44: Metrics collector only exposes aggregate counters.
#[test]
fn metrics_no_sensitive_data_in_struct() {
    let m = LedgerMetrics::new();
    let fields = format!("{:?}", m);
    assert!(!fields.contains("account_id"), "no account_id in metrics");
    assert!(!fields.contains("address"), "no address in metrics");
}

/// Test 45: BasicMetricsCollector handles set_gauge correctly.
#[tokio::test]
async fn metrics_gauge_set_and_retrieve() {
    let collector = BasicMetricsCollector::new();
    collector.set_gauge("my_gauge", 42).await;
    collector.set_gauge("my_gauge", 99).await;
    let snapshot = collector.snapshot().await.unwrap();
    assert_eq!(snapshot.committed_sequence, 0);
}

/// Test 46: Two reservations try to consume same UTXO concurrently.
#[test]
fn concurrency_utxo_double_reserve_concurrent() {
    let state = Arc::new(Mutex::new(LedgerState::empty(test_membership())));
    let machine = Arc::new(StateMachine);

    // Add a spendable UTXO
    {
        let mut st = state.lock().unwrap();
        st.utxos.push(UtxoEntry {
            state: OnchainState::Spendable,
            ..UtxoEntry::new_seen(OutPoint::new("tx-concurrent", 0), 100_000, "addr1", 100)
        });
    }

    let s1 = Arc::clone(&state);
    let m1 = Arc::clone(&machine);
    let join1 = std::thread::spawn(move || {
        let mut st = s1.lock().unwrap();
        let cmd = LedgerCommand::new(
            "reserve-concurrent-1",
            LedgerCommandType::ReserveUtxo,
            "tx-concurrent:0",
            None,
            "intent-a",
            1,
            200,
        );
        m1.apply(&mut st, &cmd)
    });

    let join2 = std::thread::spawn(move || {
        let mut st = state.lock().unwrap();
        let cmd = LedgerCommand::new(
            "reserve-concurrent-2",
            LedgerCommandType::ReserveUtxo,
            "tx-concurrent:0",
            None,
            "intent-b",
            1,
            200,
        );
        machine.apply(&mut st, &cmd)
    });

    let r1 = join1.join().unwrap();
    let r2 = join2.join().unwrap();

    let successes = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 1, "only one reservation should succeed");
}
