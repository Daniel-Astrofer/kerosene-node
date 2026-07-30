use crate::{
    apply_rbf_replacement, compute_state_root, compute_utxo_root, DetectUtxoPayload, OnchainState,
    OutPoint, ReorgPayload, UtxoEntry, LedgerCommand,
    LedgerCommandType, LedgerState, LedgerError, MembershipView, StateMachine,
    DeterministicStateMachine, InMemoryUtxoStore, UtxoStore,
};

// Helper: create a single-node membership for tests.
fn test_membership() -> MembershipView {
    MembershipView::single_node("cluster-1", "node-1")
}

// Helper: build a JSON DetectUtxo payload.
fn detect_payload(value_sats: u64, address: &str) -> String {
    serde_json::to_string(&DetectUtxoPayload {
        value_sats,
        address: address.to_string(),
    })
    .unwrap()
}

// Helper: create a DetectUtxo command.
fn detect_cmd(txid: &str, vout: u32, value_sats: u64, address: &str, bucket: u64) -> LedgerCommand {
    let outpoint = OutPoint::new(txid, vout);
    LedgerCommand::new(
        format!("detect-{}-{}", txid, vout),
        LedgerCommandType::DetectUtxo,
        outpoint.to_canonical_string(),
        None,
        detect_payload(value_sats, address),
        1,
        bucket,
    )
}

// Helper: create a ConfirmUtxo command.
fn confirm_cmd(txid: &str, vout: u32, block_height: u64, bucket: u64) -> LedgerCommand {
    let outpoint = OutPoint::new(txid, vout);
    LedgerCommand::new(
        format!("confirm-{}-{}", txid, vout),
        LedgerCommandType::ConfirmUtxo,
        outpoint.to_canonical_string(),
        None,
        block_height.to_string(),
        1,
        bucket,
    )
}

// Helper: create a MarkUtxoSpendable command.
fn spendable_cmd(txid: &str, vout: u32) -> LedgerCommand {
    let outpoint = OutPoint::new(txid, vout);
    LedgerCommand::new(
        format!("spendable-{}-{}", txid, vout),
        LedgerCommandType::MarkUtxoSpendable,
        outpoint.to_canonical_string(),
        None,
        "",
        1,
        0,
    )
}

// Helper: create a ReserveUtxo command.
fn reserve_cmd(txid: &str, vout: u32, reserved_by: &str) -> LedgerCommand {
    let outpoint = OutPoint::new(txid, vout);
    LedgerCommand::new(
        format!("reserve-{}-{}-{}", txid, vout, reserved_by),
        LedgerCommandType::ReserveUtxo,
        outpoint.to_canonical_string(),
        None,
        reserved_by,
        1,
        0,
    )
}

// Helper: create a ReleaseUtxo command.
fn release_cmd(txid: &str, vout: u32) -> LedgerCommand {
    let outpoint = OutPoint::new(txid, vout);
    LedgerCommand::new(
        format!("release-{}-{}", txid, vout),
        LedgerCommandType::ReleaseUtxo,
        outpoint.to_canonical_string(),
        None,
        "",
        1,
        0,
    )
}

// Helper: create a MarkUtxoSpent command.
fn spend_cmd(txid: &str, vout: u32, spent_by: Option<&str>) -> LedgerCommand {
    let outpoint = OutPoint::new(txid, vout);
    let auth = spent_by.unwrap_or("");
    LedgerCommand::new(
        format!("spend-{}-{}", txid, vout),
        LedgerCommandType::MarkUtxoSpent,
        outpoint.to_canonical_string(),
        None,
        auth,
        1,
        100,
    )
}

// Helper: advance a UTXO through InMempool then Confirming via direct mutation.
fn advance_to_confirming(state: &mut LedgerState, txid: &str, vout: u32) {
    if let Some(utxo) = state.utxos.iter_mut().find(|u| u.txid == txid && u.vout == vout) {
        utxo.state = OnchainState::Confirming;
        utxo.block_height = Some(100);
        utxo.confirmed_at_bucket = Some(50);
    }
}

fn advance_to_spendable(state: &mut LedgerState, txid: &str, vout: u32) {
    advance_to_confirming(state, txid, vout);
    if let Some(utxo) = state.utxos.iter_mut().find(|u| u.txid == txid && u.vout == vout) {
        utxo.state = OnchainState::Spendable;
    }
}

// ============================================================================
// UTXO lifecycle tests
// ============================================================================

#[test]
fn detect_new_utxo_creates_seen() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    let cmd = detect_cmd("tx1", 0, 50000, "addr1", 100);
    sm.apply(&mut state, &cmd).unwrap();

    assert_eq!(state.utxos.len(), 1);
    let utxo = &state.utxos[0];
    assert_eq!(utxo.txid, "tx1");
    assert_eq!(utxo.vout, 0);
    assert_eq!(utxo.value_sats, 50000);
    assert_eq!(utxo.address, "addr1");
    assert_eq!(utxo.state, OnchainState::Seen);
    assert_eq!(utxo.detected_at_bucket, 100);
}

#[test]
fn detect_same_utxo_twice_is_idempotent() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    let cmd = detect_cmd("tx1", 0, 50000, "addr1", 100);
    sm.apply(&mut state, &cmd).unwrap();
    sm.apply(&mut state, &cmd).unwrap();

    assert_eq!(state.utxos.len(), 1);
    assert_eq!(state.utxos[0].value_sats, 50000);
}

#[test]
fn detect_utxo_with_zero_value_rejected() {
    let sm = StateMachine;
    let state = LedgerState::empty(test_membership());

    // Direct validate check
    let cmd = LedgerCommand::new(
        "bad",
        LedgerCommandType::DetectUtxo,
        "tx1:0",
        None,
        detect_payload(0, "addr1"),
        1,
        100,
    );
    let err = sm.validate(&state, &cmd).unwrap_err();
    assert!(err.to_string().contains("value_sats must be > 0"), "got: {}", err);
}

#[test]
fn detect_utxo_empty_address_rejected() {
    let sm = StateMachine;
    let state = LedgerState::empty(test_membership());

    let cmd = LedgerCommand::new(
        "bad",
        LedgerCommandType::DetectUtxo,
        "tx1:0",
        None,
        detect_payload(100, ""),
        1,
        100,
    );
    let err = sm.validate(&state, &cmd).unwrap_err();
    assert!(err.to_string().contains("address must not be empty"), "got: {}", err);
}

#[test]
fn detect_utxo_invalid_outpoint_rejected() {
    let sm = StateMachine;
    let state = LedgerState::empty(test_membership());

    let cmd = LedgerCommand::new(
        "bad",
        LedgerCommandType::DetectUtxo,
        "not-an-outpoint",
        None,
        detect_payload(100, "addr1"),
        1,
        100,
    );
    let err = sm.validate(&state, &cmd).unwrap_err();
    assert!(matches!(err, LedgerError::InvalidUtxoData(_)));
}

#[test]
fn confirm_utxo_transitions_to_confirming() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();

    // Directly set to InMempool first (needed for valid transition)
    state.utxos[0].state = OnchainState::InMempool;

    let cmd = confirm_cmd("tx1", 0, 200000, 150);
    sm.apply(&mut state, &cmd).unwrap();

    let utxo = &state.utxos[0];
    assert_eq!(utxo.state, OnchainState::Confirming);
    assert_eq!(utxo.block_height, Some(200000));
    assert_eq!(utxo.confirmed_at_bucket, Some(150));
}

#[test]
fn mark_spendable_transitions_confirming_to_spendable() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_confirming(&mut state, "tx1", 0);

    let cmd = spendable_cmd("tx1", 0);
    sm.apply(&mut state, &cmd).unwrap();

    assert_eq!(state.utxos[0].state, OnchainState::Spendable);
}

#[test]
fn spend_utxo_transitions_to_spent() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_spendable(&mut state, "tx1", 0);

    let cmd = spend_cmd("tx1", 0, Some("spending-tx"));
    sm.apply(&mut state, &cmd).unwrap();

    let utxo = &state.utxos[0];
    assert_eq!(utxo.state, OnchainState::Spent);
    assert_eq!(utxo.spent_by_txid, Some("spending-tx".to_string()));
    assert_eq!(utxo.spent_at_bucket, Some(100));
}

#[test]
fn spend_releases_reservation() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_spendable(&mut state, "tx1", 0);

    // Reserve it
    let rcmd = reserve_cmd("tx1", 0, "res-1");
    sm.apply(&mut state, &rcmd).unwrap();
    assert_eq!(state.utxos[0].reserved_by, Some("res-1".to_string()));

    // Spend it (should auto-release reservation)
    let scmd = spend_cmd("tx1", 0, Some("spending-tx"));
    sm.apply(&mut state, &scmd).unwrap();

    let utxo = &state.utxos[0];
    assert_eq!(utxo.state, OnchainState::Spent);
    assert!(utxo.reserved_by.is_none());
    assert!(utxo.reserved_at_bucket.is_none());
}

#[test]
fn invalid_transition_seen_to_spent_rejected() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();

    let cmd = spend_cmd("tx1", 0, None);
    let err = sm.apply(&mut state, &cmd).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidUtxoTransition { .. }
    ));
}

#[test]
fn invalid_transition_seen_to_confirming_rejected() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();

    let cmd = confirm_cmd("tx1", 0, 100, 50);
    let err = sm.apply(&mut state, &cmd).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidUtxoTransition { .. }
    ));
}

#[test]
fn utxo_not_found_rejected() {
    let sm = StateMachine;
    let state = LedgerState::empty(test_membership());

    let cmd = confirm_cmd("nonexistent", 0, 100, 50);
    let err = sm.validate(&state, &cmd).unwrap_err();
    assert!(matches!(err, LedgerError::UtxoNotFound { .. }));
}

#[test]
fn full_utxo_lifecycle_through_state_machine() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    // 1. Detect
    sm.apply(&mut state, &detect_cmd("tx1", 0, 100000, "addr1", 10)).unwrap();
    assert_eq!(state.utxos[0].state, OnchainState::Seen);

    // 2. Transition to InMempool (direct mutation for test simplicity)
    state.utxos[0].state = OnchainState::InMempool;

    // 3. Confirm
    sm.apply(&mut state, &confirm_cmd("tx1", 0, 500000, 50)).unwrap();
    assert_eq!(state.utxos[0].state, OnchainState::Confirming);

    // 4. Mark spendable
    sm.apply(&mut state, &spendable_cmd("tx1", 0)).unwrap();
    assert_eq!(state.utxos[0].state, OnchainState::Spendable);

    // 5. Reserve
    let rcmd = reserve_cmd("tx1", 0, "res-1");
    sm.apply(&mut state, &rcmd).unwrap();
    assert_eq!(state.utxos[0].reserved_by, Some("res-1".to_string()));

    // 6. Spend
    let scmd = spend_cmd("tx1", 0, Some("spending-tx"));
    sm.apply(&mut state, &scmd).unwrap();
    let utxo = &state.utxos[0];
    assert_eq!(utxo.state, OnchainState::Spent);
    assert!(utxo.reserved_by.is_none());
    assert_eq!(utxo.spent_by_txid, Some("spending-tx".to_string()));
}

#[test]
fn detect_multiple_utxos() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 100, "addr1", 10)).unwrap();
    sm.apply(&mut state, &detect_cmd("tx1", 1, 200, "addr2", 10)).unwrap();
    sm.apply(&mut state, &detect_cmd("tx2", 0, 300, "addr3", 10)).unwrap();

    assert_eq!(state.utxos.len(), 3);

    // Verify all are seen
    assert!(state.utxos.iter().all(|u| u.state == OnchainState::Seen));
}

// ============================================================================
// Reservation tests
// ============================================================================

#[test]
fn reserve_available_utxo_succeeds() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_spendable(&mut state, "tx1", 0);

    let cmd = reserve_cmd("tx1", 0, "command-1");
    sm.apply(&mut state, &cmd).unwrap();

    assert_eq!(state.utxos[0].reserved_by, Some("command-1".to_string()));
    assert_eq!(state.utxos[0].reserved_at_bucket, Some(0));
}

#[test]
fn double_reserve_same_utxo_rejected() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_spendable(&mut state, "tx1", 0);

    let cmd1 = reserve_cmd("tx1", 0, "command-1");
    sm.apply(&mut state, &cmd1).unwrap();

    let cmd2 = reserve_cmd("tx1", 0, "command-2");
    let err = sm.apply(&mut state, &cmd2).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::UtxoAlreadyReserved { .. }
    ));
}

#[test]
fn release_reservation_succeeds() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_spendable(&mut state, "tx1", 0);

    let rcmd = reserve_cmd("tx1", 0, "command-1");
    sm.apply(&mut state, &rcmd).unwrap();
    assert_eq!(state.utxos[0].reserved_by, Some("command-1".to_string()));

    let relcmd = release_cmd("tx1", 0);
    sm.apply(&mut state, &relcmd).unwrap();

    assert!(state.utxos[0].reserved_by.is_none());
    assert!(state.utxos[0].reserved_at_bucket.is_none());
}

#[test]
fn release_unreserved_utxo_rejected() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_spendable(&mut state, "tx1", 0);

    let cmd = release_cmd("tx1", 0);
    let err = sm.apply(&mut state, &cmd).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::UtxoNotReserved
    ));
}

#[test]
fn reserve_utxo_not_spendable_rejected() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    // UTXO in Seen state — not reservable
    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();

    let cmd = reserve_cmd("tx1", 0, "command-1");
    let err = sm.apply(&mut state, &cmd).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidUtxoTransition { .. }
    ));
}

// ============================================================================
// Reorg tests
// ============================================================================

#[test]
fn reorg_disconnects_confirming_utxos() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_confirming(&mut state, "tx1", 0);

    let payload = ReorgPayload {
        disconnected_txids: vec!["tx1".to_string()],
        new_utxos: vec![],
    };
    let reorg_cmd = LedgerCommand::new(
        "reorg-1",
        LedgerCommandType::ApplyChainReorganization,
        "cluster-1",
        None,
        serde_json::to_string(&payload).unwrap(),
        1,
        200,
    );
    sm.apply(&mut state, &reorg_cmd).unwrap();

    assert_eq!(state.utxos[0].state, OnchainState::Reorged);
    assert!(state.utxos[0].block_height.is_none());
    assert!(state.utxos[0].confirmed_at_bucket.is_none());
}

#[test]
fn reorg_then_re_detect_works() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    // Detect and confirm
    sm.apply(&mut state, &detect_cmd("tx1", 0, 50000, "addr1", 100)).unwrap();
    advance_to_confirming(&mut state, "tx1", 0);

    // Reorg it
    let payload = ReorgPayload {
        disconnected_txids: vec!["tx1".to_string()],
        new_utxos: vec![],
    };
    let reorg_cmd = LedgerCommand::new(
        "reorg-1",
        LedgerCommandType::ApplyChainReorganization,
        "cluster-1",
        None,
        serde_json::to_string(&payload).unwrap(),
        1,
        200,
    );
    sm.apply(&mut state, &reorg_cmd).unwrap();
    assert_eq!(state.utxos[0].state, OnchainState::Reorged);

    // Re-detect
    let detect_cmd2 = detect_cmd("tx1", 0, 50000, "addr1", 300);
    sm.apply(&mut state, &detect_cmd2).unwrap();
    assert_eq!(state.utxos[0].state, OnchainState::Seen);
    assert_eq!(state.utxos[0].detected_at_bucket, 300);
}

#[test]
fn reorg_adds_new_utxos() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    // Existing UTXO that is NOT disconnected
    sm.apply(&mut state, &detect_cmd("tx_existing", 0, 1000, "addr1", 10)).unwrap();
    advance_to_spendable(&mut state, "tx_existing", 0);

    let new_utxo = UtxoEntry::new_seen(OutPoint::new("tx_new", 0), 2000, "addr2", 0);
    let payload = ReorgPayload {
        disconnected_txids: vec!["tx_old".to_string()],
        new_utxos: vec![new_utxo],
    };
    let reorg_cmd = LedgerCommand::new(
        "reorg-2",
        LedgerCommandType::ApplyChainReorganization,
        "cluster-1",
        None,
        serde_json::to_string(&payload).unwrap(),
        1,
        300,
    );
    sm.apply(&mut state, &reorg_cmd).unwrap();

    assert_eq!(state.utxos.len(), 2);
    assert_eq!(state.utxos[0].state, OnchainState::Spendable); // unchanged
    assert_eq!(state.utxos[1].state, OnchainState::Seen); // new
}

#[test]
fn reorg_unaffected_utxos_unchanged() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    sm.apply(&mut state, &detect_cmd("tx_unaffected", 0, 5000, "addr1", 10)).unwrap();
    advance_to_spendable(&mut state, "tx_unaffected", 0);

    let payload = ReorgPayload {
        disconnected_txids: vec!["tx_other".to_string()],
        new_utxos: vec![],
    };
    let reorg_cmd = LedgerCommand::new(
        "reorg-3",
        LedgerCommandType::ApplyChainReorganization,
        "cluster-1",
        None,
        serde_json::to_string(&payload).unwrap(),
        1,
        100,
    );
    sm.apply(&mut state, &reorg_cmd).unwrap();

    assert_eq!(state.utxos[0].state, OnchainState::Spendable);
}

// ============================================================================
// RBF tests
// ============================================================================

#[test]
fn rbf_replaces_utxos_and_releases_reservations() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    // Create UTXOs for tx1
    sm.apply(&mut state, &detect_cmd("tx1", 0, 1000, "addr1", 10)).unwrap();
    sm.apply(&mut state, &detect_cmd("tx1", 1, 2000, "addr2", 10)).unwrap();
    advance_to_spendable(&mut state, "tx1", 0);
    advance_to_spendable(&mut state, "tx1", 1);

    // Reserve one of them
    let rcmd = reserve_cmd("tx1", 0, "res-1");
    sm.apply(&mut state, &rcmd).unwrap();

    // Use the standalone RBF function
    let replacement = UtxoEntry::new_seen(OutPoint::new("tx2", 0), 3000, "addr3", 10);
    let released = apply_rbf_replacement(
        &mut state.utxos,
        "tx1",
        &[replacement],
    )
    .unwrap();

    assert_eq!(released, vec!["res-1".to_string()]);
    assert_eq!(state.utxos[0].state, OnchainState::Replaced);
    assert_eq!(state.utxos[1].state, OnchainState::Replaced);
    assert_eq!(state.utxos.len(), 3);
    assert_eq!(state.utxos[2].state, OnchainState::Seen);
    assert_eq!(state.utxos[2].txid, "tx2");
}

#[test]
fn rbf_with_no_reservations() {
    let mut state = LedgerState::empty(test_membership());
    state.utxos.push(UtxoEntry::new_seen(OutPoint::new("tx1", 0), 1000, "addr1", 10));

    let replacement = UtxoEntry::new_seen(OutPoint::new("tx2", 0), 1500, "addr2", 10);
    let released = apply_rbf_replacement(&mut state.utxos, "tx1", &[replacement]).unwrap();
    assert!(released.is_empty());
    assert_eq!(state.utxos[0].state, OnchainState::Replaced);
    assert_eq!(state.utxos.len(), 2);
}

#[test]
fn rbf_replacement_already_exists_skipped() {
    let mut state = LedgerState::empty(test_membership());
    state.utxos.push(UtxoEntry::new_seen(OutPoint::new("tx1", 0), 1000, "addr1", 10));

    // Replacement UTXO already present
    let replacement = UtxoEntry::new_seen(OutPoint::new("tx1", 0), 1000, "addr1", 10);
    let released = apply_rbf_replacement(&mut state.utxos, "tx1", &[replacement]).unwrap();
    assert!(released.is_empty());
    // Original is replaced, no duplicate added
    assert_eq!(state.utxos[0].state, OnchainState::Replaced);
    assert_eq!(state.utxos.len(), 1);
}

// ============================================================================
// State root tests
// ============================================================================

#[test]
fn state_root_includes_utxos() {
    let mut state1 = LedgerState::empty(test_membership());
    let mut state2 = LedgerState::empty(test_membership());

    let root_empty = compute_state_root(&state1);

    // Add UTXO to state1 only
    state1.utxos.push(UtxoEntry::new_seen(OutPoint::new("tx1", 0), 100, "addr1", 1));
    let root_with_utxo = compute_state_root(&state1);

    assert_ne!(root_empty, root_with_utxo, "UTXO must affect state root");

    // Same UTXO set produces same root
    state2.utxos.push(UtxoEntry::new_seen(OutPoint::new("tx1", 0), 100, "addr1", 1));
    let root2 = compute_state_root(&state2);
    assert_eq!(root_with_utxo, root2, "same UTXO set = same root");
}

#[test]
fn state_root_with_utxos_is_deterministic() {
    let mut state = LedgerState::empty(test_membership());
    state.utxos.push(UtxoEntry::new_seen(OutPoint::new("tx_b", 0), 200, "addr2", 2));
    state.utxos.push(UtxoEntry::new_seen(OutPoint::new("tx_a", 0), 100, "addr1", 1));

    let root1 = compute_state_root(&state);
    let root2 = compute_state_root(&state);
    assert_eq!(root1, root2);
}

#[test]
fn different_utxo_value_changes_root() {
    let mut state = LedgerState::empty(test_membership());
    state.utxos.push(UtxoEntry::new_seen(OutPoint::new("tx1", 0), 100, "addr1", 1));
    let root1 = compute_state_root(&state);

    let mut state2 = LedgerState::empty(test_membership());
    state2.utxos.push(UtxoEntry::new_seen(OutPoint::new("tx1", 0), 200, "addr1", 1));
    let root2 = compute_state_root(&state2);

    assert_ne!(root1, root2);
}

#[test]
fn utxo_order_does_not_affect_state_root() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    // Add UTXOs via state machine
    sm.apply(&mut state, &detect_cmd("tx_b", 0, 200, "addr2", 1)).unwrap();
    sm.apply(&mut state, &detect_cmd("tx_a", 0, 100, "addr1", 1)).unwrap();

    let root = compute_state_root(&state);

    // Rebuild with different insertion order
    let mut state2 = LedgerState::empty(test_membership());
    sm.apply(&mut state2, &detect_cmd("tx_a", 0, 100, "addr1", 1)).unwrap();
    sm.apply(&mut state2, &detect_cmd("tx_b", 0, 200, "addr2", 1)).unwrap();

    let root2 = compute_state_root(&state2);
    assert_eq!(root, root2, "state root must be order-independent");
}

#[test]
fn compute_utxo_root_deterministic() {
    let utxos = vec![
        UtxoEntry::new_seen(OutPoint::new("tx1", 0), 100, "addr1", 1),
        UtxoEntry::new_seen(OutPoint::new("tx2", 0), 200, "addr2", 2),
    ];
    let root1 = compute_utxo_root(&utxos);
    let root2 = compute_utxo_root(&utxos);
    assert_eq!(root1, root2);
}

#[test]
fn empty_utxos_root_is_deterministic() {
    let root1 = compute_utxo_root(&[]);
    let root2 = compute_utxo_root(&[]);
    assert_eq!(root1, root2);
    assert_eq!(root1.len(), 64);
}

// ============================================================================
// Store operation tests
// ============================================================================

#[tokio::test]
async fn in_memory_store_add_get_list() {
    let store = InMemoryUtxoStore::new();
    let utxo = UtxoEntry::new_seen(OutPoint::new("tx1", 0), 1000, "addr1", 1);

    store.add_utxo(utxo.clone()).await.unwrap();

    let fetched = store.get_utxo(&OutPoint::new("tx1", 0)).await.unwrap().unwrap();
    assert_eq!(fetched, utxo);

    let all = store.list_all().await.unwrap();
    assert_eq!(all.len(), 1);

    let seen = store.list_by_state(OnchainState::Seen).await.unwrap();
    assert_eq!(seen.len(), 1);

    let spent = store.list_by_state(OnchainState::Spent).await.unwrap();
    assert!(spent.is_empty());
}

#[tokio::test]
async fn in_memory_store_update_state() {
    let store = InMemoryUtxoStore::new();
    store.add_utxo(UtxoEntry::new_seen(OutPoint::new("tx1", 0), 1000, "addr1", 1)).await.unwrap();

    store.update_state(&OutPoint::new("tx1", 0), OnchainState::InMempool).await.unwrap();
    let utxo = store.get_utxo(&OutPoint::new("tx1", 0)).await.unwrap().unwrap();
    assert_eq!(utxo.state, OnchainState::InMempool);
}

#[tokio::test]
async fn in_memory_store_reserve_release() {
    let store = InMemoryUtxoStore::new();
    store.add_utxo(UtxoEntry {
        state: OnchainState::Spendable,
        ..UtxoEntry::new_seen(OutPoint::new("tx1", 0), 1000, "addr1", 1)
    }).await.unwrap();

    store.reserve(&OutPoint::new("tx1", 0), "res-1", 100).await.unwrap();
    let utxo = store.get_utxo(&OutPoint::new("tx1", 0)).await.unwrap().unwrap();
    assert_eq!(utxo.reserved_by, Some("res-1".to_string()));

    store.release(&OutPoint::new("tx1", 0)).await.unwrap();
    let utxo = store.get_utxo(&OutPoint::new("tx1", 0)).await.unwrap().unwrap();
    assert!(utxo.reserved_by.is_none());
}

#[tokio::test]
async fn in_memory_store_root_hash_deterministic() {
    let store = InMemoryUtxoStore::new();
    store.add_utxo(UtxoEntry::new_seen(OutPoint::new("tx1", 0), 100, "addr1", 1)).await.unwrap();
    store.add_utxo(UtxoEntry::new_seen(OutPoint::new("tx2", 0), 200, "addr2", 1)).await.unwrap();

    let hash1 = store.compute_utxo_root_hash().await.unwrap();
    let hash2 = store.compute_utxo_root_hash().await.unwrap();
    assert_eq!(hash1, hash2);
}

#[tokio::test]
async fn in_memory_store_empty() {
    let store = InMemoryUtxoStore::new();
    let all = store.list_all().await.unwrap();
    assert!(all.is_empty());

    let result = store.get_utxo(&OutPoint::new("nonexistent", 0)).await.unwrap();
    assert!(result.is_none());
}

// ============================================================================
// Edge cases and error handling
// ============================================================================

#[test]
fn detect_utxo_invalid_json_payload_rejected() {
    let sm = StateMachine;
    let state = LedgerState::empty(test_membership());

    let cmd = LedgerCommand::new(
        "bad",
        LedgerCommandType::DetectUtxo,
        "tx1:0",
        None,
        "not-json",
        1,
        100,
    );
    let err = sm.validate(&state, &cmd).unwrap_err();
    assert!(matches!(
        err,
        LedgerError::InvalidUtxoData(_)
    ));
}

#[test]
fn state_machine_handles_all_utxo_command_types() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    // Test that all UTXO commands can be validated/applied without panic
    let detect = detect_cmd("tx1", 0, 100, "addr1", 1);
    assert!(sm.validate(&state, &detect).is_ok());
    sm.apply(&mut state, &detect).unwrap();

    let prepare = LedgerCommand::new(
        "prepare-1",
        LedgerCommandType::PrepareWithdrawal,
        "tx1:0",
        None,
        "",
        1,
        0,
    );
    assert!(sm.validate(&state, &prepare).is_ok());
    sm.apply(&mut state, &prepare).unwrap();

    let auth = LedgerCommand::new(
        "auth-1",
        LedgerCommandType::AuthorizeWithdrawal,
        "tx1:0",
        None,
        "",
        1,
        0,
    );
    assert!(sm.validate(&state, &auth).is_ok());
    sm.apply(&mut state, &auth).unwrap();

    let broadcast = LedgerCommand::new(
        "broadcast-1",
        LedgerCommandType::BroadcastWithdrawal,
        "tx1:0",
        None,
        "",
        1,
        0,
    );
    assert!(sm.validate(&state, &broadcast).is_ok());
    sm.apply(&mut state, &broadcast).unwrap();

    let confirm_w = LedgerCommand::new(
        "confirm-w-1",
        LedgerCommandType::ConfirmWithdrawal,
        "tx1:0",
        None,
        "",
        1,
        0,
    );
    assert!(sm.validate(&state, &confirm_w).is_ok());
    sm.apply(&mut state, &confirm_w).unwrap();

    let fail_w = LedgerCommand::new(
        "fail-w-1",
        LedgerCommandType::FailWithdrawal,
        "tx1:0",
        None,
        "",
        1,
        0,
    );
    assert!(sm.validate(&state, &fail_w).is_ok());
    sm.apply(&mut state, &fail_w).unwrap();
}

#[test]
fn state_machine_apply_with_utxo_advances_version() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    assert_eq!(state.version, 0);
    let cmd = detect_cmd("tx1", 0, 100, "addr1", 1);
    let receipt = sm.apply(&mut state, &cmd).unwrap();

    assert_eq!(state.version, 1);
    assert_eq!(receipt.sequence, 0);
    assert_eq!(receipt.command_hash.len(), 64);
    assert_ne!(receipt.previous_state_root, receipt.resulting_state_root);
}

#[test]
fn state_machine_utxo_affected_accounts() {
    let sm = StateMachine;
    let mut state = LedgerState::empty(test_membership());

    let cmd = detect_cmd("tx1", 0, 100, "addr1", 1);
    let receipt = sm.apply(&mut state, &cmd).unwrap();

    assert!(receipt.affected_accounts.contains(&"utxo".to_string()));
}
