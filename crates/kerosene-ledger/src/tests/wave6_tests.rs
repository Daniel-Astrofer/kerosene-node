use crate::certificate::QuorumCertificate;
use crate::nonce::{InMemoryNonceChecker, NonceChecker};
use crate::reservation::Reservation;
use crate::settlement::{
    NonceChecker as SyncNonceChecker, PsbtCommitment, SettlementAuthorization, SettlementPolicy,
    SettlementValidator, VaultAuthorizationVerifier, VaultVerificationError,
};
use crate::state_machine::{LedgerState, MembershipView};
use crate::withdrawal::{InMemoryWithdrawalStore, WithdrawalRecord, WithdrawalStatus, WithdrawalStore};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_membership() -> MembershipView {
    MembershipView::single_node("cluster-1", "node-1")
}

fn test_qc() -> QuorumCertificate {
    QuorumCertificate::single_node(
        "cluster-1", 1, 0, 1, "cmd-hash", "prev-root", "result-root", "node-1", "sig",
    )
}

fn test_policy() -> SettlementPolicy {
    SettlementPolicy {
        max_fee_sats: 10_000,
        min_confirmations: 6,
        allowed_destination_types: vec!["p2wpkh".into(), "p2tr".into()],
        max_outputs: 10,
        rbf_allowed: true,
        max_epoch_drift: 5,
        authorization_ttl_buckets: 100,
    }
}

fn test_auth() -> SettlementAuthorization {
    SettlementAuthorization {
        intent_commitment: "intent-commit-1".into(),
        command_hash: "cmd-hash-1".into(),
        psbt_commitment: "abc123".into(),
        policy_hash: "policy-hash-1".into(),
        epoch: 1,
        expires_at_bucket: 200,
        nonce: "nonce-unique-1".into(),
        quorum_certificate: test_qc(),
    }
}

// ---------------------------------------------------------------------------
// SettlementAuthorization tests
// ---------------------------------------------------------------------------

#[test]
fn create_and_verify_basic_structure() {
    let auth = test_auth();
    assert!(auth.verify_basic().is_ok());
}

#[test]
fn verify_basic_fails_on_empty_intent_commitment() {
    let auth = SettlementAuthorization {
        intent_commitment: "".into(),
        ..test_auth()
    };
    assert!(auth.verify_basic().is_err());
}

#[test]
fn verify_basic_fails_on_empty_command_hash() {
    let auth = SettlementAuthorization {
        command_hash: "".into(),
        ..test_auth()
    };
    assert!(auth.verify_basic().is_err());
}

#[test]
fn verify_basic_fails_on_empty_psbt_commitment() {
    let auth = SettlementAuthorization {
        psbt_commitment: "".into(),
        ..test_auth()
    };
    assert!(auth.verify_basic().is_err());
}

#[test]
fn verify_basic_fails_on_empty_policy_hash() {
    let auth = SettlementAuthorization {
        policy_hash: "".into(),
        ..test_auth()
    };
    assert!(auth.verify_basic().is_err());
}

#[test]
fn verify_basic_fails_on_empty_nonce() {
    let auth = SettlementAuthorization {
        nonce: "".into(),
        ..test_auth()
    };
    assert!(auth.verify_basic().is_err());
}

#[test]
fn verify_basic_fails_on_empty_qc_signatures() {
    let mut qc = test_qc();
    qc.signatures = vec![];
    let auth = SettlementAuthorization {
        quorum_certificate: qc,
        ..test_auth()
    };
    assert!(auth.verify_basic().is_err());
}

#[test]
fn serialization_roundtrip_json() {
    let auth = test_auth();
    let json = serde_json::to_string(&auth).unwrap();
    let deserialized: SettlementAuthorization = serde_json::from_str(&json).unwrap();
    assert_eq!(auth, deserialized);
}

#[test]
fn is_expired_works_correctly() {
    let auth = test_auth(); // expires_at_bucket = 200
    assert!(!auth.is_expired(100));
    assert!(!auth.is_expired(199));
    assert!(auth.is_expired(200));
    assert!(auth.is_expired(300));
}

#[test]
fn verify_against_reservation_valid() {
    let auth = test_auth();
    let reservation = Reservation::new(
        "res-1", "account-1", 100_000, 50, 300, "intent-commit-1",
    );
    assert!(auth.verify_against_reservation(&reservation).is_ok());
}

#[test]
fn verify_against_reservation_rejects_terminal_reservation() {
    let auth = test_auth();
    let mut reservation = Reservation::new(
        "res-1", "account-1", 100_000, 50, 300, "intent-commit-1",
    );
    reservation.state = crate::reservation::ReservationState::Consumed;
    assert!(auth.verify_against_reservation(&reservation).is_err());
}

#[test]
fn verify_against_reservation_rejects_mismatched_commitment() {
    let auth = test_auth();
    let reservation = Reservation::new(
        "res-1", "account-1", 100_000, 50, 300, "different-commitment",
    );
    assert!(auth.verify_against_reservation(&reservation).is_err());
}

#[test]
fn reject_expired_authorization() {
    let auth = SettlementAuthorization {
        expires_at_bucket: 10,
        ..test_auth()
    };
    assert!(auth.is_expired(10));
    assert!(auth.is_expired(20));
}

// ---------------------------------------------------------------------------
// PsbtCommitment tests
// ---------------------------------------------------------------------------

#[test]
fn psbt_compute_hash_from_bytes() {
    let hash = PsbtCommitment::compute(b"hello psbt");
    // SHA-256 is always 64 hex chars
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn psbt_same_bytes_same_hash() {
    let data = b"same psbt data";
    let h1 = PsbtCommitment::compute(data);
    let h2 = PsbtCommitment::compute(data);
    assert_eq!(h1, h2);
}

#[test]
fn psbt_different_bytes_different_hash() {
    let h1 = PsbtCommitment::compute(b"psbt data one");
    let h2 = PsbtCommitment::compute(b"psbt data two");
    assert_ne!(h1, h2);
}

#[test]
fn psbt_commitment_tracks_input_output_count() {
    let commitment = PsbtCommitment::new(b"psbt", 3, 5, 1_000_000);
    assert_eq!(commitment.input_count, 3);
    assert_eq!(commitment.output_count, 5);
    assert_eq!(commitment.total_output_sats, 1_000_000);
}

#[test]
fn psbt_commitment_serde_roundtrip() {
    let c = PsbtCommitment::new(b"psbt-bytes", 2, 1, 500_000);
    let json = serde_json::to_string(&c).unwrap();
    let deserialized: PsbtCommitment = serde_json::from_str(&json).unwrap();
    assert_eq!(c, deserialized);
}

// ---------------------------------------------------------------------------
// SettlementPolicy tests
// ---------------------------------------------------------------------------

#[test]
fn policy_validate_valid() {
    let policy = test_policy();
    assert!(policy.validate().is_ok());
}

#[test]
fn policy_invalid_max_fee_sats() {
    let policy = SettlementPolicy {
        max_fee_sats: 0,
        ..test_policy()
    };
    assert!(policy.validate().is_err());
}

#[test]
fn policy_invalid_min_confirmations() {
    let policy = SettlementPolicy {
        min_confirmations: 0,
        ..test_policy()
    };
    assert!(policy.validate().is_err());
}

#[test]
fn policy_invalid_empty_destination_types() {
    let policy = SettlementPolicy {
        allowed_destination_types: vec![],
        ..test_policy()
    };
    assert!(policy.validate().is_err());
}

#[test]
fn policy_invalid_max_outputs() {
    let policy = SettlementPolicy {
        max_outputs: 0,
        ..test_policy()
    };
    assert!(policy.validate().is_err());
}

#[test]
fn policy_serde_roundtrip() {
    let policy = test_policy();
    let json = serde_json::to_string(&policy).unwrap();
    let deserialized: SettlementPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(policy, deserialized);
}

// ---------------------------------------------------------------------------
// SettlementValidator tests
// ---------------------------------------------------------------------------

#[test]
fn validator_accepts_valid_authorization() {
    let state = LedgerState::empty(test_membership());
    let auth = test_auth();
    let policy = test_policy();

    let result = SettlementValidator::validate_settlement(&auth, &state, &policy, 100);
    assert!(result.is_ok(), "expected Ok, got {:?}", result);
}

#[test]
fn validator_rejects_consumed_intent() {
    let mut state = LedgerState::empty(test_membership());
    // Mark intent as consumed
    state.consumed_intents.push("intent-commit-1".into());
    let auth = test_auth();
    let policy = test_policy();

    let result = SettlementValidator::validate_settlement(&auth, &state, &policy, 100);
    assert!(result.is_err());
}

#[test]
fn validator_rejects_expired_authorization() {
    let state = LedgerState::empty(test_membership());
    let auth = SettlementAuthorization {
        expires_at_bucket: 10,
        ..test_auth()
    };
    let policy = test_policy();

    let result = SettlementValidator::validate_settlement(&auth, &state, &policy, 100);
    assert!(result.is_err());
}

#[test]
fn validator_psbt_commitment_against_policy_valid() {
    let psbt = PsbtCommitment::new(b"psbt", 2, 3, 1_000_000);
    let policy = test_policy();
    assert!(SettlementValidator::validate_psbt_against_policy(&psbt, &policy).is_ok());
}

#[test]
fn validator_psbt_commitment_against_policy_too_many_outputs() {
    let psbt = PsbtCommitment {
        psbt_hash: "hash".into(),
        input_count: 1,
        output_count: 20, // policy allows max 10
        total_output_sats: 1_000_000,
    };
    let policy = test_policy();
    assert!(SettlementValidator::validate_psbt_against_policy(&psbt, &policy).is_err());
}

#[test]
fn validator_rejects_wrong_epoch() {
    let state = LedgerState::empty(test_membership());
    let auth = SettlementAuthorization {
        epoch: 100, // state.version is 0, drift is 100, but max is 5
        ..test_auth()
    };
    let policy = test_policy();

    let result = SettlementValidator::validate_settlement(&auth, &state, &policy, 100);
    assert!(result.is_err());
}

#[test]
fn validator_rejects_mismatched_qc_epoch() {
    let state = LedgerState::empty(test_membership());
    let qc = QuorumCertificate::single_node(
        "cluster-1", 99, 0, 1, "cmd-hash", "prev-root", "result-root", "node-1", "sig",
    );
    let auth = SettlementAuthorization {
        epoch: 1,
        quorum_certificate: qc,
        ..test_auth()
    };
    let policy = test_policy();

    let result = SettlementValidator::validate_settlement(&auth, &state, &policy, 100);
    assert!(result.is_err());
}

#[test]
fn validator_validate_epoch_within_drift() {
    assert!(SettlementValidator::validate_epoch(10, 12, 5).is_ok());
    assert!(SettlementValidator::validate_epoch(12, 10, 5).is_ok());
    assert!(SettlementValidator::validate_epoch(10, 10, 5).is_ok());
}

#[test]
fn validator_validate_epoch_exceeds_drift() {
    assert!(SettlementValidator::validate_epoch(1, 10, 5).is_err());
    assert!(SettlementValidator::validate_epoch(10, 1, 5).is_err());
}

#[test]
fn validator_validate_quorum_certificate_valid() {
    let qc = test_qc();
    assert!(SettlementValidator::validate_quorum_certificate(&qc, "cluster-1").is_ok());
}

#[test]
fn validator_validate_quorum_certificate_wrong_cluster() {
    let qc = test_qc();
    assert!(SettlementValidator::validate_quorum_certificate(&qc, "wrong-cluster").is_err());
}

// ---------------------------------------------------------------------------
// VaultAuthorizationVerifier tests
// ---------------------------------------------------------------------------

fn test_sync_nonce_checker() -> impl SyncNonceChecker {
    struct SimpleChecker(std::sync::Mutex<std::collections::HashSet<String>>);
    impl SyncNonceChecker for SimpleChecker {
        fn is_consumed_sync(&self, nonce: &str) -> bool {
            self.0.lock().unwrap().contains(nonce)
        }
        fn mark_consumed_sync(&self, nonce: &str) {
            self.0.lock().unwrap().insert(nonce.to_string());
        }
    }
    SimpleChecker(std::sync::Mutex::new(std::collections::HashSet::new()))
}

#[test]
fn vault_verifier_accepts_valid_auth() {
    let psbt_bytes = b"valid psbt data";
    let psbt_hash = PsbtCommitment::compute(psbt_bytes);
    let auth = SettlementAuthorization {
        psbt_commitment: psbt_hash,
        ..test_auth()
    };
    let policy = test_policy();
    let nonce_checker = test_sync_nonce_checker();

    let result = VaultAuthorizationVerifier::verify(
        &auth, psbt_bytes, 2, 3, 1_000_000, &policy, &nonce_checker, 100,
    );
    assert!(result.is_ok(), "expected Ok, got {:?}", result);
}

#[test]
fn vault_verifier_psbt_hash_mismatch() {
    let psbt_bytes = b"some psbt";
    let auth = test_auth(); // psbt_commitment = "abc123"
    let policy = test_policy();
    let nonce_checker = test_sync_nonce_checker();

    let result = VaultAuthorizationVerifier::verify(
        &auth, psbt_bytes, 2, 3, 1_000_000, &policy, &nonce_checker, 100,
    );
    assert!(matches!(result, Err(VaultVerificationError::PsbtMismatch { .. })));
}

#[test]
fn vault_verifier_nonce_consumed() {
    let psbt_bytes = b"valid psbt data";
    let psbt_hash = PsbtCommitment::compute(psbt_bytes);
    let auth = SettlementAuthorization {
        psbt_commitment: psbt_hash,
        nonce: "used-nonce".into(),
        ..test_auth()
    };
    let policy = test_policy();
    let nonce_checker = test_sync_nonce_checker();
    nonce_checker.mark_consumed_sync("used-nonce");

    let result = VaultAuthorizationVerifier::verify(
        &auth, psbt_bytes, 2, 3, 1_000_000, &policy, &nonce_checker, 100,
    );
    assert!(matches!(result, Err(VaultVerificationError::NonceReused(_))));
}

#[test]
fn vault_verifier_rejects_expired_auth() {
    let psbt_bytes = b"valid psbt data";
    let psbt_hash = PsbtCommitment::compute(psbt_bytes);
    let auth = SettlementAuthorization {
        psbt_commitment: psbt_hash,
        expires_at_bucket: 10,
        ..test_auth()
    };
    let policy = test_policy();
    let nonce_checker = test_sync_nonce_checker();

    let result = VaultAuthorizationVerifier::verify(
        &auth, psbt_bytes, 2, 3, 1_000_000, &policy, &nonce_checker, 100,
    );
    assert!(matches!(result, Err(VaultVerificationError::AuthorizationExpired { .. })));
}

#[test]
fn vault_verifier_rejects_empty_nonce() {
    let psbt_bytes = b"valid psbt data";
    let psbt_hash = PsbtCommitment::compute(psbt_bytes);
    let auth = SettlementAuthorization {
        psbt_commitment: psbt_hash,
        nonce: "".into(),
        ..test_auth()
    };
    let policy = test_policy();
    let nonce_checker = test_sync_nonce_checker();

    let result = VaultAuthorizationVerifier::verify(
        &auth, psbt_bytes, 2, 3, 1_000_000, &policy, &nonce_checker, 100,
    );
    assert!(result.is_err());
}

#[test]
fn vault_verifier_rejects_zero_inputs() {
    let psbt_bytes = b"psbt";
    let psbt_hash = PsbtCommitment::compute(psbt_bytes);
    let auth = SettlementAuthorization {
        psbt_commitment: psbt_hash,
        ..test_auth()
    };
    let policy = test_policy();
    let nonce_checker = test_sync_nonce_checker();

    let result = VaultAuthorizationVerifier::verify(
        &auth, psbt_bytes, 0, 2, 1_000_000, &policy, &nonce_checker, 100,
    );
    assert!(result.is_err());
}

#[test]
fn vault_verifier_rejects_zero_outputs() {
    let psbt_bytes = b"psbt";
    let psbt_hash = PsbtCommitment::compute(psbt_bytes);
    let auth = SettlementAuthorization {
        psbt_commitment: psbt_hash,
        ..test_auth()
    };
    let policy = test_policy();
    let nonce_checker = test_sync_nonce_checker();

    let result = VaultAuthorizationVerifier::verify(
        &auth, psbt_bytes, 2, 0, 1_000_000, &policy, &nonce_checker, 100,
    );
    assert!(result.is_err());
}

#[test]
fn vault_verifier_epoch_drift_exceeded() {
    let psbt_bytes = b"psbt";
    let psbt_hash = PsbtCommitment::compute(psbt_bytes);
    let qc = QuorumCertificate::single_node(
        "cluster-1", 100, 0, 1, "cmd-hash", "prev-root", "result-root", "node-1", "sig",
    );
    let auth = SettlementAuthorization {
        psbt_commitment: psbt_hash,
        epoch: 1,
        quorum_certificate: qc,
        ..test_auth()
    };
    let policy = SettlementPolicy {
        max_epoch_drift: 5,
        ..test_policy()
    };
    let nonce_checker = test_sync_nonce_checker();

    let result = VaultAuthorizationVerifier::verify(
        &auth, psbt_bytes, 2, 2, 1_000_000, &policy, &nonce_checker, 100,
    );
    assert!(matches!(result, Err(VaultVerificationError::EpochExpired { .. })));
}

// ---------------------------------------------------------------------------
// Withdrawal lifecycle tests (async)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_withdrawal_in_reserved_state() {
    let store = InMemoryWithdrawalStore::new();
    let wd = WithdrawalRecord::new("wd-1", "intent-1", "account-1", 100_000, "bc1qxyz", 100);
    store.create(wd.clone()).await.unwrap();
    let retrieved = store.get("wd-1").await.unwrap().unwrap();
    assert_eq!(retrieved.status, WithdrawalStatus::Reserved);
    assert_eq!(retrieved.created_at_bucket, 100);
}

#[tokio::test]
async fn update_status_through_lifecycle() {
    let store = InMemoryWithdrawalStore::new();
    let wd = WithdrawalRecord::new("wd-lifecycle", "intent", "acc", 50_000, "addr", 100);
    store.create(wd).await.unwrap();

    // Reserved -> Authorized -> Signing -> Broadcast -> Confirming -> Confirmed
    store.update_status("wd-lifecycle", WithdrawalStatus::Authorized, 110).await.unwrap();
    store.update_status("wd-lifecycle", WithdrawalStatus::Signing, 120).await.unwrap();
    store.update_status("wd-lifecycle", WithdrawalStatus::Broadcast, 130).await.unwrap();
    store.update_status("wd-lifecycle", WithdrawalStatus::Confirming, 140).await.unwrap();
    store.update_status("wd-lifecycle", WithdrawalStatus::Confirmed, 150).await.unwrap();

    let final_wd = store.get("wd-lifecycle").await.unwrap().unwrap();
    assert_eq!(final_wd.status, WithdrawalStatus::Confirmed);
    assert_eq!(final_wd.updated_at_bucket, 150);
}

#[tokio::test]
async fn withdrawal_can_fail_from_any_non_terminal_state() {
    let store = InMemoryWithdrawalStore::new();
    let wd = WithdrawalRecord::new("wd-fail", "intent", "acc", 50_000, "addr", 100);
    store.create(wd).await.unwrap();

    // Fail from Reserved
    store.update_status("wd-fail", WithdrawalStatus::Failed, 110).await.unwrap();
    let wd = store.get("wd-fail").await.unwrap().unwrap();
    assert_eq!(wd.status, WithdrawalStatus::Failed);
}

#[tokio::test]
async fn withdrawal_can_rbf_from_broadcast() {
    let store = InMemoryWithdrawalStore::new();
    let wd = WithdrawalRecord::new("wd-rbf", "intent", "acc", 50_000, "addr", 100);
    store.create(wd).await.unwrap();

    store.update_status("wd-rbf", WithdrawalStatus::Authorized, 110).await.unwrap();
    store.update_status("wd-rbf", WithdrawalStatus::Signing, 120).await.unwrap();
    store.update_status("wd-rbf", WithdrawalStatus::Broadcast, 130).await.unwrap();
    store.update_status("wd-rbf", WithdrawalStatus::Replaced, 140).await.unwrap();

    let wd = store.get("wd-rbf").await.unwrap().unwrap();
    assert_eq!(wd.status, WithdrawalStatus::Replaced);
}

#[tokio::test]
async fn withdrawal_set_authorization() {
    let store = InMemoryWithdrawalStore::new();
    let wd = WithdrawalRecord::new("wd-auth", "intent", "acc", 50_000, "addr", 100);
    store.create(wd).await.unwrap();

    let qc = QuorumCertificate::single_node(
        "cluster-1", 1, 0, 10, "cmd-hash", "prev", "result", "node-1", "sig",
    );
    let auth = SettlementAuthorization {
        intent_commitment: "intent-1".into(),
        command_hash: "cmd-hash".into(),
        psbt_commitment: "psbt-hash".into(),
        policy_hash: "policy-hash".into(),
        epoch: 1,
        expires_at_bucket: 200,
        nonce: "nonce-auth".into(),
        quorum_certificate: qc,
    };

    store.set_authorization("wd-auth", auth).await.unwrap();
    let retrieved = store.get("wd-auth").await.unwrap().unwrap();
    assert_eq!(retrieved.status, WithdrawalStatus::Authorized);
    assert!(retrieved.authorization.is_some());
}

#[tokio::test]
async fn withdrawal_set_psbt_commitment() {
    let store = InMemoryWithdrawalStore::new();
    let wd = WithdrawalRecord::new("wd-psbt", "intent", "acc", 50_000, "addr", 100);
    store.create(wd).await.unwrap();

    let commitment = PsbtCommitment::new(b"psbt-data", 2, 1, 50_000);
    store.set_psbt("wd-psbt", commitment.clone()).await.unwrap();

    let retrieved = store.get("wd-psbt").await.unwrap().unwrap();
    assert_eq!(retrieved.psbt_commitment, Some(commitment));
}

#[tokio::test]
async fn withdrawal_set_broadcast_txid() {
    let store = InMemoryWithdrawalStore::new();
    let wd = WithdrawalRecord::new("wd-txid", "intent", "acc", 50_000, "addr", 100);
    store.create(wd).await.unwrap();

    store.set_broadcast_txid("wd-txid", "abcdef123456").await.unwrap();
    let retrieved = store.get("wd-txid").await.unwrap().unwrap();
    assert_eq!(retrieved.broadcast_txid, Some("abcdef123456".into()));
}

#[tokio::test]
async fn withdrawal_broadcast_txid_immutable() {
    let store = InMemoryWithdrawalStore::new();
    let wd = WithdrawalRecord::new("wd-immutable", "intent", "acc", 50_000, "addr", 100);
    store.create(wd).await.unwrap();

    store.set_broadcast_txid("wd-immutable", "txid-1").await.unwrap();
    let err = store.set_broadcast_txid("wd-immutable", "txid-2").await.unwrap_err();
    assert!(matches!(err, crate::error::LedgerError::InvalidStateTransition(_)));
}

#[tokio::test]
async fn withdrawal_withdrawal_not_found() {
    let store = InMemoryWithdrawalStore::new();
    let result = store.get("nonexistent").await.unwrap();
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// WithdrawalStatus transition validation tests
// ---------------------------------------------------------------------------

#[test]
fn withdrawal_status_terminal_states() {
    assert!(WithdrawalStatus::Confirmed.is_terminal());
    assert!(WithdrawalStatus::Failed.is_terminal());
    assert!(WithdrawalStatus::Replaced.is_terminal());
    assert!(!WithdrawalStatus::Reserved.is_terminal());
    assert!(!WithdrawalStatus::Authorized.is_terminal());
    assert!(!WithdrawalStatus::Signing.is_terminal());
    assert!(!WithdrawalStatus::Broadcast.is_terminal());
    assert!(!WithdrawalStatus::Confirming.is_terminal());
}

#[test]
fn withdrawal_status_valid_transitions() {
    assert!(WithdrawalStatus::Reserved.can_transition_to(WithdrawalStatus::Authorized));
    assert!(WithdrawalStatus::Authorized.can_transition_to(WithdrawalStatus::Signing));
    assert!(WithdrawalStatus::Signing.can_transition_to(WithdrawalStatus::Broadcast));
    assert!(WithdrawalStatus::Broadcast.can_transition_to(WithdrawalStatus::Confirming));
    assert!(WithdrawalStatus::Confirming.can_transition_to(WithdrawalStatus::Confirmed));
    assert!(WithdrawalStatus::Broadcast.can_transition_to(WithdrawalStatus::Replaced));
    assert!(WithdrawalStatus::Confirming.can_transition_to(WithdrawalStatus::Replaced));
}

#[test]
fn withdrawal_status_invalid_transitions() {
    assert!(!WithdrawalStatus::Reserved.can_transition_to(WithdrawalStatus::Broadcast));
    assert!(!WithdrawalStatus::Reserved.can_transition_to(WithdrawalStatus::Confirmed));
    assert!(!WithdrawalStatus::Authorized.can_transition_to(WithdrawalStatus::Confirmed));
    assert!(!WithdrawalStatus::Confirmed.can_transition_to(WithdrawalStatus::Failed));
    assert!(!WithdrawalStatus::Failed.can_transition_to(WithdrawalStatus::Broadcast));
    assert!(!WithdrawalStatus::Replaced.can_transition_to(WithdrawalStatus::Confirming));
    assert!(!WithdrawalStatus::Reserved.can_transition_to(WithdrawalStatus::Reserved));
}

#[test]
fn withdrawal_status_can_fail_from_non_terminal() {
    assert!(WithdrawalStatus::Reserved.can_transition_to(WithdrawalStatus::Failed));
    assert!(WithdrawalStatus::Authorized.can_transition_to(WithdrawalStatus::Failed));
    assert!(WithdrawalStatus::Signing.can_transition_to(WithdrawalStatus::Failed));
    assert!(WithdrawalStatus::Broadcast.can_transition_to(WithdrawalStatus::Failed));
    assert!(WithdrawalStatus::Confirming.can_transition_to(WithdrawalStatus::Failed));
    assert!(!WithdrawalStatus::Confirmed.can_transition_to(WithdrawalStatus::Failed));
}

// ---------------------------------------------------------------------------
// NonceChecker tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nonce_checker_fresh_nonce() {
    let nc = InMemoryNonceChecker::new();
    assert!(!nc.is_consumed("fresh").await.unwrap());
}

#[tokio::test]
async fn nonce_checker_mark_consumed() {
    let nc = InMemoryNonceChecker::new();
    nc.mark_consumed("nonce-1").await.unwrap();
    assert!(nc.is_consumed("nonce-1").await.unwrap());
}

#[tokio::test]
async fn nonce_checker_double_consumption() {
    let nc = InMemoryNonceChecker::new();
    nc.mark_consumed("nonce-1").await.unwrap();
    let err = nc.mark_consumed("nonce-1").await;
    assert!(err.is_err());
}

#[tokio::test]
async fn nonce_checker_different_nonces_independent() {
    let nc = InMemoryNonceChecker::new();
    nc.mark_consumed("nonce-1").await.unwrap();
    assert!(!nc.is_consumed("nonce-2").await.unwrap());
    assert!(nc.is_consumed("nonce-1").await.unwrap());
}
