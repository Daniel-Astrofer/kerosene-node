use crate::account::StandardAccount;
use crate::double_entry::{InMemoryLedger, JournalEntry, LedgerPort, Posting};
use crate::error::LedgerError;

/// Helper: builds a valid genesis journal entry that transfers 1000 sats
/// from AssetCustodiedBtc (debit) to LiabilityUserBalances (credit).
fn genesis_entry(sequence: u64) -> JournalEntry {
    let debits = vec![Posting {
        account: StandardAccount::AssetCustodiedBtc,
        amount_sats: 1000,
    }];
    let credits = vec![Posting {
        account: StandardAccount::LiabilityUserBalances,
        amount_sats: 1000,
    }];
    JournalEntry {
        entry_id: format!("entry-{sequence}"),
        sequence,
        description: "genesis deposit".into(),
        debits,
        credits,
        timestamp_bucket: 1000,
        entry_hash: String::new(), // filled below
        previous_entry_hash: None,
    }
}

fn finalize_entry(mut entry: JournalEntry, prev_hash: Option<&str>) -> JournalEntry {
    entry.previous_entry_hash = prev_hash.map(|s| s.to_string());
    entry.entry_hash = JournalEntry::compute_entry_hash(
        &entry.entry_id,
        entry.sequence,
        &entry.description,
        &entry.debits,
        &entry.credits,
        entry.timestamp_bucket,
        prev_hash,
    );
    entry
}

// ---------------------------------------------------------------------------
// Basic posting tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_post_genesis_entry_succeeds() {
    let ledger = InMemoryLedger::new();
    let entry = finalize_entry(genesis_entry(0), None);
    let receipt = ledger.post_entry(entry).await.unwrap();

    assert_eq!(receipt.sequence, 0);
    assert!(receipt.previous_entry_hash.is_none());
    assert!(!receipt.entry_hash.is_empty());
    assert!(!receipt.trial_balance_hash.is_empty());
}

#[tokio::test]
async fn test_post_two_entries_chains_hashes() {
    let ledger = InMemoryLedger::new();

    let e0 = finalize_entry(genesis_entry(0), None);
    let r0 = ledger.post_entry(e0).await.unwrap();

    let e1 = finalize_entry(genesis_entry(1), Some(&r0.entry_hash));
    let r1 = ledger.post_entry(e1).await.unwrap();

    assert_eq!(r1.sequence, 1);
    assert_eq!(r1.previous_entry_hash, Some(r0.entry_hash.clone()));
    assert_ne!(r0.entry_hash, r1.entry_hash);
}

#[tokio::test]
async fn test_sequence_gap_detected() {
    let ledger = InMemoryLedger::new();
    let entry = finalize_entry(genesis_entry(5), None); // sequence 5, but expected 0
    let err = ledger.post_entry(entry).await.unwrap_err();
    assert!(
        matches!(
            err,
            LedgerError::SequenceGap {
                expected: 0,
                got: 5
            }
        ),
        "expected SequenceGap(0,5), got {err:?}"
    );
}

#[tokio::test]
async fn test_empty_entry_rejected() {
    let ledger = InMemoryLedger::new();
    let entry = JournalEntry {
        entry_id: "empty".into(),
        sequence: 0,
        description: "empty".into(),
        debits: vec![],
        credits: vec![],
        timestamp_bucket: 0,
        entry_hash: "x".into(),
        previous_entry_hash: None,
    };
    let err = ledger.post_entry(entry).await.unwrap_err();
    assert_eq!(err, LedgerError::EmptyEntry);
}

#[tokio::test]
async fn test_unbalanced_entry_rejected() {
    let ledger = InMemoryLedger::new();
    let entry = JournalEntry {
        entry_id: "unbalanced".into(),
        sequence: 0,
        description: "unbalanced".into(),
        debits: vec![Posting {
            account: StandardAccount::AssetCustodiedBtc,
            amount_sats: 1000,
        }],
        credits: vec![Posting {
            account: StandardAccount::LiabilityUserBalances,
            amount_sats: 500, // 500 != 1000
        }],
        timestamp_bucket: 0,
        entry_hash: JournalEntry::compute_entry_hash("unbalanced-test", 0, "unbalanced", &[], &[], 0, None),
        previous_entry_hash: None,
    };
    let err = ledger.post_entry(entry).await.unwrap_err();
    assert!(
        matches!(err, LedgerError::UnbalancedEntry { .. }),
        "expected UnbalancedEntry, got {err:?}"
    );
}

#[tokio::test]
async fn test_invalid_hash_rejected() {
    let ledger = InMemoryLedger::new();
    let mut entry = genesis_entry(0);
    entry.entry_hash = "not-a-valid-hash".into();
    let err = ledger.post_entry(entry).await.unwrap_err();
    assert!(
        matches!(err, LedgerError::InvalidHash(_)),
        "expected InvalidHash, got {err:?}"
    );
}

#[tokio::test]
async fn test_genesis_with_prev_hash_rejected() {
    let ledger = InMemoryLedger::new();
    let mut entry = genesis_entry(0);
    entry.previous_entry_hash = Some("some-prev-hash".into());
    entry.entry_hash = JournalEntry::compute_entry_hash(
        "prev-hash-rejected",
        0,
        &entry.description,
        &entry.debits,
        &entry.credits,
        entry.timestamp_bucket,
        Some("some-prev-hash"),
    );
    let err = ledger.post_entry(entry).await.unwrap_err();
    assert!(
        matches!(err, LedgerError::InvalidHash(_)),
        "expected InvalidHash for genesis with prev_hash, got {err:?}"
    );
}

#[tokio::test]
async fn test_non_genesis_without_prev_hash_rejected() {
    let ledger = InMemoryLedger::new();

    let e0 = finalize_entry(genesis_entry(0), None);
    ledger.post_entry(e0).await.unwrap();

    let mut e1 = genesis_entry(1);
    e1.previous_entry_hash = None;
    e1.entry_hash = JournalEntry::compute_entry_hash(
        &e1.entry_id,
        1,
        &e1.description,
        &e1.debits,
        &e1.credits,
        e1.timestamp_bucket,
        None,
    );

    let err = ledger.post_entry(e1).await.unwrap_err();
    assert!(
        matches!(err, LedgerError::InvalidHash(_)),
        "expected InvalidHash for non-genesis without prev_hash, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Idempotency tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_idempotent_post_returns_same_receipt() {
    let ledger = InMemoryLedger::new();
    let entry = finalize_entry(genesis_entry(0), None);
    let r0 = ledger.post_entry(entry.clone()).await.unwrap();
    let r1 = ledger.post_entry(entry).await.unwrap();

    assert_eq!(r0, r1);
    assert_eq!(ledger.entry_count().await.unwrap(), 1);
}

// ---------------------------------------------------------------------------
// Balance query tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_account_balance_after_post() {
    let ledger = InMemoryLedger::new();
    let entry = finalize_entry(genesis_entry(0), None);
    ledger.post_entry(entry).await.unwrap();

    let asset_bal = ledger
        .account_balance(StandardAccount::AssetCustodiedBtc)
        .await
        .unwrap();
    assert_eq!(asset_bal.total_debits_sats, 1000);
    assert_eq!(asset_bal.total_credits_sats, 0);
    assert_eq!(asset_bal.net_balance_sats, 1000);

    let liability_bal = ledger
        .account_balance(StandardAccount::LiabilityUserBalances)
        .await
        .unwrap();
    assert_eq!(liability_bal.total_credits_sats, 1000);
    assert_eq!(liability_bal.total_debits_sats, 0);
    assert_eq!(liability_bal.net_balance_sats, -1000);
}

#[tokio::test]
async fn test_trial_balance_includes_all_accounts() {
    let ledger = InMemoryLedger::new();
    let tb = ledger.trial_balance().await.unwrap();
    // All 9 accounts should be present with zero balances
    assert_eq!(tb.len(), 9);
    for bal in &tb {
        assert_eq!(bal.total_debits_sats, 0);
        assert_eq!(bal.total_credits_sats, 0);
        assert_eq!(bal.net_balance_sats, 0);
    }
}

// ---------------------------------------------------------------------------
// Hash chain verification tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_hash_chain_verifiable() {
    let ledger = InMemoryLedger::new();

    let e0 = finalize_entry(genesis_entry(0), None);
    let r0 = ledger.post_entry(e0.clone()).await.unwrap();

    let e1 = finalize_entry(genesis_entry(1), Some(&r0.entry_hash));
    let r1 = ledger.post_entry(e1.clone()).await.unwrap();

    // Verify entry hashes are correct
    let expected_hash_0 =
        JournalEntry::compute_entry_hash("entry-0", 0, "genesis deposit", &e0.debits, &e0.credits, 1000, None);
    assert_eq!(r0.entry_hash, expected_hash_0);

    let expected_hash_1 = JournalEntry::compute_entry_hash(
        "entry-1",
        1,
        "genesis deposit",
        &e1.debits,
        &e1.credits,
        1000,
        Some(&r0.entry_hash),
    );
    assert_eq!(r1.entry_hash, expected_hash_1);

    // Head hash should be the latest
    let head = ledger.head_hash().await.unwrap();
    assert_eq!(head, Some(r1.entry_hash.clone()));
}

// ---------------------------------------------------------------------------
// Negative balance enforcement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_asset_account_cannot_go_negative() {
    let ledger = InMemoryLedger::new();

    // Post an entry that credits AssetCustodiedBtc (decrease) without debiting it first
    let entry = JournalEntry {
        entry_id: "negative-asset".into(),
        sequence: 0,
        description: "try to make asset negative".into(),
        debits: vec![Posting {
            account: StandardAccount::ExpenseMinerFees,
            amount_sats: 500,
        }],
        credits: vec![Posting {
            account: StandardAccount::AssetCustodiedBtc,
            amount_sats: 500,
        }],
        timestamp_bucket: 0,
        entry_hash: String::new(),
        previous_entry_hash: None,
    };
    let entry = finalize_entry(entry, None);

    let err = ledger.post_entry(entry).await.unwrap_err();
    assert!(
        matches!(err, LedgerError::NegativeBalance { .. }),
        "expected NegativeBalance, got {err:?}"
    );
}

#[tokio::test]
async fn test_liability_account_cannot_go_positive() {
    let ledger = InMemoryLedger::new();

    // Post an entry that debits LiabilityUserBalances (decrease its credit balance)
    // without having any credit balance there first — this would make net > 0
    let entry = JournalEntry {
        entry_id: "positive-liability".into(),
        sequence: 0,
        description: "try to make liability positive".into(),
        debits: vec![Posting {
            account: StandardAccount::LiabilityUserBalances,
            amount_sats: 500,
        }],
        credits: vec![Posting {
            account: StandardAccount::ExpenseMinerFees,
            amount_sats: 500,
        }],
        timestamp_bucket: 0,
        entry_hash: String::new(),
        previous_entry_hash: None,
    };
    let entry = finalize_entry(entry, None);

    let err = ledger.post_entry(entry).await.unwrap_err();
    assert!(
        matches!(err, LedgerError::NegativeBalance { .. }),
        "expected NegativeBalance for liability going positive, got {err:?}"
    );
}

#[tokio::test]
async fn test_multi_posting_entry_succeeds() {
    let ledger = InMemoryLedger::new();

    let debits = vec![
        Posting {
            account: StandardAccount::AssetCustodiedBtc,
            amount_sats: 800,
        },
        Posting {
            account: StandardAccount::AssetHotBtc,
            amount_sats: 200,
        },
    ];
    let credits = vec![Posting {
        account: StandardAccount::LiabilityUserBalances,
        amount_sats: 1000,
    }];

    let entry = JournalEntry {
        entry_id: "multi".into(),
        sequence: 0,
        description: "multi-posting deposit".into(),
        debits,
        credits,
        timestamp_bucket: 500,
        entry_hash: String::new(),
        previous_entry_hash: None,
    };
    let entry = finalize_entry(entry, None);
    let r = ledger.post_entry(entry).await.unwrap();
    assert_eq!(r.sequence, 0);
}

#[tokio::test]
async fn test_get_entry_returns_none_for_missing() {
    let ledger = InMemoryLedger::new();
    let entry = ledger.get_entry(99).await.unwrap();
    assert!(entry.is_none());
}

#[tokio::test]
async fn test_get_entry_returns_posted_entry() {
    let ledger = InMemoryLedger::new();
    let e = finalize_entry(genesis_entry(0), None);
    ledger.post_entry(e.clone()).await.unwrap();
    let fetched = ledger.get_entry(0).await.unwrap().unwrap();
    assert_eq!(fetched.sequence, 0);
    assert_eq!(fetched.description, "genesis deposit");
}

#[tokio::test]
async fn test_trial_balance_hash_changes_after_post() {
    let ledger = InMemoryLedger::new();

    let e0 = finalize_entry(genesis_entry(0), None);
    let r0 = ledger.post_entry(e0).await.unwrap();
    let hash0 = r0.trial_balance_hash.clone();

    let e1 = finalize_entry(genesis_entry(1), Some(&r0.entry_hash));
    let r1 = ledger.post_entry(e1).await.unwrap();
    let hash1 = r1.trial_balance_hash;

    assert_ne!(hash0, hash1, "trial balance hash must change after posting");
}

#[tokio::test]
async fn test_entry_count() {
    let ledger = InMemoryLedger::new();
    assert_eq!(ledger.entry_count().await.unwrap(), 0);

    let e0 = finalize_entry(genesis_entry(0), None);
    ledger.post_entry(e0).await.unwrap();
    assert_eq!(ledger.entry_count().await.unwrap(), 1);
}

#[tokio::test]
async fn test_prev_hash_mismatch_rejected() {
    let ledger = InMemoryLedger::new();

    let e0 = finalize_entry(genesis_entry(0), None);
    let _r0 = ledger.post_entry(e0).await.unwrap();

    // Second entry with wrong previous hash
    let mut e1 = genesis_entry(1);
    e1.previous_entry_hash = Some("wrong-prev-hash".into());
    e1.entry_hash = JournalEntry::compute_entry_hash(
        &e1.entry_id,
        1,
        &e1.description,
        &e1.debits,
        &e1.credits,
        e1.timestamp_bucket,
        Some("wrong-prev-hash"),
    );

    let err = ledger.post_entry(e1).await.unwrap_err();
    assert!(
        matches!(err, LedgerError::InvalidHash(_)),
        "expected InvalidHash for prev_hash mismatch, got {err:?}"
    );
}
