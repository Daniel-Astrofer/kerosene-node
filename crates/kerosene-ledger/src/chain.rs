use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::LedgerError;

// ---------------------------------------------------------------------------
// OnchainState — UTXO lifecycle state machine
// ---------------------------------------------------------------------------

/// States in the on-chain UTXO lifecycle.
///
/// # State machine
///
/// ```text
/// Seen ↔ InMempool → Confirming → Spendable → FinalizedByPolicy
/// Seen ↔ InMempool → Replaced
/// Confirming → Reorged
/// Spendable → Spent
/// Reorged → Seen (re-detected after reorg)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OnchainState {
    /// Transaction first seen (mempool or block notification).
    Seen,
    /// In mempool, not yet in a block.
    InMempool,
    /// In a block, awaiting sufficient confirmations.
    Confirming,
    /// Sufficient confirmations / meeting policy threshold — can be spent.
    Spendable,
    /// Reached policy-final depth (e.g. 6+ confirmations).
    FinalizedByPolicy,
    /// Transaction was replaced (RBF).
    Replaced,
    /// Block was disconnected / chain reorg occurred.
    Reorged,
    /// Output has been spent.
    Spent,
}

// ---------------------------------------------------------------------------
// OutPoint
// ---------------------------------------------------------------------------

/// Identifies a specific UTXO by transaction ID and output index.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: String,
    pub vout: u32,
}

impl OutPoint {
    /// Creates a new `OutPoint`.
    pub fn new(txid: impl Into<String>, vout: u32) -> Self {
        Self {
            txid: txid.into(),
            vout,
        }
    }

    /// Returns the canonical string key for this outpoint: `"txid:vout"`.
    pub fn to_canonical_string(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }

    /// Parses an outpoint from a canonical string `"txid:vout"`.
    pub fn from_canonical_string(s: &str) -> Result<Self, LedgerError> {
        let (txid, vout_str) = s.split_once(':').ok_or_else(|| {
            LedgerError::InvalidUtxoData(format!(
                "cannot parse outpoint from '{}': expected txid:vout",
                s
            ))
        })?;
        let vout = vout_str.parse::<u32>().map_err(|e| {
            LedgerError::InvalidUtxoData(format!("invalid vout '{}': {}", vout_str, e))
        })?;
        Ok(Self::new(txid, vout))
    }
}

// ---------------------------------------------------------------------------
// UtxoEntry
// ---------------------------------------------------------------------------

/// A single UTXO tracked by the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoEntry {
    /// The outpoint identifying this UTXO.
    pub outpoint: OutPoint,
    /// Value in satoshis.
    pub value_sats: u64,
    /// The address (or script) that owns this output.
    pub address: String,
    /// Current on-chain state.
    pub state: OnchainState,
    /// Block height where this UTXO was confirmed (None if not yet in a block).
    pub block_height: Option<u64>,
    /// Time bucket when this UTXO was first detected.
    pub detected_at_bucket: u64,
    /// Time bucket when this UTXO reached Confirming state.
    pub confirmed_at_bucket: Option<u64>,
    /// Intent or command ID that reserved this UTXO.
    pub reserved_by: Option<String>,
    /// Time bucket when this UTXO was reserved.
    pub reserved_at_bucket: Option<u64>,
    /// Time bucket when this UTXO was spent.
    pub spent_at_bucket: Option<u64>,
    /// Transaction ID that spent this UTXO.
    pub spent_by_txid: Option<String>,
}

impl UtxoEntry {
    /// Creates a new UTXO entry in the `Seen` state.
    pub fn new_seen(
        outpoint: OutPoint,
        value_sats: u64,
        address: impl Into<String>,
        detected_at_bucket: u64,
    ) -> Self {
        Self {
            outpoint,
            value_sats,
            address: address.into(),
            state: OnchainState::Seen,
            block_height: None,
            detected_at_bucket,
            confirmed_at_bucket: None,
            reserved_by: None,
            reserved_at_bucket: None,
            spent_at_bucket: None,
            spent_by_txid: None,
        }
    }

    /// Returns the canonical outpoint key for deterministic sorting.
    pub fn canonical_key(&self) -> String {
        self.outpoint.to_canonical_string()
    }

    /// Returns `true` if this UTXO is in a terminal state (can no longer
    /// be meaningfully transitioned).
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, OnchainState::Replaced | OnchainState::Spent)
    }

    /// Returns `true` if this UTXO is available for reservation (Spendable
    /// or FinalizedByPolicy and not already reserved).
    pub fn is_available(&self) -> bool {
        matches!(
            self.state,
            OnchainState::Spendable | OnchainState::FinalizedByPolicy
        ) && self.reserved_by.is_none()
    }
}

// ---------------------------------------------------------------------------
// ChainObservationType
// ---------------------------------------------------------------------------

/// Types of observations the chain observer can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainObservationType {
    TransactionSeen,
    TransactionReplaced,
    UtxoDetected,
    UtxoConfirmed,
    UtxoSpent,
    BlockDisconnected,
    ChainReorganization,
}

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

/// A single observation from the chain observer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub observation_id: String,
    pub observation_type: ChainObservationType,
    pub outpoint: OutPoint,
    pub value_sats: u64,
    pub address: String,
    pub block_height: Option<u64>,
    pub detected_at_bucket: u64,
}

// ---------------------------------------------------------------------------
// UtxoSet
// ---------------------------------------------------------------------------

/// Aggregated view of all UTXO entries with a Merkle-like root hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UtxoSet {
    pub entries: Vec<UtxoEntry>,
    /// Merkle-like root of all UTXO entries for state root computation.
    pub root_hash: String,
}

impl UtxoSet {
    /// Computes the `UtxoSet` from a list of entries.
    pub fn from_entries(entries: Vec<UtxoEntry>) -> Self {
        let root_hash = compute_utxo_root(&entries);
        Self { entries, root_hash }
    }
}

// ---------------------------------------------------------------------------
// UtxoTransitionGate — validates UTXO state transitions
// ---------------------------------------------------------------------------

/// Validates UTXO state transitions.
///
/// Allowed transitions:
/// ```text
/// Seen ↔ InMempool → Confirming → Spendable → FinalizedByPolicy
/// Seen ↔ InMempool → Replaced
/// Confirming → Reorged
/// Spendable → Spent
/// Reorged → Seen
/// ```
pub struct UtxoTransitionGate;

impl UtxoTransitionGate {
    pub fn validate_transition(
        current: OnchainState,
        target: OnchainState,
    ) -> Result<(), LedgerError> {
        let allowed = matches!(
            (current, target),
            (OnchainState::Seen, OnchainState::InMempool)
                | (OnchainState::InMempool, OnchainState::Seen)
                | (OnchainState::Seen, OnchainState::Replaced)
                | (OnchainState::InMempool, OnchainState::Confirming)
                | (OnchainState::InMempool, OnchainState::Replaced)
                | (OnchainState::Confirming, OnchainState::Spendable)
                | (OnchainState::Confirming, OnchainState::Reorged)
                | (OnchainState::Spendable, OnchainState::FinalizedByPolicy)
                | (OnchainState::Spendable, OnchainState::Spent)
                | (OnchainState::Reorged, OnchainState::Seen)
        );
        if !allowed {
            return Err(LedgerError::InvalidUtxoTransition {
                from: current,
                to: target,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ReorgHandler
// ---------------------------------------------------------------------------

/// Handles chain reorganizations.
///
/// When a reorg is detected, the affected UTXOs must be transitioned:
/// - UTXOs in disconnected blocks → Reorged state
/// - New UTXOs from the new chain → detected/confirmed as appropriate
pub struct ReorgHandler;

impl ReorgHandler {
    /// Process a chain reorg: disconnect old blocks, connect new blocks.
    ///
    /// Returns the outpoint keys (canonical strings) of affected UTXOs.
    pub fn apply_reorg(
        utxos: &mut Vec<UtxoEntry>,
        disconnected_txids: &[String],
        new_utxos: &[UtxoEntry],
        current_bucket: u64,
    ) -> Result<Vec<String>, LedgerError> {
        let mut affected: Vec<String> = Vec::new();
        let disconnected_set: std::collections::HashSet<String> =
            disconnected_txids.iter().cloned().collect();

        // Mark affected UTXOs as Reorged
        for utxo in utxos.iter_mut() {
            if disconnected_set.contains(&utxo.outpoint.txid) {
                if utxo.state == OnchainState::Confirming
                    || utxo.state == OnchainState::Spendable
                    || utxo.state == OnchainState::FinalizedByPolicy
                {
                    utxo.state = OnchainState::Reorged;
                    utxo.block_height = None;
                    utxo.confirmed_at_bucket = None;
                    affected.push(utxo.canonical_key());
                }
            }
        }

        // Add new UTXOs from the new chain
        for new_utxo in new_utxos {
            // Check if already present
            let key = new_utxo.canonical_key();
            if !utxos.iter().any(|u| u.canonical_key() == key) {
                let mut entry = new_utxo.clone();
                entry.state = OnchainState::Seen;
                entry.detected_at_bucket = current_bucket;
                utxos.push(entry);
                affected.push(key);
            }
        }

        Ok(affected)
    }
}

// ---------------------------------------------------------------------------
// RBF (Replace-by-Fee)
// ---------------------------------------------------------------------------

/// When a transaction is replaced via RBF:
/// 1. Mark original UTXOs as Replaced
/// 2. Add new UTXOs from replacement tx as Seen
/// 3. Release any reservations on original UTXOs
///
/// Returns the released reservation IDs.
pub fn apply_rbf_replacement(
    utxos: &mut Vec<UtxoEntry>,
    replaced_txid: &str,
    replacement_utxos: &[UtxoEntry],
) -> Result<Vec<String>, LedgerError> {
    let mut released_reservations: Vec<String> = Vec::new();

    // Mark original UTXOs as Replaced and release reservations
    for utxo in utxos.iter_mut() {
        if utxo.outpoint.txid == replaced_txid && utxo.state != OnchainState::Replaced {
            // Release reservation if any
            if let Some(ref reserved_by) = utxo.reserved_by {
                released_reservations.push(reserved_by.clone());
                utxo.reserved_by = None;
                utxo.reserved_at_bucket = None;
            }
            utxo.state = OnchainState::Replaced;
        }
    }

    // Add replacement UTXOs as Seen (skip if already present)
    for new_utxo in replacement_utxos {
        let key = new_utxo.canonical_key();
        if !utxos.iter().any(|u| u.canonical_key() == key) {
            let mut entry = new_utxo.clone();
            entry.state = OnchainState::Seen;
            utxos.push(entry);
        }
    }

    Ok(released_reservations)
}

// ---------------------------------------------------------------------------
// Deterministic UTXO root hash computation
// ---------------------------------------------------------------------------

/// Computes a deterministic Merkle-like root hash of all UTXO entries
/// using canonical binary encoding.
///
/// Entries are sorted by canonical outpoint key before hashing to guarantee
/// determinism regardless of insertion order.
///
/// # Canonical encoding per entry
/// - domain tag "KROOTv1:utxo_entry" prefix
/// - binary u64 for all numeric fields
/// - length-prefixed strings for variable fields
/// - stable u8 discriminator for OnchainState
/// - option flag (1 byte) + data for Option fields
pub fn compute_utxo_root(utxos: &[UtxoEntry]) -> String {
    let mut sorted = utxos.to_vec();
    sorted.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));

    let mut item_hashes: Vec<[u8; 32]> = Vec::with_capacity(sorted.len());
    for utxo in &sorted {
        let mut buf = Vec::new();
        // OnchainState as stable discriminator
        let state_code: u8 = match utxo.state {
            OnchainState::Seen => 0,
            OnchainState::InMempool => 1,
            OnchainState::Confirming => 2,
            OnchainState::Spendable => 3,
            OnchainState::FinalizedByPolicy => 4,
            OnchainState::Replaced => 5,
            OnchainState::Reorged => 6,
            OnchainState::Spent => 7,
        };
        buf.push(state_code);
        buf.extend_from_slice(&utxo.value_sats.to_le_bytes());
        buf.extend_from_slice(&utxo.outpoint.vout.to_le_bytes());
        buf.extend_from_slice(&utxo.detected_at_bucket.to_le_bytes());
        // Option fields
        buf.extend_from_slice(&encode_block_height(utxo.block_height));
        buf.extend_from_slice(&encode_option_bucket(utxo.confirmed_at_bucket));
        buf.extend_from_slice(&encode_option_bucket(utxo.reserved_at_bucket));
        buf.extend_from_slice(&encode_option_bucket(utxo.spent_at_bucket));
        buf.extend_from_slice(&encode_option_string_fn(&utxo.reserved_by));
        buf.extend_from_slice(&encode_option_string_fn(&utxo.spent_by_txid));
        // Variable-length strings
        buf.extend_from_slice(&encode_string_fn(&utxo.outpoint.txid));
        buf.extend_from_slice(&encode_string_fn(&utxo.address));
        buf.extend_from_slice(&encode_string_fn(&utxo.canonical_key()));

        let hash = sha2::Sha256::digest(&buf);
        item_hashes.push(hash.into());
    }

    // Sort all item hashes for order-independence
    item_hashes.sort();

    let mut final_hasher = Sha256::new();
    final_hasher.update(b"KROOTv1:utxos");
    for h in &item_hashes {
        final_hasher.update(h);
    }
    hex::encode(final_hasher.finalize())
}

// Helper functions for canonical binary encoding
fn encode_block_height(h: Option<u64>) -> Vec<u8> {
    let mut buf = vec![u8::from(h.is_some())];
    if let Some(v) = h {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    buf
}

fn encode_option_bucket(v: Option<u64>) -> Vec<u8> {
    let mut buf = vec![u8::from(v.is_some())];
    if let Some(n) = v {
        buf.extend_from_slice(&n.to_le_bytes());
    }
    buf
}

fn encode_option_string_fn(v: &Option<String>) -> Vec<u8> {
    let mut buf = vec![u8::from(v.is_some())];
    if let Some(s) = v {
        let bytes = s.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(bytes);
    }
    buf
}

fn encode_string_fn(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut buf = Vec::with_capacity(8 + bytes.len());
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
    buf
}

// ---------------------------------------------------------------------------
// Payload types for encoding UTXO data in LedgerCommand fields
// ---------------------------------------------------------------------------

/// Payload for a DetectUtxo command, encoded in authorization_commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectUtxoPayload {
    pub value_sats: u64,
    pub address: String,
}

/// Payload for an ApplyChainReorganization command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorgPayload {
    pub disconnected_txids: Vec<String>,
    pub new_utxos: Vec<UtxoEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Transition gate tests
    // -----------------------------------------------------------------------

    #[test]
    fn valid_transition_seen_to_in_mempool() {
        UtxoTransitionGate::validate_transition(OnchainState::Seen, OnchainState::InMempool)
            .unwrap();
    }

    #[test]
    fn valid_transition_in_mempool_to_seen() {
        UtxoTransitionGate::validate_transition(OnchainState::InMempool, OnchainState::Seen)
            .unwrap();
    }

    #[test]
    fn valid_transition_seen_to_replaced() {
        UtxoTransitionGate::validate_transition(OnchainState::Seen, OnchainState::Replaced)
            .unwrap();
    }

    #[test]
    fn valid_transition_in_mempool_to_confirming() {
        UtxoTransitionGate::validate_transition(OnchainState::InMempool, OnchainState::Confirming)
            .unwrap();
    }

    #[test]
    fn valid_transition_in_mempool_to_replaced() {
        UtxoTransitionGate::validate_transition(OnchainState::InMempool, OnchainState::Replaced)
            .unwrap();
    }

    #[test]
    fn valid_transition_confirming_to_spendable() {
        UtxoTransitionGate::validate_transition(OnchainState::Confirming, OnchainState::Spendable)
            .unwrap();
    }

    #[test]
    fn valid_transition_confirming_to_reorged() {
        UtxoTransitionGate::validate_transition(OnchainState::Confirming, OnchainState::Reorged)
            .unwrap();
    }

    #[test]
    fn valid_transition_spendable_to_finalized() {
        UtxoTransitionGate::validate_transition(
            OnchainState::Spendable,
            OnchainState::FinalizedByPolicy,
        )
        .unwrap();
    }

    #[test]
    fn valid_transition_spendable_to_spent() {
        UtxoTransitionGate::validate_transition(OnchainState::Spendable, OnchainState::Spent)
            .unwrap();
    }

    #[test]
    fn valid_transition_reorged_to_seen() {
        UtxoTransitionGate::validate_transition(OnchainState::Reorged, OnchainState::Seen).unwrap();
    }

    #[test]
    fn invalid_transition_seen_to_spent() {
        let err = UtxoTransitionGate::validate_transition(OnchainState::Seen, OnchainState::Spent)
            .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidUtxoTransition { .. }));
    }

    #[test]
    fn invalid_transition_seen_to_confirming() {
        let err =
            UtxoTransitionGate::validate_transition(OnchainState::Seen, OnchainState::Confirming)
                .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidUtxoTransition { .. }));
    }

    #[test]
    fn invalid_transition_reorged_to_spent() {
        let err =
            UtxoTransitionGate::validate_transition(OnchainState::Reorged, OnchainState::Spent)
                .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidUtxoTransition { .. }));
    }

    #[test]
    fn invalid_transition_replaced_to_anything() {
        let err =
            UtxoTransitionGate::validate_transition(OnchainState::Replaced, OnchainState::Seen)
                .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidUtxoTransition { .. }));
    }

    #[test]
    fn invalid_transition_spent_to_anything() {
        let err = UtxoTransitionGate::validate_transition(OnchainState::Spent, OnchainState::Seen)
            .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidUtxoTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // OutPoint tests
    // -----------------------------------------------------------------------

    #[test]
    fn outpoint_roundtrip() {
        let op = OutPoint::new("abc123", 0);
        assert_eq!(op.txid, "abc123");
        assert_eq!(op.vout, 0);
        let s = op.to_canonical_string();
        assert_eq!(s, "abc123:0");
        let parsed = OutPoint::from_canonical_string(&s).unwrap();
        assert_eq!(parsed, op);
    }

    #[test]
    fn outpoint_from_canonical_invalid_no_colon() {
        let err = OutPoint::from_canonical_string("notxid").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidUtxoData(_)));
    }

    #[test]
    fn outpoint_from_canonical_invalid_vout() {
        let err = OutPoint::from_canonical_string("txid:abc").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidUtxoData(_)));
    }

    // -----------------------------------------------------------------------
    // UtxoEntry tests
    // -----------------------------------------------------------------------

    #[test]
    fn new_utxo_entry_is_seen() {
        let op = OutPoint::new("tx1", 0);
        let utxo = UtxoEntry::new_seen(op.clone(), 50000, "addr1", 100);
        assert_eq!(utxo.state, OnchainState::Seen);
        assert_eq!(utxo.outpoint, op);
        assert_eq!(utxo.value_sats, 50000);
        assert_eq!(utxo.address, "addr1");
        assert_eq!(utxo.detected_at_bucket, 100);
        assert!(utxo.block_height.is_none());
        assert!(utxo.reserved_by.is_none());
    }

    #[test]
    fn utxo_terminal_states() {
        let op = OutPoint::new("tx1", 0);
        let mut utxo = UtxoEntry::new_seen(op, 1000, "addr", 1);
        assert!(!utxo.is_terminal());
        utxo.state = OnchainState::Replaced;
        assert!(utxo.is_terminal());
        utxo.state = OnchainState::Spent;
        assert!(utxo.is_terminal());
    }

    #[test]
    fn utxo_available_check() {
        let op = OutPoint::new("tx1", 0);
        let mut utxo = UtxoEntry::new_seen(op, 1000, "addr", 1);
        assert!(!utxo.is_available());

        utxo.state = OnchainState::Spendable;
        assert!(utxo.is_available());

        utxo.reserved_by = Some("res-1".to_string());
        assert!(!utxo.is_available());
    }

    // -----------------------------------------------------------------------
    // ReorgHandler tests
    // -----------------------------------------------------------------------

    #[test]
    fn reorg_disconnects_confirming_utxos() {
        let op = OutPoint::new("tx1", 0);
        let mut utxos = vec![UtxoEntry {
            state: OnchainState::Confirming,
            block_height: Some(100),
            confirmed_at_bucket: Some(50),
            ..UtxoEntry::new_seen(op, 1000, "addr", 10)
        }];

        let affected =
            ReorgHandler::apply_reorg(&mut utxos, &["tx1".to_string()], &[], 60).unwrap();

        assert_eq!(affected.len(), 1);
        assert_eq!(utxos[0].state, OnchainState::Reorged);
        assert!(utxos[0].block_height.is_none());
    }

    #[test]
    fn reorg_adds_new_utxos() {
        let mut utxos: Vec<UtxoEntry> = Vec::new();
        let new_op = OutPoint::new("tx2", 0);
        let new_utxo = UtxoEntry::new_seen(new_op, 2000, "addr2", 0);

        let affected =
            ReorgHandler::apply_reorg(&mut utxos, &["tx1".to_string()], &[new_utxo], 70).unwrap();

        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].state, OnchainState::Seen);
        assert_eq!(utxos[0].detected_at_bucket, 70);
        assert_eq!(affected.len(), 1);
    }

    #[test]
    fn reorg_does_not_affect_unrelated_utxos() {
        let op = OutPoint::new("tx3", 0);
        let mut utxos = vec![UtxoEntry {
            state: OnchainState::Spendable,
            ..UtxoEntry::new_seen(op, 1000, "addr", 10)
        }];

        let affected =
            ReorgHandler::apply_reorg(&mut utxos, &["tx1".to_string(), "tx2".to_string()], &[], 60)
                .unwrap();

        assert_eq!(affected.len(), 0);
        assert_eq!(utxos[0].state, OnchainState::Spendable);
    }

    #[test]
    fn reorg_re_detect_after_reorg() {
        let op = OutPoint::new("tx1", 0);
        let mut utxos = vec![UtxoEntry {
            state: OnchainState::Reorged,
            ..UtxoEntry::new_seen(op, 1000, "addr", 10)
        }];

        // Re-detect: transition Reorged → Seen
        UtxoTransitionGate::validate_transition(utxos[0].state, OnchainState::Seen).unwrap();
        utxos[0].state = OnchainState::Seen;

        assert_eq!(utxos[0].state, OnchainState::Seen);
    }

    // -----------------------------------------------------------------------
    // RBF tests
    // -----------------------------------------------------------------------

    #[test]
    fn rbf_replaces_utxos() {
        let op1 = OutPoint::new("tx1", 0);
        let op2 = OutPoint::new("tx1", 1);
        let mut utxos = vec![
            UtxoEntry::new_seen(op1, 1000, "addr1", 10),
            UtxoEntry::new_seen(op2, 2000, "addr2", 10),
        ];

        let replacement = UtxoEntry::new_seen(OutPoint::new("tx2", 0), 3000, "addr3", 10);

        let released = apply_rbf_replacement(&mut utxos, "tx1", &[replacement]).unwrap();
        assert!(released.is_empty());

        assert_eq!(utxos[0].state, OnchainState::Replaced);
        assert_eq!(utxos[1].state, OnchainState::Replaced);
        assert_eq!(utxos.len(), 3);
        assert_eq!(utxos[2].outpoint.txid, "tx2");
        assert_eq!(utxos[2].state, OnchainState::Seen);
    }

    #[test]
    fn rbf_releases_reservations() {
        let op = OutPoint::new("tx1", 0);
        let mut utxos = vec![UtxoEntry {
            reserved_by: Some("res-1".to_string()),
            reserved_at_bucket: Some(50),
            ..UtxoEntry::new_seen(op, 1000, "addr1", 10)
        }];

        let replacement = UtxoEntry::new_seen(OutPoint::new("tx2", 0), 1000, "addr1", 10);

        let released = apply_rbf_replacement(&mut utxos, "tx1", &[replacement]).unwrap();
        assert_eq!(released, vec!["res-1".to_string()]);
        assert_eq!(utxos[0].reserved_by, None);
        assert_eq!(utxos[0].state, OnchainState::Replaced);
    }

    #[test]
    fn rbf_already_replaced_is_idempotent() {
        let op = OutPoint::new("tx1", 0);
        let mut utxos = vec![UtxoEntry {
            state: OnchainState::Replaced,
            ..UtxoEntry::new_seen(op, 1000, "addr1", 10)
        }];

        let released = apply_rbf_replacement(&mut utxos, "tx1", &[]).unwrap();
        assert!(released.is_empty());
        assert_eq!(utxos[0].state, OnchainState::Replaced);
    }

    // -----------------------------------------------------------------------
    // compute_utxo_root tests
    // -----------------------------------------------------------------------

    #[test]
    fn empty_utxo_root_is_deterministic() {
        let root1 = compute_utxo_root(&[]);
        let root2 = compute_utxo_root(&[]);
        assert_eq!(root1, root2);
        assert_eq!(root1.len(), 64);
    }

    #[test]
    fn same_utxos_produce_same_root() {
        let utxos = vec![
            UtxoEntry::new_seen(OutPoint::new("tx1", 0), 100, "addr1", 1),
            UtxoEntry::new_seen(OutPoint::new("tx2", 0), 200, "addr2", 2),
        ];
        let root1 = compute_utxo_root(&utxos);
        let root2 = compute_utxo_root(&utxos);
        assert_eq!(root1, root2);
    }

    #[test]
    fn different_utxos_produce_different_root() {
        let utxos1 = vec![UtxoEntry::new_seen(
            OutPoint::new("tx1", 0),
            100,
            "addr1",
            1,
        )];
        let utxos2 = vec![UtxoEntry::new_seen(
            OutPoint::new("tx1", 0),
            200,
            "addr1",
            1,
        )];
        assert_ne!(compute_utxo_root(&utxos1), compute_utxo_root(&utxos2));
    }

    #[test]
    fn utxo_root_is_order_independent() {
        let utxo_a = UtxoEntry::new_seen(OutPoint::new("tx_a", 0), 100, "addr1", 1);
        let utxo_b = UtxoEntry::new_seen(OutPoint::new("tx_b", 0), 200, "addr2", 2);

        let utxos1 = vec![utxo_a.clone(), utxo_b.clone()];
        let utxos2 = vec![utxo_b, utxo_a];

        let root1 = compute_utxo_root(&utxos1);
        let root2 = compute_utxo_root(&utxos2);
        assert_eq!(root1, root2, "UTXO root must be order-independent");
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn onchain_state_serde_roundtrip() {
        let states = vec![
            OnchainState::Seen,
            OnchainState::InMempool,
            OnchainState::Confirming,
            OnchainState::Spendable,
            OnchainState::FinalizedByPolicy,
            OnchainState::Replaced,
            OnchainState::Reorged,
            OnchainState::Spent,
        ];
        for state in &states {
            let json = serde_json::to_string(state).unwrap();
            let deserialized: OnchainState = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, deserialized);
        }
    }

    #[test]
    fn utxo_entry_serde_roundtrip() {
        let utxo = UtxoEntry::new_seen(OutPoint::new("tx1", 0), 50000, "addr1", 100);
        let json = serde_json::to_string(&utxo).unwrap();
        let deserialized: UtxoEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(utxo, deserialized);
    }

    #[test]
    fn utxo_set_from_entries() {
        let entries = vec![
            UtxoEntry::new_seen(OutPoint::new("tx1", 0), 100, "addr", 1),
            UtxoEntry::new_seen(OutPoint::new("tx2", 0), 200, "addr2", 2),
        ];
        let set = UtxoSet::from_entries(entries.clone());
        assert_eq!(set.entries.len(), 2);
        assert_eq!(set.root_hash.len(), 64);
        // Same entries produce same root
        let set2 = UtxoSet::from_entries(entries);
        assert_eq!(set.root_hash, set2.root_hash);
    }
}
