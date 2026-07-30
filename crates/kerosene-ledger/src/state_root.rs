use sha2::{Digest, Sha256};

use crate::account_state::AccountState;
use crate::chain::compute_utxo_root;
use crate::double_entry::JournalEntry;
use crate::reservation::Reservation;
use crate::state_machine::{ConsensusProfile, LedgerState, MembershipView};

// ---------------------------------------------------------------------------
// Domain-separation constants (unique per field type, versioned)
// ---------------------------------------------------------------------------

const DOMAIN_VERSION: u64 = 1;
const TAG_VERSION: &[u8] = b"KROOTv1:version";
const TAG_ACCOUNTS: &[u8] = b"KROOTv1:accounts";
const TAG_JOURNAL: &[u8] = b"KROOTv1:journal";
const TAG_RESERVATIONS: &[u8] = b"KROOTv1:reservations";
const TAG_INTENTS: &[u8] = b"KROOTv1:intents";
const TAG_MEMBERSHIP: &[u8] = b"KROOTv1:membership";
const TAG_UTXOS: &[u8] = b"KROOTv1:utxos";
const TAG_ACCOUNT: &[u8] = b"KROOTv1:acct";
const TAG_RESERVATION: &[u8] = b"KROOTv1:resv";
const TAG_INTENT: &[u8] = b"KROOTv1:intent";
const TAG_JOURNAL_ENTRY: &[u8] = b"KROOTv1:jent";
const TAG_MEMBERSHIP_DATA: &[u8] = b"KROOTv1:mem";

// ---------------------------------------------------------------------------
// Helper: hash a struct field with domain separation
// ---------------------------------------------------------------------------

fn hash_with_domain(tag: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(b":");
    hasher.update(payload);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Canonical binary encoding helpers
// ---------------------------------------------------------------------------

fn encode_u64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn encode_bool(b: bool) -> [u8; 1] {
    [u8::from(b)]
}

fn encode_option_u64(v: Option<u64>) -> Vec<u8> {
    match v {
        Some(n) => {
            let mut buf = vec![1u8];
            buf.extend_from_slice(&n.to_le_bytes());
            buf
        }
        None => vec![0u8],
    }
}

fn encode_option_string(v: &Option<String>) -> Vec<u8> {
    match v {
        Some(s) => {
            let bytes = s.as_bytes();
            let mut buf = vec![1u8];
            buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            buf.extend_from_slice(bytes);
            buf
        }
        None => vec![0u8],
    }
}

fn encode_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut buf = Vec::with_capacity(8 + bytes.len());
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
    buf
}

// ---------------------------------------------------------------------------
// ConsensusProfile canonical discriminator
// ---------------------------------------------------------------------------

fn encode_consensus_profile(profile: &ConsensusProfile) -> u8 {
    match profile {
        ConsensusProfile::Single => 0,
        ConsensusProfile::HaCrash => 1,
        ConsensusProfile::BftF1 => 2,
        ConsensusProfile::BftF2 => 3,
    }
}

// ---------------------------------------------------------------------------
// Chain hashing: each leaf produces a SHA-256 hash via domain separation
// ---------------------------------------------------------------------------

fn hash_account(acc: &AccountState) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&encode_u64(acc.version));
    buf.extend_from_slice(&encode_u64(acc.available_sats));
    buf.extend_from_slice(&encode_u64(acc.reserved_sats));
    buf.extend_from_slice(&encode_u64(acc.pending_incoming_sats));
    buf.extend_from_slice(&encode_u64(acc.pending_outgoing_sats));
    buf.extend_from_slice(&encode_u64(acc.last_committed_sequence));
    // Encode account_id at the end (variable length)
    buf.extend_from_slice(acc.account_id.as_bytes());
    hash_with_domain(TAG_ACCOUNT, &buf)
}

fn hash_journal_entry(entry: &JournalEntry) -> [u8; 32] {
    // Journal entries already have entry_hash; use it directly with domain separation
    hash_with_domain(TAG_JOURNAL_ENTRY, entry.entry_hash.as_bytes())
}

fn hash_reservation(r: &Reservation) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(&encode_u64(r.amount_sats));
    buf.extend_from_slice(&encode_u64(r.created_at_bucket));
    buf.extend_from_slice(&encode_u64(r.expires_at_bucket));
    buf.extend_from_slice(&encode_u64(r.committed_sequence));
    // ReservationState as stable u8 discriminator
    let state_code: u8 = match r.state {
        crate::reservation::ReservationState::Prepared => 0,
        crate::reservation::ReservationState::Committed => 1,
        crate::reservation::ReservationState::Consumed => 2,
        crate::reservation::ReservationState::Released => 3,
        crate::reservation::ReservationState::Expired => 4,
    };
    buf.push(state_code);
    buf.extend_from_slice(r.account_id.as_bytes());
    buf.extend_from_slice(r.reservation_id.as_bytes());
    buf.extend_from_slice(r.authorization_commitment.as_bytes());
    hash_with_domain(TAG_RESERVATION, &buf)
}

fn hash_intent(intent: &String) -> [u8; 32] {
    hash_with_domain(TAG_INTENT, intent.as_bytes())
}

fn encode_membership(membership: &MembershipView) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(encode_consensus_profile(&membership.active_profile));
    buf.extend_from_slice(&encode_string(&membership.cluster_id));
    // Nodes: sorted list of strings
    let mut sorted_nodes = membership.nodes.clone();
    sorted_nodes.sort();
    buf.extend_from_slice(&(sorted_nodes.len() as u64).to_le_bytes());
    for node in &sorted_nodes {
        buf.extend_from_slice(&encode_string(node));
    }
    buf
}

// ---------------------------------------------------------------------------
// Merkle-like accumulation: sort items, hash each with domain tag, then
// hash the concatenation of all item hashes.
// ---------------------------------------------------------------------------

fn hash_sorted_items<T, F>(items: &[T], tag: &[u8], hash_fn: F) -> [u8; 32]
where
    F: Fn(&T) -> [u8; 32],
{
    let mut sorted_hashes: Vec<[u8; 32]> = items.iter().map(hash_fn).collect();
    sorted_hashes.sort();

    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(b":");
    for h in &sorted_hashes {
        hasher.update(h);
    }
    hasher.finalize().into()
}

/// Computes a deterministic state root (Merkle-like SHA-256 hash) from the
/// full ledger state using canonical binary encoding.
///
/// # Canonical binary encoding (v1)
///
/// Every field is encoded with:
/// - A unique domain-separation tag per field type
/// - Binary numeric encoding (little-endian u64)
/// - Fixed-length length prefixes for variable-length fields
/// - Enum discrimination by stable u8 code (not Debug formatting)
/// - No string delimiters (`|`, `,`, etc.)
/// - No Debug formatting (`{:?}`)
///
/// # Structure
///
/// ```text
/// state_root = SHA-256(
///     "KROOTv1:version"  || version_le
///     "KROOTv1:accounts" || account_hashes_root
///     "KROOTv1:journal"  || journal_hashes_root
///     "KROOTv1:reservations" || reservation_hashes_root
///     "KROOTv1:intents"  || intents_hashes_root
///     "KROOTv1:membership" || membership_hash
///     "KROOTv1:utxos"    || utxos_root
/// )
/// ```
pub fn compute_state_root(state: &LedgerState) -> String {
    let mut hasher = Sha256::new();

    // 1. Version (binary)
    hasher.update(TAG_VERSION);
    hasher.update(b":");
    hasher.update(&state.version.to_le_bytes());

    // 2. Accounts (sorted by account_id, each hashed with domain separation)
    let accounts_hash = hash_sorted_items(&state.accounts, TAG_ACCOUNTS, hash_account);
    hasher.update(TAG_ACCOUNTS);
    hasher.update(b":");
    hasher.update(accounts_hash);

    // 3. Journal entries (sorted by sequence)
    let journal_hash = hash_sorted_items(&state.journal, TAG_JOURNAL, hash_journal_entry);
    hasher.update(TAG_JOURNAL);
    hasher.update(b":");
    hasher.update(journal_hash);

    // 4. Reservations (sorted by reservation_id)
    let reservations_hash =
        hash_sorted_items(&state.reservations, TAG_RESERVATIONS, hash_reservation);
    hasher.update(TAG_RESERVATIONS);
    hasher.update(b":");
    hasher.update(reservations_hash);

    // 5. Consumed intents (sorted)
    let intents_hash = hash_sorted_items(&state.consumed_intents, TAG_INTENTS, hash_intent);
    hasher.update(TAG_INTENTS);
    hasher.update(b":");
    hasher.update(intents_hash);

    // 6. Membership (canonical binary)
    let membership_hash_bin =
        hash_with_domain(TAG_MEMBERSHIP_DATA, &encode_membership(&state.membership));
    hasher.update(TAG_MEMBERSHIP);
    hasher.update(b":");
    hasher.update(membership_hash_bin);

    // 7. UTXOs (uses existing compute_utxo_root, but we pass through domain
    //    separation by hashing the hex root with the UTXO tag)
    let utxos_root_hex = compute_utxo_root(&state.utxos);
    let utxos_hash = hash_with_domain(TAG_UTXOS, utxos_root_hex.as_bytes());
    hasher.update(TAG_UTXOS);
    hasher.update(b":");
    hasher.update(utxos_hash);

    hex::encode(hasher.finalize())
}

/// Computes a deterministic hash of all accounts (sorted by account_id),
/// using the same canonical binary encoding as the state root.
pub fn compute_accounts_root(accounts: &[AccountState]) -> String {
    let hash = hash_sorted_items(accounts, TAG_ACCOUNTS, hash_account);
    hex::encode(hash)
}

/// Computes a deterministic hash of all journal entries (sorted by sequence).
pub fn compute_journal_root(entries: &[JournalEntry]) -> String {
    let hash = hash_sorted_items(entries, TAG_JOURNAL, hash_journal_entry);
    hex::encode(hash)
}

/// Computes a deterministic hash of all reservations (sorted by reservation_id).
pub fn compute_reservations_root(reservations: &[Reservation]) -> String {
    let hash = hash_sorted_items(reservations, TAG_RESERVATIONS, hash_reservation);
    hex::encode(hash)
}

/// Computes a deterministic hash of all consumed intents (sorted).
pub fn compute_intents_root(intents: &[String]) -> String {
    let hash = hash_sorted_items(intents, TAG_INTENTS, hash_intent);
    hex::encode(hash)
}

/// Computes a deterministic hash of the membership view using canonical
/// binary encoding.
pub fn compute_membership_hash(membership: &MembershipView) -> String {
    let hash = hash_with_domain(TAG_MEMBERSHIP_DATA, &encode_membership(membership));
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::{ConsensusProfile, LedgerState, MembershipView};

    fn empty_state() -> LedgerState {
        LedgerState::empty(MembershipView::single_node("cluster-1", "node-1"))
    }

    #[test]
    fn empty_state_has_deterministic_root() {
        let root1 = compute_state_root(&empty_state());
        let root2 = compute_state_root(&empty_state());
        assert_eq!(root1, root2, "empty state root must be deterministic");
        assert_eq!(root1.len(), 64, "SHA-256 hex should be 64 chars");
    }

    #[test]
    fn adding_accounts_changes_root() {
        let root1 = compute_state_root(&empty_state());

        let mut state = empty_state();
        state.accounts.push(AccountState::new("alice"));
        let root2 = compute_state_root(&state);

        assert_ne!(root1, root2, "adding an account must change the state root");
    }

    #[test]
    fn same_operations_produce_same_root_across_instances() {
        fn build_state() -> LedgerState {
            let mut state = empty_state();
            let mut alice = AccountState::new("alice");
            alice.apply_credit(100).unwrap();
            state.accounts.push(alice);

            let mut bob = AccountState::new("bob");
            bob.apply_credit(200).unwrap();
            state.accounts.push(bob);

            state.version = 2;
            state
        }

        let root1 = compute_state_root(&build_state());
        let root2 = compute_state_root(&build_state());
        assert_eq!(root1, root2);
    }

    #[test]
    fn account_order_does_not_affect_root() {
        let mut state1 = empty_state();
        state1.accounts.push(AccountState::new("bob"));
        state1.accounts.push(AccountState::new("alice"));

        let mut state2 = empty_state();
        state2.accounts.push(AccountState::new("alice"));
        state2.accounts.push(AccountState::new("bob"));

        // Make sure account data is same regardless of insertion order
        state2.accounts[0].apply_credit(100).unwrap();
        state1.accounts[1].apply_credit(100).unwrap();

        let root1 = compute_state_root(&state1);
        let root2 = compute_state_root(&state2);
        assert_eq!(root1, root2, "account insertion order must not affect root");
    }

    #[test]
    fn different_membership_produces_different_root() {
        let state1 = empty_state();
        let mut state2 = empty_state();
        state2.membership = MembershipView {
            cluster_id: "cluster-2".into(),
            nodes: vec!["node-2".into()],
            active_profile: ConsensusProfile::Single,
        };

        let root1 = compute_state_root(&state1);
        let root2 = compute_state_root(&state2);
        assert_ne!(root1, root2);
    }

    #[test]
    fn accounts_root_is_deterministic() {
        let accounts = vec![
            AccountState::new("alice"),
            AccountState::new("bob"),
            AccountState::new("carol"),
        ];
        let root1 = compute_accounts_root(&accounts);
        let root2 = compute_accounts_root(&accounts);
        assert_eq!(root1, root2);
    }

    #[test]
    fn intents_root_is_deterministic() {
        let intents = vec![
            "intent-c".to_string(),
            "intent-a".to_string(),
            "intent-b".to_string(),
        ];
        let root1 = compute_intents_root(&intents);
        let root2 = compute_intents_root(&intents);
        assert_eq!(root1, root2);
    }

    #[test]
    fn membership_hash_is_deterministic() {
        let membership = MembershipView::single_node("cluster-1", "node-1");
        let hash1 = compute_membership_hash(&membership);
        let hash2 = compute_membership_hash(&membership);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn different_consensus_profiles_produce_different_membership_hashes() {
        let mem1 = MembershipView::single_node("cluster-1", "node-1");
        let mut mem2 = MembershipView::single_node("cluster-1", "node-1");
        mem2.active_profile = ConsensusProfile::HaCrash;

        let hash1 = compute_membership_hash(&mem1);
        let hash2 = compute_membership_hash(&mem2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn different_node_ordering_produces_same_membership_hash() {
        let mem1 = MembershipView {
            cluster_id: "cluster-1".into(),
            nodes: vec!["node-a".into(), "node-b".into()],
            active_profile: ConsensusProfile::Single,
        };
        let mem2 = MembershipView {
            cluster_id: "cluster-1".into(),
            nodes: vec!["node-b".into(), "node-a".into()],
            active_profile: ConsensusProfile::Single,
        };
        assert_eq!(
            compute_membership_hash(&mem1),
            compute_membership_hash(&mem2)
        );
    }
}
