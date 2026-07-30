use sha2::{Digest, Sha256};

use crate::account_state::AccountState;
use crate::chain::compute_utxo_root;
use crate::double_entry::JournalEntry;
use crate::reservation::Reservation;
use crate::state_machine::LedgerState;

/// Computes a deterministic state root (Merkle-like SHA-256 hash) from the
/// full ledger state.
///
/// # Determinism
///
/// The same `LedgerState` always produces the same root because:
/// - All collection iterations are sorted before hashing
/// - No external input (clock, random, I/O) is used
/// - SHA-256 is a deterministic hash function
///
/// # Structure
///
/// ```text
/// state_root = SHA-256(
///     "version:"       || version_le
///     "accounts_root:" || compute_accounts_root(accounts)
///     "journal_root:"  || compute_journal_root(journal)
///     "reservations_root:" || compute_reservations_root(reservations)
///     "intents_root:"  || compute_intents_root(consumed_intents)
///     "membership:"    || membership_hash
///     "utxos_root:"    || compute_utxo_root(utxos)
/// )
/// ```
pub fn compute_state_root(state: &LedgerState) -> String {
    let mut hasher = Sha256::new();

    // 1. Version
    hasher.update(b"version:");
    hasher.update(state.version.to_le_bytes());
    hasher.update(b"\n");

    // 2. Accounts (sorted by account_id)
    let accounts_root = compute_accounts_root(&state.accounts);
    hasher.update(b"accounts_root:");
    hasher.update(accounts_root.as_bytes());
    hasher.update(b"\n");

    // 3. Journal entries (sorted by sequence)
    let journal_root = compute_journal_root(&state.journal);
    hasher.update(b"journal_root:");
    hasher.update(journal_root.as_bytes());
    hasher.update(b"\n");

    // 4. Reservations (sorted by reservation_id)
    let reservations_root = compute_reservations_root(&state.reservations);
    hasher.update(b"reservations_root:");
    hasher.update(reservations_root.as_bytes());
    hasher.update(b"\n");

    // 5. Consumed intents (sorted)
    let intents_root = compute_intents_root(&state.consumed_intents);
    hasher.update(b"intents_root:");
    hasher.update(intents_root.as_bytes());
    hasher.update(b"\n");

    // 6. Membership
    let membership_hash = compute_membership_hash(&state.membership);
    hasher.update(b"membership_hash:");
    hasher.update(membership_hash.as_bytes());
    hasher.update(b"\n");

    // 7. UTXOs (sorted by canonical outpoint key)
    let utxos_root = compute_utxo_root(&state.utxos);
    hasher.update(b"utxos_root:");
    hasher.update(utxos_root.as_bytes());
    hasher.update(b"\n");

    hex::encode(hasher.finalize())
}

/// Computes a deterministic hash of all accounts (sorted by account_id).
pub fn compute_accounts_root(accounts: &[AccountState]) -> String {
    let mut hasher = Sha256::new();
    let mut sorted = accounts.to_vec();
    sorted.sort_by(|a, b| a.account_id.cmp(&b.account_id));

    for acc in &sorted {
        let line = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            acc.account_id,
            acc.version,
            acc.available_sats,
            acc.reserved_sats,
            acc.pending_incoming_sats,
            acc.pending_outgoing_sats,
            acc.last_committed_sequence,
        );
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Computes a deterministic hash of all journal entries (sorted by sequence).
///
/// Uses the existing `entry_hash` chain which already provides integrity.
pub fn compute_journal_root(entries: &[JournalEntry]) -> String {
    let mut hasher = Sha256::new();
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.sequence.cmp(&b.sequence));

    for entry in &sorted {
        hasher.update(entry.entry_hash.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Computes a deterministic hash of all reservations (sorted by reservation_id).
pub fn compute_reservations_root(reservations: &[Reservation]) -> String {
    let mut hasher = Sha256::new();
    let mut sorted = reservations.to_vec();
    sorted.sort_by(|a, b| a.reservation_id.cmp(&b.reservation_id));

    for r in &sorted {
        let line = format!(
            "{}|{}|{}|{:?}|{}|{}|{}",
            r.reservation_id,
            r.account_id,
            r.amount_sats,
            r.state,
            r.created_at_bucket,
            r.expires_at_bucket,
            r.committed_sequence,
        );
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Computes a deterministic hash of all consumed intents (sorted).
pub fn compute_intents_root(intents: &[String]) -> String {
    let mut hasher = Sha256::new();
    let mut sorted = intents.to_vec();
    sorted.sort();

    for intent in &sorted {
        hasher.update(intent.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Computes a deterministic hash of the membership view.
pub fn compute_membership_hash(membership: &crate::state_machine::MembershipView) -> String {
    let mut hasher = Sha256::new();
    let mut sorted_nodes = membership.nodes.clone();
    sorted_nodes.sort();
    let material = format!(
        "{}|{}|{:?}",
        membership.cluster_id,
        sorted_nodes.join(","),
        membership.active_profile,
    );
    hasher.update(material.as_bytes());
    hex::encode(hasher.finalize())
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
}
