use async_trait::async_trait;

use crate::chain::{OnchainState, OutPoint, UtxoEntry};
use crate::error::LedgerError;

// ---------------------------------------------------------------------------
// UtxoStore trait
// ---------------------------------------------------------------------------

/// Abstract store for UTXO entries.
///
/// All implementations must be deterministic and thread-safe.
#[async_trait]
pub trait UtxoStore: Send + Sync {
    /// Adds a new UTXO entry to the store.
    async fn add_utxo(&self, utxo: UtxoEntry) -> Result<(), LedgerError>;

    /// Retrieves a UTXO by outpoint, if it exists.
    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, LedgerError>;

    /// Lists all UTXOs in the given state.
    async fn list_by_state(&self, state: OnchainState) -> Result<Vec<UtxoEntry>, LedgerError>;

    /// Lists all UTXOs in the store.
    async fn list_all(&self) -> Result<Vec<UtxoEntry>, LedgerError>;

    /// Updates the state of a UTXO.
    async fn update_state(
        &self,
        outpoint: &OutPoint,
        new_state: OnchainState,
    ) -> Result<(), LedgerError>;

    /// Reserves a UTXO for a given reservation/command.
    async fn reserve(
        &self,
        outpoint: &OutPoint,
        reserved_by: &str,
        bucket: u64,
    ) -> Result<(), LedgerError>;

    /// Releases a reservation on a UTXO.
    async fn release(&self, outpoint: &OutPoint) -> Result<(), LedgerError>;

    /// Computes a deterministic Merkle-like root hash of all UTXOs.
    async fn compute_utxo_root_hash(&self) -> Result<String, LedgerError>;
}

// ---------------------------------------------------------------------------
// InMemoryUtxoStore
// ---------------------------------------------------------------------------

/// In-memory implementation of `UtxoStore` backed by `std::sync::Mutex`.
pub struct InMemoryUtxoStore {
    inner: std::sync::Mutex<Vec<UtxoEntry>>,
}

impl InMemoryUtxoStore {
    /// Creates a new empty store.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Creates a new store pre-populated with the given entries.
    pub fn with_entries(entries: Vec<UtxoEntry>) -> Self {
        Self {
            inner: std::sync::Mutex::new(entries),
        }
    }
}

impl Default for InMemoryUtxoStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UtxoStore for InMemoryUtxoStore {
    async fn add_utxo(&self, utxo: UtxoEntry) -> Result<(), LedgerError> {
        let mut entries = self.inner.lock().unwrap();
        let key = utxo.canonical_key();
        // Idempotent: if already exists, skip
        if entries.iter().any(|e| e.canonical_key() == key) {
            return Ok(());
        }
        entries.push(utxo);
        Ok(())
    }

    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, LedgerError> {
        let entries = self.inner.lock().unwrap();
        let key = outpoint.to_canonical_string();
        Ok(entries.iter().find(|e| e.canonical_key() == key).cloned())
    }

    async fn list_by_state(&self, state: OnchainState) -> Result<Vec<UtxoEntry>, LedgerError> {
        let entries = self.inner.lock().unwrap();
        let mut result: Vec<UtxoEntry> =
            entries.iter().filter(|e| e.state == state).cloned().collect();
        // Sort for determinism
        result.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));
        Ok(result)
    }

    async fn list_all(&self) -> Result<Vec<UtxoEntry>, LedgerError> {
        let mut entries = self.inner.lock().unwrap().clone();
        // Sort for determinism
        entries.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));
        Ok(entries)
    }

    async fn update_state(
        &self,
        outpoint: &OutPoint,
        new_state: OnchainState,
    ) -> Result<(), LedgerError> {
        let mut entries = self.inner.lock().unwrap();
        let key = outpoint.to_canonical_string();
        let entry = entries
            .iter_mut()
            .find(|e| e.canonical_key() == key)
            .ok_or_else(|| LedgerError::UtxoNotFound {
                txid: outpoint.txid.clone(),
                vout: outpoint.vout,
            })?;
        let current = entry.state;
        crate::chain::UtxoTransitionGate::validate_transition(current, new_state)?;
        entry.state = new_state;
        Ok(())
    }

    async fn reserve(
        &self,
        outpoint: &OutPoint,
        reserved_by: &str,
        bucket: u64,
    ) -> Result<(), LedgerError> {
        let mut entries = self.inner.lock().unwrap();
        let key = outpoint.to_canonical_string();
        let entry = entries
            .iter_mut()
            .find(|e| e.canonical_key() == key)
            .ok_or_else(|| LedgerError::UtxoNotFound {
                txid: outpoint.txid.clone(),
                vout: outpoint.vout,
            })?;

        // Check that UTXO is in spendable or finalized state
        if !matches!(
            entry.state,
            OnchainState::Spendable | OnchainState::FinalizedByPolicy
        ) {
            return Err(LedgerError::InvalidUtxoTransition {
                from: entry.state,
                to: entry.state, // staying same, but can't reserve
            });
        }

        // Check not already reserved
        if let Some(ref existing) = entry.reserved_by {
            return Err(LedgerError::UtxoAlreadyReserved {
                reserved_by: existing.clone(),
            });
        }

        entry.reserved_by = Some(reserved_by.to_string());
        entry.reserved_at_bucket = Some(bucket);
        Ok(())
    }

    async fn release(&self, outpoint: &OutPoint) -> Result<(), LedgerError> {
        let mut entries = self.inner.lock().unwrap();
        let key = outpoint.to_canonical_string();
        let entry = entries
            .iter_mut()
            .find(|e| e.canonical_key() == key)
            .ok_or_else(|| LedgerError::UtxoNotFound {
                txid: outpoint.txid.clone(),
                vout: outpoint.vout,
            })?;

        if entry.reserved_by.is_none() {
            return Err(LedgerError::UtxoNotReserved);
        }

        entry.reserved_by = None;
        entry.reserved_at_bucket = None;
        Ok(())
    }

    async fn compute_utxo_root_hash(&self) -> Result<String, LedgerError> {
        let entries = self.inner.lock().unwrap();
        Ok(crate::chain::compute_utxo_root(&entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{OutPoint, UtxoEntry};

    fn test_utxo(txid: &str, vout: u32, value: u64) -> UtxoEntry {
        UtxoEntry::new_seen(OutPoint::new(txid, vout), value, "addr", 1)
    }

    #[tokio::test]
    async fn add_and_get_utxo() {
        let store = InMemoryUtxoStore::new();
        let utxo = test_utxo("tx1", 0, 1000);
        store.add_utxo(utxo.clone()).await.unwrap();

        let fetched = store
            .get_utxo(&OutPoint::new("tx1", 0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched, utxo);
    }

    #[tokio::test]
    async fn add_duplicate_is_idempotent() {
        let store = InMemoryUtxoStore::new();
        let utxo1 = test_utxo("tx1", 0, 1000);
        let utxo2 = test_utxo("tx1", 0, 2000);
        store.add_utxo(utxo1).await.unwrap();
        store.add_utxo(utxo2).await.unwrap();
        // First one wins (idempotent)
        let fetched = store
            .get_utxo(&OutPoint::new("tx1", 0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.value_sats, 1000);
    }

    #[tokio::test]
    async fn get_nonexistent_returns_none() {
        let store = InMemoryUtxoStore::new();
        let result = store
            .get_utxo(&OutPoint::new("nonexistent", 0))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_by_state_filters_correctly() {
        let store = InMemoryUtxoStore::new();
        store.add_utxo(test_utxo("tx1", 0, 100)).await.unwrap();
        store.add_utxo(test_utxo("tx2", 0, 200)).await.unwrap();
        store
            .add_utxo(UtxoEntry {
                state: OnchainState::Spendable,
                ..test_utxo("tx3", 0, 300)
            })
            .await
            .unwrap();

        let seen = store.list_by_state(OnchainState::Seen).await.unwrap();
        assert_eq!(seen.len(), 2);

        let spendable = store.list_by_state(OnchainState::Spendable).await.unwrap();
        assert_eq!(spendable.len(), 1);
    }

    #[tokio::test]
    async fn list_all_returns_all() {
        let store = InMemoryUtxoStore::new();
        store.add_utxo(test_utxo("tx1", 0, 100)).await.unwrap();
        store.add_utxo(test_utxo("tx2", 0, 200)).await.unwrap();
        let all = store.list_all().await.unwrap();
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn update_state_works() {
        let store = InMemoryUtxoStore::new();
        store.add_utxo(test_utxo("tx1", 0, 100)).await.unwrap();

        // First transition to InMempool, then to Confirming
        store
            .update_state(&OutPoint::new("tx1", 0), OnchainState::InMempool)
            .await
            .unwrap();
        let utxo = store
            .get_utxo(&OutPoint::new("tx1", 0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(utxo.state, OnchainState::InMempool);

        store
            .update_state(&OutPoint::new("tx1", 0), OnchainState::Confirming)
            .await
            .unwrap();
        let utxo = store
            .get_utxo(&OutPoint::new("tx1", 0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(utxo.state, OnchainState::Confirming);
    }

    #[tokio::test]
    async fn update_state_invalid_transition_rejected() {
        let store = InMemoryUtxoStore::new();
        store.add_utxo(test_utxo("tx1", 0, 100)).await.unwrap();

        let err = store
            .update_state(&OutPoint::new("tx1", 0), OnchainState::Spent)
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidUtxoTransition { .. }));
    }

    #[tokio::test]
    async fn reserve_and_release_works() {
        let store = InMemoryUtxoStore::new();
        store
            .add_utxo(UtxoEntry {
                state: OnchainState::Spendable,
                ..test_utxo("tx1", 0, 1000)
            })
            .await
            .unwrap();

        store
            .reserve(&OutPoint::new("tx1", 0), "res-1", 100)
            .await
            .unwrap();

        let utxo = store
            .get_utxo(&OutPoint::new("tx1", 0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(utxo.reserved_by, Some("res-1".to_string()));
        assert_eq!(utxo.reserved_at_bucket, Some(100));

        store.release(&OutPoint::new("tx1", 0)).await.unwrap();
        let utxo = store
            .get_utxo(&OutPoint::new("tx1", 0))
            .await
            .unwrap()
            .unwrap();
        assert!(utxo.reserved_by.is_none());
    }

    #[tokio::test]
    async fn double_reserve_rejected() {
        let store = InMemoryUtxoStore::new();
        store
            .add_utxo(UtxoEntry {
                state: OnchainState::Spendable,
                ..test_utxo("tx1", 0, 1000)
            })
            .await
            .unwrap();

        store
            .reserve(&OutPoint::new("tx1", 0), "res-1", 100)
            .await
            .unwrap();

        let err = store
            .reserve(&OutPoint::new("tx1", 0), "res-2", 200)
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::UtxoAlreadyReserved { .. }));
    }

    #[tokio::test]
    async fn release_unreserved_rejected() {
        let store = InMemoryUtxoStore::new();
        store
            .add_utxo(UtxoEntry {
                state: OnchainState::Spendable,
                ..test_utxo("tx1", 0, 1000)
            })
            .await
            .unwrap();

        let err = store.release(&OutPoint::new("tx1", 0)).await.unwrap_err();
        assert!(matches!(err, LedgerError::UtxoNotReserved));
    }

    #[tokio::test]
    async fn reserve_nonexistent_utxo_rejected() {
        let store = InMemoryUtxoStore::new();
        let err = store
            .reserve(&OutPoint::new("nonexistent", 0), "res-1", 100)
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::UtxoNotFound { .. }));
    }

    #[tokio::test]
    async fn compute_root_hash_is_deterministic() {
        let store = InMemoryUtxoStore::new();
        store.add_utxo(test_utxo("tx1", 0, 100)).await.unwrap();
        store.add_utxo(test_utxo("tx2", 0, 200)).await.unwrap();

        let hash1 = store.compute_utxo_root_hash().await.unwrap();
        let hash2 = store.compute_utxo_root_hash().await.unwrap();
        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn empty_store_returns_empty_list() {
        let store = InMemoryUtxoStore::new();
        let all = store.list_all().await.unwrap();
        assert!(all.is_empty());

        let seen = store.list_by_state(OnchainState::Seen).await.unwrap();
        assert!(seen.is_empty());
    }

    #[tokio::test]
    async fn update_state_nonexistent_utxo_rejected() {
        let store = InMemoryUtxoStore::new();
        let err = store
            .update_state(&OutPoint::new("nonexistent", 0), OnchainState::InMempool)
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::UtxoNotFound { .. }));
    }
}
