use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::certificate::CertifiedSnapshot;
use crate::error::LedgerError;
use crate::state_machine::LedgerState;

// ---------------------------------------------------------------------------
// SnapshotStore trait
// ---------------------------------------------------------------------------

/// Port trait for storing and retrieving certified snapshots.
///
/// Snapshots are used for state sync, crash recovery, and bootstrapping
/// new nodes.
#[async_trait]
pub trait SnapshotStore: Send + Sync {
    /// Persist a certified snapshot.
    async fn save_snapshot(&self, snapshot: &CertifiedSnapshot) -> Result<(), LedgerError>;

    /// Retrieve the most recent snapshot, if any.
    async fn latest_snapshot(&self) -> Result<Option<CertifiedSnapshot>, LedgerError>;

    /// Retrieve a snapshot at a specific sequence number.
    async fn get_snapshot(&self, sequence: u64) -> Result<Option<CertifiedSnapshot>, LedgerError>;

    /// Install a snapshot, returning the deserialised ledger state.
    ///
    /// The snapshot must pass basic verification before the state is returned.
    async fn install_snapshot(
        &self,
        snapshot: &CertifiedSnapshot,
    ) -> Result<LedgerState, LedgerError>;
}

// ---------------------------------------------------------------------------
// InMemorySnapshotStore
// ---------------------------------------------------------------------------

/// In-memory snapshot store backed by `Mutex<BTreeMap>`.
///
/// Snapshots are indexed by sequence number, and the highest sequence is
/// tracked for `latest_snapshot()`.
pub struct InMemorySnapshotStore {
    inner: Mutex<InMemorySnapshotStoreInner>,
}

struct InMemorySnapshotStoreInner {
    snapshots: BTreeMap<u64, CertifiedSnapshot>,
    latest_sequence: u64,
}

impl InMemorySnapshotStore {
    /// Creates a new empty snapshot store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InMemorySnapshotStoreInner {
                snapshots: BTreeMap::new(),
                latest_sequence: 0,
            }),
        }
    }
}

impl Default for InMemorySnapshotStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SnapshotStore for InMemorySnapshotStore {
    async fn save_snapshot(&self, snapshot: &CertifiedSnapshot) -> Result<(), LedgerError> {
        let mut inner = self.inner.lock().unwrap();
        // Basic verification before storing
        snapshot.verify_basic()?;
        inner.snapshots.insert(snapshot.sequence, snapshot.clone());
        if snapshot.sequence > inner.latest_sequence {
            inner.latest_sequence = snapshot.sequence;
        }
        Ok(())
    }

    async fn latest_snapshot(&self) -> Result<Option<CertifiedSnapshot>, LedgerError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.snapshots.get(&inner.latest_sequence).cloned())
    }

    async fn get_snapshot(&self, sequence: u64) -> Result<Option<CertifiedSnapshot>, LedgerError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.snapshots.get(&sequence).cloned())
    }

    async fn install_snapshot(
        &self,
        snapshot: &CertifiedSnapshot,
    ) -> Result<LedgerState, LedgerError> {
        // Verify basic integrity
        snapshot.verify_basic()?;

        // Deserialise the state
        let state: LedgerState = serde_json::from_slice(&snapshot.state_bytes).map_err(|e| {
            LedgerError::InvalidSignature(format!("failed to deserialize snapshot state: {}", e))
        })?;

        // Verify the state root matches
        let computed_root = crate::state_root::compute_state_root(&state);
        if computed_root != snapshot.state_root {
            return Err(LedgerError::StateRootMismatch {
                expected: computed_root,
                got: snapshot.state_root.clone(),
            });
        }

        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::MembershipView;
    use crate::tests::helpers::make_signed_qc;

    fn create_test_snapshot(sequence: u64) -> CertifiedSnapshot {
        let (qc, _pk_hex) = make_signed_qc(
            "cluster-1",
            1,
            0,
            sequence,
            "cmd-hash",
            "prev-root",
            "result-root",
            "node-1",
        );

        let state = LedgerState::empty(MembershipView::single_node("cluster-1", "node-1"));
        let state_root = crate::state_root::compute_state_root(&state);
        let state_bytes = serde_json::to_vec(&state).unwrap();

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

    #[tokio::test]
    async fn save_and_retrieve_latest() {
        let store = InMemorySnapshotStore::new();
        let snap = create_test_snapshot(42);
        store.save_snapshot(&snap).await.unwrap();

        let latest = store.latest_snapshot().await.unwrap().unwrap();
        assert_eq!(latest.sequence, 42);
    }

    #[tokio::test]
    async fn save_and_retrieve_by_sequence() {
        let store = InMemorySnapshotStore::new();
        let snap1 = create_test_snapshot(10);
        let snap2 = create_test_snapshot(20);
        let snap3 = create_test_snapshot(30);

        store.save_snapshot(&snap1).await.unwrap();
        store.save_snapshot(&snap2).await.unwrap();
        store.save_snapshot(&snap3).await.unwrap();

        let got = store.get_snapshot(20).await.unwrap().unwrap();
        assert_eq!(got.sequence, 20);
    }

    #[tokio::test]
    async fn latest_is_highest_sequence() {
        let store = InMemorySnapshotStore::new();
        store
            .save_snapshot(&create_test_snapshot(10))
            .await
            .unwrap();
        store
            .save_snapshot(&create_test_snapshot(30))
            .await
            .unwrap();
        store
            .save_snapshot(&create_test_snapshot(20))
            .await
            .unwrap();

        let latest = store.latest_snapshot().await.unwrap().unwrap();
        assert_eq!(latest.sequence, 30);
    }

    #[tokio::test]
    async fn install_snapshot_returns_state() {
        let store = InMemorySnapshotStore::new();
        let snap = create_test_snapshot(42);
        store.save_snapshot(&snap).await.unwrap();

        let retrieved = store.get_snapshot(42).await.unwrap().unwrap();
        let state = store.install_snapshot(&retrieved).await.unwrap();
        assert_eq!(state.membership.cluster_id, "cluster-1");
    }

    #[tokio::test]
    async fn install_invalid_snapshot_fails() {
        let store = InMemorySnapshotStore::new();
        let mut snap = create_test_snapshot(42);
        snap.state_root = "tampered-root".into();

        let err = store.install_snapshot(&snap).await.unwrap_err();
        assert!(matches!(err, LedgerError::StateRootMismatch { .. }));
    }

    #[tokio::test]
    async fn empty_store_returns_none() {
        let store = InMemorySnapshotStore::new();
        assert!(store.latest_snapshot().await.unwrap().is_none());
        assert!(store.get_snapshot(1).await.unwrap().is_none());
    }
}
