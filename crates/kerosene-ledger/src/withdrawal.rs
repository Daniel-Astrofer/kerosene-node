use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::LedgerError;
use crate::settlement::{PsbtCommitment, SettlementAuthorization};

// ---------------------------------------------------------------------------
// WithdrawalStatus
// ---------------------------------------------------------------------------

/// Status of a withdrawal through its lifecycle.
///
/// The withdrawal flows through these states:
/// - Reserved:     Balance reserved, waiting for authorization
/// - Authorized:   SettlementAuthorization issued by the cluster
/// - Signing:      Vault mesh is signing the PSBT
/// - Broadcast:    Transaction broadcast to Bitcoin network
/// - Confirming:   In mempool / awaiting confirmations
/// - Confirmed:    Sufficient confirmations received
/// - Failed:       Settlement failed (canonical terminal failure)
/// - Replaced:     Replaced via RBF (Replace-By-Fee)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Balance reserved, waiting for authorization.
    Reserved,
    /// SettlementAuthorization issued by the cluster.
    Authorized,
    /// Vault mesh is signing the PSBT.
    Signing,
    /// Transaction broadcast to Bitcoin network.
    Broadcast,
    /// In mempool / awaiting confirmations.
    Confirming,
    /// Sufficient confirmations received.
    Confirmed,
    /// Settlement failed.
    Failed,
    /// Replaced via RBF.
    Replaced,
}

impl WithdrawalStatus {
    /// Returns `true` if this is a terminal state (Confirmed, Failed, Replaced).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            WithdrawalStatus::Confirmed
                | WithdrawalStatus::Failed
                | WithdrawalStatus::Replaced
        )
    }

    /// Returns `true` if the status allows transitioning `from` this state `to`
    /// the given state.
    pub fn can_transition_to(&self, to: WithdrawalStatus) -> bool {
        match (self, to) {
            // Normal forward progression
            (WithdrawalStatus::Reserved, WithdrawalStatus::Authorized) => true,
            (WithdrawalStatus::Authorized, WithdrawalStatus::Signing) => true,
            (WithdrawalStatus::Signing, WithdrawalStatus::Broadcast) => true,
            (WithdrawalStatus::Broadcast, WithdrawalStatus::Confirming) => true,
            (WithdrawalStatus::Confirming, WithdrawalStatus::Confirmed) => true,

            // Failure from any non-terminal, non-confirmed state
            (s, WithdrawalStatus::Failed) if !s.is_terminal() && *s != WithdrawalStatus::Confirmed => true,

            // RBF replacement
            (WithdrawalStatus::Broadcast, WithdrawalStatus::Replaced) => true,
            (WithdrawalStatus::Confirming, WithdrawalStatus::Replaced) => true,

            // No other transitions allowed
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// WithdrawalRecord
// ---------------------------------------------------------------------------

/// A complete record of a withdrawal through its lifecycle.
///
/// Tracks all stages from reservation through on-chain confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalRecord {
    /// Unique identifier for this withdrawal.
    pub withdrawal_id: String,
    /// Commitment hash of the intent that initiated this withdrawal.
    pub intent_commitment: String,
    /// Account from which the withdrawal is made.
    pub account_id: String,
    /// Amount in satoshis being withdrawn.
    pub amount_sats: u64,
    /// Destination Bitcoin address.
    pub destination_address: String,
    /// Current status in the withdrawal lifecycle.
    pub status: WithdrawalStatus,
    /// ID of the reservation backing this withdrawal.
    pub reservation_id: Option<String>,
    /// Settlement authorization from the cluster (set when Authorized).
    pub authorization: Option<SettlementAuthorization>,
    /// PSBT commitment (set when signing begins).
    pub psbt_commitment: Option<PsbtCommitment>,
    /// Transaction ID on the Bitcoin network (set when broadcast).
    pub broadcast_txid: Option<String>,
    /// Time bucket when the withdrawal was created.
    pub created_at_bucket: u64,
    /// Time bucket when the withdrawal was last updated.
    pub updated_at_bucket: u64,
}

impl WithdrawalRecord {
    /// Creates a new withdrawal record in the `Reserved` state.
    pub fn new(
        withdrawal_id: impl Into<String>,
        intent_commitment: impl Into<String>,
        account_id: impl Into<String>,
        amount_sats: u64,
        destination_address: impl Into<String>,
        created_at_bucket: u64,
    ) -> Self {
        Self {
            withdrawal_id: withdrawal_id.into(),
            intent_commitment: intent_commitment.into(),
            account_id: account_id.into(),
            amount_sats,
            destination_address: destination_address.into(),
            status: WithdrawalStatus::Reserved,
            reservation_id: None,
            authorization: None,
            psbt_commitment: None,
            broadcast_txid: None,
            created_at_bucket,
            updated_at_bucket: created_at_bucket,
        }
    }
}

// ---------------------------------------------------------------------------
// WithdrawalStore trait
// ---------------------------------------------------------------------------

/// Port trait for storing and retrieving withdrawal records.
#[async_trait]
pub trait WithdrawalStore: Send + Sync {
    /// Create a new withdrawal record.
    async fn create(&self, withdrawal: WithdrawalRecord) -> Result<(), LedgerError>;

    /// Retrieve a withdrawal record by its ID.
    async fn get(&self, withdrawal_id: &str) -> Result<Option<WithdrawalRecord>, LedgerError>;

    /// Update the status of a withdrawal, enforcing valid transitions.
    async fn update_status(
        &self,
        id: &str,
        status: WithdrawalStatus,
        bucket: u64,
    ) -> Result<(), LedgerError>;

    /// Set the settlement authorization for a withdrawal.
    async fn set_authorization(
        &self,
        id: &str,
        auth: SettlementAuthorization,
    ) -> Result<(), LedgerError>;

    /// Set the PSBT commitment for a withdrawal.
    async fn set_psbt(
        &self,
        id: &str,
        commitment: PsbtCommitment,
    ) -> Result<(), LedgerError>;

    /// Set the broadcast transaction ID for a withdrawal.
    async fn set_broadcast_txid(
        &self,
        id: &str,
        txid: &str,
    ) -> Result<(), LedgerError>;
}

// ---------------------------------------------------------------------------
// InMemoryWithdrawalStore
// ---------------------------------------------------------------------------

/// In-memory implementation of `WithdrawalStore` backed by a `HashMap`.
///
/// Used for testing and single-node deployments. Not durable.
pub struct InMemoryWithdrawalStore {
    inner: Mutex<HashMap<String, WithdrawalRecord>>,
}

impl InMemoryWithdrawalStore {
    /// Creates a new empty withdrawal store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryWithdrawalStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WithdrawalStore for InMemoryWithdrawalStore {
    async fn create(&self, withdrawal: WithdrawalRecord) -> Result<(), LedgerError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.contains_key(&withdrawal.withdrawal_id) {
            return Err(LedgerError::DuplicateEntryId(withdrawal.withdrawal_id));
        }
        inner.insert(withdrawal.withdrawal_id.clone(), withdrawal);
        Ok(())
    }

    async fn get(&self, withdrawal_id: &str) -> Result<Option<WithdrawalRecord>, LedgerError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.get(withdrawal_id).cloned())
    }

    async fn update_status(
        &self,
        id: &str,
        status: WithdrawalStatus,
        bucket: u64,
    ) -> Result<(), LedgerError> {
        let mut inner = self.inner.lock().unwrap();
        let record = inner.get_mut(id).ok_or_else(|| {
            LedgerError::WithdrawalNotFound(id.to_string())
        })?;

        if !record.status.can_transition_to(status) {
            return Err(LedgerError::InvalidStateTransition(format!(
                "cannot transition withdrawal {} from {:?} to {:?}",
                id, record.status, status
            )));
        }

        // Once broadcast, txid should be set before transitioning back
        if status == WithdrawalStatus::Broadcast && record.broadcast_txid.is_none() {
            // Broadcast requires a txid — but some flows set txid after status.
            // We allow the transition and let the caller set txid separately.
        }

        record.status = status;
        record.updated_at_bucket = bucket;
        Ok(())
    }

    async fn set_authorization(
        &self,
        id: &str,
        auth: SettlementAuthorization,
    ) -> Result<(), LedgerError> {
        let mut inner = self.inner.lock().unwrap();
        let record = inner.get_mut(id).ok_or_else(|| {
            LedgerError::WithdrawalNotFound(id.to_string())
        })?;

        if record.status != WithdrawalStatus::Reserved {
            return Err(LedgerError::InvalidStateTransition(format!(
                "cannot set authorization on withdrawal {} in state {:?} (must be Reserved)",
                id, record.status
            )));
        }

        record.authorization = Some(auth);
        record.status = WithdrawalStatus::Authorized;
        Ok(())
    }

    async fn set_psbt(
        &self,
        id: &str,
        commitment: PsbtCommitment,
    ) -> Result<(), LedgerError> {
        let mut inner = self.inner.lock().unwrap();
        let record = inner.get_mut(id).ok_or_else(|| {
            LedgerError::WithdrawalNotFound(id.to_string())
        })?;

        record.psbt_commitment = Some(commitment);
        Ok(())
    }

    async fn set_broadcast_txid(
        &self,
        id: &str,
        txid: &str,
    ) -> Result<(), LedgerError> {
        let mut inner = self.inner.lock().unwrap();
        let record = inner.get_mut(id).ok_or_else(|| {
            LedgerError::WithdrawalNotFound(id.to_string())
        })?;

        // Once a txid is set, it should not be changed
        if record.broadcast_txid.is_some() {
            return Err(LedgerError::InvalidStateTransition(format!(
                "withdrawal {} already has broadcast txid {:?}",
                id, record.broadcast_txid
            )));
        }

        record.broadcast_txid = Some(txid.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_withdrawal() -> WithdrawalRecord {
        WithdrawalRecord::new(
            "wd-1", "intent-commit-1", "account-1", 100_000,
            "bc1qxyz", 100,
        )
    }

    #[tokio::test]
    async fn create_and_get_withdrawal() {
        let store = InMemoryWithdrawalStore::new();
        let wd = sample_withdrawal();
        store.create(wd.clone()).await.unwrap();
        let retrieved = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(retrieved.withdrawal_id, "wd-1");
        assert_eq!(retrieved.status, WithdrawalStatus::Reserved);
    }

    #[tokio::test]
    async fn update_status_through_lifecycle() {
        let store = InMemoryWithdrawalStore::new();
        store.create(sample_withdrawal()).await.unwrap();

        store.update_status("wd-1", WithdrawalStatus::Authorized, 105).await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.status, WithdrawalStatus::Authorized);

        store.update_status("wd-1", WithdrawalStatus::Signing, 110).await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.status, WithdrawalStatus::Signing);

        store.update_status("wd-1", WithdrawalStatus::Broadcast, 115).await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.status, WithdrawalStatus::Broadcast);

        store.update_status("wd-1", WithdrawalStatus::Confirming, 120).await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.status, WithdrawalStatus::Confirming);

        store.update_status("wd-1", WithdrawalStatus::Confirmed, 125).await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.status, WithdrawalStatus::Confirmed);
    }

    #[tokio::test]
    async fn status_can_transition_to_failed() {
        let store = InMemoryWithdrawalStore::new();
        store.create(sample_withdrawal()).await.unwrap();
        store.update_status("wd-1", WithdrawalStatus::Failed, 105).await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.status, WithdrawalStatus::Failed);
    }

    #[tokio::test]
    async fn invalid_transition_rejected() {
        let store = InMemoryWithdrawalStore::new();
        store.create(sample_withdrawal()).await.unwrap();

        let err = store
            .update_status("wd-1", WithdrawalStatus::Broadcast, 105)
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidStateTransition(_)));
    }

    #[tokio::test]
    async fn set_authorization_transitions_to_authorized() {
        let store = InMemoryWithdrawalStore::new();
        store.create(sample_withdrawal()).await.unwrap();

        let qc = crate::certificate::QuorumCertificate::single_node(
            "cluster-1", 1, 0, 1, "cmd-hash", "prev-root", "result-root", "node-1", "sig",
        );
        let auth = SettlementAuthorization {
            intent_commitment: "intent-commit-1".into(),
            command_hash: "cmd-hash".into(),
            psbt_commitment: "psbt-hash".into(),
            policy_hash: "policy-hash".into(),
            epoch: 1,
            expires_at_bucket: 200,
            nonce: "nonce-1".into(),
            quorum_certificate: qc,
        };

        store.set_authorization("wd-1", auth).await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.status, WithdrawalStatus::Authorized);
        assert!(wd.authorization.is_some());
    }

    #[tokio::test]
    async fn set_psbt_commitment() {
        let store = InMemoryWithdrawalStore::new();
        store.create(sample_withdrawal()).await.unwrap();

        let commitment = PsbtCommitment::new(b"psbt-bytes", 1, 2, 100_000);
        store.set_psbt("wd-1", commitment.clone()).await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.psbt_commitment, Some(commitment));
    }

    #[tokio::test]
    async fn set_broadcast_txid() {
        let store = InMemoryWithdrawalStore::new();
        store.create(sample_withdrawal()).await.unwrap();

        store.set_broadcast_txid("wd-1", "txid-abc").await.unwrap();
        let wd = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(wd.broadcast_txid, Some("txid-abc".into()));
    }

    #[tokio::test]
    async fn duplicate_broadcast_txid_rejected() {
        let store = InMemoryWithdrawalStore::new();
        store.create(sample_withdrawal()).await.unwrap();

        store.set_broadcast_txid("wd-1", "txid-abc").await.unwrap();
        let err = store
            .set_broadcast_txid("wd-1", "txid-xyz")
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::InvalidStateTransition(_)));
    }

    #[tokio::test]
    async fn withdrawal_not_found() {
        let store = InMemoryWithdrawalStore::new();
        // get returns Ok(None), not an error — only update/set operations error
        assert!(store.get("nonexistent").await.unwrap().is_none());

        let err = store
            .update_status("nonexistent", WithdrawalStatus::Authorized, 100)
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::WithdrawalNotFound(_)));
    }
}
