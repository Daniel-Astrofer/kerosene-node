use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use sled::Db;

use crate::account_state::AccountState;
use crate::certificate::CertifiedSnapshot;
use crate::chain::{OnchainState, OutPoint, UtxoEntry};
use crate::command::{BalanceCommand, InternalTransferCommand};
use crate::error::LedgerError;
use crate::idempotency::IdempotencyRecord;
use crate::membership::{validate_role_transition, MembershipStore, NodeMembership, NodeRole};
use crate::nonce::NonceChecker;
use crate::reservation::{Reservation, ReservationState};
use crate::settlement::{
    NonceChecker as SyncNonceChecker, PsbtCommitment, SettlementAuthorization,
};
use crate::snapshot::SnapshotStore;
use crate::state_machine::LedgerState;
use crate::traits::{IdempotencyStore, ReservationStore, VersionedAccountStore};
use crate::utxo_store::UtxoStore;
use crate::withdrawal::{WithdrawalRecord, WithdrawalStatus, WithdrawalStore};

// ---------------------------------------------------------------------------
// Helper: serialise/deserialise with JSON via sled
// ---------------------------------------------------------------------------

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, LedgerError> {
    serde_json::to_vec(value)
        .map_err(|e| LedgerError::InvariantViolation(format!("serialization error: {}", e)))
}

fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, LedgerError> {
    serde_json::from_slice(bytes)
        .map_err(|e| LedgerError::InvariantViolation(format!("deserialization error: {}", e)))
}

// ---------------------------------------------------------------------------
// Key prefixes for namespace isolation
// ---------------------------------------------------------------------------

const PREFIX_NONCE: &[u8] = b"nonce:";
const PREFIX_ACCOUNT: &[u8] = b"account:";
const PREFIX_RESERVATION: &[u8] = b"resv:";
const PREFIX_IDEMPOTENCY: &[u8] = b"idemp:";
const PREFIX_UTXO: &[u8] = b"utxo:";
const PREFIX_WITHDRAWAL: &[u8] = b"wd:";
const PREFIX_SNAPSHOT: &[u8] = b"snap:";
const PREFIX_MEMBERSHIP: &[u8] = b"member:";
const KEY_LATEST_SNAPSHOT: &[u8] = b"snap:latest_seq";

// ---------------------------------------------------------------------------
// SledNonceChecker — persistent nonce store
// ---------------------------------------------------------------------------

/// Persistent `NonceChecker` backed by sled.
///
/// Nonces survive restarts: after a restart, consumed nonces are
/// still recognised, preventing replay attacks across restarts.
pub struct SledNonceChecker {
    db: Arc<Db>,
}

impl SledNonceChecker {
    /// Opens or creates a persistent nonce store at the given sled database.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl NonceChecker for SledNonceChecker {
    async fn is_consumed(&self, nonce: &str) -> Result<bool, LedgerError> {
        let key = [PREFIX_NONCE, nonce.as_bytes()].concat();
        self.db
            .get(&key)
            .map(|v| v.is_some())
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))
    }

    async fn mark_consumed(&self, nonce: &str) -> Result<(), LedgerError> {
        let key = [PREFIX_NONCE, nonce.as_bytes()].concat();
        let prev = self
            .db
            .insert(&key, &[])
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        if prev.is_some() {
            return Err(LedgerError::AuthorizationInvalid(format!(
                "nonce already consumed: {}",
                nonce
            )));
        }
        Ok(())
    }
}

impl SyncNonceChecker for SledNonceChecker {
    fn is_consumed_sync(&self, nonce: &str) -> bool {
        let key = [PREFIX_NONCE, nonce.as_bytes()].concat();
        self.db.get(&key).ok().flatten().is_some()
    }

    fn mark_consumed_sync(&self, nonce: &str) {
        let key = [PREFIX_NONCE, nonce.as_bytes()].concat();
        let _ = self.db.insert(&key, &[]);
    }
}

// ---------------------------------------------------------------------------
// SledVersionedAccountStore — persistent versioned account store
// ---------------------------------------------------------------------------

/// Persistent `VersionedAccountStore` backed by sled.
pub struct SledVersionedAccountStore {
    db: Arc<Db>,
}

impl SledVersionedAccountStore {
    /// Opens or creates a persistent account store.
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    fn account_key(account_id: &str) -> Vec<u8> {
        [PREFIX_ACCOUNT, account_id.as_bytes()].concat()
    }
}

#[async_trait]
impl VersionedAccountStore for SledVersionedAccountStore {
    async fn get_account(&self, account_id: &str) -> Result<Option<AccountState>, LedgerError> {
        let key = Self::account_key(account_id);
        match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn apply_command(&self, cmd: &BalanceCommand) -> Result<AccountState, LedgerError> {
        let key = Self::account_key(&cmd.account_id);
        let mut state = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize::<AccountState>(&bytes)?,
            None => {
                if cmd.expected_version != 0 {
                    return Err(LedgerError::VersionConflict {
                        account: cmd.account_id.clone(),
                        expected: cmd.expected_version,
                        current: 0,
                    });
                }
                AccountState::new(&cmd.account_id)
            }
        };

        // Check version
        if state.version != cmd.expected_version {
            return Err(LedgerError::VersionConflict {
                account: cmd.account_id.clone(),
                expected: cmd.expected_version,
                current: state.version,
            });
        }

        match cmd.operation {
            crate::command::BalanceOperation::Credit => state.apply_credit(cmd.amount_sats)?,
            crate::command::BalanceOperation::Debit => state.apply_debit(cmd.amount_sats)?,
            crate::command::BalanceOperation::Reserve => state.apply_reserve(cmd.amount_sats)?,
            crate::command::BalanceOperation::ReleaseReservation => {
                state.apply_release_reservation(cmd.amount_sats)?
            }
        }

        let serialized = serialize(&state)?;
        self.db
            .insert(&key, serialized)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;

        Ok(state)
    }

    async fn apply_transfer(
        &self,
        cmd: &InternalTransferCommand,
    ) -> Result<(AccountState, AccountState), LedgerError> {
        let src_key = Self::account_key(&cmd.source_account_id);
        let dst_key = Self::account_key(&cmd.destination_account_id);

        // Read both accounts
        let src_bytes = self
            .db
            .get(&src_key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        let dst_bytes = self
            .db
            .get(&dst_key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;

        let mut src: AccountState = match src_bytes {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::AtomicTransferFailed(format!(
                    "source account '{}' not found",
                    cmd.source_account_id
                )));
            }
        };
        let mut dst: AccountState = match dst_bytes {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::AtomicTransferFailed(format!(
                    "destination account '{}' not found",
                    cmd.destination_account_id
                )));
            }
        };

        // Validate versions
        src.check_version(cmd.source_expected_version)?;
        dst.check_version(cmd.destination_expected_version)?;

        // Validate sufficient balance
        if src.spendable() < cmd.amount_sats {
            return Err(LedgerError::InsufficientFunds {
                account: src.account_id.clone(),
                available: src.spendable(),
                needed: cmd.amount_sats,
            });
        }

        // Apply transfer atomically
        src.apply_debit(cmd.amount_sats)?;
        dst.apply_credit(cmd.amount_sats)?;

        // Use a sled batch for atomicity
        let mut batch = sled::Batch::default();
        batch.insert(&*src_key, serialize(&src)?);
        batch.insert(&*dst_key, serialize(&dst)?);

        self.db
            .apply_batch(batch)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled batch error: {}", e)))?;

        Ok((src, dst))
    }
}

// ---------------------------------------------------------------------------
// SledReservationStore — persistent reservation store
// ---------------------------------------------------------------------------

/// Persistent `ReservationStore` backed by sled.
pub struct SledReservationStore {
    db: Arc<Db>,
}

impl SledReservationStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    fn reservation_key(id: &str) -> Vec<u8> {
        [PREFIX_RESERVATION, id.as_bytes()].concat()
    }
}

#[async_trait]
impl ReservationStore for SledReservationStore {
    async fn create_reservation(&self, reservation: Reservation) -> Result<(), LedgerError> {
        let key = Self::reservation_key(&reservation.reservation_id);
        let existing = self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        if existing.is_some() {
            return Err(LedgerError::InvariantViolation(format!(
                "reservation '{}' already exists",
                reservation.reservation_id
            )));
        }
        let bytes = serialize(&reservation)?;
        self.db
            .insert(&key, bytes)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn get_reservation(&self, id: &str) -> Result<Option<Reservation>, LedgerError> {
        let key = Self::reservation_key(id);
        match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn transition(
        &self,
        id: &str,
        from: ReservationState,
        to: ReservationState,
    ) -> Result<(), LedgerError> {
        let key = Self::reservation_key(id);
        let mut reservation: Reservation = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::ReservationNotFound(id.to_string()));
            }
        };

        if reservation.state != from {
            return Err(LedgerError::InvariantViolation(format!(
                "reservation '{}' expected state {:?}, found {:?}",
                id, from, reservation.state
            )));
        }

        reservation.state = to;
        self.db
            .insert(&key, serialize(&reservation)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn expire_stale(&self, current_bucket: u64) -> Result<u64, LedgerError> {
        let mut expired_count = 0u64;
        let prefix = PREFIX_RESERVATION.to_vec();

        let to_expire: Vec<(Vec<u8>, Reservation)> = self
            .db
            .scan_prefix(&prefix)
            .filter_map(|result| {
                result.ok().and_then(|(key, value)| {
                    let r: Reservation = deserialize(&value).ok()?;
                    if r.expires_at_bucket <= current_bucket && !r.is_terminal() {
                        Some((key.to_vec(), r))
                    } else {
                        None
                    }
                })
            })
            .collect();

        for (key, mut r) in to_expire {
            r.state = ReservationState::Expired;
            if let Ok(bytes) = serialize(&r) {
                let _ = self.db.insert(key, bytes);
            }
            expired_count += 1;
        }

        Ok(expired_count)
    }
}

// ---------------------------------------------------------------------------
// SledIdempotencyStore — persistent idempotency store
// ---------------------------------------------------------------------------

/// Persistent `IdempotencyStore` backed by sled.
pub struct SledIdempotencyStore {
    db: Arc<Db>,
}

impl SledIdempotencyStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    fn idempotency_key(id: &str) -> Vec<u8> {
        [PREFIX_IDEMPOTENCY, id.as_bytes()].concat()
    }
}

#[async_trait]
impl IdempotencyStore for SledIdempotencyStore {
    async fn check(
        &self,
        command_id: &str,
        command_hash: &str,
    ) -> Result<Option<IdempotencyRecord>, LedgerError> {
        let key = Self::idempotency_key(command_id);
        match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => {
                let record: IdempotencyRecord = deserialize(&bytes)?;
                if record.command_hash == command_hash {
                    Ok(Some(record))
                } else {
                    Err(LedgerError::IdempotencyConflict {
                        command_id: command_id.to_string(),
                    })
                }
            }
            None => Ok(None),
        }
    }

    async fn record(&self, record: IdempotencyRecord) -> Result<(), LedgerError> {
        let key = Self::idempotency_key(&record.command_id);
        let bytes = serialize(&record)?;
        self.db
            .insert(&key, bytes)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SledUtxoStore — persistent UTXO store
// ---------------------------------------------------------------------------

/// Persistent `UtxoStore` backed by sled.
pub struct SledUtxoStore {
    db: Arc<Db>,
}

impl SledUtxoStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    fn utxo_key(key: &str) -> Vec<u8> {
        [PREFIX_UTXO, key.as_bytes()].concat()
    }

    fn list_all_entries(&self) -> Result<Vec<UtxoEntry>, LedgerError> {
        let prefix = PREFIX_UTXO.to_vec();
        let mut entries: Vec<UtxoEntry> = self
            .db
            .scan_prefix(&prefix)
            .filter_map(|result| result.ok())
            .filter_map(|(_, value)| deserialize(&value).ok())
            .collect();
        entries.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));
        Ok(entries)
    }
}

#[async_trait]
impl UtxoStore for SledUtxoStore {
    async fn add_utxo(&self, utxo: UtxoEntry) -> Result<(), LedgerError> {
        let key = Self::utxo_key(&utxo.canonical_key());
        // Idempotent: if already exists, skip
        let existing = self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        if existing.is_some() {
            return Ok(());
        }
        let bytes = serialize(&utxo)?;
        self.db
            .insert(&key, bytes)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, LedgerError> {
        let key = Self::utxo_key(&outpoint.to_canonical_string());
        match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn list_by_state(&self, state: OnchainState) -> Result<Vec<UtxoEntry>, LedgerError> {
        let entries = self.list_all_entries()?;
        let mut result: Vec<UtxoEntry> = entries.into_iter().filter(|e| e.state == state).collect();
        result.sort_by(|a, b| a.canonical_key().cmp(&b.canonical_key()));
        Ok(result)
    }

    async fn list_all(&self) -> Result<Vec<UtxoEntry>, LedgerError> {
        self.list_all_entries()
    }

    async fn update_state(
        &self,
        outpoint: &OutPoint,
        new_state: OnchainState,
    ) -> Result<(), LedgerError> {
        let key = Self::utxo_key(&outpoint.to_canonical_string());
        let mut entry: UtxoEntry = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::UtxoNotFound {
                    txid: outpoint.txid.clone(),
                    vout: outpoint.vout,
                });
            }
        };

        crate::chain::UtxoTransitionGate::validate_transition(entry.state, new_state)?;
        entry.state = new_state;

        self.db
            .insert(&key, serialize(&entry)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn reserve(
        &self,
        outpoint: &OutPoint,
        reserved_by: &str,
        bucket: u64,
    ) -> Result<(), LedgerError> {
        let key = Self::utxo_key(&outpoint.to_canonical_string());
        let mut entry: UtxoEntry = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::UtxoNotFound {
                    txid: outpoint.txid.clone(),
                    vout: outpoint.vout,
                });
            }
        };

        if !matches!(
            entry.state,
            OnchainState::Spendable | OnchainState::FinalizedByPolicy
        ) {
            return Err(LedgerError::InvalidUtxoTransition {
                from: entry.state,
                to: entry.state,
            });
        }

        if let Some(ref existing) = entry.reserved_by {
            return Err(LedgerError::UtxoAlreadyReserved {
                reserved_by: existing.clone(),
            });
        }

        entry.reserved_by = Some(reserved_by.to_string());
        entry.reserved_at_bucket = Some(bucket);

        self.db
            .insert(&key, serialize(&entry)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn release(&self, outpoint: &OutPoint) -> Result<(), LedgerError> {
        let key = Self::utxo_key(&outpoint.to_canonical_string());
        let mut entry: UtxoEntry = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::UtxoNotFound {
                    txid: outpoint.txid.clone(),
                    vout: outpoint.vout,
                });
            }
        };

        if entry.reserved_by.is_none() {
            return Err(LedgerError::UtxoNotReserved);
        }

        entry.reserved_by = None;
        entry.reserved_at_bucket = None;

        self.db
            .insert(&key, serialize(&entry)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn compute_utxo_root_hash(&self) -> Result<String, LedgerError> {
        let entries = self.list_all_entries()?;
        Ok(crate::chain::compute_utxo_root(&entries))
    }
}

// ---------------------------------------------------------------------------
// SledWithdrawalStore — persistent withdrawal store
// ---------------------------------------------------------------------------

/// Persistent `WithdrawalStore` backed by sled.
pub struct SledWithdrawalStore {
    db: Arc<Db>,
}

impl SledWithdrawalStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    fn withdrawal_key(id: &str) -> Vec<u8> {
        [PREFIX_WITHDRAWAL, id.as_bytes()].concat()
    }
}

#[async_trait]
impl WithdrawalStore for SledWithdrawalStore {
    async fn create(&self, withdrawal: WithdrawalRecord) -> Result<(), LedgerError> {
        let key = Self::withdrawal_key(&withdrawal.withdrawal_id);
        let existing = self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        if existing.is_some() {
            return Err(LedgerError::DuplicateEntryId(withdrawal.withdrawal_id));
        }
        let bytes = serialize(&withdrawal)?;
        self.db
            .insert(&key, bytes)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn get(&self, withdrawal_id: &str) -> Result<Option<WithdrawalRecord>, LedgerError> {
        let key = Self::withdrawal_key(withdrawal_id);
        match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn update_status(
        &self,
        id: &str,
        status: WithdrawalStatus,
        bucket: u64,
    ) -> Result<(), LedgerError> {
        let key = Self::withdrawal_key(id);
        let mut record: WithdrawalRecord = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::WithdrawalNotFound(id.to_string()));
            }
        };

        if !record.status.can_transition_to(status) {
            return Err(LedgerError::InvalidStateTransition(format!(
                "cannot transition withdrawal {} from {:?} to {:?}",
                id, record.status, status
            )));
        }

        record.status = status;
        record.updated_at_bucket = bucket;

        self.db
            .insert(&key, serialize(&record)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn set_authorization(
        &self,
        id: &str,
        auth: SettlementAuthorization,
    ) -> Result<(), LedgerError> {
        let key = Self::withdrawal_key(id);
        let mut record: WithdrawalRecord = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::WithdrawalNotFound(id.to_string()));
            }
        };

        if record.status != WithdrawalStatus::Reserved {
            return Err(LedgerError::InvalidStateTransition(format!(
                "cannot set authorization on withdrawal {} in state {:?} (must be Reserved)",
                id, record.status
            )));
        }

        record.authorization = Some(auth);
        record.status = WithdrawalStatus::Authorized;

        self.db
            .insert(&key, serialize(&record)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn set_psbt(&self, id: &str, commitment: PsbtCommitment) -> Result<(), LedgerError> {
        let key = Self::withdrawal_key(id);
        let mut record: WithdrawalRecord = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::WithdrawalNotFound(id.to_string()));
            }
        };

        record.psbt_commitment = Some(commitment);

        self.db
            .insert(&key, serialize(&record)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn set_broadcast_txid(&self, id: &str, txid: &str) -> Result<(), LedgerError> {
        let key = Self::withdrawal_key(id);
        let mut record: WithdrawalRecord = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::WithdrawalNotFound(id.to_string()));
            }
        };

        if record.broadcast_txid.is_some() {
            return Err(LedgerError::InvalidStateTransition(format!(
                "withdrawal {} already has broadcast txid {:?}",
                id, record.broadcast_txid
            )));
        }

        record.broadcast_txid = Some(txid.to_string());

        self.db
            .insert(&key, serialize(&record)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SledSnapshotStore — persistent snapshot store
// ---------------------------------------------------------------------------

/// Persistent `SnapshotStore` backed by sled.
pub struct SledSnapshotStore {
    db: Arc<Db>,
}

impl SledSnapshotStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    fn snapshot_key(sequence: u64) -> Vec<u8> {
        let mut key = PREFIX_SNAPSHOT.to_vec();
        key.extend_from_slice(&sequence.to_le_bytes());
        key
    }
}

#[async_trait]
impl SnapshotStore for SledSnapshotStore {
    async fn save_snapshot(&self, snapshot: &CertifiedSnapshot) -> Result<(), LedgerError> {
        snapshot.verify_basic()?;
        let key = Self::snapshot_key(snapshot.sequence);
        let bytes = serialize(snapshot)?;

        let mut batch = sled::Batch::default();
        batch.insert(key, bytes);
        batch.insert(
            KEY_LATEST_SNAPSHOT.to_vec(),
            &snapshot.sequence.to_le_bytes(),
        );

        self.db
            .apply_batch(batch)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn latest_snapshot(&self) -> Result<Option<CertifiedSnapshot>, LedgerError> {
        match self
            .db
            .get(KEY_LATEST_SNAPSHOT)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => {
                let sequence = u64::from_le_bytes(bytes.as_ref().try_into().map_err(|_| {
                    LedgerError::InvariantViolation("invalid latest sequence".into())
                })?);
                self.get_snapshot(sequence).await
            }
            None => Ok(None),
        }
    }

    async fn get_snapshot(&self, sequence: u64) -> Result<Option<CertifiedSnapshot>, LedgerError> {
        let key = Self::snapshot_key(sequence);
        match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn install_snapshot(
        &self,
        snapshot: &CertifiedSnapshot,
    ) -> Result<LedgerState, LedgerError> {
        snapshot.verify_basic()?;

        let state: LedgerState = serde_json::from_slice(&snapshot.state_bytes).map_err(|e| {
            LedgerError::InvalidSignature(format!("failed to deserialize snapshot state: {}", e))
        })?;

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

// ---------------------------------------------------------------------------
// SledMembershipStore — persistent membership store
// ---------------------------------------------------------------------------

/// Persistent `MembershipStore` backed by sled.
pub struct SledMembershipStore {
    db: Arc<Db>,
}

impl SledMembershipStore {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    fn member_key(node_id: &str) -> Vec<u8> {
        [PREFIX_MEMBERSHIP, node_id.as_bytes()].concat()
    }

    fn list_all_nodes(&self) -> Result<Vec<NodeMembership>, LedgerError> {
        let prefix = PREFIX_MEMBERSHIP.to_vec();
        let mut nodes: Vec<NodeMembership> = self
            .db
            .scan_prefix(&prefix)
            .filter_map(|result| result.ok())
            .filter_map(|(_, value)| deserialize(&value).ok())
            .collect();
        nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Ok(nodes)
    }
}

#[async_trait]
impl MembershipStore for SledMembershipStore {
    async fn add_node(&self, node: NodeMembership) -> Result<(), LedgerError> {
        let key = Self::member_key(&node.node_id);
        let existing = self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        if existing.is_some() {
            return Err(LedgerError::InvariantViolation(format!(
                "node '{}' already exists in membership",
                node.node_id
            )));
        }
        let bytes = serialize(&node)?;
        self.db
            .insert(&key, bytes)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn get_node(&self, node_id: &str) -> Result<Option<NodeMembership>, LedgerError> {
        let key = Self::member_key(node_id);
        match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => Ok(Some(deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    async fn list_by_role(&self, role: NodeRole) -> Result<Vec<NodeMembership>, LedgerError> {
        let nodes = self.list_all_nodes()?;
        let mut result: Vec<NodeMembership> =
            nodes.into_iter().filter(|n| n.role == role).collect();
        result.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Ok(result)
    }

    async fn promote(&self, node_id: &str, target_role: NodeRole) -> Result<(), LedgerError> {
        let key = Self::member_key(node_id);
        let mut node: NodeMembership = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::NodeNotFound(node_id.to_string()));
            }
        };

        let current_role = node.role;
        validate_role_transition(current_role, target_role)?;
        node.role = target_role;

        self.db
            .insert(&key, serialize(&node)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn remove_node(&self, node_id: &str) -> Result<(), LedgerError> {
        let key = Self::member_key(node_id);
        self.db
            .remove(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }

    async fn update_heartbeat(&self, node_id: &str, bucket: u64) -> Result<(), LedgerError> {
        let key = Self::member_key(node_id);
        let mut node: NodeMembership = match self
            .db
            .get(&key)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?
        {
            Some(bytes) => deserialize(&bytes)?,
            None => {
                return Err(LedgerError::NodeNotFound(node_id.to_string()));
            }
        };

        node.last_heartbeat_bucket = bucket;

        self.db
            .insert(&key, serialize(&node)?)
            .map_err(|e| LedgerError::InvariantViolation(format!("sled error: {}", e)))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SledLedgerDb — convenience wrapper that opens a single sled DB and
// provides accessors to all persistent stores.
// ---------------------------------------------------------------------------

/// A single sled-backed persistent store for the entire ledger.
///
/// Opens a single sled database at the given path and provides
/// accessor methods for each store type. All stores share the same
/// underlying sled DB but are isolated by key prefix.
///
/// After a restart, all previously persisted state is recovered:
/// - Nonces are not reusable
/// - Idempotency is preserved
/// - Accounts, reservations, UTXOs, withdrawal records are all restored
pub struct SledLedgerDb {
    db: Arc<Db>,
}

impl SledLedgerDb {
    /// Opens (or creates) a persistent ledger database at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, LedgerError> {
        let db = sled::open(path).map_err(|e| {
            LedgerError::InvariantViolation(format!("failed to open sled db: {}", e))
        })?;
        Ok(Self { db: Arc::new(db) })
    }

    /// Returns a persistent nonce checker.
    pub fn nonce_checker(&self) -> SledNonceChecker {
        SledNonceChecker::new(self.db.clone())
    }

    /// Returns a persistent account store.
    pub fn account_store(&self) -> SledVersionedAccountStore {
        SledVersionedAccountStore::new(self.db.clone())
    }

    /// Returns a persistent reservation store.
    pub fn reservation_store(&self) -> SledReservationStore {
        SledReservationStore::new(self.db.clone())
    }

    /// Returns a persistent idempotency store.
    pub fn idempotency_store(&self) -> SledIdempotencyStore {
        SledIdempotencyStore::new(self.db.clone())
    }

    /// Returns a persistent UTXO store.
    pub fn utxo_store(&self) -> SledUtxoStore {
        SledUtxoStore::new(self.db.clone())
    }

    /// Returns a persistent withdrawal store.
    pub fn withdrawal_store(&self) -> SledWithdrawalStore {
        SledWithdrawalStore::new(self.db.clone())
    }

    /// Returns a persistent snapshot store.
    pub fn snapshot_store(&self) -> SledSnapshotStore {
        SledSnapshotStore::new(self.db.clone())
    }

    /// Returns a persistent membership store.
    pub fn membership_store(&self) -> SledMembershipStore {
        SledMembershipStore::new(self.db.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::OutPoint;
    use tempfile::TempDir;

    fn create_db() -> (TempDir, SledLedgerDb) {
        let dir = TempDir::new().unwrap();
        let db = SledLedgerDb::open(dir.path().join("test.db")).unwrap();
        (dir, db)
    }

    // -----------------------------------------------------------------------
    // SledNonceChecker tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sled_nonce_fresh_not_consumed() {
        let (_dir, db) = create_db();
        let nc = db.nonce_checker();
        assert!(!nc.is_consumed("nonce-1").await.unwrap());
    }

    #[tokio::test]
    async fn sled_nonce_mark_consumed() {
        let (_dir, db) = create_db();
        let nc = db.nonce_checker();
        nc.mark_consumed("nonce-1").await.unwrap();
        assert!(nc.is_consumed("nonce-1").await.unwrap());
    }

    #[tokio::test]
    async fn sled_nonce_double_consumption_rejected() {
        let (_dir, db) = create_db();
        let nc = db.nonce_checker();
        nc.mark_consumed("nonce-1").await.unwrap();
        let err = nc.mark_consumed("nonce-1").await.unwrap_err();
        assert!(matches!(err, LedgerError::AuthorizationInvalid(_)));
    }

    #[tokio::test]
    async fn sled_nonce_survives_restart() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");

        // First session
        {
            let db = SledLedgerDb::open(&path).unwrap();
            let nc = db.nonce_checker();
            nc.mark_consumed("nonce-1").await.unwrap();
        }
        // Second session (simulates restart)
        {
            let db = SledLedgerDb::open(&path).unwrap();
            let nc = db.nonce_checker();
            assert!(
                nc.is_consumed("nonce-1").await.unwrap(),
                "nonce must survive restart"
            );
            assert!(
                !nc.is_consumed("nonce-2").await.unwrap(),
                "nonce-2 should be fresh"
            );
        }
    }

    // -----------------------------------------------------------------------
    // SledVersionedAccountStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sled_account_apply_credit() {
        let (_dir, db) = create_db();
        let store = db.account_store();
        let cmd = BalanceCommand::new(
            "c1",
            "alice",
            0,
            crate::command::BalanceOperation::Credit,
            100,
            1,
        );
        let state = store.apply_command(&cmd).await.unwrap();
        assert_eq!(state.available_sats, 100);
        assert_eq!(state.version, 1);
    }

    #[tokio::test]
    async fn sled_account_version_conflict() {
        let (_dir, db) = create_db();
        let store = db.account_store();
        let cmd1 = BalanceCommand::new(
            "c1",
            "alice",
            0,
            crate::command::BalanceOperation::Credit,
            100,
            1,
        );
        store.apply_command(&cmd1).await.unwrap();

        let cmd2 = BalanceCommand::new(
            "c2",
            "alice",
            0,
            crate::command::BalanceOperation::Credit,
            50,
            1,
        );
        let err = store.apply_command(&cmd2).await.unwrap_err();
        assert!(matches!(err, LedgerError::VersionConflict { .. }));
    }

    // -----------------------------------------------------------------------
    // SledUtxoStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sled_utxo_add_and_get() {
        let (_dir, db) = create_db();
        let store = db.utxo_store();
        let utxo = UtxoEntry::new_seen(OutPoint::new("tx1", 0), 1000, "addr", 1);
        store.add_utxo(utxo.clone()).await.unwrap();

        let fetched = store
            .get_utxo(&OutPoint::new("tx1", 0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched, utxo);
    }

    #[tokio::test]
    async fn sled_utxo_survives_restart() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");

        {
            let db = SledLedgerDb::open(&path).unwrap();
            let store = db.utxo_store();
            store
                .add_utxo(UtxoEntry::new_seen(
                    OutPoint::new("tx1", 0),
                    1000,
                    "addr",
                    1,
                ))
                .await
                .unwrap();
        }

        {
            let db = SledLedgerDb::open(&path).unwrap();
            let store = db.utxo_store();
            let fetched = store
                .get_utxo(&OutPoint::new("tx1", 0))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(fetched.value_sats, 1000);
        }
    }

    // -----------------------------------------------------------------------
    // SledWithdrawalStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sled_withdrawal_create_and_get() {
        let (_dir, db) = create_db();
        let store = db.withdrawal_store();
        let wd = WithdrawalRecord::new("wd-1", "intent-1", "account-1", 100_000, "bc1qxyz", 100);
        store.create(wd.clone()).await.unwrap();
        let fetched = store.get("wd-1").await.unwrap().unwrap();
        assert_eq!(fetched.withdrawal_id, "wd-1");
    }

    // -----------------------------------------------------------------------
    // SledSnapshotStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sled_snapshot_save_and_latest() {
        let (_dir, db) = create_db();
        let store = db.snapshot_store();

        let qc = crate::tests::helpers::make_signed_qc(
            "cluster-1",
            1,
            0,
            42,
            "hash",
            "prev",
            "result",
            "node-1",
        )
        .0;
        let state = crate::state_machine::LedgerState::empty(
            crate::state_machine::MembershipView::single_node("cluster-1", "node-1"),
        );
        let state_root = crate::state_root::compute_state_root(&state);
        let state_bytes = serde_json::to_vec(&state).unwrap();

        let snap = CertifiedSnapshot {
            cluster_id: "cluster-1".into(),
            epoch: 1,
            sequence: 42,
            state_bytes,
            state_root,
            membership_hash: "mem-hash".into(),
            constitution_hash: "const-hash".into(),
            policy_hash: "policy-hash".into(),
            ledger_totals_hash: "totals-hash".into(),
            utxo_set_root: "utxo-root".into(),
            consumed_intents_root: "intents-root".into(),
            quorum_certificate: qc,
        };

        store.save_snapshot(&snap).await.unwrap();
        let latest = store.latest_snapshot().await.unwrap().unwrap();
        assert_eq!(latest.sequence, 42);
    }

    // -----------------------------------------------------------------------
    // SledMembershipStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sled_membership_add_and_get() {
        let (_dir, db) = create_db();
        let store = db.membership_store();
        let node = NodeMembership {
            node_id: "node-1".into(),
            role: NodeRole::Voter,
            onion_endpoint: None,
            identity_pubkey: "pubkey".into(),
            attested_at_bucket: 100,
            joined_epoch: 1,
            last_heartbeat_bucket: 100,
            admission_signature: None,
        };
        store.add_node(node.clone()).await.unwrap();
        let fetched = store.get_node("node-1").await.unwrap().unwrap();
        assert_eq!(fetched.node_id, "node-1");
    }
}
