use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::account_state::AccountState;
use crate::command::{BalanceCommand, BalanceOperation, InternalTransferCommand};
use crate::error::LedgerError;
use crate::idempotency::IdempotencyRecord;
use crate::reservation::{Reservation, ReservationState};
use crate::traits::{IdempotencyStore, ReservationStore, VersionedAccountStore};

// ---------------------------------------------------------------------------
// InMemoryVersionedAccountStore
// ---------------------------------------------------------------------------

/// In-memory versioned account store backed by `Mutex<HashMap>`.
///
/// Accounts are created lazily on first use via `apply_command`.
/// Transfers require both accounts to already exist.
pub struct InMemoryVersionedAccountStore {
    inner: Mutex<HashMap<String, AccountState>>,
}

impl InMemoryVersionedAccountStore {
    /// Creates a new empty store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a new store pre-populated with the given accounts.
    pub fn with_accounts(accounts: Vec<AccountState>) -> Self {
        let map: HashMap<_, _> = accounts
            .into_iter()
            .map(|a| (a.account_id.clone(), a))
            .collect();
        Self {
            inner: Mutex::new(map),
        }
    }

    /// Manually insert or update an account (useful for test setup).
    pub fn insert(&self, state: AccountState) {
        let mut map = self.inner.lock().unwrap();
        map.insert(state.account_id.clone(), state);
    }
}

impl Default for InMemoryVersionedAccountStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VersionedAccountStore for InMemoryVersionedAccountStore {
    async fn get_account(&self, account_id: &str) -> Result<Option<AccountState>, LedgerError> {
        let map = self.inner.lock().unwrap();
        Ok(map.get(account_id).cloned())
    }

    async fn apply_command(&self, cmd: &BalanceCommand) -> Result<AccountState, LedgerError> {
        let mut map = self.inner.lock().unwrap();

        // Get or create the account with version 0
        let state = if let Some(s) = map.get_mut(&cmd.account_id) {
            s.check_version(cmd.expected_version)?;
            s
        } else {
            if cmd.expected_version != 0 {
                return Err(LedgerError::VersionConflict {
                    account: cmd.account_id.clone(),
                    expected: cmd.expected_version,
                    current: 0,
                });
            }
            map.insert(cmd.account_id.clone(), AccountState::new(&cmd.account_id));
            map.get_mut(&cmd.account_id).unwrap()
        };

        match cmd.operation {
            BalanceOperation::Credit => state.apply_credit(cmd.amount_sats)?,
            BalanceOperation::Debit => state.apply_debit(cmd.amount_sats)?,
            BalanceOperation::Reserve => state.apply_reserve(cmd.amount_sats)?,
            BalanceOperation::ReleaseReservation => {
                state.apply_release_reservation(cmd.amount_sats)?
            }
        }

        Ok(state.clone())
    }

    async fn apply_transfer(
        &self,
        cmd: &InternalTransferCommand,
    ) -> Result<(AccountState, AccountState), LedgerError> {
        let mut map = self.inner.lock().unwrap();

        // Clone both states to avoid borrow checker issues
        let src = map.get(&cmd.source_account_id).cloned().ok_or_else(|| {
            LedgerError::AtomicTransferFailed(format!(
                "source account '{}' not found",
                cmd.source_account_id
            ))
        })?;

        let dst = map
            .get(&cmd.destination_account_id)
            .cloned()
            .ok_or_else(|| {
                LedgerError::AtomicTransferFailed(format!(
                    "destination account '{}' not found",
                    cmd.destination_account_id
                ))
            })?;

        // Validate versions
        src.check_version(cmd.source_expected_version)?;
        dst.check_version(cmd.destination_expected_version)?;

        // Validate source has sufficient spendable balance
        if src.spendable() < cmd.amount_sats {
            return Err(LedgerError::InsufficientFunds {
                account: src.account_id.clone(),
                available: src.spendable(),
                needed: cmd.amount_sats,
            });
        }

        // Apply the transfer atomically
        let mut updated_src = src.clone();
        let mut updated_dst = dst.clone();

        updated_src.apply_debit(cmd.amount_sats)?;
        updated_dst.apply_credit(cmd.amount_sats)?;

        // Write both back
        map.insert(updated_src.account_id.clone(), updated_src.clone());
        map.insert(updated_dst.account_id.clone(), updated_dst.clone());

        Ok((updated_src, updated_dst))
    }
}

// ---------------------------------------------------------------------------
// InMemoryReservationStore
// ---------------------------------------------------------------------------

/// In-memory reservation store backed by `Mutex<HashMap>`.
pub struct InMemoryReservationStore {
    inner: Mutex<HashMap<String, Reservation>>,
}

impl InMemoryReservationStore {
    /// Creates a new empty reservation store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryReservationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ReservationStore for InMemoryReservationStore {
    async fn create_reservation(&self, reservation: Reservation) -> Result<(), LedgerError> {
        let mut map = self.inner.lock().unwrap();
        if map.contains_key(&reservation.reservation_id) {
            return Err(LedgerError::InvariantViolation(format!(
                "reservation '{}' already exists",
                reservation.reservation_id
            )));
        }
        map.insert(reservation.reservation_id.clone(), reservation);
        Ok(())
    }

    async fn get_reservation(&self, id: &str) -> Result<Option<Reservation>, LedgerError> {
        let map = self.inner.lock().unwrap();
        Ok(map.get(id).cloned())
    }

    async fn transition(
        &self,
        id: &str,
        from: ReservationState,
        to: ReservationState,
    ) -> Result<(), LedgerError> {
        let mut map = self.inner.lock().unwrap();
        let reservation = map
            .get_mut(id)
            .ok_or_else(|| LedgerError::ReservationNotFound(id.to_string()))?;

        if reservation.state != from {
            return Err(LedgerError::InvariantViolation(format!(
                "reservation '{}' expected state {:?}, found {:?}",
                id, from, reservation.state
            )));
        }

        reservation.state = to;
        Ok(())
    }

    async fn expire_stale(&self, current_bucket: u64) -> Result<u64, LedgerError> {
        let mut map = self.inner.lock().unwrap();
        let mut expired_count = 0u64;
        let to_expire: Vec<String> = map
            .iter()
            .filter(|(_, r)| r.expires_at_bucket <= current_bucket && !r.is_terminal())
            .map(|(id, _)| id.clone())
            .collect();

        for id in &to_expire {
            if let Some(r) = map.get_mut(id) {
                r.state = ReservationState::Expired;
                expired_count += 1;
            }
        }

        Ok(expired_count)
    }
}

// ---------------------------------------------------------------------------
// InMemoryIdempotencyStore
// ---------------------------------------------------------------------------

/// In-memory idempotency store backed by `Mutex<HashMap>`.
pub struct InMemoryIdempotencyStore {
    inner: Mutex<HashMap<String, IdempotencyRecord>>,
}

impl InMemoryIdempotencyStore {
    /// Creates a new empty idempotency store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryIdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdempotencyStore for InMemoryIdempotencyStore {
    async fn check(
        &self,
        command_id: &str,
        command_hash: &str,
    ) -> Result<Option<IdempotencyRecord>, LedgerError> {
        let map = self.inner.lock().unwrap();
        match map.get(command_id) {
            Some(existing) => {
                if existing.command_hash == command_hash {
                    // Same command_id + same hash → return existing result
                    Ok(Some(existing.clone()))
                } else {
                    // Same command_id + different hash → idempotency conflict
                    Err(LedgerError::IdempotencyConflict {
                        command_id: command_id.to_string(),
                    })
                }
            }
            None => Ok(None),
        }
    }

    async fn record(&self, record: IdempotencyRecord) -> Result<(), LedgerError> {
        let mut map = self.inner.lock().unwrap();
        map.insert(record.command_id.clone(), record);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // VersionedAccountStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn get_account_returns_none_for_unknown() {
        let store = InMemoryVersionedAccountStore::new();
        let result = store.get_account("unknown").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn apply_credit_creates_account() {
        let store = InMemoryVersionedAccountStore::new();
        let cmd = BalanceCommand::new("c1", "alice", 0, BalanceOperation::Credit, 100, 1);
        let state = store.apply_command(&cmd).await.unwrap();
        assert_eq!(state.available_sats, 100);
        assert_eq!(state.version, 1);
    }

    #[tokio::test]
    async fn apply_command_checks_version() {
        let store = InMemoryVersionedAccountStore::new();
        // Create account with version 0
        let cmd1 = BalanceCommand::new("c1", "alice", 0, BalanceOperation::Credit, 100, 1);
        store.apply_command(&cmd1).await.unwrap();

        // Try with wrong version
        let cmd2 = BalanceCommand::new("c2", "alice", 0, BalanceOperation::Credit, 50, 1);
        let err = store.apply_command(&cmd2).await.unwrap_err();
        assert!(matches!(err, LedgerError::VersionConflict { .. }));
    }

    #[tokio::test]
    async fn apply_debit_reduces_balance() {
        let store = InMemoryVersionedAccountStore::new();
        let credit = BalanceCommand::new("c1", "bob", 0, BalanceOperation::Credit, 200, 1);
        store.apply_command(&credit).await.unwrap();

        let debit = BalanceCommand::new("c2", "bob", 1, BalanceOperation::Debit, 80, 1);
        let state = store.apply_command(&debit).await.unwrap();
        assert_eq!(state.available_sats, 120);
        assert_eq!(state.version, 2);
    }

    #[tokio::test]
    async fn apply_debit_fails_insufficient_funds() {
        let store = InMemoryVersionedAccountStore::new();
        let credit = BalanceCommand::new("c1", "bob", 0, BalanceOperation::Credit, 50, 1);
        store.apply_command(&credit).await.unwrap();

        let debit = BalanceCommand::new("c2", "bob", 1, BalanceOperation::Debit, 100, 1);
        let err = store.apply_command(&debit).await.unwrap_err();
        assert!(matches!(err, LedgerError::InsufficientFunds { .. }));
    }

    #[tokio::test]
    async fn apply_reserve_moves_funds() {
        let store = InMemoryVersionedAccountStore::new();
        let credit = BalanceCommand::new("c1", "carol", 0, BalanceOperation::Credit, 500, 1);
        store.apply_command(&credit).await.unwrap();

        let reserve = BalanceCommand::new("c2", "carol", 1, BalanceOperation::Reserve, 200, 1);
        let state = store.apply_command(&reserve).await.unwrap();
        assert_eq!(state.available_sats, 300);
        assert_eq!(state.reserved_sats, 200);
    }

    #[tokio::test]
    async fn apply_release_restores_balance() {
        let store = InMemoryVersionedAccountStore::new();
        store
            .apply_command(&BalanceCommand::new(
                "c1",
                "carol",
                0,
                BalanceOperation::Credit,
                500,
                1,
            ))
            .await
            .unwrap();
        store
            .apply_command(&BalanceCommand::new(
                "c2",
                "carol",
                1,
                BalanceOperation::Reserve,
                200,
                1,
            ))
            .await
            .unwrap();

        let release = BalanceCommand::new(
            "c3",
            "carol",
            2,
            BalanceOperation::ReleaseReservation,
            100,
            1,
        );
        let state = store.apply_command(&release).await.unwrap();
        assert_eq!(state.available_sats, 400);
        assert_eq!(state.reserved_sats, 100);
    }

    #[tokio::test]
    async fn concurrent_debits_dont_overflow() {
        let store = InMemoryVersionedAccountStore::new();
        store
            .apply_command(&BalanceCommand::new(
                "c1",
                "dave",
                0,
                BalanceOperation::Credit,
                1000,
                1,
            ))
            .await
            .unwrap();

        // Simulate two concurrent debits both seeing version 1
        let debit1 = BalanceCommand::new("c2", "dave", 1, BalanceOperation::Debit, 600, 1);
        let debit2 = BalanceCommand::new("c3", "dave", 1, BalanceOperation::Debit, 500, 1);

        // One should succeed, one should fail with VersionConflict
        let r1 = store.apply_command(&debit1).await;
        let r2 = store.apply_command(&debit2).await;

        // Exactly one should succeed
        let successes = [r1.as_ref().ok(), r2.as_ref().ok()]
            .iter()
            .filter(|r| r.is_some())
            .count();
        assert_eq!(successes, 1);

        // The other should be a version conflict
        let conflicts = [&r1, &r2]
            .iter()
            .filter(|r| matches!(r, Err(LedgerError::VersionConflict { .. })))
            .count();
        assert_eq!(conflicts, 1);
    }

    // -----------------------------------------------------------------------
    // Transfer tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn valid_transfer_updates_both_accounts() {
        let store = InMemoryVersionedAccountStore::new();
        store
            .apply_command(&BalanceCommand::new(
                "c1",
                "alice",
                0,
                BalanceOperation::Credit,
                1000,
                1,
            ))
            .await
            .unwrap();
        store
            .apply_command(&BalanceCommand::new(
                "c2",
                "bob",
                0,
                BalanceOperation::Credit,
                500,
                1,
            ))
            .await
            .unwrap();

        let transfer = InternalTransferCommand::new("tx1", "alice", 1, "bob", 1, 300, "auth-1");
        let (src, dst) = store.apply_transfer(&transfer).await.unwrap();

        assert_eq!(src.available_sats, 700);
        assert_eq!(src.version, 2);
        assert_eq!(dst.available_sats, 800);
        assert_eq!(dst.version, 2);
    }

    #[tokio::test]
    async fn transfer_insufficient_source_balance_rejected() {
        let store = InMemoryVersionedAccountStore::new();
        store
            .apply_command(&BalanceCommand::new(
                "c1",
                "alice",
                0,
                BalanceOperation::Credit,
                100,
                1,
            ))
            .await
            .unwrap();
        store
            .apply_command(&BalanceCommand::new(
                "c2",
                "bob",
                0,
                BalanceOperation::Credit,
                500,
                1,
            ))
            .await
            .unwrap();

        let transfer = InternalTransferCommand::new("tx1", "alice", 1, "bob", 1, 300, "auth-1");
        let err = store.apply_transfer(&transfer).await.unwrap_err();
        assert!(matches!(err, LedgerError::InsufficientFunds { .. }));

        // Verify neither account changed
        let alice = store.get_account("alice").await.unwrap().unwrap();
        let bob = store.get_account("bob").await.unwrap().unwrap();
        assert_eq!(alice.available_sats, 100);
        assert_eq!(bob.available_sats, 500);
    }

    #[tokio::test]
    async fn transfer_version_mismatch_on_source_rejected() {
        let store = InMemoryVersionedAccountStore::new();
        store
            .apply_command(&BalanceCommand::new(
                "c1",
                "alice",
                0,
                BalanceOperation::Credit,
                1000,
                1,
            ))
            .await
            .unwrap();
        store
            .apply_command(&BalanceCommand::new(
                "c2",
                "bob",
                0,
                BalanceOperation::Credit,
                500,
                1,
            ))
            .await
            .unwrap();

        let transfer = InternalTransferCommand::new("tx1", "alice", 0, "bob", 1, 300, "auth-1");
        let err = store.apply_transfer(&transfer).await.unwrap_err();
        assert!(matches!(err, LedgerError::VersionConflict { .. }));
    }

    #[tokio::test]
    async fn transfer_version_mismatch_on_dest_rejected() {
        let store = InMemoryVersionedAccountStore::new();
        store
            .apply_command(&BalanceCommand::new(
                "c1",
                "alice",
                0,
                BalanceOperation::Credit,
                1000,
                1,
            ))
            .await
            .unwrap();
        store
            .apply_command(&BalanceCommand::new(
                "c2",
                "bob",
                0,
                BalanceOperation::Credit,
                500,
                1,
            ))
            .await
            .unwrap();

        let transfer = InternalTransferCommand::new("tx1", "alice", 1, "bob", 0, 300, "auth-1");
        let err = store.apply_transfer(&transfer).await.unwrap_err();
        assert!(matches!(err, LedgerError::VersionConflict { .. }));
    }

    #[tokio::test]
    async fn transfer_source_not_found_rejected() {
        let store = InMemoryVersionedAccountStore::new();
        store
            .apply_command(&BalanceCommand::new(
                "c1",
                "bob",
                0,
                BalanceOperation::Credit,
                500,
                1,
            ))
            .await
            .unwrap();

        let transfer =
            InternalTransferCommand::new("tx1", "nonexistent", 0, "bob", 1, 100, "auth-1");
        let err = store.apply_transfer(&transfer).await.unwrap_err();
        assert!(matches!(err, LedgerError::AtomicTransferFailed(_)));
    }

    #[tokio::test]
    async fn transfer_dest_not_found_rejected() {
        let store = InMemoryVersionedAccountStore::new();
        store
            .apply_command(&BalanceCommand::new(
                "c1",
                "alice",
                0,
                BalanceOperation::Credit,
                1000,
                1,
            ))
            .await
            .unwrap();

        let transfer =
            InternalTransferCommand::new("tx1", "alice", 1, "nonexistent", 0, 100, "auth-1");
        let err = store.apply_transfer(&transfer).await.unwrap_err();
        assert!(matches!(err, LedgerError::AtomicTransferFailed(_)));
    }

    // -----------------------------------------------------------------------
    // ReservationStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_and_get_reservation() {
        let store = InMemoryReservationStore::new();
        let r = Reservation::new("res-1", "alice", 500, 10, 100, "auth-1");
        store.create_reservation(r.clone()).await.unwrap();

        let fetched = store.get_reservation("res-1").await.unwrap();
        assert_eq!(fetched, Some(r));
    }

    #[tokio::test]
    async fn double_reservation_rejected() {
        let store = InMemoryReservationStore::new();
        let r = Reservation::new("res-1", "alice", 500, 10, 100, "auth-1");
        store.create_reservation(r.clone()).await.unwrap();
        let err = store.create_reservation(r).await.unwrap_err();
        assert!(matches!(err, LedgerError::InvariantViolation(_)));
    }

    #[tokio::test]
    async fn transition_works() {
        let store = InMemoryReservationStore::new();
        let r = Reservation::new("res-1", "alice", 500, 10, 100, "auth-1");
        store.create_reservation(r).await.unwrap();

        store
            .transition(
                "res-1",
                ReservationState::Prepared,
                ReservationState::Committed,
            )
            .await
            .unwrap();
        let fetched = store.get_reservation("res-1").await.unwrap().unwrap();
        assert_eq!(fetched.state, ReservationState::Committed);

        store
            .transition(
                "res-1",
                ReservationState::Committed,
                ReservationState::Consumed,
            )
            .await
            .unwrap();
        let fetched = store.get_reservation("res-1").await.unwrap().unwrap();
        assert_eq!(fetched.state, ReservationState::Consumed);
    }

    #[tokio::test]
    async fn transition_wrong_from_state_rejected() {
        let store = InMemoryReservationStore::new();
        let r = Reservation::new("res-1", "alice", 500, 10, 100, "auth-1");
        store.create_reservation(r).await.unwrap();

        let err = store
            .transition(
                "res-1",
                ReservationState::Committed,
                ReservationState::Consumed,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::InvariantViolation(_)));
    }

    #[tokio::test]
    async fn reservation_not_found() {
        let store = InMemoryReservationStore::new();
        let result = store.get_reservation("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn expire_stale_expires_unconsumed_reservations() {
        let store = InMemoryReservationStore::new();
        let r1 = Reservation::new("res-1", "a", 100, 0, 10, "auth");
        let r2 = Reservation::new("res-2", "b", 200, 0, 20, "auth");
        let r3 = Reservation::new("res-3", "c", 300, 0, 30, "auth");

        store.create_reservation(r1).await.unwrap();
        store.create_reservation(r2).await.unwrap();
        store.create_reservation(r3).await.unwrap();

        // Manually transition r3 to consumed
        store
            .transition(
                "res-3",
                ReservationState::Prepared,
                ReservationState::Committed,
            )
            .await
            .unwrap();
        store
            .transition(
                "res-3",
                ReservationState::Committed,
                ReservationState::Consumed,
            )
            .await
            .unwrap();

        let count = store.expire_stale(25).await.unwrap();
        assert_eq!(count, 2); // res-1 and res-2 should expire

        let f1 = store.get_reservation("res-1").await.unwrap().unwrap();
        assert_eq!(f1.state, ReservationState::Expired);

        let f2 = store.get_reservation("res-2").await.unwrap().unwrap();
        assert_eq!(f2.state, ReservationState::Expired);

        // Consumed reservation should not be expired
        let f3 = store.get_reservation("res-3").await.unwrap().unwrap();
        assert_eq!(f3.state, ReservationState::Consumed);
    }

    // -----------------------------------------------------------------------
    // IdempotencyStore tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn idempotency_same_hash_returns_existing() {
        let store = InMemoryIdempotencyStore::new();
        let rec = IdempotencyRecord::new("cmd-1", "hash-abc", "result-xyz", 42, "root-123");
        store.record(rec.clone()).await.unwrap();

        let result = store.check("cmd-1", "hash-abc").await.unwrap();
        assert_eq!(result, Some(rec));
    }

    #[tokio::test]
    async fn idempotency_different_hash_returns_conflict() {
        let store = InMemoryIdempotencyStore::new();
        let rec = IdempotencyRecord::new("cmd-1", "hash-abc", "result-xyz", 42, "root-123");
        store.record(rec).await.unwrap();

        let err = store.check("cmd-1", "hash-def").await.unwrap_err();
        assert!(matches!(err, LedgerError::IdempotencyConflict { .. }));
    }

    #[tokio::test]
    async fn idempotency_no_record_returns_none() {
        let store = InMemoryIdempotencyStore::new();
        let result = store.check("unknown", "hash").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn idempotency_record_stored_and_retrievable() {
        let store = InMemoryIdempotencyStore::new();
        let rec = IdempotencyRecord::new("cmd-1", "hash-abc", "result-xyz", 42, "root-123");
        store.record(rec.clone()).await.unwrap();

        let result = store.check("cmd-1", "hash-abc").await.unwrap();
        assert_eq!(result, Some(rec));
    }
}
