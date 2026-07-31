use async_trait::async_trait;

use crate::account_state::AccountState;
use crate::command::{BalanceCommand, InternalTransferCommand};
use crate::error::LedgerError;
use crate::idempotency::IdempotencyRecord;
use crate::reservation::{Reservation, ReservationState};

// ---------------------------------------------------------------------------
// VersionedAccountStore — per-account optimistic versioning
// ---------------------------------------------------------------------------

/// Port trait for a versioned per-account state store.
///
/// Every command that modifies an account carries an `expected_version`.
/// If the current version differs, the store returns `VersionConflict`.
#[async_trait]
pub trait VersionedAccountStore: Send + Sync {
    /// Retrieve the current state of an account. Returns `None` if the
    /// account has never been written.
    async fn get_account(&self, account_id: &str) -> Result<Option<AccountState>, LedgerError>;

    /// Apply a balance command to an account.
    ///
    /// If the account does not exist, it is created (version 0) and the
    /// command is applied if `expected_version == 0`.
    async fn apply_command(&self, cmd: &BalanceCommand) -> Result<AccountState, LedgerError>;

    /// Apply an atomic internal transfer between two accounts.
    ///
    /// Both accounts must exist. The operation is atomic: either both sides
    /// are updated or neither is.
    async fn apply_transfer(
        &self,
        cmd: &InternalTransferCommand,
    ) -> Result<(AccountState, AccountState), LedgerError>;
}

// ---------------------------------------------------------------------------
// ReservationStore — two-phase reservation lifecycle
// ---------------------------------------------------------------------------

/// Port trait for managing reservations.
#[async_trait]
pub trait ReservationStore: Send + Sync {
    /// Create a new reservation in the `Prepared` state.
    async fn create_reservation(&self, reservation: Reservation) -> Result<(), LedgerError>;

    /// Retrieve a reservation by its ID.
    async fn get_reservation(&self, id: &str) -> Result<Option<Reservation>, LedgerError>;

    /// Transition a reservation from one state to another.
    /// Returns an error if the current state does not match `from`.
    async fn transition(
        &self,
        id: &str,
        from: ReservationState,
        to: ReservationState,
    ) -> Result<(), LedgerError>;

    /// Expire all reservations whose `expires_at_bucket <= current_bucket`
    /// and that are not already in a terminal state.
    /// Returns the count of reservations expired.
    async fn expire_stale(&self, current_bucket: u64) -> Result<u64, LedgerError>;
}

// ---------------------------------------------------------------------------
// IdempotencyStore — duplicate command detection
// ---------------------------------------------------------------------------

/// Port trait for idempotency record storage.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Check if a command with the given `command_id` and `command_hash`
    /// has already been recorded.
    ///
    /// Returns:
    /// - `Ok(Some(record))` if a matching command_id + command_hash exists
    /// - `Ok(None)` if no record exists for this command_id
    /// - `Err(IdempotencyConflict)` if a record exists with a *different* hash
    async fn check(
        &self,
        command_id: &str,
        command_hash: &str,
    ) -> Result<Option<IdempotencyRecord>, LedgerError>;

    /// Record a completed command execution.
    async fn record(&self, record: IdempotencyRecord) -> Result<(), LedgerError>;
}
