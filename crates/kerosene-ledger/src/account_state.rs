use serde::{Deserialize, Serialize};

use crate::error::LedgerError;

/// Per-account versioned state tracker.
///
/// Every account has an independent monotonically-increasing version counter,
/// and all balance-modifying operations check the caller-supplied expected version
/// against the current version to prevent lost updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountState {
    /// Unique identifier for this account.
    pub account_id: String,
    /// Monotonically increasing version (starts at 0, increments on every change).
    pub version: u64,
    /// Balance available for spending (not reserved).
    pub available_sats: u64,
    /// Balance reserved for pending external settlements.
    pub reserved_sats: u64,
    /// Incoming transfers not yet settled.
    pub pending_incoming_sats: u64,
    /// Outgoing transfers not yet settled.
    pub pending_outgoing_sats: u64,
    /// Sequence number of the last committed journal entry for this account.
    pub last_committed_sequence: u64,
}

impl AccountState {
    /// Creates a new account state initialized to zero for all balances,
    /// version 0.
    pub fn new(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            version: 0,
            available_sats: 0,
            reserved_sats: 0,
            pending_incoming_sats: 0,
            pending_outgoing_sats: 0,
            last_committed_sequence: 0,
        }
    }

    /// Returns the effective spendable balance.
    /// Since `available_sats` already excludes reserved funds, this is simply
    /// `available_sats`.  Saturates at zero (never negative).
    pub fn spendable(&self) -> u64 {
        self.available_sats
    }

    /// Checks the expected version against the current version.
    /// Returns `VersionConflict` if they differ.
    pub fn check_version(&self, expected: u64) -> Result<(), LedgerError> {
        if self.version != expected {
            return Err(LedgerError::VersionConflict {
                account: self.account_id.clone(),
                expected,
                current: self.version,
            });
        }
        Ok(())
    }

    /// Applies a credit (increases available balance).
    /// Increments version on success.
    pub fn apply_credit(&mut self, amount: u64) -> Result<(), LedgerError> {
        self.available_sats = self.available_sats.checked_add(amount).ok_or_else(|| {
            LedgerError::InvariantViolation(format!(
                "balance overflow on credit for account {}",
                self.account_id
            ))
        })?;
        self.version += 1;
        Ok(())
    }

    /// Applies a debit (decreases available balance).
    /// Requires sufficient spendable balance.
    /// Increments version on success.
    pub fn apply_debit(&mut self, amount: u64) -> Result<(), LedgerError> {
        if self.spendable() < amount {
            return Err(LedgerError::InsufficientFunds {
                account: self.account_id.clone(),
                available: self.spendable(),
                needed: amount,
            });
        }
        self.available_sats = self.available_sats.checked_sub(amount).ok_or_else(|| {
            LedgerError::InvariantViolation(format!(
                "balance underflow on debit for account {}",
                self.account_id
            ))
        })?;
        self.version += 1;
        Ok(())
    }

    /// Reserves an amount: moves `amount` from available to reserved.
    /// Requires sufficient spendable balance.
    /// Increments version on success.
    pub fn apply_reserve(&mut self, amount: u64) -> Result<(), LedgerError> {
        if self.spendable() < amount {
            return Err(LedgerError::InsufficientFunds {
                account: self.account_id.clone(),
                available: self.spendable(),
                needed: amount,
            });
        }
        self.available_sats = self.available_sats.checked_sub(amount).ok_or_else(|| {
            LedgerError::InvariantViolation(format!(
                "balance underflow on reserve for account {}",
                self.account_id
            ))
        })?;
        self.reserved_sats = self.reserved_sats.checked_add(amount).ok_or_else(|| {
            LedgerError::InvariantViolation(format!(
                "reserved overflow for account {}",
                self.account_id
            ))
        })?;
        self.version += 1;
        Ok(())
    }

    /// Releases a reservation: moves `amount` from reserved back to available.
    /// Increments version on success.
    pub fn apply_release_reservation(&mut self, amount: u64) -> Result<(), LedgerError> {
        if self.reserved_sats < amount {
            return Err(LedgerError::InvariantViolation(format!(
                "cannot release {} from reserved (only {} reserved) for account {}",
                amount, self.reserved_sats, self.account_id
            )));
        }
        self.reserved_sats = self.reserved_sats.checked_sub(amount).ok_or_else(|| {
            LedgerError::InvariantViolation(format!(
                "reserved underflow on release for account {}",
                self.account_id
            ))
        })?;
        self.available_sats = self.available_sats.checked_add(amount).ok_or_else(|| {
            LedgerError::InvariantViolation(format!(
                "available overflow on release for account {}",
                self.account_id
            ))
        })?;
        self.version += 1;
        Ok(())
    }

    /// Consumes a reservation: removes `amount` from reserved without
    /// restoring to available (e.g. external settlement succeeded).
    /// Increments version on success.
    pub fn apply_consume_reservation(&mut self, amount: u64) -> Result<(), LedgerError> {
        if self.reserved_sats < amount {
            return Err(LedgerError::InvariantViolation(format!(
                "cannot consume {} from reserved (only {} reserved) for account {}",
                amount, self.reserved_sats, self.account_id
            )));
        }
        self.reserved_sats = self.reserved_sats.checked_sub(amount).ok_or_else(|| {
            LedgerError::InvariantViolation(format!(
                "reserved underflow on consume for account {}",
                self.account_id
            ))
        })?;
        self.version += 1;
        Ok(())
    }

    /// Sets the last committed sequence number.
    pub fn set_last_committed_sequence(&mut self, sequence: u64) {
        self.last_committed_sequence = sequence;
        self.version += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_version_zero() {
        let acc = AccountState::new("test");
        assert_eq!(acc.version, 0);
        assert_eq!(acc.available_sats, 0);
        assert_eq!(acc.reserved_sats, 0);
        assert_eq!(acc.spendable(), 0);
    }

    #[test]
    fn credit_increases_available_and_version() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(100).unwrap();
        assert_eq!(acc.available_sats, 100);
        assert_eq!(acc.version, 1);
    }

    #[test]
    fn debit_reduces_available() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(100).unwrap();
        acc.apply_debit(40).unwrap();
        assert_eq!(acc.available_sats, 60);
        assert_eq!(acc.version, 2);
    }

    #[test]
    fn debit_fails_on_insufficient_funds() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(50).unwrap();
        let err = acc.apply_debit(100).unwrap_err();
        assert!(matches!(err, LedgerError::InsufficientFunds { .. }));
        assert_eq!(acc.available_sats, 50); // unchanged
    }

    #[test]
    fn debit_fails_when_reserved_consumes_available() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(100).unwrap();
        acc.apply_reserve(80).unwrap();
        // spendable = 20, so debit 30 should fail
        let err = acc.apply_debit(30).unwrap_err();
        assert!(matches!(err, LedgerError::InsufficientFunds { .. }));
        assert_eq!(acc.available_sats, 20); // 100 - 80 reserved
        assert_eq!(acc.reserved_sats, 80);
    }

    #[test]
    fn reserve_moves_to_reserved() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(100).unwrap();
        acc.apply_reserve(60).unwrap();
        assert_eq!(acc.available_sats, 40);
        assert_eq!(acc.reserved_sats, 60);
        assert_eq!(acc.spendable(), 40); // reserved funds excluded from available
        assert_eq!(acc.version, 2);
    }

    #[test]
    fn reserve_fails_when_insufficient() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(30).unwrap();
        let err = acc.apply_reserve(50).unwrap_err();
        assert!(matches!(err, LedgerError::InsufficientFunds { .. }));
        assert_eq!(acc.available_sats, 30);
    }

    #[test]
    fn release_restores_available() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(100).unwrap();
        acc.apply_reserve(60).unwrap();
        acc.apply_release_reservation(30).unwrap();
        assert_eq!(acc.available_sats, 70); // 40 + 30
        assert_eq!(acc.reserved_sats, 30);
        assert_eq!(acc.version, 3);
    }

    #[test]
    fn release_fails_on_excessive_amount() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(100).unwrap();
        acc.apply_reserve(30).unwrap();
        let err = acc.apply_release_reservation(50).unwrap_err();
        assert!(matches!(err, LedgerError::InvariantViolation(_)));
    }

    #[test]
    fn consume_removes_from_reserved() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(100).unwrap();
        acc.apply_reserve(60).unwrap();
        acc.apply_consume_reservation(60).unwrap();
        assert_eq!(acc.available_sats, 40);
        assert_eq!(acc.reserved_sats, 0);
        assert_eq!(acc.version, 3);
    }

    #[test]
    fn consume_fails_on_excessive_amount() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(100).unwrap();
        acc.apply_reserve(30).unwrap();
        let err = acc.apply_consume_reservation(50).unwrap_err();
        assert!(matches!(err, LedgerError::InvariantViolation(_)));
    }

    #[test]
    fn version_conflict_on_mismatch() {
        let mut acc = AccountState::new("test");
        acc.apply_credit(50).unwrap(); // version = 1
        let err = acc.check_version(0).unwrap_err();
        assert!(matches!(err, LedgerError::VersionConflict { .. }));
    }

    #[test]
    fn spendable_saturates_correctly() {
        let mut acc = AccountState::new("test");
        // With no balance, spendable is 0
        assert_eq!(acc.spendable(), 0);
        // With only reserved, spendable is 0 (no available)
        acc.reserved_sats = 100;
        assert_eq!(acc.spendable(), 0);
        // With available > 0 (reserved is excluded from available_sats)
        acc.available_sats = 200;
        assert_eq!(acc.spendable(), 200); // spendable = available_sats
    }

    #[test]
    fn set_last_committed_sequence_increments_version() {
        let mut acc = AccountState::new("test");
        assert_eq!(acc.version, 0);
        acc.set_last_committed_sequence(42);
        assert_eq!(acc.last_committed_sequence, 42);
        assert_eq!(acc.version, 1);
    }
}
