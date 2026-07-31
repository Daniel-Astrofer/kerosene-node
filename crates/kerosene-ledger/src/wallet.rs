use serde::{Deserialize, Serialize};

/// Describes how the wallet's keys and funds are controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WalletControl {
    /// Internal platform ledger balance (no on-chain wallet)
    InternalLedger,
    /// Hot wallet custodied by Kerosene
    CustodiedHot,
    /// Cold wallet custodied by Kerosene
    CustodiedCold,
    /// External wallet that is only observed, keys not held by Kerosene
    ExternalWatchOnly,
    /// External wallet whose keys are fully controlled by the user
    ExternalUserControlled,
}

/// A snapshot of all balance components for a single wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceView {
    /// Internal ledger balance available (not reserved)
    pub internal_available_sats: u64,
    /// Internal ledger balance reserved
    pub internal_reserved_sats: u64,
    /// On-chain confirmed balance
    pub onchain_confirmed_sats: u64,
    /// On-chain unconfirmed balance
    pub onchain_unconfirmed_sats: u64,
    /// On-chain reserved (e.g. UTXOs locked for signing)
    pub onchain_reserved_sats: u64,
    /// Incoming transfers not yet settled
    pub pending_incoming_sats: u64,
    /// Outgoing transfers not yet settled
    pub pending_outgoing_sats: u64,
    /// Balance controlled externally (user-controlled wallets only)
    pub externally_controlled_sats: u64,
    /// Effective balance that Kerosene can spend or move
    pub spendable_by_kerosene_sats: u64,
    /// Monotonically increasing version counter
    pub state_version: u64,
    /// Merkle-style state root hash
    pub state_root: String,
}

impl BalanceView {
    /// Returns the spendable balance for an internal-ledger wallet:
    /// `internal_available_sats - internal_reserved_sats`.
    pub fn internal_spendable(&self) -> u64 {
        self.internal_available_sats
            .saturating_sub(self.internal_reserved_sats)
    }

    /// Returns the spendable balance for a custodied wallet:
    /// `min(internal_spendable(), onchain_confirmed - onchain_reserved)`.
    pub fn custodied_spendable(&self) -> u64 {
        std::cmp::min(
            self.internal_spendable(),
            self.onchain_confirmed_sats
                .saturating_sub(self.onchain_reserved_sats),
        )
    }

    /// Returns `true` when `spendable_by_kerosene_sats` is zero,
    /// indicating a watch-only or fully user-controlled wallet.
    pub fn is_watch_only(&self) -> bool {
        self.spendable_by_kerosene_sats == 0
    }

    /// Validates all balance invariants.
    pub fn validate(&self) -> Result<(), crate::LedgerError> {
        crate::invariants::check_available_non_negative(self)?;
        crate::invariants::check_reserved_not_exceed_available(self)?;
        crate::invariants::check_pending_outgoing_not_exceed_available(self)?;
        crate::invariants::check_spendable_consistency(self)?;
        crate::invariants::check_state_version_monotonic(self)?;
        crate::invariants::check_no_balance_overflow(self)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_balance() -> BalanceView {
        BalanceView {
            internal_available_sats: 100_000,
            internal_reserved_sats: 10_000,
            onchain_confirmed_sats: 200_000,
            onchain_unconfirmed_sats: 5_000,
            onchain_reserved_sats: 20_000,
            pending_incoming_sats: 1_000,
            pending_outgoing_sats: 500,
            externally_controlled_sats: 0,
            spendable_by_kerosene_sats: 90_000,
            state_version: 1,
            state_root: "abc".into(),
        }
    }

    #[test]
    fn internal_spendable_subtracts_reserved() {
        let b = sample_balance();
        assert_eq!(b.internal_spendable(), 90_000);
    }

    #[test]
    fn internal_spendable_saturates_at_zero() {
        let b = BalanceView {
            internal_available_sats: 100,
            internal_reserved_sats: 200,
            ..sample_balance()
        };
        assert_eq!(b.internal_spendable(), 0);
    }

    #[test]
    fn custodied_spendable_is_min_of_both() {
        let b = sample_balance();
        // internal_spendable = 90_000, onchain confirmed - reserved = 180_000
        assert_eq!(b.custodied_spendable(), 90_000);
    }

    #[test]
    fn watch_only_detection() {
        let b = BalanceView {
            spendable_by_kerosene_sats: 0,
            ..sample_balance()
        };
        assert!(b.is_watch_only());
    }

    #[test]
    fn not_watch_only_when_spendable_positive() {
        assert!(!sample_balance().is_watch_only());
    }

    #[test]
    fn validate_passes_for_valid_balance() {
        let b = sample_balance();
        assert!(b.validate().is_ok());
    }

    #[test]
    fn validate_fails_when_reserved_exceeds_available() {
        let b = BalanceView {
            internal_available_sats: 100,
            internal_reserved_sats: 200,
            ..sample_balance()
        };
        assert!(b.validate().is_err());
    }

    #[test]
    fn validate_fails_when_pending_outgoing_exceeds_available() {
        let b = BalanceView {
            internal_available_sats: 100,
            pending_outgoing_sats: 200,
            ..sample_balance()
        };
        assert!(b.validate().is_err());
    }
}
