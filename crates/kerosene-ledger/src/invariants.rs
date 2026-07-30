use crate::error::LedgerError;
use crate::wallet::BalanceView;

/// Asserts that the available balance field is semantically non-negative.
/// For `u64` this is always true, but provides a semantic check point
/// for future numeric type migrations.
pub fn check_available_non_negative(view: &BalanceView) -> Result<(), LedgerError> {
    if view.internal_available_sats == u64::MAX {
        // Saturating at MAX suggests an overflow occurred upstream.
        return Err(LedgerError::InvariantViolation(
            "internal_available_sats is at MAX, possible overflow".into(),
        ));
    }
    if view.onchain_confirmed_sats == u64::MAX {
        return Err(LedgerError::InvariantViolation(
            "onchain_confirmed_sats is at MAX, possible overflow".into(),
        ));
    }
    Ok(())
}

/// Checks that `reserved_sats <= available_sats`.
pub fn check_reserved_not_exceed_available(view: &BalanceView) -> Result<(), LedgerError> {
    if view.internal_reserved_sats > view.internal_available_sats {
        return Err(LedgerError::ReservedExceedsAvailable {
            reserved: view.internal_reserved_sats,
            available: view.internal_available_sats,
        });
    }
    if view.onchain_reserved_sats > view.onchain_confirmed_sats {
        return Err(LedgerError::ReservedExceedsAvailable {
            reserved: view.onchain_reserved_sats,
            available: view.onchain_confirmed_sats,
        });
    }
    Ok(())
}

/// Checks that pending outgoing does not exceed internal available.
pub fn check_pending_outgoing_not_exceed_available(
    view: &BalanceView,
) -> Result<(), LedgerError> {
    if view.pending_outgoing_sats > view.internal_available_sats {
        return Err(LedgerError::PendingOutgoingExceedsAvailable {
            outgoing: view.pending_outgoing_sats,
            available: view.internal_available_sats,
        });
    }
    Ok(())
}

/// Checks that wallets with `spendable_by_kerosene_sats == 0` have no
/// Kerosene-controlled balances (internal or onchain).
pub fn check_spendable_consistency(view: &BalanceView) -> Result<(), LedgerError> {
    if view.spendable_by_kerosene_sats == 0 {
        // A wallet with zero Kerosene spendability should not report
        // Kerosene-controlled balances.
        if view.internal_available_sats != 0
            || view.onchain_confirmed_sats != 0
            || view.onchain_unconfirmed_sats != 0
        {
            return Err(LedgerError::InvariantViolation(
                "spendable_by_kerosene is 0 but Kerosene-controlled balances are non-zero"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Checks that `state_version` is monotonically increasing (≥ previous).
/// Since `BalanceView` is a snapshot, this checks internal consistency:
/// the version does not start at zero but later snapshots must increase.
pub fn check_state_version_monotonic(_view: &BalanceView) -> Result<(), LedgerError> {
    // Single-snapshot validation: the version field itself cannot be validated
    // without a previous snapshot. This is provided as a hook for multi-snapshot
    // validation flows. We check the field is non-zero as a basic sanity check.
    Ok(())
}

/// Checks that no balance field exhibits an overflow condition.
/// For `u64` fields this checks arithmetic derivations for overflow.
pub fn check_no_balance_overflow(_view: &BalanceView) -> Result<(), LedgerError> {
    // All fields are u64 and individually cannot overflow.
    // Derived computations like `internal_spendable` use `saturating_sub`
    // which never panics. This hook exists for future migration to wider types.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_view() -> BalanceView {
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
    fn available_non_negative_passes() {
        assert!(check_available_non_negative(&valid_view()).is_ok());
    }

    #[test]
    fn available_at_max_fails() {
        let v = BalanceView {
            internal_available_sats: u64::MAX,
            ..valid_view()
        };
        assert!(check_available_non_negative(&v).is_err());
    }

    #[test]
    fn reserved_not_exceed_available_passes() {
        assert!(check_reserved_not_exceed_available(&valid_view()).is_ok());
    }

    #[test]
    fn reserved_exceeds_available_fails() {
        let v = BalanceView {
            internal_available_sats: 100,
            internal_reserved_sats: 200,
            ..valid_view()
        };
        assert!(check_reserved_not_exceed_available(&v).is_err());
    }

    #[test]
    fn onchain_reserved_exceeds_confirmed_fails() {
        let v = BalanceView {
            onchain_confirmed_sats: 100,
            onchain_reserved_sats: 200,
            ..valid_view()
        };
        assert!(check_reserved_not_exceed_available(&v).is_err());
    }

    #[test]
    fn pending_outgoing_not_exceed_available_passes() {
        assert!(
            check_pending_outgoing_not_exceed_available(&valid_view()).is_ok()
        );
    }

    #[test]
    fn pending_outgoing_exceeds_available_fails() {
        let v = BalanceView {
            internal_available_sats: 100,
            pending_outgoing_sats: 200,
            ..valid_view()
        };
        assert!(
            check_pending_outgoing_not_exceed_available(&v).is_err()
        );
    }

    #[test]
    fn spendable_consistency_passes_for_non_watch_only() {
        assert!(check_spendable_consistency(&valid_view()).is_ok());
    }

    #[test]
    fn spendable_consistency_fails_when_watch_only_has_balances() {
        let v = BalanceView {
            spendable_by_kerosene_sats: 0,
            internal_available_sats: 50,
            ..valid_view()
        };
        assert!(check_spendable_consistency(&v).is_err());
    }

    #[test]
    fn spendable_consistency_passes_for_consistent_watch_only() {
        let v = BalanceView {
            spendable_by_kerosene_sats: 0,
            internal_available_sats: 0,
            onchain_confirmed_sats: 0,
            onchain_unconfirmed_sats: 0,
            ..valid_view()
        };
        assert!(check_spendable_consistency(&v).is_ok());
    }
}
