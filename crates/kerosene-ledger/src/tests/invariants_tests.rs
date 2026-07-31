use crate::invariants::{
    check_available_non_negative, check_no_balance_overflow,
    check_pending_outgoing_not_exceed_available, check_reserved_not_exceed_available,
    check_spendable_consistency, check_state_version_monotonic,
};
use crate::wallet::BalanceView;

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
fn test_available_non_negative_passes() {
    assert!(check_available_non_negative(&valid_view()).is_ok());
}

#[test]
fn test_available_non_negative_detects_internal_overflow() {
    let view = BalanceView {
        internal_available_sats: u64::MAX,
        ..valid_view()
    };
    assert!(check_available_non_negative(&view).is_err());
}

#[test]
fn test_available_non_negative_detects_onchain_overflow() {
    let view = BalanceView {
        onchain_confirmed_sats: u64::MAX,
        ..valid_view()
    };
    assert!(check_available_non_negative(&view).is_err());
}

#[test]
fn test_reserved_not_exceed_available_passes() {
    assert!(check_reserved_not_exceed_available(&valid_view()).is_ok());
}

#[test]
fn test_reserved_exceeds_available_fails() {
    let view = BalanceView {
        internal_available_sats: 50,
        internal_reserved_sats: 100,
        ..valid_view()
    };
    assert!(check_reserved_not_exceed_available(&view).is_err());
}

#[test]
fn test_onchain_reserved_exceeds_confirmed_fails() {
    let view = BalanceView {
        onchain_confirmed_sats: 50,
        onchain_reserved_sats: 100,
        ..valid_view()
    };
    assert!(check_reserved_not_exceed_available(&view).is_err());
}

#[test]
fn test_pending_outgoing_not_exceed_available_passes() {
    assert!(check_pending_outgoing_not_exceed_available(&valid_view()).is_ok());
}

#[test]
fn test_pending_outgoing_exceeds_available_fails() {
    let view = BalanceView {
        internal_available_sats: 10,
        pending_outgoing_sats: 20,
        ..valid_view()
    };
    assert!(check_pending_outgoing_not_exceed_available(&view).is_err());
}

#[test]
fn test_spendable_consistency_passes_for_non_watch_only() {
    assert!(check_spendable_consistency(&valid_view()).is_ok());
}

#[test]
fn test_spendable_consistency_passes_for_consistent_watch_only() {
    let view = BalanceView {
        spendable_by_kerosene_sats: 0,
        internal_available_sats: 0,
        onchain_confirmed_sats: 0,
        onchain_unconfirmed_sats: 0,
        ..valid_view()
    };
    assert!(check_spendable_consistency(&view).is_ok());
}

#[test]
fn test_spendable_consistency_fails_when_watch_only_has_balances() {
    let view = BalanceView {
        spendable_by_kerosene_sats: 0,
        internal_available_sats: 100,
        ..valid_view()
    };
    assert!(check_spendable_consistency(&view).is_err());
}

#[test]
fn test_state_version_monotonic_does_not_fail() {
    assert!(check_state_version_monotonic(&valid_view()).is_ok());
}

#[test]
fn test_no_balance_overflow_does_not_fail() {
    assert!(check_no_balance_overflow(&valid_view()).is_ok());
}

#[test]
fn test_validate_passes_on_valid_balance() {
    assert!(valid_view().validate().is_ok());
}

#[test]
fn test_validate_fails_on_invalid_reserved() {
    let view = BalanceView {
        internal_available_sats: 10,
        internal_reserved_sats: 100,
        ..valid_view()
    };
    assert!(view.validate().is_err());
}
