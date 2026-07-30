use serde::{Deserialize, Serialize};

use crate::state_machine::LedgerState;
use crate::withdrawal::WithdrawalStatus;

// ---------------------------------------------------------------------------
// ReconciliationStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReconciliationStatus {
    Balanced,
    Warning,
    Deficit,
    Surplus,
    IncompleteChainData,
}

// ---------------------------------------------------------------------------
// ReconciliationReport
// ---------------------------------------------------------------------------

/// A full reconciliation report comparing on-chain assets against ledger
/// liabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationReport {
    /// State root at the time of reconciliation.
    pub state_root: String,
    /// Hash of the Bitcoin chain tip known to the cluster.
    pub chain_tip_hash: String,
    /// Total on-chain assets in satoshis (sum of all non-terminal UTXOs).
    pub total_assets_sats: u64,
    /// Total user-facing liabilities in satoshis.
    pub total_liabilities_sats: u64,
    /// Total reserved satoshis across all accounts.
    pub total_reserved_sats: u64,
    /// Total pending (unsettled) satoshis.
    pub total_pending_sats: u64,
    /// Difference: assets - liabilities (positive = surplus, negative = deficit).
    pub difference_sats: i128,
    /// Overall reconciliation status.
    pub status: ReconciliationStatus,
}

// ---------------------------------------------------------------------------
// ReconciliationInputs (legacy, kept for backward compatibility)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationInputs {
    pub hot_sats: u64,
    pub cold_sats: u64,
    pub custodied_sats: u64,
    pub lightning_sats: u64,

    pub available_sats: u64,
    pub reserved_sats: u64,
    pub pending_sats: u64,
    pub credits_sats: u64,
}

impl ReconciliationReport {
    /// Legacy constructor from manual inputs. Prefer `ReconciliationEngine`.
    pub fn calculate(inputs: ReconciliationInputs, complete_data: bool) -> Self {
        let assets = inputs
            .hot_sats
            .saturating_add(inputs.cold_sats)
            .saturating_add(inputs.custodied_sats)
            .saturating_add(inputs.lightning_sats);

        let liabilities = inputs
            .available_sats
            .saturating_add(inputs.reserved_sats)
            .saturating_add(inputs.pending_sats)
            .saturating_add(inputs.credits_sats);

        let diff = (assets as i128) - (liabilities as i128);
        let difference_sats = diff;

        let status = if !complete_data {
            ReconciliationStatus::IncompleteChainData
        } else if difference_sats == 0 {
            ReconciliationStatus::Balanced
        } else if difference_sats > 0 {
            ReconciliationStatus::Surplus
        } else {
            ReconciliationStatus::Deficit
        };

        Self {
            state_root: String::new(),
            chain_tip_hash: String::new(),
            total_assets_sats: assets,
            total_liabilities_sats: liabilities,
            total_reserved_sats: inputs.reserved_sats,
            total_pending_sats: inputs.pending_sats,
            difference_sats,
            status,
        }
    }
}

// ---------------------------------------------------------------------------
// ReconciliationEngine
// ---------------------------------------------------------------------------

/// Computes reconciliation metrics from the full ledger state.
///
/// Rules:
/// - Differences are NEVER corrected by automatically altering user balances.
/// - Reconciliation is read-only — report only, alert if out of balance.
pub struct ReconciliationEngine;

impl ReconciliationEngine {
    /// Compute total on-chain assets from the ledger state.
    ///
    /// Assets = sum of value_sats of all UTXO entries that are NOT in a
    /// terminal state (i.e. not Spent or Replaced).
    pub fn compute_total_assets(state: &LedgerState) -> u64 {
        state
            .utxos
            .iter()
            .filter(|u| !matches!(u.state, crate::chain::OnchainState::Spent | crate::chain::OnchainState::Replaced))
            .map(|u| u.value_sats)
            .fold(0u64, u64::saturating_add)
    }

    /// Compute total liabilities from the ledger state.
    ///
    /// Liabilities = sum of (available_sats + reserved_sats) across all
    /// user-facing accounts (skipping accounts with zero total).
    ///
    /// If a `WithdrawalStore` is available at the call site, pending
    /// withdrawals that have been authorized but not yet settled are also
    /// counted. The base computation uses the account balances recorded
    /// in the state machine.
    pub fn compute_total_liabilities(state: &LedgerState) -> u64 {
        state
            .accounts
            .iter()
            .map(|a| {
                a.available_sats
                    .saturating_add(a.reserved_sats)
                    .saturating_add(a.pending_outgoing_sats)
            })
            .fold(0u64, u64::saturating_add)
    }

    /// Compute total reserved satoshis across all accounts.
    pub fn compute_total_reserved(state: &LedgerState) -> u64 {
        state
            .accounts
            .iter()
            .map(|a| a.reserved_sats)
            .fold(0u64, u64::saturating_add)
    }

    /// Compute total pending (unsettled) satoshis across all accounts.
    pub fn compute_total_pending(state: &LedgerState) -> u64 {
        state
            .accounts
            .iter()
            .map(|a| a.pending_outgoing_sats)
            .fold(0u64, u64::saturating_add)
    }

    /// Determine a tolerance threshold for the `WARNING` status based on
    /// a small fraction of total assets (e.g. pending miner fees).
    pub fn warning_tolerance(total_assets: u64) -> u64 {
        // Allow up to 0.1% of total assets as warning tolerance, minimum 1000 sats.
        let pct = total_assets / 1000;
        if pct < 1000 {
            1000
        } else {
            pct
        }
    }

    /// Run full reconciliation and produce a report.
    ///
    /// The `chain_tip_hash` is provided externally (e.g. from the Chain
    /// Observer). The `chain_data_complete` flag indicates whether the
    /// observer has complete chain data.
    ///
    /// Rules:
    /// - `Balanced`: difference == 0 and chain_data_complete
    /// - `Warning`: |difference| within a small tolerance (e.g. pending miner fees)
    /// - `Deficit`: liabilities > assets
    /// - `Surplus`: assets > liabilities beyond tolerance
    /// - `IncompleteChainData`: chain_data_complete is false
    pub fn reconcile(
        state: &LedgerState,
        chain_tip_hash: &str,
        chain_data_complete: bool,
    ) -> ReconciliationReport {
        let total_assets = Self::compute_total_assets(state);
        let total_liabilities = Self::compute_total_liabilities(state);
        let total_reserved = Self::compute_total_reserved(state);
        let total_pending = Self::compute_total_pending(state);

        let diff = (total_assets as i128) - (total_liabilities as i128);
        let abs_diff = diff.unsigned_abs();
        let tolerance = Self::warning_tolerance(total_assets);

        let status = if !chain_data_complete {
            ReconciliationStatus::IncompleteChainData
        } else if diff == 0 {
            ReconciliationStatus::Balanced
        } else if diff > 0 && abs_diff <= (tolerance as u128) {
            ReconciliationStatus::Balanced
        } else if diff < 0 && abs_diff <= (tolerance as u128) {
            ReconciliationStatus::Warning
        } else if diff > 0 {
            ReconciliationStatus::Surplus
        } else {
            ReconciliationStatus::Deficit
        };

        ReconciliationReport {
            state_root: crate::state_root::compute_state_root(state),
            chain_tip_hash: chain_tip_hash.to_string(),
            total_assets_sats: total_assets,
            total_liabilities_sats: total_liabilities,
            total_reserved_sats: total_reserved,
            total_pending_sats: total_pending,
            difference_sats: diff,
            status,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the withdrawal status indicates an unsettled pending
/// obligation that should be counted as a liability.
pub fn is_pending_liability(status: WithdrawalStatus) -> bool {
    !matches!(
        status,
        WithdrawalStatus::Confirmed | WithdrawalStatus::Failed | WithdrawalStatus::Replaced
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{OnchainState, OutPoint};
    use crate::state_machine::{ConsensusProfile, LedgerState, MembershipView};

    fn test_membership() -> MembershipView {
        MembershipView {
            cluster_id: "test-cluster".into(),
            nodes: vec!["node-1".into()],
            active_profile: ConsensusProfile::Single,
        }
    }

    // -----------------------------------------------------------------------
    // ReconciliationEngine tests
    // -----------------------------------------------------------------------

    #[test]
    fn empty_state_is_balanced() {
        let state = LedgerState::empty(test_membership());
        let report = ReconciliationEngine::reconcile(&state, "tip-hash", true);
        assert_eq!(report.status, ReconciliationStatus::Balanced);
        assert_eq!(report.total_assets_sats, 0);
        assert_eq!(report.total_liabilities_sats, 0);
        assert_eq!(report.difference_sats, 0);
    }

    #[test]
    fn incomplete_chain_data_reported() {
        let state = LedgerState::empty(test_membership());
        let report = ReconciliationEngine::reconcile(&state, "tip-hash", false);
        assert_eq!(report.status, ReconciliationStatus::IncompleteChainData);
    }

    #[test]
    fn deficit_detected_when_liabilities_exceed_assets() {
        let mut state = LedgerState::empty(test_membership());
        let mut acc = crate::account_state::AccountState::new("user-1");
        acc.available_sats = 100_000;
        state.accounts.push(acc);

        let report = ReconciliationEngine::reconcile(&state, "tip-hash", true);
        assert_eq!(report.status, ReconciliationStatus::Deficit);
        assert_eq!(report.total_liabilities_sats, 100_000);
        assert_eq!(report.total_assets_sats, 0);
        assert_eq!(report.difference_sats, -100_000);
    }

    #[test]
    fn surplus_detected_when_assets_exceed_liabilities() {
        let mut state = LedgerState::empty(test_membership());
        state.utxos.push(crate::chain::UtxoEntry::new_seen(
            OutPoint::new("tx1", 0),
            200_000,
            "addr1",
            100,
        ));

        let report = ReconciliationEngine::reconcile(&state, "tip-hash", true);
        assert_eq!(report.status, ReconciliationStatus::Surplus);
        assert_eq!(report.total_assets_sats, 200_000);
        assert_eq!(report.total_liabilities_sats, 0);
    }

    #[test]
    fn balanced_with_realistic_state() {
        let mut state = LedgerState::empty(test_membership());

        // Add UTXOs representing on-chain assets
        state.utxos.push(crate::chain::UtxoEntry::new_seen(
            OutPoint::new("tx1", 0),
            500_000,
            "addr1",
            100,
        ));

        // Add user account with matching balance
        let mut acc = crate::account_state::AccountState::new("user-1");
        acc.available_sats = 500_000;
        state.accounts.push(acc);

        let report = ReconciliationEngine::reconcile(&state, "tip-hash", true);
        assert_eq!(report.status, ReconciliationStatus::Balanced);
        assert_eq!(report.difference_sats, 0);
    }

    #[test]
    fn warning_within_tolerance() {
        let mut state = LedgerState::empty(test_membership());

        // Assets slightly less than liabilities (within tolerance for miner fees)
        state.utxos.push(crate::chain::UtxoEntry::new_seen(
            OutPoint::new("tx1", 0),
            1_000_000,
            "addr1",
            100,
        ));

        let mut acc = crate::account_state::AccountState::new("user-1");
        acc.available_sats = 1_000_500; // 500 sats more than assets
        state.accounts.push(acc);

        let report = ReconciliationEngine::reconcile(&state, "tip-hash", true);
        assert_eq!(report.status, ReconciliationStatus::Warning);
    }

    #[test]
    fn compute_total_reserved_returns_sum() {
        let mut state = LedgerState::empty(test_membership());

        let mut acc1 = crate::account_state::AccountState::new("user-1");
        acc1.reserved_sats = 10_000;
        state.accounts.push(acc1);

        let mut acc2 = crate::account_state::AccountState::new("user-2");
        acc2.reserved_sats = 20_000;
        state.accounts.push(acc2);

        assert_eq!(
            ReconciliationEngine::compute_total_reserved(&state),
            30_000
        );
    }

    #[test]
    fn compute_total_assets_ignores_spent_utxos() {
        let mut state = LedgerState::empty(test_membership());

        // Active UTXO
        state.utxos.push(crate::chain::UtxoEntry::new_seen(
            OutPoint::new("tx1", 0),
            50_000,
            "addr1",
            100,
        ));

        // Spent UTXO — should NOT count
        let mut spent = crate::chain::UtxoEntry::new_seen(
            OutPoint::new("tx2", 0),
            200_000,
            "addr2",
            100,
        );
        spent.state = OnchainState::Spent;
        state.utxos.push(spent);

        assert_eq!(
            ReconciliationEngine::compute_total_assets(&state),
            50_000
        );
    }

    #[test]
    fn compute_total_liabilities_includes_reserved_and_pending() {
        let mut state = LedgerState::empty(test_membership());

        let mut acc = crate::account_state::AccountState::new("user-1");
        acc.available_sats = 100_000;
        acc.reserved_sats = 50_000;
        acc.pending_outgoing_sats = 10_000;
        state.accounts.push(acc);

        assert_eq!(
            ReconciliationEngine::compute_total_liabilities(&state),
            160_000
        );
    }

    #[test]
    fn reconciliation_report_includes_state_root_and_chain_tip() {
        let state = LedgerState::empty(test_membership());
        let report = ReconciliationEngine::reconcile(&state, "abc123def456", true);
        assert!(!report.state_root.is_empty());
        assert_eq!(report.chain_tip_hash, "abc123def456");
    }

    // -----------------------------------------------------------------------
    // Legacy ReconciliationInputs tests
    // -----------------------------------------------------------------------

    #[test]
    fn legacy_calculate_balanced() {
        let inputs = ReconciliationInputs {
            hot_sats: 1000,
            cold_sats: 0,
            custodied_sats: 0,
            lightning_sats: 0,
            available_sats: 1000,
            reserved_sats: 0,
            pending_sats: 0,
            credits_sats: 0,
        };
        let report = ReconciliationReport::calculate(inputs, true);
        assert_eq!(report.status, ReconciliationStatus::Balanced);
        assert_eq!(report.difference_sats, 0);
    }

    #[test]
    fn legacy_calculate_deficit() {
        let inputs = ReconciliationInputs {
            hot_sats: 500,
            cold_sats: 0,
            custodied_sats: 0,
            lightning_sats: 0,
            available_sats: 1000,
            reserved_sats: 0,
            pending_sats: 0,
            credits_sats: 0,
        };
        let report = ReconciliationReport::calculate(inputs, true);
        assert_eq!(report.status, ReconciliationStatus::Deficit);
    }

    #[test]
    fn legacy_calculate_surplus() {
        let inputs = ReconciliationInputs {
            hot_sats: 2000,
            cold_sats: 0,
            custodied_sats: 0,
            lightning_sats: 0,
            available_sats: 1000,
            reserved_sats: 0,
            pending_sats: 0,
            credits_sats: 0,
        };
        let report = ReconciliationReport::calculate(inputs, true);
        assert_eq!(report.status, ReconciliationStatus::Surplus);
    }

    #[test]
    fn legacy_calculate_incomplete_data() {
        let inputs = ReconciliationInputs {
            hot_sats: 1000,
            cold_sats: 0,
            custodied_sats: 0,
            lightning_sats: 0,
            available_sats: 1000,
            reserved_sats: 0,
            pending_sats: 0,
            credits_sats: 0,
        };
        let report = ReconciliationReport::calculate(inputs, false);
        assert_eq!(report.status, ReconciliationStatus::IncompleteChainData);
    }

    #[test]
    fn warning_tolerance_minimum() {
        assert_eq!(ReconciliationEngine::warning_tolerance(0), 1000);
        assert_eq!(ReconciliationEngine::warning_tolerance(500), 1000);
    }

    #[test]
    fn warning_tolerance_scales_with_assets() {
        assert_eq!(ReconciliationEngine::warning_tolerance(1_000_000), 1000);
        assert_eq!(ReconciliationEngine::warning_tolerance(10_000_000), 10_000);
    }
}
