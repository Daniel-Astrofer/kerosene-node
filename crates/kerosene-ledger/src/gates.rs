use serde::{Deserialize, Serialize};

use crate::metrics::LedgerMetrics;
use crate::reconciliation::ReconciliationReport;
use crate::replication::{ReplicationStatus, SyncStatus};
use crate::state_machine::MembershipView;

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// The result of evaluating a production gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Whether the operation is allowed.
    pub allowed: bool,
    /// Human-readable reasons why the gate blocked (empty if allowed).
    pub reasons: Vec<String>,
}

impl GateResult {
    /// Creates a successful (allowed) gate result.
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            reasons: Vec::new(),
        }
    }

    /// Creates a blocked gate result with one or more reasons.
    pub fn blocked(reasons: Vec<String>) -> Self {
        Self {
            allowed: false,
            reasons,
        }
    }
}

// ---------------------------------------------------------------------------
// DegradedMode
// ---------------------------------------------------------------------------

/// The current operational mode of the cluster.
///
/// Gates are fail-closed: if a condition cannot be determined, the
/// operation is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DegradedMode {
    /// Full operation — all gates pass (when their specific conditions are met).
    Normal,
    /// Some operations are blocked by default.
    Degraded {
        /// Are withdrawals blocked?
        withdrawals_blocked: bool,
        /// Are membership changes blocked?
        membership_changes_blocked: bool,
        /// Is key rotation blocked?
        key_rotation_blocked: bool,
        /// Are internal transfers still allowed?
        internal_transfers_allowed: bool,
        /// Are credit operations still allowed?
        credits_allowed: bool,
    },
    /// Only read operations are allowed.
    ReadOnly,
}

impl DegradedMode {
    /// Returns `true` if withdrawals are allowed under this mode.
    pub fn withdrawals_allowed(&self) -> bool {
        match self {
            DegradedMode::Normal => true,
            DegradedMode::Degraded {
                withdrawals_blocked,
                ..
            } => !withdrawals_blocked,
            DegradedMode::ReadOnly => false,
        }
    }

    /// Returns `true` if internal transfers are allowed under this mode.
    pub fn internal_transfers_allowed(&self) -> bool {
        match self {
            DegradedMode::Normal => true,
            DegradedMode::Degraded {
                internal_transfers_allowed,
                ..
            } => *internal_transfers_allowed,
            DegradedMode::ReadOnly => false,
        }
    }

    /// Returns `true` if credit operations are allowed under this mode.
    pub fn credits_allowed(&self) -> bool {
        match self {
            DegradedMode::Normal => true,
            DegradedMode::Degraded {
                credits_allowed, ..
            } => *credits_allowed,
            DegradedMode::ReadOnly => false,
        }
    }
}

// ---------------------------------------------------------------------------
// ProductionGates
// ---------------------------------------------------------------------------

/// Production gates that must pass before certain operations are allowed.
///
/// Gates are **fail-closed**: if any condition cannot be determined or the
/// cluster is in an unhealthy state, the operation is blocked.
///
/// These gates are the last line of defence before critical operations
/// (withdrawals, deposits, membership changes, key rotation) are permitted.
pub struct ProductionGates;

impl ProductionGates {
    /// Can the cluster authorize withdrawals?
    ///
    /// Blocked if:
    /// - Sync is not healthy
    /// - Quorum is unavailable
    /// - Reconciliation shows a deficit
    /// - Node is diverged or quarantined
    /// - Sequence lag exceeds a threshold
    pub fn can_authorize_withdrawals(
        metrics: &LedgerMetrics,
        report: &ReconciliationReport,
        status: &ReplicationStatus,
    ) -> GateResult {
        let mut reasons = Vec::new();

        // Sync health
        if status.sync_status != SyncStatus::Healthy {
            reasons.push(format!(
                "sync status is {:?}, must be Healthy",
                status.sync_status
            ));
        }

        // Sequence lag
        if metrics.sequence_lag > 0 {
            reasons.push(format!(
                "sequence lag is {}, must be 0",
                metrics.sequence_lag
            ));
        }

        // Reconciliation
        use crate::reconciliation::ReconciliationStatus::*;
        match report.status {
            Balanced | Warning | Surplus => { /* allowed from financial safety perspective */ }
            Deficit => {
                reasons.push(format!(
                    "reconciliation deficit: {} sats",
                    report.difference_sats
                ));
            }
            IncompleteChainData => {
                reasons.push("reconciliation data is incomplete".into());
            }
        }

        // Quorum availability (inferred from sync status)
        if status.committed_sequence == 0
            && status.applied_sequence == 0
            && metrics.quorum_unavailable_total > 0
        {
            reasons.push("quorum appears unavailable".into());
        }

        if reasons.is_empty() {
            GateResult::allowed()
        } else {
            GateResult::blocked(reasons)
        }
    }

    /// Can the cluster accept deposits?
    ///
    /// Blocked if:
    /// - Sync is not healthy (Diverged / Quarantined)
    /// - Node is significantly behind
    pub fn can_accept_deposits(metrics: &LedgerMetrics, status: &ReplicationStatus) -> GateResult {
        let mut reasons = Vec::new();

        // Sync health
        if matches!(
            status.sync_status,
            SyncStatus::Diverged | SyncStatus::Quarantined
        ) {
            reasons.push(format!(
                "sync status is {:?}, cannot accept deposits",
                status.sync_status
            ));
        }

        // Sequence lag threshold — large lags risk incorrect deposit attribution
        if metrics.sequence_lag > 100 {
            reasons.push(format!(
                "sequence lag {} exceeds threshold for deposits",
                metrics.sequence_lag
            ));
        }

        if reasons.is_empty() {
            GateResult::allowed()
        } else {
            GateResult::blocked(reasons)
        }
    }

    /// Can new nodes join the cluster?
    ///
    /// Blocked if:
    /// - Sync is not healthy on this node
    /// - Membership is full (arbitrary safety limit)
    pub fn can_add_nodes(
        _metrics: &LedgerMetrics,
        status: &ReplicationStatus,
        membership: &MembershipView,
    ) -> GateResult {
        let mut reasons = Vec::new();

        if status.sync_status != SyncStatus::Healthy {
            reasons.push(format!(
                "sync status is {:?}, must be Healthy to add nodes",
                status.sync_status
            ));
        }

        // Safety limit: prevent unbounded membership growth
        if membership.nodes.len() >= 100 {
            reasons.push(format!(
                "membership size {} exceeds safety limit",
                membership.nodes.len()
            ));
        }

        if reasons.is_empty() {
            GateResult::allowed()
        } else {
            GateResult::blocked(reasons)
        }
    }

    /// Can the cluster change membership configuration?
    ///
    /// Blocked if sync is not healthy or the node cannot vote.
    pub fn can_change_membership(status: &ReplicationStatus) -> GateResult {
        let mut reasons = Vec::new();

        if status.sync_status != SyncStatus::Healthy {
            reasons.push(format!(
                "sync status is {:?}, must be Healthy to change membership",
                status.sync_status
            ));
        }

        if status.applied_sequence != status.committed_sequence {
            reasons.push(format!(
                "applied sequence {} != committed sequence {}",
                status.applied_sequence, status.committed_sequence
            ));
        }

        if reasons.is_empty() {
            GateResult::allowed()
        } else {
            GateResult::blocked(reasons)
        }
    }

    /// Can keys be rotated?
    ///
    /// Blocked if sync is not healthy — key rotation requires full cluster
    /// participation.
    pub fn can_rotate_keys(status: &ReplicationStatus) -> GateResult {
        let mut reasons = Vec::new();

        if status.sync_status != SyncStatus::Healthy {
            reasons.push(format!(
                "sync status is {:?}, must be Healthy to rotate keys",
                status.sync_status
            ));
        }

        if status.applied_sequence != status.committed_sequence {
            reasons.push(format!(
                "applied sequence {} != committed sequence {}",
                status.applied_sequence, status.committed_sequence
            ));
        }

        if reasons.is_empty() {
            GateResult::allowed()
        } else {
            GateResult::blocked(reasons)
        }
    }

    /// Evaluate all gates and return the appropriate degraded mode.
    ///
    /// This is a convenience method for determining the cluster's
    /// operational envelope from a single call.
    pub fn evaluate_degraded_mode(
        metrics: &LedgerMetrics,
        report: &ReconciliationReport,
        status: &ReplicationStatus,
        membership: &MembershipView,
    ) -> DegradedMode {
        let withdrawals_gate = Self::can_authorize_withdrawals(metrics, report, status);
        let deposits_gate = Self::can_accept_deposits(metrics, status);
        let membership_gate = Self::can_change_membership(status);
        let key_rotation_gate = Self::can_rotate_keys(status);
        let add_nodes_gate = Self::can_add_nodes(metrics, status, membership);

        let withdrawals_blocked = !withdrawals_gate.allowed;
        let membership_changes_blocked = !membership_gate.allowed;
        let key_rotation_blocked = !key_rotation_gate.allowed;

        if !withdrawals_gate.allowed || !deposits_gate.allowed || !membership_gate.allowed {
            DegradedMode::Degraded {
                withdrawals_blocked,
                membership_changes_blocked,
                key_rotation_blocked,
                internal_transfers_allowed: true,
                credits_allowed: true,
            }
        } else if !add_nodes_gate.allowed {
            DegradedMode::Degraded {
                withdrawals_blocked: false,
                membership_changes_blocked,
                key_rotation_blocked,
                internal_transfers_allowed: true,
                credits_allowed: true,
            }
        } else {
            DegradedMode::Normal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconciliation::ReconciliationEngine;
    use crate::replication::ReplicationStatus;
    use crate::state_machine::{ConsensusProfile, LedgerState, MembershipView};

    fn healthy_status() -> ReplicationStatus {
        ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 42,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::Healthy,
        }
    }

    fn balanced_report() -> ReconciliationReport {
        let state = LedgerState::empty(test_membership());
        ReconciliationEngine::reconcile(&state, "tip", true)
    }

    fn test_membership() -> MembershipView {
        MembershipView {
            cluster_id: "test-cluster".into(),
            nodes: vec!["node-1".into()],
            active_profile: ConsensusProfile::Single,
        }
    }

    fn default_metrics() -> LedgerMetrics {
        LedgerMetrics::new()
    }

    // -----------------------------------------------------------------------
    // Withdrawal gate tests
    // -----------------------------------------------------------------------

    #[test]
    fn withdrawals_allowed_when_healthy_and_balanced() {
        let metrics = default_metrics();
        let report = balanced_report();
        let status = healthy_status();

        let result = ProductionGates::can_authorize_withdrawals(&metrics, &report, &status);
        assert!(
            result.allowed,
            "expected allowed, got reasons: {:?}",
            result.reasons
        );
    }

    #[test]
    fn withdrawals_blocked_on_deficit() {
        let metrics = default_metrics();
        let mut state = LedgerState::empty(test_membership());
        let mut acc = crate::account_state::AccountState::new("user-1");
        acc.available_sats = 100_000;
        state.accounts.push(acc);
        let report = ReconciliationEngine::reconcile(&state, "tip", true);
        let status = healthy_status();

        let result = ProductionGates::can_authorize_withdrawals(&metrics, &report, &status);
        assert!(!result.allowed);
        assert!(result.reasons.iter().any(|r| r.contains("deficit")));
    }

    #[test]
    fn withdrawals_blocked_on_unhealthy_sync() {
        let metrics = default_metrics();
        let report = balanced_report();
        let mut status = healthy_status();
        status.sync_status = SyncStatus::Diverged;

        let result = ProductionGates::can_authorize_withdrawals(&metrics, &report, &status);
        assert!(!result.allowed);
    }

    #[test]
    fn withdrawals_blocked_with_sequence_lag() {
        let metrics = LedgerMetrics {
            sequence_lag: 5,
            ..Default::default()
        };
        let report = balanced_report();
        let status = healthy_status();

        let result = ProductionGates::can_authorize_withdrawals(&metrics, &report, &status);
        assert!(!result.allowed);
        assert!(result.reasons.iter().any(|r| r.contains("lag")));
    }

    #[test]
    fn withdrawals_blocked_on_incomplete_chain_data() {
        let metrics = default_metrics();
        let state = LedgerState::empty(test_membership());
        let report = ReconciliationEngine::reconcile(&state, "tip", false);
        let status = healthy_status();

        let result = ProductionGates::can_authorize_withdrawals(&metrics, &report, &status);
        assert!(!result.allowed);
        assert!(result.reasons.iter().any(|r| r.contains("incomplete")));
    }

    // -----------------------------------------------------------------------
    // Deposit gate tests
    // -----------------------------------------------------------------------

    #[test]
    fn deposits_allowed_when_healthy() {
        let metrics = default_metrics();
        let status = healthy_status();

        let result = ProductionGates::can_accept_deposits(&metrics, &status);
        assert!(result.allowed);
    }

    #[test]
    fn deposits_blocked_when_diverged() {
        let metrics = default_metrics();
        let mut status = healthy_status();
        status.sync_status = SyncStatus::Diverged;

        let result = ProductionGates::can_accept_deposits(&metrics, &status);
        assert!(!result.allowed);
    }

    #[test]
    fn deposits_blocked_when_quarantined() {
        let metrics = default_metrics();
        let mut status = healthy_status();
        status.sync_status = SyncStatus::Quarantined;

        let result = ProductionGates::can_accept_deposits(&metrics, &status);
        assert!(!result.allowed);
    }

    #[test]
    fn deposits_blocked_with_large_lag() {
        let metrics = LedgerMetrics {
            sequence_lag: 200,
            ..Default::default()
        };
        let status = healthy_status();

        let result = ProductionGates::can_accept_deposits(&metrics, &status);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // Add nodes gate tests
    // -----------------------------------------------------------------------

    #[test]
    fn add_nodes_allowed_when_healthy() {
        let metrics = default_metrics();
        let status = healthy_status();
        let membership = test_membership();

        let result = ProductionGates::can_add_nodes(&metrics, &status, &membership);
        assert!(result.allowed);
    }

    #[test]
    fn add_nodes_blocked_when_not_healthy() {
        let metrics = default_metrics();
        let mut status = healthy_status();
        status.sync_status = SyncStatus::CatchingUp;
        let membership = test_membership();

        let result = ProductionGates::can_add_nodes(&metrics, &status, &membership);
        assert!(!result.allowed);
    }

    #[test]
    fn add_nodes_blocked_when_membership_full() {
        let metrics = default_metrics();
        let status = healthy_status();
        let membership = MembershipView {
            nodes: (0..100).map(|i| format!("node-{}", i)).collect(),
            ..test_membership()
        };

        let result = ProductionGates::can_add_nodes(&metrics, &status, &membership);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // Membership change gate tests
    // -----------------------------------------------------------------------

    #[test]
    fn membership_change_allowed_when_synced() {
        let status = healthy_status();
        let result = ProductionGates::can_change_membership(&status);
        assert!(result.allowed);
    }

    #[test]
    fn membership_change_blocked_when_not_healthy() {
        let mut status = healthy_status();
        status.sync_status = SyncStatus::CatchingUp;
        let result = ProductionGates::can_change_membership(&status);
        assert!(!result.allowed);
    }

    #[test]
    fn membership_change_blocked_when_behind() {
        let mut status = healthy_status();
        status.applied_sequence = 40;
        let result = ProductionGates::can_change_membership(&status);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // Key rotation gate tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_rotation_allowed_when_synced() {
        let status = healthy_status();
        let result = ProductionGates::can_rotate_keys(&status);
        assert!(result.allowed);
    }

    #[test]
    fn key_rotation_blocked_when_not_healthy() {
        let mut status = healthy_status();
        status.sync_status = SyncStatus::Diverged;
        let result = ProductionGates::can_rotate_keys(&status);
        assert!(!result.allowed);
    }

    #[test]
    fn key_rotation_blocked_when_behind() {
        let mut status = healthy_status();
        status.applied_sequence = 30;
        let result = ProductionGates::can_rotate_keys(&status);
        assert!(!result.allowed);
    }

    // -----------------------------------------------------------------------
    // DegradedMode tests
    // -----------------------------------------------------------------------

    #[test]
    fn normal_mode_when_all_gates_pass() {
        let metrics = default_metrics();
        let report = balanced_report();
        let status = healthy_status();
        let membership = test_membership();

        let mode = ProductionGates::evaluate_degraded_mode(&metrics, &report, &status, &membership);
        assert_eq!(mode, DegradedMode::Normal);
    }

    #[test]
    fn degraded_mode_when_withdrawals_blocked() {
        let metrics = default_metrics();
        let mut state = LedgerState::empty(test_membership());
        let mut acc = crate::account_state::AccountState::new("user-1");
        acc.available_sats = 100_000;
        state.accounts.push(acc);
        let report = ReconciliationEngine::reconcile(&state, "tip", true);
        let status = healthy_status();
        let membership = test_membership();

        let mode = ProductionGates::evaluate_degraded_mode(&metrics, &report, &status, &membership);
        assert!(matches!(mode, DegradedMode::Degraded { .. }));
    }

    #[test]
    fn degraded_mode_read_only_not_auto_selected() {
        // ReadOnly must be explicitly set by operators.
        let mode = DegradedMode::ReadOnly;
        assert!(!mode.withdrawals_allowed());
        assert!(!mode.internal_transfers_allowed());
        assert!(!mode.credits_allowed());
    }

    #[test]
    fn degraded_mode_withdrawals_blocked_flag() {
        let mode = DegradedMode::Degraded {
            withdrawals_blocked: true,
            membership_changes_blocked: false,
            key_rotation_blocked: false,
            internal_transfers_allowed: true,
            credits_allowed: true,
        };
        assert!(!mode.withdrawals_allowed());
        assert!(mode.internal_transfers_allowed());
        assert!(mode.credits_allowed());
    }

    // -----------------------------------------------------------------------
    // GateResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn gate_result_allowed_has_empty_reasons() {
        let result = GateResult::allowed();
        assert!(result.allowed);
        assert!(result.reasons.is_empty());
    }

    #[test]
    fn gate_result_blocked_reports_reasons() {
        let result = GateResult::blocked(vec!["reason-1".into(), "reason-2".into()]);
        assert!(!result.allowed);
        assert_eq!(result.reasons.len(), 2);
        assert_eq!(result.reasons[0], "reason-1");
    }

    #[test]
    fn gate_result_serde_roundtrip() {
        let result = GateResult::blocked(vec!["sync unhealthy".into()]);
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, deserialized);
    }
}
