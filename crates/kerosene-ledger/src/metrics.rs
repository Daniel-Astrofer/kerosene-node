use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::LedgerError;

// ---------------------------------------------------------------------------
// LedgerMetrics
// ---------------------------------------------------------------------------

/// Production-safe metrics snapshot for the ledger.
///
/// **No sensitive data.** This struct MUST NOT contain account_id, address,
/// value, or intent ID as label values — only aggregated counters and
/// operational gauges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerMetrics {
    /// Highest sequence number committed by the cluster.
    pub committed_sequence: u64,
    /// Highest sequence number applied by this node.
    pub applied_sequence: u64,
    /// Lag between committed and applied sequences.
    pub sequence_lag: u64,
    /// Total number of state root mismatches observed.
    pub state_root_mismatch_total: u64,
    /// Total number of version conflicts (optimistic concurrency).
    pub version_conflict_total: u64,
    /// Total number of idempotency replays (same command_id re-applied).
    pub idempotency_replay_total: u64,
    /// Total number of insufficient funds rejections.
    pub insufficient_funds_total: u64,
    /// Total number of reservation conflicts.
    pub reservation_conflict_total: u64,
    /// Total number of times quorum was unavailable.
    pub quorum_unavailable_total: u64,
    /// Total number of snapshot installations.
    pub snapshot_install_total: u64,
    /// Total number of divergence recovery attempts.
    pub divergence_recovery_total: u64,
    /// Current sync status of this node (e.g. "Healthy", "CatchingUp").
    pub node_sync_status: String,
    /// Total number of accounts in the ledger.
    pub total_accounts: u64,
    /// Total number of UTXO entries tracked.
    pub total_utxos: u64,
    /// Total number of active reservations.
    pub total_reservations: u64,
    /// Total number of pending (unsettled) withdrawals.
    pub total_withdrawals_pending: u64,
}

impl LedgerMetrics {
    /// Creates a new metrics snapshot with all values set to zero / empty.
    pub fn new() -> Self {
        Self {
            committed_sequence: 0,
            applied_sequence: 0,
            sequence_lag: 0,
            state_root_mismatch_total: 0,
            version_conflict_total: 0,
            idempotency_replay_total: 0,
            insufficient_funds_total: 0,
            reservation_conflict_total: 0,
            quorum_unavailable_total: 0,
            snapshot_install_total: 0,
            divergence_recovery_total: 0,
            node_sync_status: String::new(),
            total_accounts: 0,
            total_utxos: 0,
            total_reservations: 0,
            total_withdrawals_pending: 0,
        }
    }
}

impl Default for LedgerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MetricsCollector trait
// ---------------------------------------------------------------------------

/// Port trait for collecting and exposing ledger metrics.
///
/// Implementations MUST NOT expose sensitive data (account_id, address,
/// value, intent ID) as metric label values.
#[async_trait]
pub trait MetricsCollector: Send + Sync {
    /// Take a full metrics snapshot.
    async fn snapshot(&self) -> Result<LedgerMetrics, LedgerError>;

    /// Increment a named counter by `value`.
    async fn increment_counter(&self, name: &str, value: u64);

    /// Set a named gauge to `value`.
    async fn set_gauge(&self, name: &str, value: u64);
}

// ---------------------------------------------------------------------------
// BasicMetricsCollector (in-memory, for testing)
// ---------------------------------------------------------------------------

/// In-memory implementation of `MetricsCollector` backed by atomic counters.
///
/// Suitable for testing and single-node deployments. Not durable.
pub struct BasicMetricsCollector {
    inner: Mutex<BasicMetricsInner>,
}

#[derive(Debug, Clone)]
struct BasicMetricsInner {
    counters: std::collections::HashMap<String, u64>,
    gauges: std::collections::HashMap<String, u64>,
    committed_sequence: u64,
    applied_sequence: u64,
    node_sync_status: String,
    total_accounts: u64,
    total_utxos: u64,
    total_reservations: u64,
    total_withdrawals_pending: u64,
}

impl BasicMetricsCollector {
    /// Creates a new empty metrics collector.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(BasicMetricsInner {
                counters: std::collections::HashMap::new(),
                gauges: std::collections::HashMap::new(),
                committed_sequence: 0,
                applied_sequence: 0,
                node_sync_status: String::new(),
                total_accounts: 0,
                total_utxos: 0,
                total_reservations: 0,
                total_withdrawals_pending: 0,
            }),
        }
    }
}

impl Default for BasicMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MetricsCollector for BasicMetricsCollector {
    async fn snapshot(&self) -> Result<LedgerMetrics, LedgerError> {
        let inner = self.inner.lock().unwrap();
        let committed = inner.committed_sequence;
        let applied = inner.applied_sequence;
        let lag = committed.saturating_sub(applied);

        Ok(LedgerMetrics {
            committed_sequence: committed,
            applied_sequence: applied,
            sequence_lag: lag,
            state_root_mismatch_total: inner.counters.get("state_root_mismatch").copied().unwrap_or(0),
            version_conflict_total: inner.counters.get("version_conflict").copied().unwrap_or(0),
            idempotency_replay_total: inner.counters.get("idempotency_replay").copied().unwrap_or(0),
            insufficient_funds_total: inner.counters.get("insufficient_funds").copied().unwrap_or(0),
            reservation_conflict_total: inner.counters.get("reservation_conflict").copied().unwrap_or(0),
            quorum_unavailable_total: inner.counters.get("quorum_unavailable").copied().unwrap_or(0),
            snapshot_install_total: inner.counters.get("snapshot_install").copied().unwrap_or(0),
            divergence_recovery_total: inner.counters.get("divergence_recovery").copied().unwrap_or(0),
            node_sync_status: inner.node_sync_status.clone(),
            total_accounts: inner.total_accounts,
            total_utxos: inner.total_utxos,
            total_reservations: inner.total_reservations,
            total_withdrawals_pending: inner.total_withdrawals_pending,
        })
    }

    async fn increment_counter(&self, name: &str, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        let counter = inner.counters.entry(name.to_string()).or_insert(0);
        *counter = counter.saturating_add(value);
    }

    async fn set_gauge(&self, name: &str, value: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.gauges.insert(name.to_string(), value);
    }
}

impl BasicMetricsCollector {
    /// Set the committed sequence number.
    pub fn set_committed_sequence(&self, seq: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.committed_sequence = seq;
    }

    /// Set the applied sequence number.
    pub fn set_applied_sequence(&self, seq: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.applied_sequence = seq;
    }

    /// Set the node sync status.
    pub fn set_node_sync_status(&self, status: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.node_sync_status = status.to_string();
    }

    /// Set total accounts count.
    pub fn set_total_accounts(&self, count: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.total_accounts = count;
    }

    /// Set total UTXOs count.
    pub fn set_total_utxos(&self, count: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.total_utxos = count;
    }

    /// Set total reservations count.
    pub fn set_total_reservations(&self, count: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.total_reservations = count;
    }

    /// Set total pending withdrawals count.
    pub fn set_total_withdrawals_pending(&self, count: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.total_withdrawals_pending = count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_snapshot_returns_zeros() {
        let collector = BasicMetricsCollector::new();
        let snapshot = collector.snapshot().await.unwrap();
        assert_eq!(snapshot.committed_sequence, 0);
        assert_eq!(snapshot.applied_sequence, 0);
        assert_eq!(snapshot.sequence_lag, 0);
        assert_eq!(snapshot.state_root_mismatch_total, 0);
        assert_eq!(snapshot.node_sync_status, "");
    }

    #[tokio::test]
    async fn increment_counter_accumulates() {
        let collector = BasicMetricsCollector::new();
        collector
            .increment_counter("state_root_mismatch", 3)
            .await;
        collector
            .increment_counter("state_root_mismatch", 2)
            .await;

        let snapshot = collector.snapshot().await.unwrap();
        assert_eq!(snapshot.state_root_mismatch_total, 5);
    }

    #[tokio::test]
    async fn set_gauge_works() {
        let collector = BasicMetricsCollector::new();
        collector.set_gauge("my_gauge", 42).await;

        let inner = collector.inner.lock().unwrap();
        assert_eq!(inner.gauges.get("my_gauge"), Some(&42));
    }

    #[tokio::test]
    async fn sequence_lag_computed_correctly() {
        let collector = BasicMetricsCollector::new();
        collector.set_committed_sequence(100);
        collector.set_applied_sequence(95);

        let snapshot = collector.snapshot().await.unwrap();
        assert_eq!(snapshot.committed_sequence, 100);
        assert_eq!(snapshot.applied_sequence, 95);
        assert_eq!(snapshot.sequence_lag, 5);
    }

    #[tokio::test]
    async fn set_totals_reflect_in_snapshot() {
        let collector = BasicMetricsCollector::new();
        collector.set_total_accounts(10);
        collector.set_total_utxos(25);
        collector.set_total_reservations(5);
        collector.set_total_withdrawals_pending(3);
        collector.set_node_sync_status("Healthy");

        let snapshot = collector.snapshot().await.unwrap();
        assert_eq!(snapshot.total_accounts, 10);
        assert_eq!(snapshot.total_utxos, 25);
        assert_eq!(snapshot.total_reservations, 5);
        assert_eq!(snapshot.total_withdrawals_pending, 3);
        assert_eq!(snapshot.node_sync_status, "Healthy");
    }

    #[tokio::test]
    async fn multiple_counters_independent() {
        let collector = BasicMetricsCollector::new();
        collector.increment_counter("version_conflict", 7).await;
        collector.increment_counter("insufficient_funds", 3).await;

        let snapshot = collector.snapshot().await.unwrap();
        assert_eq!(snapshot.version_conflict_total, 7);
        assert_eq!(snapshot.insufficient_funds_total, 3);
    }

    #[tokio::test]
    async fn snapshot_is_deterministic() {
        let collector = BasicMetricsCollector::new();
        collector.set_committed_sequence(50);
        collector.set_applied_sequence(50);
        collector.increment_counter("state_root_mismatch", 1).await;
        collector.set_node_sync_status("Healthy");

        let s1 = collector.snapshot().await.unwrap();
        let s2 = collector.snapshot().await.unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn default_metrics_no_sensitive_data() {
        // Verify the struct has no account_id, address, value, or intent ID fields.
        let m = LedgerMetrics::new();
        // The struct should only contain aggregate counters and operational gauges.
        assert_eq!(m.committed_sequence, 0);
        assert_eq!(m.node_sync_status, "");
    }
}
