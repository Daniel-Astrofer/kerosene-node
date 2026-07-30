use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::LedgerError;
use crate::replication::ReplicationStatus;

// ---------------------------------------------------------------------------
// NodeRole
// ---------------------------------------------------------------------------

/// The role of a node in the Kerosene cluster.
///
/// Nodes progress through roles as they gain trust:
/// `UNTRUSTED → OBSERVER → LEARNER → VOTER`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeRole {
    /// Node is not yet attested.
    Untrusted,
    /// Node can observe ledger state (read-only access).
    Observer,
    /// Node has installed a snapshot and is catching up.
    Learner,
    /// Node is a full voting member of the cluster.
    Voter,
}

// ---------------------------------------------------------------------------
// NodeMembership
// ---------------------------------------------------------------------------

/// Full membership record for a single node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMembership {
    /// Globally unique node identifier.
    pub node_id: String,
    /// Current role in the cluster.
    pub role: NodeRole,
    /// Optional onion-routed endpoint for peer-to-peer communication.
    pub onion_endpoint: Option<String>,
    /// Public key for identity verification.
    pub identity_pubkey: String,
    /// Time bucket when this node was attested.
    pub attested_at_bucket: u64,
    /// Epoch in which this node joined the cluster.
    pub joined_epoch: u64,
    /// Last heartbeat time bucket (for liveness tracking).
    pub last_heartbeat_bucket: u64,
    /// Optional admission signature from an existing member.
    pub admission_signature: Option<String>,
}

// ---------------------------------------------------------------------------
// MembershipStore trait
// ---------------------------------------------------------------------------

/// Port trait for storing and querying node membership data.
#[async_trait]
pub trait MembershipStore: Send + Sync {
    /// Adds a new node to the membership store.
    async fn add_node(&self, node: NodeMembership) -> Result<(), LedgerError>;

    /// Retrieves a node by its ID, returning `None` if not found.
    async fn get_node(&self, node_id: &str) -> Result<Option<NodeMembership>, LedgerError>;

    /// Lists all nodes with the given role.
    async fn list_by_role(&self, role: NodeRole) -> Result<Vec<NodeMembership>, LedgerError>;

    /// Promotes a node to the target role (validated by
    /// [`validate_role_transition`]).
    async fn promote(&self, node_id: &str, target_role: NodeRole) -> Result<(), LedgerError>;

    /// Removes a node from the membership store entirely.
    async fn remove_node(&self, node_id: &str) -> Result<(), LedgerError>;

    /// Updates the heartbeat timestamp for a node.
    async fn update_heartbeat(&self, node_id: &str, bucket: u64) -> Result<(), LedgerError>;
}

// ---------------------------------------------------------------------------
// InMemoryMembershipStore
// ---------------------------------------------------------------------------

/// In-memory membership store backed by `Mutex<HashMap>`.
pub struct InMemoryMembershipStore {
    inner: Mutex<HashMap<String, NodeMembership>>,
}

impl InMemoryMembershipStore {
    /// Creates a new empty membership store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryMembershipStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MembershipStore for InMemoryMembershipStore {
    async fn add_node(&self, node: NodeMembership) -> Result<(), LedgerError> {
        let mut map = self.inner.lock().unwrap();
        if map.contains_key(&node.node_id) {
            return Err(LedgerError::InvariantViolation(format!(
                "node '{}' already exists in membership",
                node.node_id
            )));
        }
        map.insert(node.node_id.clone(), node);
        Ok(())
    }

    async fn get_node(&self, node_id: &str) -> Result<Option<NodeMembership>, LedgerError> {
        let map = self.inner.lock().unwrap();
        Ok(map.get(node_id).cloned())
    }

    async fn list_by_role(&self, role: NodeRole) -> Result<Vec<NodeMembership>, LedgerError> {
        let map = self.inner.lock().unwrap();
        let mut nodes: Vec<NodeMembership> =
            map.values().filter(|n| n.role == role).cloned().collect();
        // Sort by node_id for determinism
        nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        Ok(nodes)
    }

    async fn promote(&self, node_id: &str, target_role: NodeRole) -> Result<(), LedgerError> {
        let mut map = self.inner.lock().unwrap();
        let node = map
            .get_mut(node_id)
            .ok_or_else(|| LedgerError::NodeNotFound(node_id.to_string()))?;

        let current_role = node.role;
        validate_role_transition(current_role, target_role)?;
        node.role = target_role;
        Ok(())
    }

    async fn remove_node(&self, node_id: &str) -> Result<(), LedgerError> {
        let mut map = self.inner.lock().unwrap();
        map.remove(node_id);
        Ok(())
    }

    async fn update_heartbeat(&self, node_id: &str, bucket: u64) -> Result<(), LedgerError> {
        let mut map = self.inner.lock().unwrap();
        let node = map
            .get_mut(node_id)
            .ok_or_else(|| LedgerError::NodeNotFound(node_id.to_string()))?;
        node.last_heartbeat_bucket = bucket;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// validate_role_transition
// ---------------------------------------------------------------------------

/// Validates that a role transition is allowed by the secure admission flow.
///
/// Allowed transitions:
/// - `UNTRUSTED → OBSERVER`: initial admission
/// - `OBSERVER → LEARNER`: after snapshot download + verification
/// - `LEARNER → VOTER`: after reaching current sequence + stability window
/// - `VOTER → OBSERVER`: demotion
/// - Any → `UNTRUSTED`: removal
pub fn validate_role_transition(current: NodeRole, target: NodeRole) -> Result<(), LedgerError> {
    use NodeRole::*;

    let valid = match (current, target) {
        (Untrusted, Observer) => true,
        (Observer, Learner) => true,
        (Learner, Voter) => true,
        (Voter, Observer) => true,
        (_, Untrusted) => true,
        _ => false,
    };

    if valid {
        Ok(())
    } else {
        Err(LedgerError::InvalidRoleTransition {
            from: current,
            to: target,
        })
    }
}

// ---------------------------------------------------------------------------
// AdmissionFlow
// ---------------------------------------------------------------------------

/// Describes the secure admission flow for new nodes.
///
/// Flow: `UNTRUSTED → OBSERVER → LEARNER → VOTER`
///
/// 1. Generate local identity
/// 2. Register onion endpoint
/// 3. Receive signed admission
/// 4. Enter as observer
/// 5. Download certified snapshot
/// 6. Verify certificate, membership, constitution, policy
/// 7. Install snapshot
/// 8. Replay subsequent commands
/// 9. Recompute state_root
/// 10. Reach current commit
/// 11. Remain stable for a configured window
/// 12. Promote by consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionFlow {
    /// Number of time buckets the node must remain stable as a Learner before
    /// being promoted to Voter.
    pub required_stability_window_buckets: u64,
}

impl Default for AdmissionFlow {
    fn default() -> Self {
        Self {
            required_stability_window_buckets: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// MembershipGate
// ---------------------------------------------------------------------------

/// Gates that enforce membership constraints on reading and voting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipGate {
    /// Minimum number of Voter nodes required for the cluster to function.
    pub min_voter_count: usize,
    /// Whether Observer nodes are allowed to read ledger state.
    pub allow_observer_read: bool,
}

impl Default for MembershipGate {
    fn default() -> Self {
        Self {
            min_voter_count: 1,
            allow_observer_read: true,
        }
    }
}

// ---------------------------------------------------------------------------
// VotingGate
// ---------------------------------------------------------------------------

/// Evaluates whether a specific node is allowed to vote or propose.
///
/// A node can only vote when ALL conditions are met:
/// - `role == Voter`
/// - `applied_sequence == committed_sequence`
/// - `sync_status == Healthy`
pub struct VotingGate {
    /// The replication status of this node.
    pub sync_status: ReplicationStatus,
    /// The membership record of this node.
    pub membership: NodeMembership,
}

impl VotingGate {
    /// Returns `true` if the node is allowed to vote.
    pub fn can_vote(&self) -> bool {
        self.membership.role == NodeRole::Voter
            && self.sync_status.applied_sequence == self.sync_status.committed_sequence
            && self.sync_status.sync_status == crate::replication::SyncStatus::Healthy
    }

    /// Returns `true` if the node is allowed to propose new commands.
    pub fn can_propose(&self) -> bool {
        self.can_vote()
    }

    /// Returns a list of human-readable reasons why this node is blocked from
    /// voting. An empty list means the node can vote.
    pub fn reason_blocked(&self) -> Vec<String> {
        let mut reasons = Vec::new();

        if self.membership.role != NodeRole::Voter {
            reasons.push(format!(
                "node {} is not a voter (role: {:?})",
                self.membership.node_id, self.membership.role
            ));
        }

        if self.sync_status.applied_sequence != self.sync_status.committed_sequence {
            reasons.push(format!(
                "applied sequence {} != committed sequence {}",
                self.sync_status.applied_sequence, self.sync_status.committed_sequence
            ));
        }

        if self.sync_status.sync_status != crate::replication::SyncStatus::Healthy {
            reasons.push(format!("sync status is {:?}", self.sync_status.sync_status));
        }

        reasons
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::SyncStatus;

    // -----------------------------------------------------------------------
    // NodeRole transition tests
    // -----------------------------------------------------------------------

    #[test]
    fn untrusted_to_observer_allowed() {
        assert!(validate_role_transition(NodeRole::Untrusted, NodeRole::Observer).is_ok());
    }

    #[test]
    fn observer_to_learner_allowed() {
        assert!(validate_role_transition(NodeRole::Observer, NodeRole::Learner).is_ok());
    }

    #[test]
    fn learner_to_voter_allowed() {
        assert!(validate_role_transition(NodeRole::Learner, NodeRole::Voter).is_ok());
    }

    #[test]
    fn voter_to_observer_demotion_allowed() {
        assert!(validate_role_transition(NodeRole::Voter, NodeRole::Observer).is_ok());
    }

    #[test]
    fn any_to_untrusted_removal_allowed() {
        assert!(validate_role_transition(NodeRole::Untrusted, NodeRole::Untrusted).is_ok());
        assert!(validate_role_transition(NodeRole::Observer, NodeRole::Untrusted).is_ok());
        assert!(validate_role_transition(NodeRole::Learner, NodeRole::Untrusted).is_ok());
        assert!(validate_role_transition(NodeRole::Voter, NodeRole::Untrusted).is_ok());
    }

    #[test]
    fn untrusted_to_voter_direct_rejected() {
        let err = validate_role_transition(NodeRole::Untrusted, NodeRole::Voter).unwrap_err();
        assert!(matches!(err, LedgerError::InvalidRoleTransition { .. }));
    }

    #[test]
    fn untrusted_to_learner_direct_rejected() {
        let err = validate_role_transition(NodeRole::Untrusted, NodeRole::Learner).unwrap_err();
        assert!(matches!(err, LedgerError::InvalidRoleTransition { .. }));
    }

    #[test]
    fn observer_to_voter_direct_rejected() {
        let err = validate_role_transition(NodeRole::Observer, NodeRole::Voter).unwrap_err();
        assert!(matches!(err, LedgerError::InvalidRoleTransition { .. }));
    }

    #[test]
    fn voter_to_learner_direct_rejected() {
        let err = validate_role_transition(NodeRole::Voter, NodeRole::Learner).unwrap_err();
        assert!(matches!(err, LedgerError::InvalidRoleTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // VotingGate tests
    // -----------------------------------------------------------------------

    fn make_voter_status() -> ReplicationStatus {
        ReplicationStatus {
            epoch: 1,
            committed_sequence: 42,
            applied_sequence: 42,
            state_root: "root".into(),
            leader_view: 0,
            sync_status: SyncStatus::Healthy,
        }
    }

    fn make_voter_membership() -> NodeMembership {
        NodeMembership {
            node_id: "node-1".into(),
            role: NodeRole::Voter,
            onion_endpoint: None,
            identity_pubkey: "pubkey".into(),
            attested_at_bucket: 100,
            joined_epoch: 1,
            last_heartbeat_bucket: 100,
            admission_signature: None,
        }
    }

    #[test]
    fn voting_gate_allows_voter() {
        let gate = VotingGate {
            sync_status: make_voter_status(),
            membership: make_voter_membership(),
        };
        assert!(gate.can_vote());
        assert!(gate.can_propose());
        assert!(gate.reason_blocked().is_empty());
    }

    #[test]
    fn voting_gate_blocks_non_voter() {
        let mut membership = make_voter_membership();
        membership.role = NodeRole::Observer;

        let gate = VotingGate {
            sync_status: make_voter_status(),
            membership,
        };
        assert!(!gate.can_vote());
        assert!(!gate.can_propose());
        let reasons = gate.reason_blocked();
        assert!(!reasons.is_empty());
        assert!(reasons[0].contains("not a voter"));
    }

    #[test]
    fn voting_gate_blocks_out_of_sync() {
        let status = ReplicationStatus {
            applied_sequence: 40,
            ..make_voter_status()
        };

        let gate = VotingGate {
            sync_status: status,
            membership: make_voter_membership(),
        };
        assert!(!gate.can_vote());
        let reasons = gate.reason_blocked();
        assert!(reasons.iter().any(|r| r.contains("applied sequence")));
    }

    #[test]
    fn voting_gate_blocks_unhealthy_sync() {
        let status = ReplicationStatus {
            sync_status: SyncStatus::Diverged,
            ..make_voter_status()
        };

        let gate = VotingGate {
            sync_status: status,
            membership: make_voter_membership(),
        };
        assert!(!gate.can_vote());
        let reasons = gate.reason_blocked();
        assert!(reasons.iter().any(|r| r.contains("sync status")));
    }

    #[test]
    fn voting_gate_reasons_are_informative_multiple_blockers() {
        let mut membership = make_voter_membership();
        membership.role = NodeRole::Learner;

        let status = ReplicationStatus {
            applied_sequence: 30,
            sync_status: SyncStatus::CatchingUp,
            ..make_voter_status()
        };

        let gate = VotingGate {
            sync_status: status,
            membership,
        };
        let reasons = gate.reason_blocked();
        assert!(reasons.len() >= 2);
        assert!(reasons.iter().any(|r| r.contains("not a voter")));
        assert!(reasons.iter().any(|r| r.contains("applied sequence")));
    }

    // -----------------------------------------------------------------------
    // InMemoryMembershipStore tests
    // -----------------------------------------------------------------------

    fn sample_node(node_id: &str, role: NodeRole) -> NodeMembership {
        NodeMembership {
            node_id: node_id.into(),
            role,
            onion_endpoint: None,
            identity_pubkey: format!("pubkey-{}", node_id),
            attested_at_bucket: 100,
            joined_epoch: 1,
            last_heartbeat_bucket: 100,
            admission_signature: None,
        }
    }

    #[tokio::test]
    async fn new_node_starts_as_untrusted() {
        let store = InMemoryMembershipStore::new();
        let node = sample_node("node-1", NodeRole::Untrusted);
        store.add_node(node.clone()).await.unwrap();

        let fetched = store.get_node("node-1").await.unwrap().unwrap();
        assert_eq!(fetched.role, NodeRole::Untrusted);
        assert_eq!(fetched.node_id, "node-1");
    }

    #[tokio::test]
    async fn can_add_as_observer() {
        let store = InMemoryMembershipStore::new();
        let node = sample_node("node-1", NodeRole::Observer);
        store.add_node(node.clone()).await.unwrap();

        let fetched = store.get_node("node-1").await.unwrap().unwrap();
        assert_eq!(fetched.role, NodeRole::Observer);
    }

    #[tokio::test]
    async fn observer_promoted_to_learner() {
        let store = InMemoryMembershipStore::new();
        store
            .add_node(sample_node("node-1", NodeRole::Observer))
            .await
            .unwrap();

        store.promote("node-1", NodeRole::Learner).await.unwrap();
        let fetched = store.get_node("node-1").await.unwrap().unwrap();
        assert_eq!(fetched.role, NodeRole::Learner);
    }

    #[tokio::test]
    async fn learner_promoted_to_voter() {
        let store = InMemoryMembershipStore::new();
        store
            .add_node(sample_node("node-1", NodeRole::Learner))
            .await
            .unwrap();

        store.promote("node-1", NodeRole::Voter).await.unwrap();
        let fetched = store.get_node("node-1").await.unwrap().unwrap();
        assert_eq!(fetched.role, NodeRole::Voter);
    }

    #[tokio::test]
    async fn voter_demoted_to_observer() {
        let store = InMemoryMembershipStore::new();
        store
            .add_node(sample_node("node-1", NodeRole::Voter))
            .await
            .unwrap();

        store.promote("node-1", NodeRole::Observer).await.unwrap();
        let fetched = store.get_node("node-1").await.unwrap().unwrap();
        assert_eq!(fetched.role, NodeRole::Observer);
    }

    #[tokio::test]
    async fn invalid_role_transition_rejected() {
        let store = InMemoryMembershipStore::new();
        store
            .add_node(sample_node("node-1", NodeRole::Untrusted))
            .await
            .unwrap();

        let err = store.promote("node-1", NodeRole::Voter).await.unwrap_err();
        assert!(matches!(err, LedgerError::InvalidRoleTransition { .. }));
    }

    #[tokio::test]
    async fn remove_node_works() {
        let store = InMemoryMembershipStore::new();
        store
            .add_node(sample_node("node-1", NodeRole::Voter))
            .await
            .unwrap();

        store.remove_node("node-1").await.unwrap();
        let fetched = store.get_node("node-1").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn list_by_role_returns_matching_nodes() {
        let store = InMemoryMembershipStore::new();
        store
            .add_node(sample_node("voter-1", NodeRole::Voter))
            .await
            .unwrap();
        store
            .add_node(sample_node("voter-2", NodeRole::Voter))
            .await
            .unwrap();
        store
            .add_node(sample_node("observer-1", NodeRole::Observer))
            .await
            .unwrap();

        let voters = store.list_by_role(NodeRole::Voter).await.unwrap();
        assert_eq!(voters.len(), 2);
        assert!(voters.iter().all(|n| n.role == NodeRole::Voter));
    }

    #[tokio::test]
    async fn update_heartbeat_works() {
        let store = InMemoryMembershipStore::new();
        store
            .add_node(sample_node("node-1", NodeRole::Voter))
            .await
            .unwrap();

        store.update_heartbeat("node-1", 200).await.unwrap();
        let fetched = store.get_node("node-1").await.unwrap().unwrap();
        assert_eq!(fetched.last_heartbeat_bucket, 200);
    }

    #[tokio::test]
    async fn get_nonexistent_node_returns_none() {
        let store = InMemoryMembershipStore::new();
        let fetched = store.get_node("nonexistent").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn promote_nonexistent_node_fails() {
        let store = InMemoryMembershipStore::new();
        let err = store
            .promote("nonexistent", NodeRole::Voter)
            .await
            .unwrap_err();
        assert!(matches!(err, LedgerError::NodeNotFound(_)));
    }

    #[tokio::test]
    async fn admission_flow_defaults() {
        let flow = AdmissionFlow::default();
        assert_eq!(flow.required_stability_window_buckets, 10);
    }

    #[tokio::test]
    async fn membership_gate_defaults() {
        let gate = MembershipGate::default();
        assert_eq!(gate.min_voter_count, 1);
        assert!(gate.allow_observer_read);
    }

    #[tokio::test]
    async fn node_serde_roundtrip() {
        let node = sample_node("node-1", NodeRole::Voter);
        let json = serde_json::to_string(&node).unwrap();
        let deserialized: NodeMembership = serde_json::from_str(&json).unwrap();
        assert_eq!(node, deserialized);
    }
}
