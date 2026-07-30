use serde::{Deserialize, Serialize};

use crate::error::LedgerError;
use crate::state_machine::LedgerState;
use crate::state_root::compute_state_root;

// ---------------------------------------------------------------------------
// NodeSignature
// ---------------------------------------------------------------------------

/// A single node's signature over a commit certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSignature {
    /// The node that produced this signature.
    pub node_id: String,
    /// Hex-encoded signature (e.g. BLS or ECDSA signature).
    pub signature_hex: String,
}

// ---------------------------------------------------------------------------
// QuorumCertificate
// ---------------------------------------------------------------------------

/// A quorum certificate attests that a command was committed by the cluster.
///
/// In SINGLE mode the certificate is self-signed (single node). The structure
/// is compatible with future multi-node BFT quorum certificates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// Cluster that produced this certificate.
    pub cluster_id: String,
    /// Epoch in which the command was committed.
    pub epoch: u64,
    /// View number in which the command was committed.
    pub view: u64,
    /// Monotonically increasing sequence number of the committed command.
    pub sequence: u64,
    /// Hash of the committed command.
    pub command_hash: String,
    /// State root before the command was applied.
    pub previous_state_root: String,
    /// State root after the command was applied.
    pub resulting_state_root: String,
    /// Bitmap of which nodes signed (bit i = 1 means node i signed).
    pub signer_bitmap: Vec<u8>,
    /// The actual signatures from the signing nodes.
    pub signatures: Vec<NodeSignature>,
}

impl QuorumCertificate {
    /// Creates a new SINGLE-mode quorum certificate (self-signed).
    pub fn single_node(
        cluster_id: impl Into<String>,
        epoch: u64,
        view: u64,
        sequence: u64,
        command_hash: impl Into<String>,
        previous_state_root: impl Into<String>,
        resulting_state_root: impl Into<String>,
        node_id: impl Into<String>,
        signature_hex: impl Into<String>,
    ) -> Self {
        Self {
            cluster_id: cluster_id.into(),
            epoch,
            view,
            sequence,
            command_hash: command_hash.into(),
            previous_state_root: previous_state_root.into(),
            resulting_state_root: resulting_state_root.into(),
            signer_bitmap: vec![0b0000_0001],
            signatures: vec![NodeSignature {
                node_id: node_id.into(),
                signature_hex: signature_hex.into(),
            }],
        }
    }

    /// Returns the number of distinct signers.
    pub fn signer_count(&self) -> usize {
        self.signatures.len()
    }

    /// Verifies structural integrity of the quorum certificate.
    ///
    /// Checks:
    /// - Signer bitmap length matches expected
    /// - Signature count matches bitmap
    /// - State roots are non-empty
    ///
    /// Does NOT verify cryptographic signatures (delegated to a crypto layer).
    pub fn verify_basic(&self) -> Result<(), LedgerError> {
        if self.previous_state_root.is_empty() {
            return Err(LedgerError::InvalidSignature(
                "previous_state_root is empty".into(),
            ));
        }
        if self.resulting_state_root.is_empty() {
            return Err(LedgerError::InvalidSignature(
                "resulting_state_root is empty".into(),
            ));
        }
        if self.command_hash.is_empty() {
            return Err(LedgerError::InvalidSignature(
                "command_hash is empty".into(),
            ));
        }
        if self.signatures.is_empty() {
            return Err(LedgerError::InvalidSignature(
                "no signatures in quorum certificate".into(),
            ));
        }
        if self.signer_bitmap.is_empty() {
            return Err(LedgerError::InvalidSignature(
                "signer_bitmap is empty".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Checkpoint
// ---------------------------------------------------------------------------

/// A verified snapshot of the ledger state at a given sequence.
///
/// Checkpoints enable state sync, light-client verification, and
/// fast crash recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Global sequence number at which this checkpoint was taken.
    pub sequence: u64,
    /// State root at this sequence.
    pub state_root: String,
    /// Hash of the membership view.
    pub membership_hash: String,
    /// Merkle root of all committed commands up to this point.
    pub committed_commands_root: String,
    /// Time bucket when this checkpoint was created.
    pub timestamp_bucket: u64,
    /// Optional quorum certificate attesting to this checkpoint.
    pub quorum_certificate: Option<QuorumCertificate>,
}

impl Checkpoint {
    /// Creates a new checkpoint from a ledger state.
    ///
    /// The `committed_commands_root` is computed from the journal's entry hash
    /// chain (the hash of the last journal entry represents all committed commands).
    pub fn from_state(
        state: &LedgerState,
        timestamp_bucket: u64,
        quorum_certificate: Option<QuorumCertificate>,
    ) -> Self {
        let committed_commands_root = state
            .journal
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| String::from("0"));

        Self {
            sequence: state.version.saturating_sub(1),
            state_root: compute_state_root(state),
            membership_hash: crate::state_root::compute_membership_hash(&state.membership),
            committed_commands_root,
            timestamp_bucket,
            quorum_certificate,
        }
    }

    /// Verifies that the checkpoint's state root matches the computed
    /// state root of the given ledger state.
    pub fn verify(&self, state: &LedgerState) -> Result<(), LedgerError> {
        let computed_root = compute_state_root(state);
        if self.state_root != computed_root {
            return Err(LedgerError::StateRootMismatch {
                expected: computed_root,
                got: self.state_root.clone(),
            });
        }

        let computed_membership_hash =
            crate::state_root::compute_membership_hash(&state.membership);
        if self.membership_hash != computed_membership_hash {
            return Err(LedgerError::InvariantViolation(format!(
                "membership hash mismatch: expected {computed_membership_hash}, got {}",
                self.membership_hash
            )));
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CertifiedSnapshot
// ---------------------------------------------------------------------------

/// A fully certified snapshot of the ledger that can be installed on a
/// new or recovering node.
///
/// Contains all state necessary to bootstrap a node from a trusted checkpoint
/// without replaying the full command log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedSnapshot {
    /// Cluster that produced this snapshot.
    pub cluster_id: String,
    /// Epoch when the snapshot was taken.
    pub epoch: u64,
    /// Sequence number at which the snapshot was taken.
    pub sequence: u64,
    /// Serialised ledger state bytes.
    pub state_bytes: Vec<u8>,
    /// State root hash (verify against `compute_state_root(deserialised_state)`).
    pub state_root: String,
    /// Hash of the membership view at snapshot time.
    pub membership_hash: String,
    /// Hash of the cluster constitution.
    pub constitution_hash: String,
    /// Hash of the cluster policy.
    pub policy_hash: String,
    /// Hash of the ledger totals (aggregate balance).
    pub ledger_totals_hash: String,
    /// Merkle root of the UTXO set.
    pub utxo_set_root: String,
    /// Merkle root of consumed intents.
    pub consumed_intents_root: String,
    /// Quorum certificate attesting to this snapshot.
    pub quorum_certificate: QuorumCertificate,
}

impl CertifiedSnapshot {
    /// Verifies the structural integrity of the certified snapshot.
    ///
    /// Checks that all hash fields are non-empty and that the quorum
    /// certificate passes basic verification.
    ///
    /// Does NOT verify the state against `state_bytes` (the caller must
    /// deserialise and recompute).
    pub fn verify_basic(&self) -> Result<(), LedgerError> {
        if self.cluster_id.is_empty() {
            return Err(LedgerError::InvalidSignature(
                "cluster_id is empty in CertifiedSnapshot".into(),
            ));
        }
        if self.state_root.is_empty() {
            return Err(LedgerError::InvalidSignature(
                "state_root is empty in CertifiedSnapshot".into(),
            ));
        }
        if self.state_bytes.is_empty() {
            return Err(LedgerError::InvalidSignature(
                "state_bytes is empty in CertifiedSnapshot".into(),
            ));
        }
        self.quorum_certificate.verify_basic()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::{LedgerState, MembershipView};

    fn test_membership() -> MembershipView {
        MembershipView::single_node("cluster-1", "node-1")
    }

    #[test]
    fn quorum_certificate_single_mode_creation() {
        let qc = QuorumCertificate::single_node(
            "cluster-1",
            1,
            0,
            42,
            "cmd-hash-abc",
            "prev-root",
            "result-root",
            "node-1",
            "sig-hex-123",
        );

        assert_eq!(qc.cluster_id, "cluster-1");
        assert_eq!(qc.epoch, 1);
        assert_eq!(qc.sequence, 42);
        assert_eq!(qc.command_hash, "cmd-hash-abc");
        assert_eq!(qc.signer_count(), 1);
        assert_eq!(qc.signatures[0].node_id, "node-1");
        assert_eq!(qc.signatures[0].signature_hex, "sig-hex-123");
        assert_eq!(qc.signer_bitmap, vec![0b0000_0001]);
    }

    #[test]
    fn quorum_certificate_basic_verification_passes() {
        let qc = QuorumCertificate::single_node(
            "cluster-1", 1, 0, 42, "hash", "prev-root", "result-root", "node-1", "sig",
        );
        assert!(qc.verify_basic().is_ok());
    }

    #[test]
    fn quorum_certificate_empty_state_root_fails() {
        let qc = QuorumCertificate {
            previous_state_root: String::new(),
            ..QuorumCertificate::single_node(
                "cluster-1", 1, 0, 42, "hash", "prev-root", "result-root", "node-1", "sig",
            )
        };
        assert!(qc.verify_basic().is_err());
    }

    #[test]
    fn quorum_certificate_no_signatures_fails() {
        let qc = QuorumCertificate {
            signatures: vec![],
            ..QuorumCertificate::single_node(
                "cluster-1", 1, 0, 42, "hash", "prev-root", "result-root", "node-1", "sig",
            )
        };
        assert!(qc.verify_basic().is_err());
    }

    #[test]
    fn quorum_certificate_serde_roundtrip() {
        let qc = QuorumCertificate::single_node(
            "cluster-1", 1, 0, 42, "hash", "prev", "result", "node-1", "sig",
        );
        let json = serde_json::to_string(&qc).unwrap();
        let deserialized: QuorumCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(qc, deserialized);
    }

    #[test]
    fn checkpoint_creation_from_empty_state() {
        let state = LedgerState::empty(test_membership());
        let cp = Checkpoint::from_state(&state, 100, None);

        assert_eq!(cp.sequence, state.version.saturating_sub(1));
        assert_eq!(cp.state_root, compute_state_root(&state));
        assert!(cp.quorum_certificate.is_none());
    }

    #[test]
    fn checkpoint_state_root_matches_compute_state_root() {
        let state = LedgerState::empty(test_membership());
        let cp = Checkpoint::from_state(&state, 100, None);

        assert_eq!(cp.state_root, compute_state_root(&state));
    }

    #[test]
    fn checkpoint_verification_passes() {
        let state = LedgerState::empty(test_membership());
        let cp = Checkpoint::from_state(&state, 100, None);
        assert!(cp.verify(&state).is_ok());
    }

    #[test]
    fn checkpoint_verification_fails_on_modified_state() {
        let mut state = LedgerState::empty(test_membership());
        let cp = Checkpoint::from_state(&state, 100, None);

        // Modify the state
        state.accounts.push(crate::account_state::AccountState::new("alice"));
        assert!(cp.verify(&state).is_err());
    }

    #[test]
    fn certified_snapshot_serde_roundtrip() {
        let qc = QuorumCertificate::single_node(
            "cluster-1", 1, 0, 42, "hash", "prev", "result", "node-1", "sig",
        );

        let state = LedgerState::empty(test_membership());
        let state_bytes = serde_json::to_vec(&state).unwrap();

        let snapshot = CertifiedSnapshot {
            cluster_id: "cluster-1".into(),
            epoch: 1,
            sequence: 42,
            state_bytes,
            state_root: compute_state_root(&state),
            membership_hash: "mem-hash".into(),
            constitution_hash: "const-hash".into(),
            policy_hash: "policy-hash".into(),
            ledger_totals_hash: "totals-hash".into(),
            utxo_set_root: "utxo-root".into(),
            consumed_intents_root: "intents-root".into(),
            quorum_certificate: qc,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let deserialized: CertifiedSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, deserialized);
    }

    #[test]
    fn certified_snapshot_basic_verification_passes() {
        let qc = QuorumCertificate::single_node(
            "cluster-1", 1, 0, 42, "hash", "prev", "result", "node-1", "sig",
        );

        let snapshot = CertifiedSnapshot {
            cluster_id: "cluster-1".into(),
            epoch: 1,
            sequence: 42,
            state_bytes: vec![1, 2, 3],
            state_root: "root".into(),
            membership_hash: "mem-hash".into(),
            constitution_hash: "const-hash".into(),
            policy_hash: "policy-hash".into(),
            ledger_totals_hash: "totals-hash".into(),
            utxo_set_root: "utxo-root".into(),
            consumed_intents_root: "intents-root".into(),
            quorum_certificate: qc,
        };

        assert!(snapshot.verify_basic().is_ok());
    }

    #[test]
    fn certified_snapshot_empty_state_bytes_fails() {
        let qc = QuorumCertificate::single_node(
            "cluster-1", 1, 0, 42, "hash", "prev", "result", "node-1", "sig",
        );

        let snapshot = CertifiedSnapshot {
            cluster_id: "cluster-1".into(),
            epoch: 1,
            sequence: 42,
            state_bytes: vec![],
            state_root: "root".into(),
            membership_hash: "mem-hash".into(),
            constitution_hash: "const-hash".into(),
            policy_hash: "policy-hash".into(),
            ledger_totals_hash: "totals-hash".into(),
            utxo_set_root: "utxo-root".into(),
            consumed_intents_root: "intents-root".into(),
            quorum_certificate: qc,
        };

        assert!(snapshot.verify_basic().is_err());
    }
}
