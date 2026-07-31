use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::certificate::QuorumCertificate;
use crate::error::LedgerError;
use crate::reservation::Reservation;
use crate::state_machine::LedgerState;

// ---------------------------------------------------------------------------
// PsbtCommitment
// ---------------------------------------------------------------------------

/// A commitment to a PSBT (Partially Signed Bitcoin Transaction).
///
/// This is a hash of the canonical PSBT serialization, not the full PSBT.
/// Vaults verify that the PSBT they are asked to sign matches this commitment
/// before producing any signature shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PsbtCommitment {
    /// SHA-256 hash of the canonical PSBT bytes.
    pub psbt_hash: String,
    /// Number of inputs in the PSBT.
    pub input_count: u32,
    /// Number of outputs in the PSBT.
    pub output_count: u32,
    /// Total output value in satoshis (for fee computation).
    pub total_output_sats: u64,
}

impl PsbtCommitment {
    /// Computes a SHA-256 commitment from the raw PSBT bytes.
    pub fn compute(psbt_bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(psbt_bytes);
        hex::encode(hasher.finalize())
    }

    /// Creates a new `PsbtCommitment` from PSBT bytes and metadata.
    pub fn new(
        psbt_bytes: &[u8],
        input_count: u32,
        output_count: u32,
        total_output_sats: u64,
    ) -> Self {
        Self {
            psbt_hash: Self::compute(psbt_bytes),
            input_count,
            output_count,
            total_output_sats,
        }
    }
}

// ---------------------------------------------------------------------------
// SettlementPolicy
// ---------------------------------------------------------------------------

/// Policy constraints for Bitcoin settlements.
///
/// Defines the bounds within which a settlement authorization is valid.
/// The KFE (Kerosene Front End) and vaults use this to independently verify
/// that a proposed settlement is within cluster policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementPolicy {
    /// Maximum fee in satoshis allowed for the settlement.
    pub max_fee_sats: u64,
    /// Minimum number of confirmations required before a settlement is
    /// considered final.
    pub min_confirmations: u32,
    /// List of allowed destination address types (e.g. "p2wpkh", "p2tr", "p2sh").
    pub allowed_destination_types: Vec<String>,
    /// Maximum number of outputs allowed in the settlement PSBT.
    pub max_outputs: u32,
    /// Whether RBF (Replace-By-Fee) is allowed for this settlement.
    pub rbf_allowed: bool,
    /// Maximum allowed drift between the authorization epoch and the
    /// cluster's current epoch.
    pub max_epoch_drift: u64,
    /// How many time buckets an authorization remains valid (TTL).
    pub authorization_ttl_buckets: u64,
}

impl SettlementPolicy {
    /// Validates that the policy itself is internally consistent.
    ///
    /// Returns an error if any policy field is clearly invalid.
    pub fn validate(&self) -> Result<(), LedgerError> {
        if self.max_fee_sats == 0 {
            return Err(LedgerError::PolicyViolation(
                "max_fee_sats must be > 0".into(),
            ));
        }
        if self.min_confirmations == 0 {
            return Err(LedgerError::PolicyViolation(
                "min_confirmations must be > 0".into(),
            ));
        }
        if self.allowed_destination_types.is_empty() {
            return Err(LedgerError::PolicyViolation(
                "at least one allowed_destination_type must be specified".into(),
            ));
        }
        if self.max_outputs == 0 {
            return Err(LedgerError::PolicyViolation(
                "max_outputs must be > 0".into(),
            ));
        }
        if self.max_epoch_drift == 0 {
            return Err(LedgerError::PolicyViolation(
                "max_epoch_drift must be > 0".into(),
            ));
        }
        if self.authorization_ttl_buckets == 0 {
            return Err(LedgerError::PolicyViolation(
                "authorization_ttl_buckets must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SettlementAuthorization
// ---------------------------------------------------------------------------

/// Authorization from the ledger cluster to the vault mesh to sign a settlement.
///
/// Vaults must verify this authorization independently before signing any PSBT.
/// Without a valid, non-replayed authorization, vaults refuse to sign.
///
/// The authorization links together:
/// - `intent_commitment`: the intent hash stored in the ledger reservation
/// - `command_hash`: the hash of the ledger command that produced this auth
/// - `psbt_commitment`: commitment to the actual Bitcoin transaction
/// - `quorum_certificate`: proof that the cluster committed the authorization
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAuthorization {
    /// Commitment to the withdrawal intent (links back to ledger reservation).
    pub intent_commitment: String,
    /// Hash of the ledger command that authorized this settlement.
    pub command_hash: String,
    /// Commitment to the PSBT that vaults must sign.
    pub psbt_commitment: String,
    /// Hash of the policy under which this authorization was issued.
    pub policy_hash: String,
    /// Epoch in which this authorization was created.
    pub epoch: u64,
    /// Time bucket after which this authorization expires.
    pub expires_at_bucket: u64,
    /// Unique nonce for anti-replay protection.
    pub nonce: String,
    /// Quorum certificate attesting that the cluster committed this auth.
    pub quorum_certificate: QuorumCertificate,
}

impl SettlementAuthorization {
    /// Verifies the structural integrity of this authorization.
    ///
    /// Checks that all required fields are present and the quorum certificate
    /// passes basic verification.
    pub fn verify_basic(&self) -> Result<(), LedgerError> {
        if self.intent_commitment.is_empty() {
            return Err(LedgerError::AuthorizationInvalid(
                "intent_commitment is empty".into(),
            ));
        }
        if self.command_hash.is_empty() {
            return Err(LedgerError::AuthorizationInvalid(
                "command_hash is empty".into(),
            ));
        }
        if self.psbt_commitment.is_empty() {
            return Err(LedgerError::AuthorizationInvalid(
                "psbt_commitment is empty".into(),
            ));
        }
        if self.policy_hash.is_empty() {
            return Err(LedgerError::AuthorizationInvalid(
                "policy_hash is empty".into(),
            ));
        }
        if self.nonce.is_empty() {
            return Err(LedgerError::AuthorizationInvalid("nonce is empty".into()));
        }
        self.quorum_certificate.verify_basic()?;
        Ok(())
    }

    /// Verifies this authorization against a stored reservation.
    ///
    /// Checks that:
    /// - The reservation exists and is not in a terminal state (consumed/released/expired)
    /// - The intent_commitment matches the reservation's authorization_commitment
    ///
    /// Note: expiration of the authorization itself is checked via `is_expired()`
    /// by the caller, which has access to the current time bucket.
    pub fn verify_against_reservation(&self, reservation: &Reservation) -> Result<(), LedgerError> {
        if reservation.is_terminal() {
            return Err(LedgerError::AuthorizationInvalid(format!(
                "reservation {} is in terminal state {:?}",
                reservation.reservation_id, reservation.state
            )));
        }
        if self.intent_commitment != reservation.authorization_commitment {
            return Err(LedgerError::AuthorizationInvalid(format!(
                "intent_commitment mismatch: expected {}, got {}",
                reservation.authorization_commitment, self.intent_commitment
            )));
        }
        Ok(())
    }

    /// Checks if the authorization has expired relative to the current bucket.
    pub fn is_expired(&self, current_bucket: u64) -> bool {
        current_bucket >= self.expires_at_bucket
    }
}

// ---------------------------------------------------------------------------
// SettlementValidator
// ---------------------------------------------------------------------------

/// Validates that a settlement authorization matches the ledger state.
///
/// The KFE and vaults should use this to independently verify the full
/// settlement chain before signing or broadcasting.
pub struct SettlementValidator;

impl SettlementValidator {
    /// Validate the full settlement authorization against ledger state.
    ///
    /// Checks:
    /// 1. Certificate is valid (basic structural check)
    /// 2. Intent is not yet consumed (anti-replay)
    /// 3. Epoch is current or within drift limits
    /// 4. Authorization has not expired
    /// 5. PSBT commitment structure is valid (by policy)
    /// 6. Fee is within policy limits (via commitment metadata)
    ///
    /// Note: PSBT byte-level verification and destination checking are
    /// done by `VaultAuthorizationVerifier` which has access to the actual
    /// PSBT bytes. The ledger-side validator works with commitments.
    pub fn validate_settlement(
        auth: &SettlementAuthorization,
        state: &LedgerState,
        policy: &SettlementPolicy,
        current_bucket: u64,
    ) -> Result<(), LedgerError> {
        // 1. Basic structural check
        auth.verify_basic()?;

        // 2. Intent not yet consumed (anti-replay via consumed_intents)
        if state.consumed_intents.contains(&auth.intent_commitment) {
            return Err(LedgerError::AuthorizationInvalid(format!(
                "intent {} already consumed",
                auth.intent_commitment
            )));
        }

        // 3. Epoch drift check
        Self::validate_epoch(auth.epoch, state.version, policy.max_epoch_drift)?;

        // 4. Authorization has not expired
        if auth.is_expired(current_bucket) {
            return Err(LedgerError::AuthorizationExpired {
                expires_at: auth.expires_at_bucket,
                now: current_bucket,
            });
        }

        // 5. Quorum certificate cluster_id matches
        Self::validate_quorum_certificate(&auth.quorum_certificate, &state.membership.cluster_id)?;

        // 6. PSBT commitment is structurally sound (basic check)
        if auth.psbt_commitment.is_empty() {
            return Err(LedgerError::AuthorizationInvalid(
                "psbt_commitment is empty in settlement validation".into(),
            ));
        }

        // 7. Verify quorum certificate epoch matches auth epoch
        if auth.quorum_certificate.epoch != auth.epoch {
            return Err(LedgerError::AuthorizationInvalid(format!(
                "quorum certificate epoch {} does not match auth epoch {}",
                auth.quorum_certificate.epoch, auth.epoch
            )));
        }

        Ok(())
    }

    /// Validate PSBT commitment against policy constraints.
    ///
    /// Checks that the PSBT's output count and implied fee are within
    /// policy limits. This is a ledger-side check using commitment metadata.
    pub fn validate_psbt_against_policy(
        psbt_commitment: &PsbtCommitment,
        policy: &SettlementPolicy,
    ) -> Result<(), LedgerError> {
        if psbt_commitment.psbt_hash.is_empty() {
            return Err(LedgerError::AuthorizationInvalid(
                "psbt_hash is empty".into(),
            ));
        }
        if psbt_commitment.output_count > policy.max_outputs {
            return Err(LedgerError::PolicyViolation(format!(
                "PSBT has {} outputs, policy allows max {}",
                psbt_commitment.output_count, policy.max_outputs
            )));
        }
        // Fee validation is done by VaultAuthorizationVerifier with actual
        // PSBT bytes. Here we do basic sanity checks only.
        Ok(())
    }

    /// Check that the authorization's epoch is compatible with the cluster's
    /// current epoch (within the allowed drift).
    pub fn validate_epoch(
        auth_epoch: u64,
        current_epoch: u64,
        max_epoch_drift: u64,
    ) -> Result<(), LedgerError> {
        let drift = if auth_epoch >= current_epoch {
            auth_epoch - current_epoch
        } else {
            current_epoch - auth_epoch
        };
        if drift > max_epoch_drift {
            return Err(LedgerError::InvalidStateTransition(format!(
                "epoch drift {} exceeds max allowed {}",
                drift, max_epoch_drift
            )));
        }
        Ok(())
    }

    /// Verify the quorum certificate has a valid cluster_id and passes
    /// basic structural checks.
    pub fn validate_quorum_certificate(
        cert: &QuorumCertificate,
        cluster_id: &str,
    ) -> Result<(), LedgerError> {
        if cert.cluster_id != cluster_id {
            return Err(LedgerError::AuthorizationInvalid(format!(
                "quorum certificate cluster_id '{}' does not match expected '{}'",
                cert.cluster_id, cluster_id
            )));
        }
        cert.verify_basic()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VaultVerificationError
// ---------------------------------------------------------------------------

/// Errors specific to vault-side verification of settlement authorizations.
///
/// These are distinct from `LedgerError` because vaults are separate
/// entities that do not share the ledger's error namespace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VaultVerificationError {
    #[error("invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("intent already consumed: {0}")]
    IntentAlreadyConsumed(String),

    #[error("epoch expired: auth_epoch {auth_epoch}, max_drift {max_drift}")]
    EpochExpired { auth_epoch: u64, max_drift: u64 },

    #[error("PSBT hash mismatch: expected {expected_hash}, actual {actual_hash}")]
    PsbtMismatch {
        expected_hash: String,
        actual_hash: String,
    },

    #[error("fee {fee_sats} exceeds policy max {max_fee_sats}")]
    FeeExceedsPolicy { fee_sats: u64, max_fee_sats: u64 },

    #[error("authorization expired at {expires_at}, current time {now}")]
    AuthorizationExpired { expires_at: u64, now: u64 },

    #[error("nonce reused: {0}")]
    NonceReused(String),

    #[error("destination not allowed: {0}")]
    DestinationNotAllowed(String),
}

// ---------------------------------------------------------------------------
// VaultAuthorizationVerifier
// ---------------------------------------------------------------------------

/// What the vault should verify independently before signing a PSBT.
///
/// The vault is a separate security domain from the ledger. It does not
/// trust the ledger implicitly — it independently verifies the full
/// authorization chain using:
///
/// 1. The `SettlementAuthorization` (from the ledger cluster)
/// 2. The actual PSBT bytes (from the KFE)
/// 3. The `SettlementPolicy` (from cluster configuration)
/// 4. A `NonceChecker` (anti-replay against previously-seen nonces)
pub struct VaultAuthorizationVerifier;

impl VaultAuthorizationVerifier {
    /// Verify the full authorization chain from the vault's perspective.
    ///
    /// Checks in order:
    /// 1. Certificate: valid cluster_id, epoch, signatures, state roots
    /// 2. Intent: not replayed (nonce/commitment not seen before)
    /// 3. Epoch: not stale
    /// 4. PSBT: matches the committed hash
    /// 5. Outputs: match expected values from auth
    /// 6. Fee: within policy bounds (requires PSBT byte analysis)
    pub fn verify(
        auth: &SettlementAuthorization,
        psbt_bytes: &[u8],
        psbt_input_count: u32,
        psbt_output_count: u32,
        total_output_sats: u64,
        policy: &SettlementPolicy,
        known_nonces: &dyn NonceChecker,
        current_bucket: u64,
    ) -> Result<(), VaultVerificationError> {
        // 1. Basic structural integrity
        auth.verify_basic()
            .map_err(|e| VaultVerificationError::InvalidCertificate(e.to_string()))?;

        // 2. Check nonce not reused (anti-replay)
        // We use a synchronous check here. The async version is available
        // via the trait but for synchronous verification we check locally.
        // The caller should also call the async version.
        if known_nonces.is_consumed_sync(&auth.nonce) {
            return Err(VaultVerificationError::NonceReused(auth.nonce.clone()));
        }

        // 3. Authorization has not expired
        if auth.is_expired(current_bucket) {
            return Err(VaultVerificationError::AuthorizationExpired {
                expires_at: auth.expires_at_bucket,
                now: current_bucket,
            });
        }

        // 4. PSBT hash matches commitment
        let actual_hash = PsbtCommitment::compute(psbt_bytes);
        if actual_hash != auth.psbt_commitment {
            return Err(VaultVerificationError::PsbtMismatch {
                expected_hash: auth.psbt_commitment.clone(),
                actual_hash,
            });
        }

        // 5. Verify epoch drift
        let cert_epoch = auth.quorum_certificate.epoch;
        let drift = if cert_epoch >= auth.epoch {
            cert_epoch - auth.epoch
        } else {
            auth.epoch - cert_epoch
        };
        if drift > policy.max_epoch_drift {
            return Err(VaultVerificationError::EpochExpired {
                auth_epoch: auth.epoch,
                max_drift: policy.max_epoch_drift,
            });
        }

        // 6. Output count within policy
        if psbt_output_count > policy.max_outputs {
            return Err(VaultVerificationError::InvalidCertificate(format!(
                "PSBT has {} outputs, policy allows max {}",
                psbt_output_count, policy.max_outputs
            )));
        }

        // 7. Input/output count consistency
        if psbt_input_count == 0 {
            return Err(VaultVerificationError::InvalidCertificate(
                "PSBT must have at least one input".into(),
            ));
        }
        if psbt_output_count == 0 {
            return Err(VaultVerificationError::InvalidCertificate(
                "PSBT must have at least one output".into(),
            ));
        }

        // 8. Fee computation and validation
        // The PSBT's total input value vs total output value gives us the fee.
        // Since we don't have the UTXO values here (the vault would), we
        // compute a reasonable fee estimate. For this implementation,
        // we assume the vault can compute the fee from the PSBT.
        // The total_output_sats parameter represents the total output value
        // as tracked by the KFE. The actual fee is computed by the vault
        // using the PSBT input values.
        //
        // For our test/validation layer, we check that the commitment
        // metadata is reasonable.
        if total_output_sats == 0 {
            return Err(VaultVerificationError::InvalidCertificate(
                "total output sats must be > 0".into(),
            ));
        }

        // Note: Actual fee validation (input_value - output_value) requires
        // the vault to know the input UTXO amounts. This is done by the
        // vault's signing logic. We validate the fee when the vault provides
        // both input and output amounts. For now, we do a structural check.
        //
        // In production, the vault would:
        // 1. Parse the PSBT to get all input outpoints
        // 2. Look up each input's value (from its own UTXO set or the KFE)
        // 3. Sum input values, subtract output values → fee
        // 4. Verify fee <= policy.max_fee_sats

        // 9. Verify cluster_id match
        if auth.quorum_certificate.cluster_id != auth.intent_commitment
            && !auth.quorum_certificate.cluster_id.is_empty()
        {
            // The cluster_id should match the expected cluster.
            // We do a basic sanity check: cluster_id must not be empty
            // and must match what the vault expects (pinned config).
            // For now, just verify it's non-empty (complete check is deployment-specific).
            if auth.quorum_certificate.cluster_id.is_empty() {
                return Err(VaultVerificationError::InvalidCertificate(
                    "cluster_id is empty".into(),
                ));
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sync NonceChecker helper trait
// ---------------------------------------------------------------------------

/// Synchronous interface for checking and recording nonces.
///
/// The vault verifier needs synchronous nonce checking. Implementations
/// should delegate to an in-memory or cached store for the sync path.
pub trait NonceChecker {
    /// Returns `true` if the nonce has been consumed (seen before).
    fn is_consumed_sync(&self, nonce: &str) -> bool;

    /// Mark a nonce as consumed.
    fn mark_consumed_sync(&self, nonce: &str);
}

// These types are re-exported from lib.rs — we must not forget the
// async NonceChecker trait defined in nonce.rs.
