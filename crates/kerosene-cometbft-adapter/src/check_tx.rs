use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint::abci::{request, response, Code};

/// Context passed to `check_tx` for transaction validation.
pub struct CheckTxCtx<'a> {
    pub network_id: &'a str,
    pub sender_sequences: &'a RwLock<HashMap<String, u64>>,
    pub authorized_keys: &'a HashSet<String>,
}

/// The on-wire format for a Kerosene transaction.
///
/// Security properties:
/// - `network_id` prevents replay across networks
/// - `sequence_number` provides per-sender replay protection (replaces global nonce)
/// - `public_key` identifies the sender and must belong to the authorized set
/// - `signature` covers all other fields via `signing_bytes()`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// The command to execute (e.g., `"set"`, `"delete"`).
    pub command: String,
    /// The key for the state mutation.
    pub key: String,
    /// The value (base64 or hex encoded, depending on encoding field).
    pub value: String,
    /// The network this transaction is intended for (prevents cross-network replay).
    pub network_id: String,
    /// Per-sender monotonic sequence number (prevents replay within network).
    pub sequence_number: u64,
    /// Hex-encoded Ed25519 public key of the signer.
    pub public_key: String,
    /// Hex-encoded Ed25519 signature over the canonical signing bytes.
    pub signature: String,
}

impl Transaction {
    /// Compute the canonical bytes to sign.
    ///
    /// Includes all fields except `signature`:
    /// `command || key || value || network_id || sequence_number || public_key`
    ///
    /// Including `network_id` prevents replay attacks across different networks.
    /// Including `sequence_number` binds the signature to a specific sender sequence.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.command.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.key.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.value.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.network_id.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.sequence_number.to_le_bytes());
        hasher.update(b"\x00");
        hasher.update(self.public_key.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Verify the Ed25519 signature on this transaction.
    pub fn verify(&self) -> Result<(), AppCheckTxError> {
        let public_bytes = hex::decode(&self.public_key)
            .map_err(|_| AppCheckTxError::InvalidPublicKey)?;
        let verifying_key = VerifyingKey::from_bytes(
            &public_bytes.try_into().map_err(|_| AppCheckTxError::InvalidPublicKey)?,
        )
        .map_err(|_| AppCheckTxError::InvalidPublicKey)?;

        let sig_bytes = hex::decode(&self.signature)
            .map_err(|_| AppCheckTxError::InvalidSignature)?;
        let signature = Signature::from_bytes(
            &sig_bytes.try_into().map_err(|_| AppCheckTxError::InvalidSignature)?,
        );

        let msg = self.signing_bytes();
        verifying_key
            .verify(&msg, &signature)
            .map_err(|_| AppCheckTxError::InvalidSignature)
    }
}

/// Errors that can occur during transaction checking.
#[derive(Debug)]
pub enum AppCheckTxError {
    InvalidTxFormat(String),
    InvalidSequence {
        sender: String,
        expected: u64,
        actual: u64,
    },
    InvalidPublicKey,
    InvalidSignature,
    UnauthorizedKey(String),
    NetworkMismatch {
        expected: String,
        actual: String,
    },
    UnknownCommand(String),
}

/// Validate a single transaction via ABCI CheckTx.
///
/// Checks performed:
/// 1. Transaction can be deserialized from JSON
/// 2. `network_id` matches the local network (cross-network replay protection)
/// 3. `public_key` is in the authorized keys set (membership authorization)
/// 4. `sequence_number` > last seen for this sender (per-sender replay protection)
/// 5. Ed25519 signature is valid
/// 6. Command is recognized
pub fn check_tx(ctx: CheckTxCtx<'_>, req: &request::CheckTx) -> response::CheckTx {
    let tx: Transaction = match serde_json::from_slice(&req.tx) {
        Ok(tx) => tx,
        Err(e) => {
            return response::CheckTx {
                code: Code::Err(std::num::NonZeroU32::new(1).expect("valid non-zero")),
                log: format!("invalid transaction format: {e}"),
                ..Default::default()
            };
        }
    };

    // Validate network_id matches
    if tx.network_id != ctx.network_id {
        return response::CheckTx {
            code: Code::Err(std::num::NonZeroU32::new(8).expect("valid non-zero")),
            log: format!(
                "network mismatch: expected '{}', got '{}'",
                ctx.network_id, tx.network_id
            ),
            ..Default::default()
        };
    }

    // Validate command is known
    match tx.command.as_str() {
        "set" | "delete" => {}
        other => {
            return response::CheckTx {
                code: Code::Err(std::num::NonZeroU32::new(5).expect("valid non-zero")),
                log: format!("unknown command: {other}"),
                ..Default::default()
            };
        }
    }

    // Check sender is authorized (membership authorization)
    if !ctx.authorized_keys.is_empty() && !ctx.authorized_keys.contains(&tx.public_key) {
        return response::CheckTx {
            code: Code::Err(
                std::num::NonZeroU32::new(9).expect("valid non-zero"),
            ),
            log: format!("unauthorized key: {}", tx.public_key),
            ..Default::default()
        };
    }

    // Verify Ed25519 signature
    if let Err(e) = tx.verify() {
        let (code, msg) = match &e {
            AppCheckTxError::InvalidPublicKey => (3, "invalid public key".into()),
            AppCheckTxError::InvalidSignature => (3, "invalid signature".into()),
            AppCheckTxError::UnauthorizedKey(key) => {
                (9, format!("unauthorized key: {key}"))
            }
            AppCheckTxError::NetworkMismatch { expected, actual } => {
                (8, format!("network mismatch: expected {expected}, got {actual}"))
            }
            AppCheckTxError::InvalidSequence { sender, expected, actual } => {
                (2, format!("{sender}: expected seq > {expected}, got {actual}"))
            }
            AppCheckTxError::UnknownCommand(cmd) => (5, format!("unknown command: {cmd}")),
            AppCheckTxError::InvalidTxFormat(msg) => (1, msg.clone()),
        };
        return response::CheckTx {
            code: Code::Err(std::num::NonZeroU32::new(code).expect("valid non-zero")),
            log: msg,
            ..Default::default()
        };
    }

    // Check per-sender sequence number (replaces global nonce)
    let mut sequences = ctx.sender_sequences.write();
    let last_seq = sequences.get(&tx.public_key).copied().unwrap_or(0);
    if tx.sequence_number <= last_seq {
        return response::CheckTx {
            code: Code::Err(std::num::NonZeroU32::new(2).expect("valid non-zero")),
            log: format!(
                "{}: expected seq > {last_seq}, got {}",
                tx.public_key, tx.sequence_number
            ),
            ..Default::default()
        };
    }
    // Reserve the sequence number — don't increment yet, FinalizeBlock will commit it.
    // We record it here to prevent the next CheckTx call (mempool) from accepting a duplicate.
    sequences.insert(tx.public_key.clone(), tx.sequence_number);
    drop(sequences);

    response::CheckTx {
        code: Code::Ok,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn create_signed_tx(
        command: &str,
        key: &str,
        value: &str,
        network_id: &str,
        sequence_number: u64,
        signing_key: &SigningKey,
    ) -> Transaction {
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let mut tx = Transaction {
            command: command.into(),
            key: key.into(),
            value: value.into(),
            network_id: network_id.into(),
            sequence_number,
            public_key,
            signature: String::new(),
        };
        let msg = tx.signing_bytes();
        let sig = signing_key.sign(&msg);
        tx.signature = hex::encode(sig.to_bytes());
        tx
    }

    #[test]
    fn valid_transaction_passes_check_tx() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let tx = create_signed_tx("set", "alice", "100", "testnet", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        let sender_sequences = RwLock::new(HashMap::new());
        let authorized_keys: HashSet<String> = [pub_hex].into_iter().collect();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_ok(), "expected Ok, got log: {}", resp.log);
    }

    #[test]
    fn network_mismatch_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let tx = create_signed_tx("set", "alice", "100", "othernet", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        let sender_sequences = RwLock::new(HashMap::new());
        let authorized_keys: HashSet<String> = [pub_hex].into_iter().collect();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_err(), "should reject network mismatch");
        assert!(resp.log.contains("network mismatch"));
    }

    #[test]
    fn duplicate_sequence_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let tx = create_signed_tx("set", "alice", "100", "testnet", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        let sender_sequences = RwLock::new(HashMap::from([(pub_hex.clone(), 1u64)]));
        let authorized_keys: HashSet<String> = [pub_hex].into_iter().collect();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_err(), "should reject duplicate sequence");
        assert!(resp.log.contains("expected seq > 1"));
    }

    #[test]
    fn out_of_order_sequence_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());

        // seq=5 passes when last seq=0
        let tx5 = create_signed_tx("set", "k", "v", "testnet", 5, &signing_key);
        let tx5_bytes = serde_json::to_vec(&tx5).unwrap();
        let sender_sequences = RwLock::new(HashMap::new());
        let authorized_keys: HashSet<String> = [pub_hex.clone()].into_iter().collect();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req5 = request::CheckTx {
            tx: tx5_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp5 = check_tx(ctx, &req5);
        assert!(resp5.code.is_ok());

        // seq=3 is now out of order (last is 5)
        let tx3 = create_signed_tx("set", "k", "v", "testnet", 3, &signing_key);
        let tx3_bytes = serde_json::to_vec(&tx3).unwrap();
        let sender_sequences = RwLock::new(HashMap::from([(pub_hex.clone(), 5u64)]));
        let authorized_keys: HashSet<String> = [pub_hex].into_iter().collect();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req3 = request::CheckTx {
            tx: tx3_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp3 = check_tx(ctx, &req3);
        assert!(resp3.code.is_err(), "should reject out-of-order seq");
    }

    #[test]
    fn unauthorized_key_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let tx = create_signed_tx("set", "alice", "100", "testnet", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        // Authorized keys does NOT include this key
        let other_key = SigningKey::generate(&mut OsRng);
        let other_pub_hex = hex::encode(other_key.verifying_key().as_bytes());
        let sender_sequences = RwLock::new(HashMap::new());
        let authorized_keys: HashSet<String> = [other_pub_hex].into_iter().collect();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_err(), "should reject unauthorized key");
        assert!(resp.log.contains("unauthorized key"));
    }

    #[test]
    fn empty_authorized_set_accepts_all() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let tx = create_signed_tx("set", "alice", "100", "testnet", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        let sender_sequences = RwLock::new(HashMap::new());
        let authorized_keys: HashSet<String> = HashSet::new(); // empty = no restriction
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_ok(), "empty set should allow all keys");
    }

    #[test]
    fn invalid_signature_rejected() {
        let signing_key1 = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key1.verifying_key().as_bytes());
        let mut tx = create_signed_tx("set", "alice", "100", "testnet", 1, &signing_key1);
        // Tamper with the signature
        tx.signature = hex::encode([0u8; 64]);

        let tx_bytes = serde_json::to_vec(&tx).unwrap();
        let sender_sequences = RwLock::new(HashMap::new());
        let authorized_keys: HashSet<String> = [pub_hex].into_iter().collect();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_err(), "should reject invalid signature");
    }

    #[test]
    fn unknown_command_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let tx = create_signed_tx("unknown_cmd", "key", "value", "testnet", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        let sender_sequences = RwLock::new(HashMap::new());
        let authorized_keys: HashSet<String> = [pub_hex].into_iter().collect();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_err(), "should reject unknown command");
        assert!(resp.log.contains("unknown command"));
    }

    #[test]
    fn malformed_json_rejected() {
        let sender_sequences = RwLock::new(HashMap::new());
        let authorized_keys: HashSet<String> = HashSet::new();
        let ctx = CheckTxCtx {
            network_id: "testnet",
            sender_sequences: &sender_sequences,
            authorized_keys: &authorized_keys,
        };
        let req = request::CheckTx {
            tx: b"not valid json".to_vec().into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_err(), "should reject malformed tx");
    }

    #[test]
    fn signing_bytes_are_deterministic() {
        let tx1 = Transaction {
            command: "set".into(),
            key: "foo".into(),
            value: "bar".into(),
            network_id: "testnet".into(),
            sequence_number: 42,
            public_key: "abcd".into(),
            signature: "sig".into(),
        };
        let tx2 = Transaction {
            command: "set".into(),
            key: "foo".into(),
            value: "bar".into(),
            network_id: "testnet".into(),
            sequence_number: 42,
            public_key: "abcd".into(),
            signature: "sig".into(),
        };
        assert_eq!(tx1.signing_bytes(), tx2.signing_bytes());
    }

    #[test]
    fn signing_bytes_differ_by_network_id() {
        let tx_a = Transaction {
            command: "set".into(),
            key: "foo".into(),
            value: "bar".into(),
            network_id: "net-a".into(),
            sequence_number: 42,
            public_key: "abcd".into(),
            signature: "sig".into(),
        };
        let tx_b = Transaction {
            command: "set".into(),
            key: "foo".into(),
            value: "bar".into(),
            network_id: "net-b".into(),
            sequence_number: 42,
            public_key: "abcd".into(),
            signature: "sig".into(),
        };
        assert_ne!(tx_a.signing_bytes(), tx_b.signing_bytes());
    }

    #[test]
    fn signing_bytes_differ_by_sequence_number() {
        let tx1 = Transaction {
            command: "set".into(),
            key: "foo".into(),
            value: "bar".into(),
            network_id: "testnet".into(),
            sequence_number: 1,
            public_key: "abcd".into(),
            signature: "sig".into(),
        };
        let tx2 = Transaction {
            command: "set".into(),
            key: "foo".into(),
            value: "bar".into(),
            network_id: "testnet".into(),
            sequence_number: 2,
            public_key: "abcd".into(),
            signature: "sig".into(),
        };
        assert_ne!(tx1.signing_bytes(), tx2.signing_bytes());
    }
}
