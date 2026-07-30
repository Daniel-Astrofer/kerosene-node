use std::collections::HashSet;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint::abci::{request, response, Code};

/// Context passed to `check_tx` for transaction validation.
pub struct CheckTxCtx<'a> {
    pub network_id: &'a str,
    pub used_nonces: &'a RwLock<HashSet<u64>>,
}

/// The on-wire format for a Kerosene transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// The command to execute (e.g., `"set"`, `"delete"`).
    pub command: String,
    /// The key for the state mutation.
    pub key: String,
    /// The value (base64 or hex encoded, depending on encoding field).
    pub value: String,
    /// Monotonic nonce to prevent replay attacks.
    pub nonce: u64,
    /// Hex-encoded Ed25519 public key of the signer.
    pub public_key: String,
    /// Hex-encoded Ed25519 signature over the canonical signing bytes.
    pub signature: String,
}

impl Transaction {
    /// Compute the canonical bytes to sign (all fields except `signature`).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.command.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.key.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.value.as_bytes());
        hasher.update(b"\x00");
        hasher.update(self.nonce.to_le_bytes());
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
    InvalidNonce(u64),
    InvalidPublicKey,
    InvalidSignature,
    UnknownCommand(String),
}

/// Validate a single transaction via ABCI CheckTx.
///
/// Checks performed:
/// 1. Transaction can be deserialized from JSON
/// 2. Nonce has not been used before (replay protection)
/// 3. Ed25519 signature is valid
/// 4. Command is recognized
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

    // Check nonce replay protection
    let used_nonces = ctx.used_nonces.read();
    if used_nonces.contains(&tx.nonce) {
        return response::CheckTx {
            code: Code::Err(std::num::NonZeroU32::new(2).expect("valid non-zero")),
            log: format!("nonce {} already used", tx.nonce),
            ..Default::default()
        };
    }
    drop(used_nonces);

    // Verify Ed25519 signature
    if let Err(e) = tx.verify() {
        let (code, msg) = match e {
            AppCheckTxError::InvalidPublicKey => (3, "invalid public key".into()),
            AppCheckTxError::InvalidSignature => (3, "invalid signature".into()),
            AppCheckTxError::InvalidNonce(n) => (2, format!("nonce {n} already used")),
            AppCheckTxError::UnknownCommand(cmd) => (5, format!("unknown command: {cmd}")),
            AppCheckTxError::InvalidTxFormat(msg) => (1, msg),
        };
        return response::CheckTx {
            code: Code::Err(std::num::NonZeroU32::new(code).expect("valid non-zero")),
            log: msg,
            ..Default::default()
        };
    }

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
        nonce: u64,
        signing_key: &SigningKey,
    ) -> Transaction {
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let mut tx = Transaction {
            command: command.into(),
            key: key.into(),
            value: value.into(),
            nonce,
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
        let tx = create_signed_tx("set", "alice", "100", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        let used_nonces = RwLock::new(HashSet::new());
        let ctx = CheckTxCtx {
            network_id: "testnet",
            used_nonces: &used_nonces,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_ok(), "expected Ok, got log: {}", resp.log);
    }

    #[test]
    fn duplicate_nonce_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let tx = create_signed_tx("set", "alice", "100", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        let used_nonces = RwLock::new(HashSet::from([1]));
        let ctx = CheckTxCtx {
            network_id: "testnet",
            used_nonces: &used_nonces,
        };
        let req = request::CheckTx {
            tx: tx_bytes.into(),
            kind: request::CheckTxKind::New,
        };
        let resp = check_tx(ctx, &req);
        assert!(resp.code.is_err(), "should reject duplicate nonce");
        assert!(resp.log.contains("nonce 1"), "log: {}", resp.log);
    }

    #[test]
    fn invalid_signature_rejected() {
        let signing_key1 = SigningKey::generate(&mut OsRng);
        let mut tx = create_signed_tx("set", "alice", "100", 1, &signing_key1);
        // Tamper with the signature
        tx.signature = hex::encode([0u8; 64]);

        let tx_bytes = serde_json::to_vec(&tx).unwrap();
        let used_nonces = RwLock::new(HashSet::new());
        let ctx = CheckTxCtx {
            network_id: "testnet",
            used_nonces: &used_nonces,
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
        let tx = create_signed_tx("unknown_cmd", "key", "value", 1, &signing_key);
        let tx_bytes = serde_json::to_vec(&tx).unwrap();

        let used_nonces = RwLock::new(HashSet::new());
        let ctx = CheckTxCtx {
            network_id: "testnet",
            used_nonces: &used_nonces,
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
        let used_nonces = RwLock::new(HashSet::new());
        let ctx = CheckTxCtx {
            network_id: "testnet",
            used_nonces: &used_nonces,
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
            nonce: 42,
            public_key: "abcd".into(),
            signature: "sig".into(),
        };
        let tx2 = Transaction {
            command: "set".into(),
            key: "foo".into(),
            value: "bar".into(),
            nonce: 42,
            public_key: "abcd".into(),
            signature: "sig".into(),
        };
        assert_eq!(tx1.signing_bytes(), tx2.signing_bytes());
    }
}
