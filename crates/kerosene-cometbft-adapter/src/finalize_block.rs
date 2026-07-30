use std::collections::HashSet;

use parking_lot::RwLock;
use tendermint::abci::{request, response, Code};
use tracing::{info, warn};

use crate::check_tx::{check_tx, CheckTxCtx, Transaction};
use crate::config::CometBftConfig;
use crate::state::AppState;

/// Execute a finalized block — apply validated transactions to the state machine.
///
/// This is called by CometBFT when a block is decided. It processes each
/// transaction in order, applying valid state mutations and recording results.
pub fn finalize_block(
    state: &RwLock<AppState>,
    used_nonces: &RwLock<HashSet<u64>>,
    config: &CometBftConfig,
    req: &request::FinalizeBlock,
) -> response::FinalizeBlock {
    let height: u64 = u64::from(req.height);
    let mut tx_results = Vec::with_capacity(req.txs.len());

    info!(
        height = height,
        tx_count = req.txs.len(),
        "FinalizeBlock"
    );

    // Begin block: set height
    {
        let mut s = state.write();
        s.set_height(height);
    }

    for (i, tx_bytes) in req.txs.iter().enumerate() {
        let check_req = request::CheckTx {
            tx: tx_bytes.clone(),
            kind: request::CheckTxKind::New,
        };

        let ctx = CheckTxCtx {
            network_id: &config.network_id,
            used_nonces,
        };

        let check_resp = check_tx(ctx, &check_req);

        if check_resp.code.is_err() {
            warn!(
                tx_index = i,
                log = %check_resp.log,
                "transaction rejected in FinalizeBlock"
            );
            tx_results.push(response::ExecTxResult {
                code: check_resp.code,
                log: check_resp.log,
                ..Default::default()
            });
            continue;
        }

        // Parse the transaction to apply it
        let tx: Transaction = match serde_json::from_slice(tx_bytes) {
            Ok(tx) => tx,
            Err(e) => {
                warn!(tx_index = i, error = %e, "failed to parse tx in FinalizeBlock");
                tx_results.push(response::ExecTxResult {
                    code: Code::Err(std::num::NonZeroU32::new(1).expect("valid non-zero")),
                    log: format!("parse error: {e}"),
                    ..Default::default()
                });
                continue;
            }
        };

        // Apply the transaction to state
        let result = match tx.command.as_str() {
            "set" => {
                let mut s = state.write();
                s.apply(&tx.key, tx.value.as_bytes());
                response::ExecTxResult {
                    code: Code::Ok,
                    ..Default::default()
                }
            }
            "delete" => {
                let mut s = state.write();
                if s.delete(&tx.key).is_some() {
                    response::ExecTxResult {
                        code: Code::Ok,
                        ..Default::default()
                    }
                } else {
                    response::ExecTxResult {
                        code: Code::Err(
                            std::num::NonZeroU32::new(4).expect("valid non-zero"),
                        ),
                        log: format!("key not found: {}", tx.key),
                        ..Default::default()
                    }
                }
            }
            _ => {
                response::ExecTxResult {
                    code: Code::Err(
                        std::num::NonZeroU32::new(5).expect("valid non-zero"),
                    ),
                    log: format!("unknown command: {}", tx.command),
                    ..Default::default()
                }
            }
        };

        tx_results.push(result);

        // Record nonce to prevent replay
        used_nonces.write().insert(tx.nonce);
    }

    // Compute app hash after all transactions are applied
    let app_hash = {
        let s = state.read();
        let hash = s.root_hash();
        tendermint::AppHash::try_from(hash.to_vec()).unwrap_or_default()
    };

    info!(
        height = height,
        tx_count = req.txs.len(),
        app_hash = %app_hash,
        "FinalizeBlock complete"
    );

    response::FinalizeBlock {
        tx_results,
        app_hash,
        events: Vec::new(),
        validator_updates: Vec::new(),
        consensus_param_updates: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check_tx::Transaction;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn signed_tx_bytes(
        command: &str,
        key: &str,
        value: &str,
        nonce: u64,
        signing_key: &SigningKey,
    ) -> Vec<u8> {
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
        serde_json::to_vec(&tx).unwrap()
    }

    /// Helper to construct a minimal FinalizeBlock request for testing.
    fn make_finalize_request(txs: Vec<Vec<u8>>, height: u64) -> request::FinalizeBlock {
        use tendermint_proto::v0_38::abci as pb;
        use tendermint_proto::Protobuf;

        let mut proto = pb::RequestFinalizeBlock::default();
        proto.txs = txs.into_iter().map(Into::into).collect();
        proto.height = height as i64;
        proto.hash = vec![0u8; 32];
        proto.time = Some(Default::default());
        proto.next_validators_hash = vec![0u8; 32];
        let mut addr = vec![0u8; 20];
        addr[0] = height as u8;
        proto.proposer_address = addr;
        proto.decided_last_commit = Some(pb::CommitInfo::default());
        proto.misbehavior = vec![];

        request::FinalizeBlock::try_from(proto).unwrap()
    }

    #[test]
    fn finalize_block_applies_transactions() {
        let state = RwLock::new(AppState::new());
        let used_nonces = RwLock::new(HashSet::new());
        let signing_key = SigningKey::generate(&mut OsRng);

        let txs = vec![
            signed_tx_bytes("set", "alice", "100", 1, &signing_key),
            signed_tx_bytes("set", "bob", "200", 2, &signing_key),
        ];

        let req = make_finalize_request(txs, 1);

        let config = CometBftConfig {
            listen_addr: "unused".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
        };

        let resp = finalize_block(&state, &used_nonces, &config, &req);

        assert_eq!(resp.tx_results.len(), 2);
        assert!(resp.tx_results[0].code.is_ok());
        assert!(resp.tx_results[1].code.is_ok());

        let s = state.read();
        assert_eq!(s.get("alice"), Some(b"100" as &[u8]));
        assert_eq!(s.get("bob"), Some(b"200" as &[u8]));
        assert_eq!(s.height(), 1);
    }

    #[test]
    fn finalize_block_rejects_invalid_tx() {
        let state = RwLock::new(AppState::new());
        let used_nonces = RwLock::new(HashSet::new());

        let txs = vec![b"invalid json".to_vec()];
        let req = make_finalize_request(txs, 1);

        let config = CometBftConfig {
            listen_addr: "unused".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
        };

        let resp = finalize_block(&state, &used_nonces, &config, &req);
        assert_eq!(resp.tx_results.len(), 1);
        assert!(resp.tx_results[0].code.is_err());
    }

    #[test]
    fn finalize_block_app_hash_is_deterministic() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let txs = vec![
            signed_tx_bytes("set", "x", "1", 1, &signing_key),
            signed_tx_bytes("set", "y", "2", 2, &signing_key),
        ];

        let config = CometBftConfig {
            listen_addr: "unused".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
        };

        // First execution
        let state1 = RwLock::new(AppState::new());
        let nonces1 = RwLock::new(HashSet::new());
        let req1 = make_finalize_request(txs.clone(), 1);
        let resp1 = finalize_block(&state1, &nonces1, &config, &req1);

        // Second execution (same input should produce same app hash)
        let state2 = RwLock::new(AppState::new());
        let nonces2 = RwLock::new(HashSet::new());
        let req2 = make_finalize_request(txs, 1);
        let resp2 = finalize_block(&state2, &nonces2, &config, &req2);

        assert_eq!(resp1.app_hash, resp2.app_hash);
    }
}
