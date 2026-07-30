use std::collections::{HashMap, HashSet};

use parking_lot::RwLock;
use tendermint::abci::{request, response, Code, types::ExecTxResult};
use tracing::{info, warn};

#[cfg(feature = "kerosene-kfe-bridge")]
use kerosene_kfe_bridge::KfeBridge;

use crate::check_tx::{check_tx, CheckTxCtx, Transaction};
use crate::config::CometBftConfig;
use crate::state::AppState;

/// Execute a finalized block — apply validated transactions to the state machine.
///
/// This is called by CometBFT when a block is decided. It processes each
/// transaction in order, applying valid state mutations and recording results.
/// If a KFE bridge is configured, transactions are first validated by the KFE
/// and state transitions are committed through the bridge.
pub async fn finalize_block(
    state: &RwLock<AppState>,
    sender_sequences: &RwLock<HashMap<String, u64>>,
    config: &CometBftConfig,
    req: &request::FinalizeBlock,
    #[cfg(feature = "kerosene-kfe-bridge")] kfe_bridge: Option<&KfeBridge>,
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
        let mut state_writer = state.write();
        state_writer.set_height(height);
    }

    // Optionally delegate to KFE bridge for transaction filtering
    let txs_to_process: Vec<Vec<u8>> = if cfg!(feature = "kerosene-kfe-bridge") {
        #[cfg(feature = "kerosene-kfe-bridge")]
        if let Some(bridge) = kfe_bridge {
            let all_txs_json = req
                .txs
                .iter()
                .map(|tx| String::from_utf8_lossy(tx).to_string())
                .collect::<Vec<_>>()
                .join("\n");
            match bridge.prepare_block(&all_txs_json, height).await {
                Ok(prep_resp) => {
                    if !prep_resp.error.is_empty() {
                        warn!("KFE prepare_block returned error: {}", prep_resp.error);
                    }
                    // Filter to only valid transactions
                    let valid_indices: HashSet<usize> =
                        prep_resp.valid_tx_indices.into_iter().collect();
                    req.txs
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| valid_indices.contains(i))
                        .map(|(_, tx)| tx.to_vec())
                        .collect()
                }
                Err(e) => {
                    warn!("KFE prepare_block failed: {e}; processing all transactions");
                    req.txs.clone()
                }
            }
        } else {
            req.txs.iter().map(|b| b.to_vec()).collect()
        }
        #[cfg(not(feature = "kerosene-kfe-bridge"))]
        req.txs.iter().map(|b| b.to_vec()).collect()
    } else {
        req.txs.iter().map(|b| b.to_vec()).collect()
    };

    // Build authorized keys set from config
    let authorized_keys: HashSet<String> = config.authorized_keys.iter().cloned().collect();

    for (i, tx_bytes) in txs_to_process.iter().enumerate() {
        let check_req = request::CheckTx {
            tx: tx_bytes.clone().into(),
            kind: request::CheckTxKind::New,
        };

        let ctx = CheckTxCtx {
            network_id: &config.network_id,
            sender_sequences,
            authorized_keys: &authorized_keys,
        };

        let check_resp = check_tx(ctx, &check_req);
        if check_resp.code.is_err() {
            warn!(tx_index = i, "transaction failed validation in FinalizeBlock");
            tx_results.push(ExecTxResult {
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
                tx_results.push(ExecTxResult {
                    code: Code::Err(std::num::NonZeroU32::new(1).expect("valid non-zero")),
                    log: format!("parse error: {e}"),
                    ..Default::default()
                });
                continue;
            }
        };

        // Apply the transaction to state with WAL persistence
        let result = match tx.command.as_str() {
            "set" => {
                // Write-ahead log: record mutation before applying
                if let Err(e) = AppState::record_wal_set(&config.state_path, &tx.key, tx.value.as_bytes()) {
                    warn!(tx_index = i, error = %e, "WAL set record failed");
                }
                let mut s = state.write();
                s.apply(&tx.key, tx.value.as_bytes());
                ExecTxResult {
                    code: Code::Ok,
                    ..Default::default()
                }
            }
            "delete" => {
                // Write-ahead log: record deletion before applying
                if let Err(e) = AppState::record_wal_delete(&config.state_path, &tx.key) {
                    warn!(tx_index = i, error = %e, "WAL delete record failed");
                }
                let mut s = state.write();
                s.delete(&tx.key);
                ExecTxResult {
                    code: Code::Ok,
                    ..Default::default()
                }
            }
            _ => {
                ExecTxResult {
                    code: Code::Err(
                        std::num::NonZeroU32::new(5).expect("valid non-zero"),
                    ),
                    log: format!("unknown command: {}", tx.command),
                    ..Default::default()
                }
            }
        };

        tx_results.push(result);

        // Record per-sender sequence number (already reserved in CheckTx)
        sender_sequences.write().insert(tx.public_key.clone(), tx.sequence_number);
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
        network_id: &str,
        sequence_number: u64,
        signing_key: &SigningKey,
    ) -> Vec<u8> {
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
        serde_json::to_vec(&tx).unwrap()
    }

    /// Helper to construct a minimal FinalizeBlock request for testing.
    fn make_finalize_request(txs: Vec<Vec<u8>>, height: u64) -> request::FinalizeBlock {
        use tendermint_proto::v0_38::abci as pb;

        let mut proto = pb::RequestFinalizeBlock::default();
        proto.txs = txs.into_iter().map(Into::into).collect();
        proto.height = height as i64;
        proto.hash = vec![0u8; 32].into();
        proto.time = Some(Default::default());
        proto.next_validators_hash = vec![0u8; 32].into();
        let mut addr = vec![0u8; 20];
        addr[0] = height as u8;
        proto.proposer_address = addr.into();
        proto.decided_last_commit = Some(pb::CommitInfo::default());
        proto.misbehavior = vec![];

        request::FinalizeBlock::try_from(proto).unwrap()
    }

    #[tokio::test]
    async fn finalize_block_applies_transactions() {
        let state = RwLock::new(AppState::new());
        let sender_sequences = RwLock::new(HashMap::new());
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let txs = vec![
            signed_tx_bytes("set", "alice", "100", "testnet", 1, &signing_key),
            signed_tx_bytes("set", "bob", "200", "testnet", 2, &signing_key),
        ];

        let req = make_finalize_request(txs, 1);

        let config = CometBftConfig {
            listen_addr: "unused".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
            kfe_socket_path: None,
            authorized_keys: vec![pub_hex],
        };

        let resp = finalize_block(&state, &sender_sequences, &config, &req).await;

        assert_eq!(resp.tx_results.len(), 2);
        assert!(resp.tx_results[0].code.is_ok());
        assert!(resp.tx_results[1].code.is_ok());

        let s = state.read();
        assert_eq!(s.get("alice"), Some(b"100" as &[u8]));
        assert_eq!(s.get("bob"), Some(b"200" as &[u8]));
        assert_eq!(s.height(), 1);
    }

    #[tokio::test]
    async fn finalize_block_rejects_invalid_tx() {
        let state = RwLock::new(AppState::new());
        let sender_sequences = RwLock::new(HashMap::new());

        let txs = vec![b"invalid json".to_vec()];
        let req = make_finalize_request(txs, 1);

        let config = CometBftConfig {
            listen_addr: "unused".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
            kfe_socket_path: None,
            authorized_keys: Vec::new(),
        };

        let resp = finalize_block(&state, &sender_sequences, &config, &req).await;
        assert_eq!(resp.tx_results.len(), 1);
        assert!(resp.tx_results[0].code.is_err());
    }

    #[tokio::test]
    async fn finalize_block_app_hash_is_deterministic() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let txs = vec![
            signed_tx_bytes("set", "x", "1", "testnet", 1, &signing_key),
            signed_tx_bytes("set", "y", "2", "testnet", 2, &signing_key),
        ];

        let config = CometBftConfig {
            listen_addr: "unused".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
            kfe_socket_path: None,
            authorized_keys: vec![pub_hex.clone()],
        };

        // First execution
        let state1 = RwLock::new(AppState::new());
        let nonces1 = RwLock::new(HashMap::new());
        let req1 = make_finalize_request(txs.clone(), 1);
        let resp1 = finalize_block(&state1, &nonces1, &config, &req1).await;

        // Second execution (same input should produce same app hash)
        let state2 = RwLock::new(AppState::new());
        let nonces2 = RwLock::new(HashMap::new());
        let req2 = make_finalize_request(txs, 1);
        let resp2 = finalize_block(&state2, &nonces2, &config, &req2).await;

        assert_eq!(resp1.app_hash, resp2.app_hash);
    }

    #[tokio::test]
    async fn finalize_block_tracks_sender_sequences() {
        let state = RwLock::new(AppState::new());
        let sender_sequences = RwLock::new(HashMap::new());
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_hex = hex::encode(signing_key.verifying_key().as_bytes());

        let txs = vec![
            signed_tx_bytes("set", "a", "1", "testnet", 1, &signing_key),
            signed_tx_bytes("set", "b", "2", "testnet", 2, &signing_key),
        ];

        let req = make_finalize_request(txs, 1);

        let config = CometBftConfig {
            listen_addr: "unused".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
            kfe_socket_path: None,
            authorized_keys: vec![pub_hex.clone()],
        };

        let _resp = finalize_block(&state, &sender_sequences, &config, &req).await;

        let seqs = sender_sequences.read();
        assert_eq!(seqs.get(&pub_hex), Some(&2u64));
    }
}
