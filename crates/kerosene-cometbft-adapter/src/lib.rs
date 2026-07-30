pub mod check_tx;
pub mod commit;
pub mod config;
pub mod error;
pub mod finalize_block;
pub mod state;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::RwLock;
use tendermint::abci::{request, response, Code, Request, Response};
use tower::Service;
use tracing::{info, warn};

#[cfg(feature = "kerosene-kfe-bridge")]
use kerosene_kfe_bridge::KfeBridge;

use crate::check_tx::{check_tx, CheckTxCtx};
use crate::commit::commit_state;
use crate::config::CometBftConfig;
use crate::finalize_block::finalize_block;
use crate::state::AppState;

/// The core ABCI application for the Kerosene node.
///
/// Implements `tower::Service<Request>` for use with `tower-abci`.
/// The service processes all ABCI request categories (consensus, mempool,
/// info, snapshot) and delegates to per-method handlers.
///
/// # Persistence
/// On construction with `new()` or `with_state()`, the app attempts to
/// recover the last committed state from the sled database at `state_path`.
/// Every `Commit` persists a full snapshot to sled.
///
/// # Security
/// Transactions are validated for:
/// - Ed25519 signature against the signer's public key
/// - Membership authorization (public key must be in `authorized_keys`)
/// - Network identity (network_id must match)
/// - Per-sender sequence number replay protection
#[derive(Clone)]
pub struct AbciApp {
    inner: Arc<AbciAppInner>,
}

struct AbciAppInner {
    state: RwLock<AppState>,
    config: CometBftConfig,
    sender_sequences: RwLock<HashMap<String, u64>>,
    authorized_keys: RwLock<HashSet<String>>,
    #[cfg(feature = "kerosene-kfe-bridge")]
    kfe_bridge: Option<KfeBridge>,
}

impl AbciApp {
    /// Create a new ABCI application with the given config.
    ///
    /// Attempts to recover state from the sled database at `config.state_path`.
    /// If no persisted state is found, starts with an empty state.
    pub fn new(config: CometBftConfig) -> Self {
        // Attempt recovery from sled persistent storage
        let state = AppState::recover(&config.state_path).unwrap_or_else(|e| {
            warn!(error = %e, "State recovery failed; starting fresh");
            AppState::new()
        });

        let recovered_height = state.height();
        info!(
            transport = ?config.transport,
            addr = %config.listen_addr,
            height = recovered_height,
            authorized_keys = config.authorized_keys.len(),
            kfe = config.kfe_socket_path.is_some(),
            "ABCI application initialized"
        );

        let authorized_keys: HashSet<String> =
            config.authorized_keys.iter().cloned().collect();

        #[cfg(feature = "kerosene-kfe-bridge")]
        let kfe_bridge = config.kfe_socket_path.as_ref().map(|path| {
            info!(socket = %path, "KFE bridge configured");
            KfeBridge::new(path.clone())
        });

        Self {
            inner: Arc::new(AbciAppInner {
                state: RwLock::new(state),
                config,
                sender_sequences: RwLock::new(HashMap::new()),
                authorized_keys: RwLock::new(authorized_keys),
                #[cfg(feature = "kerosene-kfe-bridge")]
                kfe_bridge,
            }),
        }
    }

    /// Create a new ABCI application with a pre-loaded state (from snapshot).
    pub fn with_state(config: CometBftConfig, state: AppState) -> Self {
        let authorized_keys: HashSet<String> =
            config.authorized_keys.iter().cloned().collect();

        info!(
            transport = ?config.transport,
            addr = %config.listen_addr,
            height = state.height(),
            "ABCI application restored from snapshot"
        );

        #[cfg(feature = "kerosene-kfe-bridge")]
        let kfe_bridge = config.kfe_socket_path.as_ref().map(|path| {
            info!(socket = %path, "KFE bridge configured");
            KfeBridge::new(path.clone())
        });

        Self {
            inner: Arc::new(AbciAppInner {
                state: RwLock::new(state),
                config,
                sender_sequences: RwLock::new(HashMap::new()),
                authorized_keys: RwLock::new(authorized_keys),
                #[cfg(feature = "kerosene-kfe-bridge")]
                kfe_bridge,
            }),
        }
    }

    /// Access the application configuration.
    pub fn config(&self) -> &CometBftConfig {
        &self.inner.config
    }

    /// Access the current state (for inspection, not mutation).
    pub fn state(&self) -> AppState {
        self.inner.state.read().clone()
    }

    /// Update the set of authorized public keys (membership change).
    ///
    /// This is called when the membership set changes (e.g., via joint consensus).
    /// Keys not in this set will have their transactions rejected by CheckTx.
    pub fn set_authorized_keys(&self, keys: HashSet<String>) {
        let mut auth = self.inner.authorized_keys.write();
        *auth = keys;
        info!("Authorized keys updated ({} entries)", auth.len());
    }

    /// Get the current set of authorized public keys.
    pub fn authorized_keys(&self) -> HashSet<String> {
        self.inner.authorized_keys.read().clone()
    }

    /// Record a sender's sequence number (for recovery).
    pub fn record_sender_sequence(&self, sender: String, seq: u64) {
        self.inner
            .sender_sequences
            .write()
            .insert(sender, seq);
    }

    /// Get the current application hash (SHA-256 of state root).
    pub fn app_hash(&self) -> [u8; 32] {
        self.inner.state.read().root_hash()
    }

    /// Handle ABCI InitChain — initializes the blockchain state.
    fn handle_init_chain(&self, _req: request::InitChain) -> response::InitChain {
        info!("InitChain called");
        let app_hash = self.inner.state.read().root_hash();
        response::InitChain {
            app_hash: tendermint::AppHash::try_from(app_hash.to_vec())
                .unwrap_or_default(),
            ..Default::default()
        }
    }

    /// Handle ABCI Info — returns application info.
    fn handle_info(&self, _req: request::Info) -> response::Info {
        let state = self.inner.state.read();
        let app_hash = state.root_hash();
        response::Info {
            data: "kerosene-cometbft-adapter".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            app_version: state.app_version(),
            last_block_height: tendermint::block::Height::try_from(state.height())
                .unwrap_or_default(),
            last_block_app_hash: tendermint::AppHash::try_from(app_hash.to_vec())
                .unwrap_or_default(),
        }
    }

    /// Handle ABCI Query — simple key-value query.
    fn handle_query(&self, req: request::Query) -> response::Query {
        let key = String::from_utf8_lossy(&req.data).to_string();
        let state = self.inner.state.read();
        let value = state.get(&key).map(|v| v.to_vec());
        match value {
            Some(data) => response::Query {
                code: Code::Ok,
                key: req.data.clone(),
                value: data.into(),
                ..Default::default()
            },
            None => response::Query {
                code: Code::Err(
                    std::num::NonZeroU32::new(1).expect("valid non-zero"),
                ),
                log: format!("key not found: {key}"),
                ..Default::default()
            },
        }
    }
}

impl Service<Request> for AbciApp {
    type Response = Response;
    type Error = tower_abci::BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let self_clone = self.clone();
        Box::pin(async move {
            match req {
                Request::Echo(echo_req) => {
                    Ok(Response::Echo(response::Echo {
                        message: echo_req.message,
                    }))
                }
                Request::Flush => Ok(Response::Flush),
                Request::Info(info_req) => {
                    Ok(Response::Info(self_clone.handle_info(info_req)))
                }
                Request::InitChain(init_chain_req) => {
                    Ok(Response::InitChain(
                        self_clone.handle_init_chain(init_chain_req),
                    ))
                }
                Request::Query(query_req) => {
                    Ok(Response::Query(self_clone.handle_query(query_req)))
                }
                Request::CheckTx(check_tx_req) => {
                    // Optionally validate against KFE bridge first
                    #[cfg(feature = "kerosene-kfe-bridge")]
                    if let Some(bridge) = &self_clone.inner.kfe_bridge {
                        let tx_str = String::from_utf8_lossy(&check_tx_req.tx);
                        match bridge.check_transaction(&tx_str).await {
                            Ok(resp) => {
                                if !resp.allowed {
                                    return Ok(Response::CheckTx(response::CheckTx {
                                        code: Code::Err(
                                            std::num::NonZeroU32::new(6).expect("valid non-zero"),
                                        ),
                                        log: format!("KFE rejected transaction: {}", resp.reason),
                                        ..Default::default()
                                    }));
                                }
                            }
                            Err(e) => {
                                warn!("KFE check_transaction failed: {e}; proceeding with local check");
                            }
                        }
                    }

                    let ctx = CheckTxCtx {
                        network_id: &self_clone.inner.config.network_id,
                        sender_sequences: &self_clone.inner.sender_sequences,
                        authorized_keys: &self_clone.inner.authorized_keys.read(),
                    };
                    let resp = check_tx(ctx, &check_tx_req);
                    Ok(Response::CheckTx(resp))
                }
                Request::FinalizeBlock(finalize_req) => {
                    let resp = finalize_block(
                        &self_clone.inner.state,
                        &self_clone.inner.sender_sequences,
                        &self_clone.inner.config,
                        &finalize_req,
                        #[cfg(feature = "kerosene-kfe-bridge")]
                        self_clone.inner.kfe_bridge.as_ref(),
                    )
                    .await;
                    Ok(Response::FinalizeBlock(resp))
                }
                Request::Commit => {
                    let resp = commit_state(
                        &self_clone.inner.state,
                        &self_clone.inner.config.state_path,
                    );
                    Ok(Response::Commit(resp))
                }
                // Snapshot methods — not yet supported
                Request::ListSnapshots => {
                    Ok(Response::ListSnapshots(response::ListSnapshots::default()))
                }
                Request::OfferSnapshot(_) => {
                    Ok(Response::OfferSnapshot(response::OfferSnapshot::default()))
                }
                Request::LoadSnapshotChunk(_) => {
                    Ok(Response::LoadSnapshotChunk(
                        response::LoadSnapshotChunk::default(),
                    ))
                }
                Request::ApplySnapshotChunk(_) => {
                    Ok(Response::ApplySnapshotChunk(
                        response::ApplySnapshotChunk::default(),
                    ))
                }
                // Proposal & vote extensions
                Request::PrepareProposal(req) => {
                    warn!("PrepareProposal called but not implemented");
                    Ok(Response::PrepareProposal(
                        response::PrepareProposal {
                            txs: req.txs,
                        },
                    ))
                }
                Request::ProcessProposal(_) => {
                    Ok(Response::ProcessProposal(
                        response::ProcessProposal::Accept,
                    ))
                }
                Request::ExtendVote(_) => {
                    Ok(Response::ExtendVote(response::ExtendVote {
                        vote_extension: vec![].into(),
                    }))
                }
                Request::VerifyVoteExtension(_) => {
                    Ok(Response::VerifyVoteExtension(
                        response::VerifyVoteExtension::Accept,
                    ))
                }
            }
        })
    }
}

/// Run the ABCI server, blocking the current task.
///
/// This creates the split services, wraps them with appropriate Tower layers,
/// and starts the tower-abci server.
pub async fn run_abci_server(app: AbciApp) -> Result<(), tower_abci::BoxError> {
    let config = app.config().clone();
    let listen_addr = config.listen_addr.clone();

    // Split the single ABCI service into four category services.
    // The bound parameter (10) controls internal channel capacity.
    // Note: split::service returns (Consensus, Mempool, Snapshot, Info).
    let (consensus, mempool, snapshot, info) = tower_abci::v038::split::service(app, 10);

    let server = tower_abci::v038::ServerBuilder::default()
        .consensus(consensus)
        .mempool(mempool)
        .info(info)
        .snapshot(snapshot)
        .finish()
        .ok_or_else(|| "failed to build ABCI server: missing service".to_string())?;

    info!(addr = %listen_addr, "Starting ABCI server");

    match config.transport {
        config::CometBftTransport::Unix => {
            let _ = std::fs::remove_file(&listen_addr);
            server.listen_unix(&listen_addr).await
        }
        config::CometBftTransport::Tcp => {
            server.listen_tcp(&listen_addr).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
        fn test_config() -> CometBftConfig {
        CometBftConfig {
            listen_addr: "/tmp/test-abci.sock".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp/test-abci-state"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
            kfe_socket_path: None,
            authorized_keys: Vec::new(),
        }
    }

    #[test]
    fn app_initializes_with_default_state() {
        // Use a unique directory to avoid sled contamination between tests
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.state_path = dir.path().join("abci.db");
        let app = AbciApp::new(config);
        let state = app.state();
        assert!(state.is_empty());
        assert_eq!(state.height(), 0);
    }

    #[test]
    fn app_recovery_from_sled() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("recovery.db");

        // Create and persist state
        {
            let mut config = test_config();
            config.state_path = state_path.clone();
            let app = AbciApp::new(config);
            {
                let mut s = app.inner.state.write();
                s.apply("recovery_key", b"recovery_val");
                s.set_height(10);
            }
            // Commit persists the snapshot
            commit_state(&app.inner.state, &state_path);
        }

        // Create a new app that should recover from sled
        {
            let mut config = test_config();
            config.state_path = state_path;
            let recovered = AbciApp::new(config);
            let state = recovered.state();
            assert_eq!(state.get("recovery_key"), Some(b"recovery_val" as &[u8]));
            assert_eq!(state.height(), 10);
        }
    }

    #[test]
    fn info_response_contains_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.state_path = dir.path().join("info.db");
        let app = AbciApp::new(config);
        let req = request::Info {
            version: "".into(),
            block_version: 0,
            p2p_version: 0,
            abci_version: "".into(),
        };
        let resp = app.handle_info(req);
        assert_eq!(resp.data, "kerosene-cometbft-adapter");
        assert!(!resp.version.is_empty());
    }

    #[test]
    fn init_chain_returns_app_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.state_path = dir.path().join("init.db");
        let app = AbciApp::new(config);
        let app_hash_before = app.app_hash();
        assert!(!app_hash_before.iter().all(|&b| b == 0));
    }

    #[test]
    fn query_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.state_path = dir.path().join("query.db");
        let app = AbciApp::new(config);
        app.inner.state.write().apply("mykey", b"myvalue");
        let req = request::Query {
            data: "mykey".into(),
            path: "".into(),
            height: 0u32.into(),
            prove: false,
        };
        let resp = app.handle_query(req);
        assert!(resp.code.is_ok());
        assert_eq!(&resp.value[..], b"myvalue");
    }

    #[test]
    fn query_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.state_path = dir.path().join("query-missing.db");
        let app = AbciApp::new(config);
        let req = request::Query {
            data: "nonexistent".into(),
            path: "".into(),
            height: 0u32.into(),
            prove: false,
        };
        let resp = app.handle_query(req);
        assert!(resp.code.is_err());
    }

    #[test]
    fn sequence_tracking() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.state_path = dir.path().join("seq.db");
        let app = AbciApp::new(config);

        // Initially no sequences
        {
            let seqs = app.inner.sender_sequences.read();
            assert!(seqs.is_empty());
        }

        // Record a sequence
        app.record_sender_sequence("sender1".into(), 5);
        {
            let seqs = app.inner.sender_sequences.read();
            assert_eq!(seqs.get("sender1"), Some(&5));
        }
    }

    #[test]
    fn authorized_keys_update() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.state_path = dir.path().join("auth.db");
        let app = AbciApp::new(config);

        let mut keys = HashSet::new();
        keys.insert("key1".into());
        keys.insert("key2".into());
        app.set_authorized_keys(keys);

        let result = app.authorized_keys();
        assert!(result.contains("key1"));
        assert!(result.contains("key2"));
        assert_eq!(result.len(), 2);
    }
}
