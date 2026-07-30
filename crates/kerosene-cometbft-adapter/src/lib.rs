pub mod check_tx;
pub mod commit;
pub mod config;
pub mod error;
pub mod finalize_block;
pub mod state;

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::RwLock;
use tendermint::abci::{request, response, Code, Request, Response};
use tower::Service;
use tracing::{info, warn};

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
#[derive(Clone)]
pub struct AbciApp {
    inner: Arc<AbciAppInner>,
}

struct AbciAppInner {
    state: RwLock<AppState>,
    config: CometBftConfig,
    used_nonces: RwLock<HashSet<u64>>,
}

impl AbciApp {
    /// Create a new ABCI application with the given config.
    pub fn new(config: CometBftConfig) -> Self {
        let state = AppState::new();
        info!(
            transport = ?config.transport,
            addr = %config.listen_addr,
            "ABCI application initialized"
        );
        Self {
            inner: Arc::new(AbciAppInner {
                state: RwLock::new(state),
                config,
                used_nonces: RwLock::new(HashSet::new()),
            }),
        }
    }

    /// Create a new ABCI application with a pre-loaded state (from snapshot).
    pub fn with_state(config: CometBftConfig, state: AppState) -> Self {
        info!(
            transport = ?config.transport,
            addr = %config.listen_addr,
            height = state.height(),
            "ABCI application restored from snapshot"
        );
        Self {
            inner: Arc::new(AbciAppInner {
                state: RwLock::new(state),
                config,
                used_nonces: RwLock::new(HashSet::new()),
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

    /// Record a nonce as used (for replay protection).
    pub fn record_nonce(&self, nonce: u64) {
        self.inner.used_nonces.write().insert(nonce);
    }

    /// Check if a nonce has already been used.
    pub fn has_nonce(&self, nonce: u64) -> bool {
        self.inner.used_nonces.read().contains(&nonce)
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
                    let ctx = CheckTxCtx {
                        network_id: &self_clone.inner.config.network_id,
                        used_nonces: &self_clone.inner.used_nonces,
                    };
                    let resp = check_tx(ctx, &check_tx_req);
                    Ok(Response::CheckTx(resp))
                }
                Request::FinalizeBlock(finalize_req) => {
                    let resp = finalize_block(
                        &self_clone.inner.state,
                        &self_clone.inner.used_nonces,
                        &self_clone.inner.config,
                        &finalize_req,
                    );
                    Ok(Response::FinalizeBlock(resp))
                }
                Request::Commit => {
                    let resp = commit_state(&self_clone.inner.state);
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

    // Split the single ABCI service into four category services
    let (consensus, mempool, info, snapshot) = tower_abci::v038::split::service(app);

    // Build the ABCI server with appropriate concurrency limits
    use tower::ServiceBuilder;

    let consensus = ServiceBuilder::new()
        .buffer(1)
        .concurrency_limit(1)
        .service(consensus);

    let mempool = ServiceBuilder::new()
        .buffer(100)
        .concurrency_limit(10)
        .service(mempool);

    let info = ServiceBuilder::new()
        .buffer(10)
        .concurrency_limit(5)
        .service(info);

    let snapshot = ServiceBuilder::new()
        .buffer(1)
        .concurrency_limit(1)
        .service(snapshot);

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
    use std::str::FromStr;

    fn test_config() -> CometBftConfig {
        CometBftConfig {
            listen_addr: "/tmp/test-abci.sock".into(),
            transport: crate::config::CometBftTransport::Unix,
            state_path: std::path::PathBuf::from("/tmp/test-abci-state"),
            network_id: "testnet".into(),
            max_tx_per_block: 100,
        }
    }

    #[test]
    fn app_initializes_with_default_state() {
        let config = test_config();
        let app = AbciApp::new(config);
        let state = app.state();
        assert!(state.is_empty());
        assert_eq!(state.height(), 0);
    }

    #[test]
    fn info_response_contains_metadata() {
        let config = test_config();
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
        let config = test_config();
        let app = AbciApp::new(config);
        let req = request::InitChain {
            time: tendermint::Time::from_str("2025-01-01T00:00:00Z").unwrap(),
            chain_id: "testnet".into(),
            consensus_params: None,
            validators: vec![],
            app_state_bytes: vec![].into(),
            initial_height: 0,
        };
        let resp = app.handle_init_chain(req);
        assert!(!resp.app_hash.as_bytes().is_empty());
    }

    #[test]
    fn query_existing_key() {
        let config = test_config();
        let app = AbciApp::new(config);
        app.inner.state.write().apply("mykey", b"myvalue");
        let req = request::Query {
            data: "mykey".into(),
            path: "".into(),
            height: 0,
            prove: false,
        };
        let resp = app.handle_query(req);
        assert!(resp.code.is_ok());
        assert_eq!(&resp.value[..], b"myvalue");
    }

    #[test]
    fn query_missing_key() {
        let config = test_config();
        let app = AbciApp::new(config);
        let req = request::Query {
            data: "nonexistent".into(),
            path: "".into(),
            height: 0,
            prove: false,
        };
        let resp = app.handle_query(req);
        assert!(resp.code.is_err());
    }

    #[test]
    fn nonce_tracking() {
        let config = test_config();
        let app = AbciApp::new(config);
        assert!(!app.has_nonce(42));
        app.record_nonce(42);
        assert!(app.has_nonce(42));
    }
}
