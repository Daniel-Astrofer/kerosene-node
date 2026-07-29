use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use kerosene_contracts::{canonical_hash, DiscoveryPlane, MembershipManifestV1, PeerHelloV1};
use kerosene_discovery::{
    ChallengeResponse, ChallengeStore, DiscoveryError, HelloExchangeRequest, PeerAuthenticator,
    PersistentPeerStore,
};
use kerosene_identity_core::NodeIdentity;
use kerosene_membership::{MembershipError, MembershipVerifier};
use kerosene_sync::{
    Lifecycle, LifecycleState, LifecycleStore, StateSnapshot, StateSynchronizer, SyncError,
};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

#[derive(Clone)]
pub struct NodeService {
    inner: Arc<NodeServiceInner>,
}

struct NodeServiceInner {
    identity: Arc<NodeIdentity>,
    endpoint: String,
    plane: DiscoveryPlane,
    challenges: Arc<ChallengeStore>,
    authenticator: PeerAuthenticator,
    membership: Arc<RwLock<MembershipVerifier>>,
    peer_store: Arc<PersistentPeerStore>,
    lifecycle: Mutex<Lifecycle>,
    lifecycle_store: LifecycleStore,
    active_peers: RwLock<HashMap<String, u64>>,
    peer_live_window_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    pub live: bool,
    pub local_ready: bool,
    pub member_ready: bool,
    pub quorum_ready: bool,
    pub financial_ready: bool,
    pub plane: DiscoveryPlane,
    pub lifecycle: LifecycleState,
    pub operational_state: &'static str,
    pub verified_members: usize,
    pub live_members: usize,
    pub required_threshold: usize,
    pub manifest_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

impl NodeService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: Arc<NodeIdentity>,
        endpoint: String,
        plane: DiscoveryPlane,
        membership: MembershipVerifier,
        peer_store: Arc<PersistentPeerStore>,
        lifecycle_store: LifecycleStore,
        challenge_ttl_ms: u64,
        peer_live_window_ms: u64,
    ) -> Result<Self, String> {
        kerosene_discovery::validate_onion_endpoint(&endpoint)
            .map_err(|error| error.to_string())?;
        let membership = Arc::new(RwLock::new(membership));
        let challenges = Arc::new(ChallengeStore::new(challenge_ttl_ms));
        let authenticator = PeerAuthenticator::new(
            identity.network_id(),
            plane,
            challenge_ttl_ms,
            challenges.clone(),
            membership.clone(),
        );
        let mut lifecycle = lifecycle_store.load().map_err(|error| error.to_string())?;
        bootstrap_local_lifecycle(&mut lifecycle).map_err(|error| error.to_string())?;
        lifecycle_store
            .save(&lifecycle)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            inner: Arc::new(NodeServiceInner {
                identity,
                endpoint,
                plane,
                challenges,
                authenticator,
                membership,
                peer_store,
                lifecycle: Mutex::new(lifecycle),
                lifecycle_store,
                active_peers: RwLock::new(HashMap::new()),
                peer_live_window_ms,
            }),
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/live", get(live))
            .route("/ready-local", get(ready_local))
            .route("/ready-member", get(ready_member))
            .route("/ready-quorum", get(ready_quorum))
            .route("/ready-financial", get(ready_financial))
            .route("/v1/readiness", get(readiness))
            .route("/v1/discovery/challenge", get(challenge))
            .route("/v1/discovery/hello", post(hello))
            .route("/v1/membership/current", get(current_manifest))
            .route("/v1/membership", post(accept_manifest))
            .with_state(self.clone())
    }

    pub fn readiness(&self, now_epoch_ms: u64) -> Readiness {
        self.expire_peers(now_epoch_ms);
        let membership = self.inner.membership.read();
        let local_member = membership.is_member(
            self.inner.identity.member_id(),
            &self.inner.identity.root_public_key_hex(),
        );
        let authorized = membership.authorized_keys();
        let live_remote = self
            .inner
            .active_peers
            .read()
            .keys()
            .filter(|member_id| authorized.contains_key(*member_id))
            .count();
        let live_members = live_remote + usize::from(local_member);
        let threshold = membership.threshold();
        let quorum = local_member && live_members >= threshold;
        let lifecycle = self.inner.lifecycle.lock().state();
        let state_verified = matches!(
            lifecycle,
            LifecycleState::StateVerified | LifecycleState::Eligible | LifecycleState::Active
        );
        Readiness {
            live: true,
            local_ready: lifecycle != LifecycleState::Created,
            member_ready: local_member,
            quorum_ready: quorum,
            financial_ready: quorum && lifecycle == LifecycleState::Active,
            plane: self.inner.plane,
            lifecycle,
            operational_state: if lifecycle == LifecycleState::Active && quorum {
                "ACTIVE"
            } else if state_verified {
                "ELIGIBLE_WAITING_FOR_QUORUM"
            } else {
                "ACTIVE_LOCAL_WAITING_FOR_PEERS"
            },
            verified_members: membership.member_count(),
            live_members,
            required_threshold: threshold,
            manifest_hash: membership.current_hash(),
        }
    }

    pub fn issue_challenge(&self, now_epoch_ms: u64) -> String {
        self.inner.challenges.issue(now_epoch_ms)
    }

    pub fn observe_peer(
        &self,
        hello: &PeerHelloV1,
        now_epoch_ms: u64,
    ) -> Result<(), DiscoveryError> {
        if hello.member_id == self.inner.identity.member_id() {
            return Err(DiscoveryError::SelfConnection);
        }
        let peer = self.inner.authenticator.authenticate(hello, now_epoch_ms)?;
        self.inner.peer_store.upsert_authenticated(peer.clone())?;
        self.inner
            .peer_store
            .record_success(&peer.member_id, &peer.endpoint, now_epoch_ms)?;
        self.inner
            .active_peers
            .write()
            .insert(peer.member_id, now_epoch_ms);
        self.advance_after_authentication();
        self.activate_if_quorum(now_epoch_ms);
        Ok(())
    }

    pub fn exchange_hello(
        &self,
        request: &HelloExchangeRequest,
        now_epoch_ms: u64,
    ) -> Result<PeerHelloV1, DiscoveryError> {
        if request.hello.member_id == self.inner.identity.member_id() {
            return Err(DiscoveryError::SelfConnection);
        }
        let peer = self
            .inner
            .authenticator
            .authenticate(&request.hello, now_epoch_ms)?;
        self.inner.peer_store.upsert_authenticated(peer.clone())?;
        self.inner
            .peer_store
            .record_success(&peer.member_id, &peer.endpoint, now_epoch_ms)?;
        self.inner
            .active_peers
            .write()
            .insert(peer.member_id, now_epoch_ms);
        self.advance_after_authentication();
        self.activate_if_quorum(now_epoch_ms);
        Ok(self.inner.identity.sign_hello(
            request.response_challenge.clone(),
            self.inner.endpoint.clone(),
            now_epoch_ms,
        ))
    }

    pub fn accept_membership(&self, manifest: MembershipManifestV1) -> Result<(), MembershipError> {
        let manifest_hash = canonical_hash(&manifest);
        if self.inner.membership.read().current_hash().as_deref() == Some(manifest_hash.as_str()) {
            return Ok(());
        }
        let mut candidate = self.inner.membership.read().clone();
        candidate.accept(manifest.clone())?;
        self.inner
            .peer_store
            .append_manifest(&manifest)
            .map_err(|_| MembershipError::HashChain)?;
        *self.inner.membership.write() = candidate;
        self.activate_if_quorum(now_epoch_ms());
        Ok(())
    }

    pub fn current_manifest(&self) -> Option<MembershipManifestV1> {
        self.inner.membership.read().current().cloned()
    }

    pub async fn synchronize_state(
        &self,
        synchronizer: &dyn StateSynchronizer,
    ) -> Result<StateSnapshot, SyncError> {
        let snapshot = synchronizer.synchronize().await?;
        self.verify_state_snapshot(&snapshot)?;
        Ok(snapshot)
    }

    pub fn verify_state_snapshot(&self, snapshot: &StateSnapshot) -> Result<(), SyncError> {
        snapshot.verify()?;
        let mut lifecycle = self.inner.lifecycle.lock();
        if lifecycle.state() != LifecycleState::Syncing {
            return Err(SyncError::InvalidTransition {
                from: lifecycle.state(),
                to: LifecycleState::StateVerified,
            });
        }
        lifecycle.advance(LifecycleState::StateVerified)?;
        lifecycle.advance(LifecycleState::Eligible)?;
        self.inner.lifecycle_store.save(&lifecycle)?;
        drop(lifecycle);
        self.activate_if_quorum(now_epoch_ms());
        Ok(())
    }

    fn advance_after_authentication(&self) {
        let mut lifecycle = self.inner.lifecycle.lock();
        if lifecycle.state() == LifecycleState::Discovering {
            let _ = lifecycle.advance(LifecycleState::Authenticated);
        }
        let local_member = self.inner.membership.read().is_member(
            self.inner.identity.member_id(),
            &self.inner.identity.root_public_key_hex(),
        );
        if local_member && lifecycle.state() == LifecycleState::Authenticated {
            let _ = lifecycle.advance(LifecycleState::MemberVerified);
            let _ = lifecycle.advance(LifecycleState::Syncing);
        }
        let _ = self.inner.lifecycle_store.save(&lifecycle);
    }

    fn activate_if_quorum(&self, now_epoch_ms: u64) {
        let readiness = self.readiness(now_epoch_ms);
        let mut lifecycle = self.inner.lifecycle.lock();
        if readiness.quorum_ready && lifecycle.state() == LifecycleState::Eligible {
            let _ = lifecycle.advance(LifecycleState::Active);
            let _ = self.inner.lifecycle_store.save(&lifecycle);
        }
    }

    fn expire_peers(&self, now_epoch_ms: u64) {
        self.inner.active_peers.write().retain(|_, last_seen| {
            now_epoch_ms.saturating_sub(*last_seen) <= self.inner.peer_live_window_ms
        });
    }
}

fn bootstrap_local_lifecycle(lifecycle: &mut Lifecycle) -> Result<(), kerosene_sync::SyncError> {
    while matches!(
        lifecycle.state(),
        LifecycleState::Created | LifecycleState::IdentityReady | LifecycleState::TransportReady
    ) {
        let next = lifecycle.state().next().expect("bootstrap state has next");
        lifecycle.advance(next)?;
    }
    Ok(())
}

async fn live() -> Json<serde_json::Value> {
    Json(serde_json::json!({"live": true}))
}

async fn ready_local(State(service): State<NodeService>) -> (StatusCode, Json<Readiness>) {
    readiness_status(service.readiness(now_epoch_ms()), |ready| ready.local_ready)
}

async fn ready_member(State(service): State<NodeService>) -> (StatusCode, Json<Readiness>) {
    readiness_status(service.readiness(now_epoch_ms()), |ready| {
        ready.member_ready
    })
}

async fn ready_quorum(State(service): State<NodeService>) -> (StatusCode, Json<Readiness>) {
    readiness_status(service.readiness(now_epoch_ms()), |ready| {
        ready.quorum_ready
    })
}

async fn ready_financial(State(service): State<NodeService>) -> (StatusCode, Json<Readiness>) {
    readiness_status(service.readiness(now_epoch_ms()), |ready| {
        ready.financial_ready
    })
}

async fn readiness(State(service): State<NodeService>) -> Json<Readiness> {
    Json(service.readiness(now_epoch_ms()))
}

async fn challenge(State(service): State<NodeService>) -> Json<ChallengeResponse> {
    Json(ChallengeResponse {
        challenge: service.issue_challenge(now_epoch_ms()),
    })
}

async fn hello(
    State(service): State<NodeService>,
    Json(request): Json<HelloExchangeRequest>,
) -> Result<Json<PeerHelloV1>, (StatusCode, Json<ErrorBody>)> {
    service
        .exchange_hello(&request, now_epoch_ms())
        .map(Json)
        .map_err(|error| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorBody {
                    error: error.to_string(),
                }),
            )
        })
}

async fn current_manifest(
    State(service): State<NodeService>,
) -> Result<Json<MembershipManifestV1>, StatusCode> {
    service
        .inner
        .membership
        .read()
        .current()
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn accept_manifest(
    State(service): State<NodeService>,
    Json(manifest): Json<MembershipManifestV1>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let hash = canonical_hash(&manifest);
    service
        .accept_membership(manifest)
        .map(|()| Json(serde_json::json!({"accepted": true, "manifest_hash": hash})))
        .map_err(|error| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorBody {
                    error: error.to_string(),
                }),
            )
        })
}

fn readiness_status(
    readiness: Readiness,
    predicate: impl FnOnce(&Readiness) -> bool,
) -> (StatusCode, Json<Readiness>) {
    let status = if predicate(&readiness) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(readiness))
}

pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
