use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use kerosene_contracts::{
    DiscoveryPlane, ManifestMember, MembershipManifestV1, PeerHelloV1, DISCOVERY_CONTRACT_VERSION,
};
use kerosene_identity_core::{IdentityError, NodeIdentity};
use kerosene_membership::MembershipVerifier;
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub const PEERS_DB: &str = "peers.db";
pub const ENDPOINTS_DB: &str = "endpoints.db";
pub const SUCCESSFUL_CONNECTIONS_DB: &str = "successful-connections.db";
pub const MEMBERSHIP_MANIFESTS_DB: &str = "membership-manifests.db";

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("only HTTPS v3 onion endpoints are accepted")]
    InvalidEndpoint,
    #[error("peer hello contract, network, or plane mismatch")]
    ScopeMismatch,
    #[error("peer hello timestamp is outside the accepted window")]
    ClockSkew,
    #[error("challenge is unknown, expired, or already consumed")]
    ChallengeRejected,
    #[error("peer is authenticated but is not a verified member")]
    NotMember,
    #[error("a node cannot authenticate itself as a remote peer")]
    SelfConnection,
    #[error("peer identity verification failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("peer-store IO failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("peer-store data is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Tor transport failed: {0}")]
    Transport(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub member_id: String,
    pub plane: DiscoveryPlane,
    pub root_public_key: String,
    pub endpoint: String,
    pub authenticated_at_epoch_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPeer {
    pub member_id: String,
    pub plane: DiscoveryPlane,
    pub root_public_key: String,
    pub endpoint: String,
    pub authenticated_at_epoch_ms: u64,
    pub last_success_epoch_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub member_id: String,
    pub endpoint: String,
    pub source: DiscoverySource,
    pub observed_at_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    PreviousConnection,
    CurrentManifest,
    Genesis,
    Mirror,
    AuthenticatedPeer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuccessfulConnection {
    pub member_id: String,
    pub endpoint: String,
    pub connected_at_epoch_ms: u64,
}

#[derive(Debug)]
pub struct ChallengeStore {
    ttl_ms: u64,
    pending: Mutex<HashMap<String, u64>>,
}

impl ChallengeStore {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            ttl_ms: ttl_ms.max(1),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn issue(&self, now_epoch_ms: u64) -> String {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let challenge = hex::encode(bytes);
        self.pending
            .lock()
            .insert(challenge.clone(), now_epoch_ms.saturating_add(self.ttl_ms));
        challenge
    }

    pub fn consume(&self, challenge: &str, now_epoch_ms: u64) -> Result<(), DiscoveryError> {
        let mut pending = self.pending.lock();
        pending.retain(|_, expires_at| *expires_at >= now_epoch_ms);
        match pending.remove(challenge) {
            Some(expires_at) if expires_at >= now_epoch_ms => Ok(()),
            _ => Err(DiscoveryError::ChallengeRejected),
        }
    }
}

pub struct PeerAuthenticator {
    network_id: String,
    plane: DiscoveryPlane,
    max_clock_skew_ms: u64,
    challenges: Arc<ChallengeStore>,
    membership: Arc<RwLock<MembershipVerifier>>,
}

impl PeerAuthenticator {
    pub fn new(
        network_id: impl Into<String>,
        plane: DiscoveryPlane,
        max_clock_skew_ms: u64,
        challenges: Arc<ChallengeStore>,
        membership: Arc<RwLock<MembershipVerifier>>,
    ) -> Self {
        Self {
            network_id: network_id.into(),
            plane,
            max_clock_skew_ms,
            challenges,
            membership,
        }
    }

    pub fn authenticate(
        &self,
        hello: &PeerHelloV1,
        now_epoch_ms: u64,
    ) -> Result<AuthenticatedPeer, DiscoveryError> {
        if hello.contract_version != DISCOVERY_CONTRACT_VERSION
            || hello.network_id != self.network_id
            || hello.plane != self.plane
        {
            return Err(DiscoveryError::ScopeMismatch);
        }
        if hello.issued_at_epoch_ms.abs_diff(now_epoch_ms) > self.max_clock_skew_ms {
            return Err(DiscoveryError::ClockSkew);
        }
        validate_onion_endpoint(&hello.endpoint)?;
        NodeIdentity::verify_hello_signature(hello)?;
        self.challenges.consume(&hello.challenge, now_epoch_ms)?;
        if !self
            .membership
            .read()
            .is_member(&hello.member_id, &hello.root_public_key)
        {
            return Err(DiscoveryError::NotMember);
        }
        Ok(AuthenticatedPeer {
            member_id: hello.member_id.clone(),
            plane: hello.plane,
            root_public_key: hello.root_public_key.clone(),
            endpoint: hello.endpoint.clone(),
            authenticated_at_epoch_ms: now_epoch_ms,
        })
    }
}

pub fn validate_onion_endpoint(endpoint: &str) -> Result<(), DiscoveryError> {
    let url = Url::parse(endpoint).map_err(|_| DiscoveryError::InvalidEndpoint)?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "" && url.path() != "/")
    {
        return Err(DiscoveryError::InvalidEndpoint);
    }
    let host = url.host_str().ok_or(DiscoveryError::InvalidEndpoint)?;
    let Some(service_id) = host.strip_suffix(".onion") else {
        return Err(DiscoveryError::InvalidEndpoint);
    };
    if service_id.len() != 56
        || !service_id
            .bytes()
            .all(|value| value.is_ascii_lowercase() || (b'2'..=b'7').contains(&value))
    {
        return Err(DiscoveryError::InvalidEndpoint);
    }
    Ok(())
}

#[async_trait]
pub trait PeerDiscovery: Send + Sync {
    async fn discover(&self, plane: DiscoveryPlane) -> Result<Vec<EndpointRecord>, DiscoveryError>;
}

pub struct PersistentPeerStore {
    root: PathBuf,
    write_lock: Mutex<()>,
}

impl PersistentPeerStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, DiscoveryError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        let store = Self {
            root,
            write_lock: Mutex::new(()),
        };
        store.ensure_file::<StoredPeer>(PEERS_DB)?;
        store.ensure_file::<EndpointRecord>(ENDPOINTS_DB)?;
        store.ensure_file::<SuccessfulConnection>(SUCCESSFUL_CONNECTIONS_DB)?;
        store.ensure_file::<MembershipManifestV1>(MEMBERSHIP_MANIFESTS_DB)?;
        Ok(store)
    }

    pub fn upsert_authenticated(&self, peer: AuthenticatedPeer) -> Result<(), DiscoveryError> {
        let _guard = self.write_lock.lock();
        let mut peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        peers.retain(|saved| saved.member_id != peer.member_id);
        peers.push(StoredPeer {
            member_id: peer.member_id.clone(),
            plane: peer.plane,
            root_public_key: peer.root_public_key,
            endpoint: peer.endpoint.clone(),
            authenticated_at_epoch_ms: peer.authenticated_at_epoch_ms,
            last_success_epoch_ms: None,
        });
        self.write(PEERS_DB, &peers)?;

        let mut endpoints: Vec<EndpointRecord> = self.read(ENDPOINTS_DB)?;
        endpoints.retain(|saved| {
            saved.member_id != peer.member_id || saved.source != DiscoverySource::AuthenticatedPeer
        });
        endpoints.push(EndpointRecord {
            member_id: peer.member_id,
            endpoint: peer.endpoint,
            source: DiscoverySource::AuthenticatedPeer,
            observed_at_epoch_ms: peer.authenticated_at_epoch_ms,
        });
        self.write(ENDPOINTS_DB, &endpoints)
    }

    pub fn record_success(
        &self,
        member_id: &str,
        endpoint: &str,
        now_epoch_ms: u64,
    ) -> Result<(), DiscoveryError> {
        validate_onion_endpoint(endpoint)?;
        let _guard = self.write_lock.lock();
        let mut successes: Vec<SuccessfulConnection> = self.read(SUCCESSFUL_CONNECTIONS_DB)?;
        successes.retain(|saved| saved.member_id != member_id || saved.endpoint != endpoint);
        successes.push(SuccessfulConnection {
            member_id: member_id.into(),
            endpoint: endpoint.into(),
            connected_at_epoch_ms: now_epoch_ms,
        });
        self.write(SUCCESSFUL_CONNECTIONS_DB, &successes)?;

        let mut peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        for peer in &mut peers {
            if peer.member_id == member_id && peer.endpoint == endpoint {
                peer.last_success_epoch_ms = Some(now_epoch_ms);
            }
        }
        self.write(PEERS_DB, &peers)
    }

    pub fn append_manifest(&self, manifest: &MembershipManifestV1) -> Result<(), DiscoveryError> {
        let _guard = self.write_lock.lock();
        let mut manifests: Vec<MembershipManifestV1> = self.read(MEMBERSHIP_MANIFESTS_DB)?;
        manifests.push(manifest.clone());
        self.write(MEMBERSHIP_MANIFESTS_DB, &manifests)
    }

    pub fn manifests(&self) -> Result<Vec<MembershipManifestV1>, DiscoveryError> {
        self.read(MEMBERSHIP_MANIFESTS_DB)
    }

    pub fn authenticated_count(&self, plane: DiscoveryPlane) -> Result<usize, DiscoveryError> {
        let peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        Ok(peers.iter().filter(|peer| peer.plane == plane).count())
    }

    pub fn authenticated_endpoints(
        &self,
        plane: DiscoveryPlane,
    ) -> Result<Vec<EndpointRecord>, DiscoveryError> {
        let peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        Ok(peers
            .into_iter()
            .filter(|peer| peer.plane == plane)
            .map(|peer| EndpointRecord {
                member_id: peer.member_id,
                endpoint: peer.endpoint,
                source: DiscoverySource::AuthenticatedPeer,
                observed_at_epoch_ms: peer.authenticated_at_epoch_ms,
            })
            .collect())
    }

    pub fn ordered_candidates(
        &self,
        plane: DiscoveryPlane,
        current_manifest: Option<&MembershipManifestV1>,
        genesis: &[EndpointRecord],
        mirrors: &[EndpointRecord],
        authenticated_suggestions: &[EndpointRecord],
    ) -> Result<Vec<EndpointRecord>, DiscoveryError> {
        let successes: Vec<SuccessfulConnection> = self.read(SUCCESSFUL_CONNECTIONS_DB)?;
        let peers: Vec<StoredPeer> = self.read(PEERS_DB)?;
        let mut candidates = Vec::new();

        let mut successes = successes;
        successes.sort_by_key(|item| std::cmp::Reverse(item.connected_at_epoch_ms));
        for success in successes {
            if let Some(peer) = peers
                .iter()
                .find(|peer| peer.member_id == success.member_id && peer.plane == plane)
            {
                candidates.push(EndpointRecord {
                    member_id: peer.member_id.clone(),
                    endpoint: success.endpoint,
                    source: DiscoverySource::PreviousConnection,
                    observed_at_epoch_ms: success.connected_at_epoch_ms,
                });
            }
        }
        if let Some(manifest) = current_manifest {
            candidates.extend(manifest.members.iter().map(|member| EndpointRecord {
                member_id: member.member_id.clone(),
                endpoint: member.endpoint.clone(),
                source: DiscoverySource::CurrentManifest,
                observed_at_epoch_ms: manifest.epoch,
            }));
        }
        candidates.extend_from_slice(genesis);
        candidates.extend_from_slice(mirrors);
        candidates.extend_from_slice(authenticated_suggestions);
        deduplicate_valid(candidates)
    }

    fn ensure_file<T: Serialize>(&self, name: &str) -> Result<(), DiscoveryError> {
        let path = self.root.join(name);
        if !path.exists() {
            self.write(name, &Vec::<T>::new())?;
        }
        Ok(())
    }

    fn read<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Vec<T>, DiscoveryError> {
        let bytes = fs::read(self.root.join(name))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn write<T: Serialize>(&self, name: &str, values: &[T]) -> Result<(), DiscoveryError> {
        let path = self.root.join(name);
        let temporary = self.root.join(format!("{name}.tmp"));
        let bytes = serde_json::to_vec(values)?;
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)?;
        Ok(())
    }
}

fn deduplicate_valid(
    candidates: Vec<EndpointRecord>,
) -> Result<Vec<EndpointRecord>, DiscoveryError> {
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    for candidate in candidates {
        validate_onion_endpoint(&candidate.endpoint)?;
        if seen.insert(candidate.endpoint.clone()) {
            ordered.push(candidate);
        }
    }
    Ok(ordered)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloExchangeRequest {
    pub hello: PeerHelloV1,
    pub response_challenge: String,
}

pub struct TorHandshakeClient {
    client: reqwest::Client,
}

impl TorHandshakeClient {
    pub fn new_mtls(
        socks_proxy: &str,
        client_identity_pem: &[u8],
        ca_pem: &[u8],
    ) -> Result<Self, DiscoveryError> {
        if !socks_proxy.starts_with("socks5h://") {
            return Err(DiscoveryError::Transport(
                "Tor proxy must use socks5h remote resolution".into(),
            ));
        }
        let proxy = reqwest::Proxy::all(socks_proxy)
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let identity = reqwest::Identity::from_pem(client_identity_pem)
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let ca = reqwest::Certificate::from_pem(ca_pem)
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let client = reqwest::Client::builder()
            .proxy(proxy)
            .https_only(true)
            .identity(identity)
            .add_root_certificate(ca)
            .build()
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        Ok(Self { client })
    }

    pub async fn exchange(
        &self,
        endpoint: &str,
        local_identity: &NodeIdentity,
        local_endpoint: &str,
        response_challenge: String,
        now_epoch_ms: u64,
    ) -> Result<PeerHelloV1, DiscoveryError> {
        validate_onion_endpoint(endpoint)?;
        validate_onion_endpoint(local_endpoint)?;
        let challenge: ChallengeResponse = self
            .client
            .get(format!("{endpoint}/v1/discovery/challenge"))
            .send()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .error_for_status()
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .json()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?;
        let request = HelloExchangeRequest {
            hello: local_identity.sign_hello(challenge.challenge, local_endpoint, now_epoch_ms),
            response_challenge,
        };
        self.client
            .post(format!("{endpoint}/v1/discovery/hello"))
            .json(&request)
            .send()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .error_for_status()
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .json()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))
    }

    pub async fn fetch_manifest(
        &self,
        endpoint: &str,
    ) -> Result<MembershipManifestV1, DiscoveryError> {
        validate_onion_endpoint(endpoint)?;
        self.client
            .get(format!("{endpoint}/v1/membership/current"))
            .send()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .error_for_status()
            .map_err(|error| DiscoveryError::Transport(error.to_string()))?
            .json()
            .await
            .map_err(|error| DiscoveryError::Transport(error.to_string()))
    }
}

pub fn manifest_endpoint_records(manifest: &MembershipManifestV1) -> Vec<EndpointRecord> {
    manifest
        .members
        .iter()
        .map(manifest_member_to_endpoint)
        .collect()
}

fn manifest_member_to_endpoint(member: &ManifestMember) -> EndpointRecord {
    EndpointRecord {
        member_id: member.member_id.clone(),
        endpoint: member.endpoint.clone(),
        source: DiscoverySource::CurrentManifest,
        observed_at_epoch_ms: 0,
    }
}

pub fn db_files(root: &Path) -> [PathBuf; 4] {
    [
        root.join(PEERS_DB),
        root.join(ENDPOINTS_DB),
        root.join(SUCCESSFUL_CONNECTIONS_DB),
        root.join(MEMBERSHIP_MANIFESTS_DB),
    ]
}
