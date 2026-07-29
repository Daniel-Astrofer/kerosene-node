use std::sync::Arc;

use kerosene_contracts::{
    member_id, DiscoveryPlane, GenesisTrustBundleV1, TrustMember, TrustPlane,
    DISCOVERY_CONTRACT_VERSION,
};
use kerosene_discovery::{
    db_files, validate_onion_endpoint, ChallengeStore, DiscoveryError, PeerAuthenticator,
    PersistentPeerStore,
};
use kerosene_identity_core::NodeIdentity;
use kerosene_membership::MembershipVerifier;
use parking_lot::RwLock;

fn onion(character: char) -> String {
    format!("https://{}.onion", character.to_string().repeat(56))
}

fn fixture() -> (NodeIdentity, Arc<ChallengeStore>, PeerAuthenticator) {
    let identity = NodeIdentity::from_secret("network-a", DiscoveryPlane::Vault, [8; 32]);
    let root_public_key = identity.root_public_key_hex();
    let trust_member = TrustMember {
        member_id: member_id(
            "network-a",
            &hex::decode(&root_public_key).unwrap().try_into().unwrap(),
        ),
        root_public_key,
    };
    let plane = TrustPlane {
        threshold: 1,
        members: vec![trust_member],
    };
    let bundle = GenesisTrustBundleV1 {
        contract_version: DISCOVERY_CONTRACT_VERSION.into(),
        network_id: "network-a".into(),
        bank: plane.clone(),
        vault: plane,
        created_at_epoch_ms: 1,
    };
    let membership = Arc::new(RwLock::new(
        MembershipVerifier::new(&bundle, DiscoveryPlane::Vault).unwrap(),
    ));
    let challenges = Arc::new(ChallengeStore::new(10_000));
    let authenticator = PeerAuthenticator::new(
        "network-a",
        DiscoveryPlane::Vault,
        1_000,
        challenges.clone(),
        membership,
    );
    (identity, challenges, authenticator)
}

#[test]
fn rejects_clearnet_local_services_and_non_v3_onions() {
    for endpoint in [
        "https://vault:7801",
        "http://vault.example.com",
        "https://127.0.0.1:7801",
        "https://short.onion",
        "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0.onion",
    ] {
        assert!(
            validate_onion_endpoint(endpoint).is_err(),
            "{endpoint} must be rejected"
        );
    }
    validate_onion_endpoint(&onion('a')).unwrap();
}

#[test]
fn hello_is_single_use_and_membership_bound() {
    let (identity, challenges, authenticator) = fixture();
    let now = 10_000;
    let challenge = challenges.issue(now);
    let hello = identity.sign_hello(challenge, onion('b'), now);
    let authenticated = authenticator.authenticate(&hello, now).unwrap();
    assert_eq!(authenticated.member_id, identity.member_id());
    assert!(matches!(
        authenticator.authenticate(&hello, now),
        Err(DiscoveryError::ChallengeRejected)
    ));
}

#[test]
fn spoofed_endpoint_does_not_consume_valid_challenge() {
    let (identity, challenges, authenticator) = fixture();
    let now = 10_000;
    let challenge = challenges.issue(now);
    let hello = identity.sign_hello(challenge, onion('b'), now);
    let mut spoofed = hello.clone();
    spoofed.endpoint = onion('c');
    assert!(matches!(
        authenticator.authenticate(&spoofed, now),
        Err(DiscoveryError::Identity(_))
    ));
    authenticator.authenticate(&hello, now).unwrap();
}

#[test]
fn peer_store_survives_restart_and_creates_all_required_databases() {
    let root = tempfile::tempdir().unwrap();
    let (identity, challenges, authenticator) = fixture();
    let now = 10_000;
    let hello = identity.sign_hello(challenges.issue(now), onion('d'), now);
    let peer = authenticator.authenticate(&hello, now).unwrap();

    let store = PersistentPeerStore::open(root.path()).unwrap();
    store.upsert_authenticated(peer).unwrap();
    store
        .record_success(identity.member_id(), &onion('d'), now + 1)
        .unwrap();
    drop(store);

    let reopened = PersistentPeerStore::open(root.path()).unwrap();
    assert_eq!(
        reopened.authenticated_count(DiscoveryPlane::Vault).unwrap(),
        1
    );
    for path in db_files(root.path()) {
        assert!(path.is_file(), "{} is missing", path.display());
    }
}
