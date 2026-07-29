use ed25519_dalek::{Signer, SigningKey};
use kerosene_contracts::{
    canonical_hash, member_id, CanonicalSignable, DiscoveryPlane, GenesisTrustBundleV1,
    ManifestMember, ManifestSignature, MembershipManifestV1, MembershipPhase, TrustMember,
    TrustPlane, DISCOVERY_CONTRACT_VERSION,
};
use kerosene_membership::{MembershipError, MembershipVerifier};

const NETWORK: &str = "kerosene-test";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn trust(key: &SigningKey) -> TrustMember {
    TrustMember {
        member_id: member_id(NETWORK, key.verifying_key().as_bytes()),
        root_public_key: hex::encode(key.verifying_key().as_bytes()),
    }
}

fn member(key: &SigningKey, onion_char: char) -> ManifestMember {
    ManifestMember {
        member_id: member_id(NETWORK, key.verifying_key().as_bytes()),
        root_public_key: hex::encode(key.verifying_key().as_bytes()),
        endpoint: format!("https://{}.onion", onion_char.to_string().repeat(56)),
    }
}

fn bundle(keys: &[SigningKey]) -> GenesisTrustBundleV1 {
    let plane = TrustPlane {
        threshold: 2,
        members: keys.iter().map(trust).collect(),
    };
    GenesisTrustBundleV1 {
        contract_version: DISCOVERY_CONTRACT_VERSION.into(),
        network_id: NETWORK.into(),
        bank: plane.clone(),
        vault: plane,
        created_at_epoch_ms: 1,
    }
}

fn manifest(
    epoch: u64,
    phase: MembershipPhase,
    previous: String,
    members: Vec<ManifestMember>,
    next_epoch: Option<u64>,
) -> MembershipManifestV1 {
    MembershipManifestV1 {
        contract_version: DISCOVERY_CONTRACT_VERSION.into(),
        network_id: NETWORK.into(),
        plane: DiscoveryPlane::Vault,
        epoch,
        phase,
        previous_manifest_hash: previous,
        threshold: 2,
        members,
        next_epoch,
        signatures: vec![],
    }
}

fn sign(manifest: &mut MembershipManifestV1, keys: &[&SigningKey]) {
    manifest.signatures = keys
        .iter()
        .map(|key| ManifestSignature {
            signer_id: member_id(NETWORK, key.verifying_key().as_bytes()),
            signature: hex::encode(key.sign(&manifest.signing_bytes()).to_bytes()),
        })
        .collect();
}

#[test]
fn rejects_manifest_below_genesis_threshold() {
    let old = [key(1), key(2), key(3)];
    let mut verifier = MembershipVerifier::new(&bundle(&old), DiscoveryPlane::Vault).unwrap();
    let mut initial = manifest(
        1,
        MembershipPhase::Stable,
        "0".repeat(64),
        old.iter().map(|key| member(key, 'a')).collect(),
        None,
    );
    sign(&mut initial, &[&old[0]]);
    assert_eq!(
        verifier.accept(initial),
        Err(MembershipError::InsufficientSignatures)
    );
}

#[test]
fn enforces_old_joint_new_transition() {
    let old = [key(1), key(2), key(3)];
    let new = [key(4), key(5), key(6)];
    let mut verifier = MembershipVerifier::new(&bundle(&old), DiscoveryPlane::Vault).unwrap();

    let mut initial = manifest(
        1,
        MembershipPhase::Stable,
        "0".repeat(64),
        old.iter().map(|key| member(key, 'a')).collect(),
        None,
    );
    sign(&mut initial, &[&old[0], &old[1]]);
    verifier.accept(initial.clone()).unwrap();

    let mut direct = manifest(
        2,
        MembershipPhase::Stable,
        canonical_hash(&initial),
        new.iter().map(|key| member(key, 'b')).collect(),
        None,
    );
    sign(&mut direct, &[&old[0], &old[1]]);
    assert_eq!(
        verifier.accept(direct),
        Err(MembershipError::JointConsensusRequired)
    );

    let mut joint = manifest(
        2,
        MembershipPhase::Joint,
        canonical_hash(&initial),
        new.iter().map(|key| member(key, 'b')).collect(),
        Some(3),
    );
    sign(&mut joint, &[&old[0], &old[1], &new[0], &new[1]]);
    verifier.accept(joint.clone()).unwrap();

    let mut stable = manifest(
        3,
        MembershipPhase::Stable,
        canonical_hash(&joint),
        new.iter().map(|key| member(key, 'b')).collect(),
        None,
    );
    sign(&mut stable, &[&new[0], &new[1]]);
    verifier.accept(stable).unwrap();

    assert!(verifier.is_member(
        &member_id(NETWORK, new[2].verifying_key().as_bytes()),
        &hex::encode(new[2].verifying_key().as_bytes())
    ));
    assert!(!verifier.is_member(
        &member_id(NETWORK, old[0].verifying_key().as_bytes()),
        &hex::encode(old[0].verifying_key().as_bytes())
    ));
}

#[test]
fn rejects_replayed_or_forked_hash_chain() {
    let old = [key(1), key(2), key(3)];
    let mut verifier = MembershipVerifier::new(&bundle(&old), DiscoveryPlane::Vault).unwrap();
    let mut initial = manifest(
        1,
        MembershipPhase::Stable,
        "0".repeat(64),
        old.iter().map(|key| member(key, 'a')).collect(),
        None,
    );
    sign(&mut initial, &[&old[0], &old[1]]);
    verifier.accept(initial).unwrap();

    let mut fork = manifest(
        2,
        MembershipPhase::Stable,
        "f".repeat(64),
        old.iter().map(|key| member(key, 'a')).collect(),
        None,
    );
    sign(&mut fork, &[&old[0], &old[1]]);
    assert_eq!(verifier.accept(fork), Err(MembershipError::HashChain));
}

#[test]
fn restores_manifest_and_exposes_only_the_effective_roster() {
    let keys = [key(1), key(2), key(3)];
    let trust_bundle = bundle(&keys);
    let genesis = MembershipVerifier::new(&trust_bundle, DiscoveryPlane::Bank).unwrap();
    assert_eq!(genesis.threshold(), 2);
    assert_eq!(genesis.member_count(), 3);
    assert!(genesis.current().is_none());
    assert!(genesis.current_hash().is_none());
    assert_eq!(genesis.authorized_keys().len(), 3);

    let mut initial = manifest(
        1,
        MembershipPhase::Stable,
        "0".repeat(64),
        keys.iter().map(|key| member(key, 'a')).collect(),
        None,
    );
    sign(&mut initial, &[&keys[0], &keys[1]]);
    let restored =
        MembershipVerifier::restore(&trust_bundle, DiscoveryPlane::Vault, [initial.clone()])
            .unwrap();
    assert_eq!(restored.current(), Some(&initial));
    assert_eq!(restored.current_hash(), Some(canonical_hash(&initial)));
    assert_eq!(restored.threshold(), 2);
    assert_eq!(restored.member_count(), 3);
    assert_eq!(restored.authorized_keys().len(), 3);
}

#[test]
fn rejects_clearnet_endpoint_inside_a_signed_manifest() {
    let keys = [key(1), key(2), key(3)];
    let mut verifier = MembershipVerifier::new(&bundle(&keys), DiscoveryPlane::Vault).unwrap();
    let mut members = keys.iter().map(|key| member(key, 'a')).collect::<Vec<_>>();
    members[0].endpoint = "https://vault.default.svc.cluster.local".into();
    let mut initial = manifest(1, MembershipPhase::Stable, "0".repeat(64), members, None);
    sign(&mut initial, &[&keys[0], &keys[1]]);
    assert_eq!(
        verifier.accept(initial),
        Err(MembershipError::InvalidEndpoint)
    );
}
