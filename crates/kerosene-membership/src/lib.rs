use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kerosene_contracts::{
    canonical_hash, member_id, CanonicalSignable, DiscoveryPlane, GenesisTrustBundleV1,
    ManifestMember, MembershipManifestV1, MembershipPhase, TrustMember, TrustPlane,
    DISCOVERY_CONTRACT_VERSION,
};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MembershipError {
    #[error("unsupported discovery contract version")]
    ContractVersion,
    #[error("network or discovery plane mismatch")]
    ScopeMismatch,
    #[error("threshold is invalid for the roster")]
    InvalidThreshold,
    #[error("member ID does not match its network-bound root key")]
    MemberIdMismatch,
    #[error("member endpoint must be an HTTPS v3 onion URL")]
    InvalidEndpoint,
    #[error("duplicate member or signer")]
    DuplicateIdentity,
    #[error("manifest hash chain is invalid")]
    HashChain,
    #[error("manifest epoch transition is invalid")]
    EpochTransition,
    #[error("membership change must use OLD -> JOINT -> NEW")]
    JointConsensusRequired,
    #[error("joint consensus transition changed its proposed roster")]
    JointRosterMismatch,
    #[error("manifest has insufficient valid signatures")]
    InsufficientSignatures,
}

#[derive(Debug, Clone)]
pub struct MembershipVerifier {
    network_id: String,
    plane: DiscoveryPlane,
    genesis: TrustPlane,
    current: Option<MembershipManifestV1>,
}

impl MembershipVerifier {
    pub fn new(
        bundle: &GenesisTrustBundleV1,
        plane: DiscoveryPlane,
    ) -> Result<Self, MembershipError> {
        if bundle.contract_version != DISCOVERY_CONTRACT_VERSION {
            return Err(MembershipError::ContractVersion);
        }
        validate_trust_plane(&bundle.network_id, &bundle.bank)?;
        validate_trust_plane(&bundle.network_id, &bundle.vault)?;
        Ok(Self {
            network_id: bundle.network_id.clone(),
            plane,
            genesis: match plane {
                DiscoveryPlane::Bank => bundle.bank.clone(),
                DiscoveryPlane::Vault => bundle.vault.clone(),
            },
            current: None,
        })
    }

    pub fn restore(
        bundle: &GenesisTrustBundleV1,
        plane: DiscoveryPlane,
        manifests: impl IntoIterator<Item = MembershipManifestV1>,
    ) -> Result<Self, MembershipError> {
        let mut verifier = Self::new(bundle, plane)?;
        for manifest in manifests {
            verifier.accept(manifest)?;
        }
        Ok(verifier)
    }

    pub fn accept(&mut self, manifest: MembershipManifestV1) -> Result<(), MembershipError> {
        self.validate_structure(&manifest)?;
        match self.current.as_ref() {
            None => self.verify_initial(&manifest)?,
            Some(current) if current.phase == MembershipPhase::Stable => {
                self.verify_after_stable(current, &manifest)?
            }
            Some(current) => self.verify_after_joint(current, &manifest)?,
        }
        self.current = Some(manifest);
        Ok(())
    }

    pub fn current(&self) -> Option<&MembershipManifestV1> {
        self.current.as_ref()
    }

    pub fn current_hash(&self) -> Option<String> {
        self.current.as_ref().map(canonical_hash)
    }

    pub fn threshold(&self) -> usize {
        self.current
            .as_ref()
            .map_or(self.genesis.threshold as usize, |manifest| {
                manifest.threshold as usize
            })
    }

    pub fn member_count(&self) -> usize {
        self.current
            .as_ref()
            .map_or(self.genesis.members.len(), |manifest| {
                manifest.members.len()
            })
    }

    pub fn is_member(&self, member: &str, public_key: &str) -> bool {
        self.authorized_keys()
            .get(member)
            .is_some_and(|expected| expected == public_key)
    }

    pub fn authorized_keys(&self) -> HashMap<String, String> {
        match self.current.as_ref() {
            Some(manifest) => manifest
                .members
                .iter()
                .map(|member| (member.member_id.clone(), member.root_public_key.clone()))
                .collect(),
            None => self
                .genesis
                .members
                .iter()
                .map(|member| (member.member_id.clone(), member.root_public_key.clone()))
                .collect(),
        }
    }

    fn validate_structure(&self, manifest: &MembershipManifestV1) -> Result<(), MembershipError> {
        if manifest.contract_version != DISCOVERY_CONTRACT_VERSION {
            return Err(MembershipError::ContractVersion);
        }
        if manifest.network_id != self.network_id || manifest.plane != self.plane {
            return Err(MembershipError::ScopeMismatch);
        }
        validate_manifest_members(&self.network_id, &manifest.members, manifest.threshold)?;
        let mut signers = HashSet::new();
        if manifest
            .signatures
            .iter()
            .any(|signature| !signers.insert(&signature.signer_id))
        {
            return Err(MembershipError::DuplicateIdentity);
        }
        match manifest.phase {
            MembershipPhase::Stable if manifest.next_epoch.is_some() => {
                Err(MembershipError::EpochTransition)
            }
            MembershipPhase::Joint
                if manifest
                    .next_epoch
                    .is_none_or(|next| next <= manifest.epoch) =>
            {
                Err(MembershipError::EpochTransition)
            }
            _ => Ok(()),
        }
    }

    fn verify_initial(&self, manifest: &MembershipManifestV1) -> Result<(), MembershipError> {
        if manifest.phase != MembershipPhase::Stable
            || manifest.epoch == 0
            || manifest.previous_manifest_hash != "0".repeat(64)
        {
            return Err(MembershipError::EpochTransition);
        }
        require_signatures(
            manifest,
            trust_keys(&self.genesis.members),
            self.genesis.threshold as usize,
        )
    }

    fn verify_after_stable(
        &self,
        current: &MembershipManifestV1,
        next: &MembershipManifestV1,
    ) -> Result<(), MembershipError> {
        require_chain(current, next, current.epoch.saturating_add(1))?;
        let old_keys = manifest_keys(&current.members);
        require_signatures(next, old_keys, current.threshold as usize)?;

        if next.phase == MembershipPhase::Stable {
            if !same_roster(current, next) {
                return Err(MembershipError::JointConsensusRequired);
            }
            return Ok(());
        }

        let new_keys = manifest_keys(&next.members);
        require_signatures(next, new_keys, next.threshold as usize)
    }

    fn verify_after_joint(
        &self,
        joint: &MembershipManifestV1,
        next: &MembershipManifestV1,
    ) -> Result<(), MembershipError> {
        if next.phase != MembershipPhase::Stable {
            return Err(MembershipError::EpochTransition);
        }
        let expected_epoch = joint.next_epoch.ok_or(MembershipError::EpochTransition)?;
        require_chain(joint, next, expected_epoch)?;
        if !same_roster(joint, next) {
            return Err(MembershipError::JointRosterMismatch);
        }
        require_signatures(
            next,
            manifest_keys(&joint.members),
            joint.threshold as usize,
        )
    }
}

fn require_chain(
    current: &MembershipManifestV1,
    next: &MembershipManifestV1,
    expected_epoch: u64,
) -> Result<(), MembershipError> {
    if next.previous_manifest_hash != canonical_hash(current) {
        return Err(MembershipError::HashChain);
    }
    if next.epoch != expected_epoch {
        return Err(MembershipError::EpochTransition);
    }
    Ok(())
}

fn require_signatures(
    manifest: &MembershipManifestV1,
    allowed: HashMap<String, String>,
    threshold: usize,
) -> Result<(), MembershipError> {
    let valid = manifest
        .signatures
        .iter()
        .filter(|candidate| {
            allowed
                .get(&candidate.signer_id)
                .is_some_and(|key| verify_signature(key, &candidate.signature, manifest))
        })
        .count();
    if valid < threshold {
        return Err(MembershipError::InsufficientSignatures);
    }
    Ok(())
}

fn verify_signature(public_key: &str, signature: &str, manifest: &MembershipManifestV1) -> bool {
    let Ok(key_bytes) = decode_array::<32>(public_key) else {
        return false;
    };
    let Ok(signature_bytes) = decode_array::<64>(signature) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    key.verify(
        &manifest.signing_bytes(),
        &Signature::from_bytes(&signature_bytes),
    )
    .is_ok()
}

fn validate_trust_plane(network: &str, plane: &TrustPlane) -> Result<(), MembershipError> {
    if plane.threshold == 0 || plane.threshold as usize > plane.members.len() {
        return Err(MembershipError::InvalidThreshold);
    }
    let mut ids = HashSet::new();
    for member in &plane.members {
        validate_member(network, &member.member_id, &member.root_public_key)?;
        if !ids.insert(&member.member_id) {
            return Err(MembershipError::DuplicateIdentity);
        }
    }
    Ok(())
}

fn validate_manifest_members(
    network: &str,
    members: &[ManifestMember],
    threshold: u16,
) -> Result<(), MembershipError> {
    if threshold == 0 || threshold as usize > members.len() {
        return Err(MembershipError::InvalidThreshold);
    }
    let mut ids = HashSet::new();
    for member in members {
        validate_member(network, &member.member_id, &member.root_public_key)?;
        validate_onion_endpoint(&member.endpoint)?;
        if !ids.insert(&member.member_id) {
            return Err(MembershipError::DuplicateIdentity);
        }
    }
    Ok(())
}

fn validate_onion_endpoint(endpoint: &str) -> Result<(), MembershipError> {
    let url = Url::parse(endpoint).map_err(|_| MembershipError::InvalidEndpoint)?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "" && url.path() != "/")
    {
        return Err(MembershipError::InvalidEndpoint);
    }
    let host = url.host_str().ok_or(MembershipError::InvalidEndpoint)?;
    let Some(service_id) = host.strip_suffix(".onion") else {
        return Err(MembershipError::InvalidEndpoint);
    };
    if service_id.len() != 56
        || !service_id
            .bytes()
            .all(|value| value.is_ascii_lowercase() || (b'2'..=b'7').contains(&value))
    {
        return Err(MembershipError::InvalidEndpoint);
    }
    Ok(())
}

fn validate_member(network: &str, id: &str, key: &str) -> Result<(), MembershipError> {
    let bytes = decode_array::<32>(key).map_err(|_| MembershipError::MemberIdMismatch)?;
    if member_id(network, &bytes) != id {
        return Err(MembershipError::MemberIdMismatch);
    }
    Ok(())
}

fn same_roster(left: &MembershipManifestV1, right: &MembershipManifestV1) -> bool {
    left.threshold == right.threshold && left.members == right.members
}

fn trust_keys(members: &[TrustMember]) -> HashMap<String, String> {
    members
        .iter()
        .map(|member| (member.member_id.clone(), member.root_public_key.clone()))
        .collect()
}

fn manifest_keys(members: &[ManifestMember]) -> HashMap<String, String> {
    members
        .iter()
        .map(|member| (member.member_id.clone(), member.root_public_key.clone()))
        .collect()
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}
