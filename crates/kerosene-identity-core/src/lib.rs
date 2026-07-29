use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use kerosene_contracts::{
    member_id, CanonicalSignable, DiscoveryPlane, PeerHelloV1, DISCOVERY_CONTRACT_VERSION,
};
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("identity key IO failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity key must contain exactly 32 bytes encoded as lowercase hex")]
    InvalidSecret,
    #[error("peer public key is invalid")]
    InvalidPublicKey,
    #[error("peer signature is invalid")]
    InvalidSignature,
    #[error("peer member ID does not match its network-bound root key")]
    MemberIdMismatch,
}

pub struct NodeIdentity {
    network_id: String,
    plane: DiscoveryPlane,
    signing_key: SigningKey,
    member_id: String,
}

impl NodeIdentity {
    pub fn generate(network_id: impl Into<String>, plane: DiscoveryPlane) -> Self {
        Self::from_signing_key(network_id.into(), plane, SigningKey::generate(&mut OsRng))
    }

    pub fn from_secret(
        network_id: impl Into<String>,
        plane: DiscoveryPlane,
        secret: [u8; 32],
    ) -> Self {
        Self::from_signing_key(network_id.into(), plane, SigningKey::from_bytes(&secret))
    }

    pub fn load_or_create(
        path: &Path,
        network_id: impl Into<String>,
        plane: DiscoveryPlane,
    ) -> Result<Self, IdentityError> {
        let network_id = network_id.into();
        match OpenOptions::new().read(true).open(path) {
            Ok(mut file) => {
                let mut encoded = String::new();
                file.read_to_string(&mut encoded)?;
                let mut bytes =
                    hex::decode(encoded.trim()).map_err(|_| IdentityError::InvalidSecret)?;
                if bytes.len() != 32 {
                    bytes.zeroize();
                    return Err(IdentityError::InvalidSecret);
                }
                let mut secret = [0_u8; 32];
                secret.copy_from_slice(&bytes);
                bytes.zeroize();
                let identity = Self::from_secret(network_id, plane, secret);
                secret.zeroize();
                Ok(identity)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let identity = Self::generate(network_id, plane);
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(path)?;
                let mut encoded = hex::encode(identity.signing_key.to_bytes());
                file.write_all(encoded.as_bytes())?;
                file.write_all(b"\n")?;
                file.sync_all()?;
                encoded.zeroize();
                Ok(identity)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    pub fn root_public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    pub fn plane(&self) -> DiscoveryPlane {
        self.plane
    }

    pub fn sign_hello(
        &self,
        challenge: impl Into<String>,
        endpoint: impl Into<String>,
        issued_at_epoch_ms: u64,
    ) -> PeerHelloV1 {
        let mut hello = PeerHelloV1 {
            contract_version: DISCOVERY_CONTRACT_VERSION.into(),
            network_id: self.network_id.clone(),
            plane: self.plane,
            member_id: self.member_id.clone(),
            root_public_key: self.root_public_key_hex(),
            challenge: challenge.into(),
            issued_at_epoch_ms,
            endpoint: endpoint.into(),
            signature: String::new(),
        };
        hello.signature = hex::encode(self.signing_key.sign(&hello.signing_bytes()).to_bytes());
        hello
    }

    pub fn verify_hello_signature(hello: &PeerHelloV1) -> Result<(), IdentityError> {
        let public_bytes = decode_array::<32>(&hello.root_public_key)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_bytes).map_err(|_| IdentityError::InvalidPublicKey)?;
        if member_id(&hello.network_id, &public_bytes) != hello.member_id {
            return Err(IdentityError::MemberIdMismatch);
        }
        let signature_bytes =
            decode_array::<64>(&hello.signature).map_err(|_| IdentityError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&hello.signing_bytes(), &signature)
            .map_err(|_| IdentityError::InvalidSignature)
    }

    fn from_signing_key(
        network_id: String,
        plane: DiscoveryPlane,
        signing_key: SigningKey,
    ) -> Self {
        let id = member_id(&network_id, signing_key.verifying_key().as_bytes());
        Self {
            network_id,
            plane,
            signing_key,
            member_id: id,
        }
    }
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], hex::FromHexError> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_persists_and_does_not_change_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");
        let first = NodeIdentity::load_or_create(&path, "network-a", DiscoveryPlane::Bank).unwrap();
        let second =
            NodeIdentity::load_or_create(&path, "network-a", DiscoveryPlane::Bank).unwrap();
        assert_eq!(first.member_id(), second.member_id());
    }

    #[test]
    fn hello_binds_challenge_endpoint_plane_and_network() {
        let identity = NodeIdentity::from_secret("network-a", DiscoveryPlane::Vault, [9; 32]);
        let hello = identity.sign_hello(
            "a".repeat(64),
            format!("https://{}.onion", "b".repeat(56)),
            42,
        );
        NodeIdentity::verify_hello_signature(&hello).unwrap();

        let mut spoofed = hello.clone();
        spoofed.endpoint = format!("https://{}.onion", "c".repeat(56));
        assert!(matches!(
            NodeIdentity::verify_hello_signature(&spoofed),
            Err(IdentityError::InvalidSignature)
        ));
    }
}
