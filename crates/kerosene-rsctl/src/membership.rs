use std::fs;
use std::time::Duration;

use anyhow::{bail, Result};
use ed25519_dalek::{Signer, SigningKey};
use kerosene_contracts::{
    canonical_hash, member_id, CanonicalSignable, GenesisTrustBundleV1, ManifestMember,
    ManifestSignature, MembershipManifestV1, MembershipPhase, DISCOVERY_CONTRACT_VERSION,
};
use kerosene_membership::MembershipVerifier;
use serde_json::{json, Value};

pub async fn handle_membership(command: super::MembershipCommand) -> Result<Value> {
    match command {
        super::MembershipCommand::Create(args) => Ok(create_manifest(args)?),
        super::MembershipCommand::Sign(args) => Ok(sign_manifest(args)?),
        super::MembershipCommand::Assemble(args) => Ok(assemble_manifest(args)?),
        super::MembershipCommand::Verify(args) => Ok(verify_manifest(args)?),
        super::MembershipCommand::Publish(args) => publish_manifest(args).await,
    }
}

fn create_manifest(args: super::CreateManifest) -> Result<Value> {
    let members: Vec<ManifestMember> = crate::read_json(&args.members)?;
    if members.is_empty() {
        bail!("membership roster cannot be empty");
    }
    let manifest = MembershipManifestV1 {
        contract_version: DISCOVERY_CONTRACT_VERSION.into(),
        network_id: args.network,
        plane: args.plane.into(),
        epoch: args.epoch,
        phase: if args.joint {
            MembershipPhase::Joint
        } else {
            MembershipPhase::Stable
        },
        previous_manifest_hash: args.previous_manifest_hash,
        threshold: args.threshold,
        members,
        next_epoch: args.next_epoch,
        signatures: Vec::new(),
    };
    crate::write_private_json(&args.output, &manifest)?;
    Ok(json!({"created": true, "manifest_hash": canonical_hash(&manifest), "path": args.output}))
}

fn sign_manifest(args: super::SignManifest) -> Result<Value> {
    let mut manifest: MembershipManifestV1 = crate::read_json(&args.manifest)?;
    let secret = crate::read_secret(&args.identity)?;
    let key = SigningKey::from_bytes(&secret);
    let signer_id = member_id(&manifest.network_id, key.verifying_key().as_bytes());
    if !manifest
        .members
        .iter()
        .any(|member| member.member_id == signer_id)
    {
        bail!("signing identity is absent from the proposed roster");
    }
    manifest
        .signatures
        .retain(|signature| signature.signer_id != signer_id);
    manifest.signatures.push(ManifestSignature {
        signer_id,
        signature: hex::encode(key.sign(&manifest.signing_bytes()).to_bytes()),
    });
    crate::write_private_json(&args.output, &manifest)?;
    Ok(json!({"signed": true, "manifest_hash": canonical_hash(&manifest), "path": args.output}))
}

fn assemble_manifest(args: super::AssembleManifest) -> Result<Value> {
    let mut manifest: MembershipManifestV1 = crate::read_json(&args.manifest)?;
    let expected = manifest.signing_bytes();
    for path in args.signed_manifests {
        let signed: MembershipManifestV1 = crate::read_json(&path)?;
        if signed.signing_bytes() != expected {
            bail!(
                "signed manifest {} does not describe the same proposal",
                path.display()
            );
        }
        for signature in signed.signatures {
            manifest
                .signatures
                .retain(|existing| existing.signer_id != signature.signer_id);
            manifest.signatures.push(signature);
        }
    }
    manifest
        .signatures
        .sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    crate::write_private_json(&args.output, &manifest)?;
    Ok(json!({
        "assembled": true,
        "signature_count": manifest.signatures.len(),
        "manifest_hash": canonical_hash(&manifest),
        "path": args.output
    }))
}

fn verify_manifest(args: super::VerifyManifest) -> Result<Value> {
    let manifest: MembershipManifestV1 = crate::read_json(&args.manifest)?;
    let bundle: GenesisTrustBundleV1 = crate::read_json(&args.trust_bundle)?;
    let mut verifier = MembershipVerifier::new(&bundle, manifest.plane)?;
    verifier.accept(manifest.clone())?;
    Ok(json!({"valid": true, "manifest_hash": canonical_hash(&manifest)}))
}

async fn publish_manifest(args: super::PublishManifest) -> Result<Value> {
    let manifest: MembershipManifestV1 = crate::read_json(&args.manifest)?;
    let identity = reqwest::Identity::from_pem(&fs::read(args.identity_pem)?)?;
    let ca = reqwest::Certificate::from_pem(&fs::read(args.ca)?)?;
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .identity(identity)
        .add_root_certificate(ca)
        .timeout(Duration::from_secs(15));
    if let Some(proxy) = args.socks5h {
        if !proxy.starts_with("socks5h://") {
            bail!("membership publish proxy must use socks5h://");
        }
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    let response = builder
        .build()?
        .post(format!(
            "{}/v1/membership",
            args.endpoint.trim_end_matches('/')
        ))
        .json(&manifest)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_manifest_rejects_empty_members() {
        let dir = tempfile::tempdir().unwrap();
        let members_path = dir.path().join("members.json");
        std::fs::write(&members_path, "[]").unwrap();
        let output_path = dir.path().join("manifest.json");

        let args = crate::CreateManifest {
            network: "testnet".into(),
            plane: crate::Plane::Vault,
            epoch: 1,
            threshold: 1,
            members: members_path,
            output: output_path,
            joint: false,
            previous_manifest_hash: "0".repeat(64),
            next_epoch: None,
        };

        let result = create_manifest(args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }
}
