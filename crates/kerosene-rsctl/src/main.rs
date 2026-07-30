use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signer, SigningKey};
use kerosene_contracts::{
    canonical_hash, member_id, CanonicalSignable, DiscoveryPlane, GenesisTrustBundleV1,
    ManifestMember, ManifestSignature, MembershipManifestV1, MembershipPhase,
    DISCOVERY_CONTRACT_VERSION,
};
use kerosene_membership::MembershipVerifier;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(
    name = "kerosene-rsctl",
    version,
    about = "Kerosene infrastructure administration client"
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value = "text")]
    output: Output,
    #[arg(long, global = true, default_value_t = 10)]
    timeout: u64,
    #[arg(long, global = true)]
    endpoint: Option<String>,
    #[arg(long, global = true)]
    profile: Option<String>,
    #[arg(long, global = true)]
    identity_pem: Option<PathBuf>,
    #[arg(long, global = true)]
    ca: Option<PathBuf>,
    #[arg(long, global = true)]
    socks5h: Option<String>,
    #[arg(long, global = true)]
    request_id: Option<String>,
    #[arg(long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Text,
    Json,
    JsonPretty,
}

#[derive(Subcommand)]
enum Command {
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },
    Quorum {
        #[command(subcommand)]
        command: QuorumCommand,
    },
    Membership {
        #[command(subcommand)]
        command: MembershipCommand,
    },
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    Compatibility {
        #[command(subcommand)]
        command: CompatibilityCommand,
    },
    Doctor,
}

#[derive(Subcommand)]
enum NodeCommand {
    Status,
    Peers,
    Membership {
        #[command(subcommand)]
        command: NodeMembershipCommand,
    },
}

#[derive(Subcommand)]
enum NodeMembershipCommand {
    List,
}

#[derive(Subcommand)]
enum VaultCommand {
    Status,
    Health,
    Ceremony {
        #[command(subcommand)]
        command: CeremonyCommand,
    },
}

#[derive(Subcommand)]
enum CeremonyCommand {
    Inspect,
}

#[derive(Subcommand)]
enum QuorumCommand {
    Status,
}

#[derive(Subcommand)]
enum ArtifactCommand {
    Verify {
        path: PathBuf,
        #[arg(long)]
        sha256: Option<String>,
    },
}

#[derive(Subcommand)]
enum CompatibilityCommand {
    Check,
}

#[derive(Subcommand)]
enum MembershipCommand {
    Create(CreateManifest),
    Sign(SignManifest),
    Assemble(AssembleManifest),
    Verify(VerifyManifest),
    Publish(PublishManifest),
}

#[derive(Args)]
struct CreateManifest {
    #[arg(long)]
    network: String,
    #[arg(long, value_enum)]
    plane: Plane,
    #[arg(long)]
    epoch: u64,
    #[arg(long)]
    threshold: u16,
    #[arg(long)]
    members: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = false)]
    joint: bool,
    #[arg(
        long,
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    previous_manifest_hash: String,
    #[arg(long)]
    next_epoch: Option<u64>,
}

#[derive(Args)]
struct SignManifest {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct AssembleManifest {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long = "signed-manifest", required = true)]
    signed_manifests: Vec<PathBuf>,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct VerifyManifest {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    trust_bundle: PathBuf,
}

#[derive(Args)]
struct PublishManifest {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    identity_pem: PathBuf,
    #[arg(long)]
    ca: PathBuf,
    #[arg(long)]
    socks5h: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Plane {
    Bank,
    Vault,
}

impl From<Plane> for DiscoveryPlane {
    fn from(value: Plane) -> Self {
        match value {
            Plane::Bank => Self::Bank,
            Plane::Vault => Self::Vault,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(if cli.verbose { "debug" } else { "warn" })
        .with_writer(std::io::stderr)
        .init();
    if cli.profile.is_some() {
        bail!("--profile is reserved until the profiles.toml parser is released; pass endpoints and credential paths explicitly");
    }
    let request_id = request_id(cli.request_id.clone());
    let client = admin_client(
        cli.timeout,
        cli.identity_pem.as_deref(),
        cli.ca.as_deref(),
        cli.socks5h.as_deref(),
    )?;

    let value = match cli.command {
        Command::Node { command } => {
            let endpoint = endpoint(cli.endpoint.as_deref(), "KEROSENE_NODE_ENDPOINT")?;
            match command {
                NodeCommand::Status
                | NodeCommand::Membership {
                    command: NodeMembershipCommand::List,
                } => {
                    let path = if matches!(command, NodeCommand::Status) {
                        "/v1/readiness"
                    } else {
                        "/v1/membership/current"
                    };
                    get_json(&client, &endpoint, path, &request_id).await?
                }
                NodeCommand::Peers => {
                    get_json(&client, &endpoint, "/v1/discovery/peers", &request_id).await?
                }
            }
        }
        Command::Vault { command } => {
            let endpoint = endpoint(cli.endpoint.as_deref(), "KEROSENE_VAULT_ENDPOINT")?;
            match command {
                VaultCommand::Status => {
                    get_json(&client, &endpoint, "/v1/admin/status", &request_id).await?
                }
                VaultCommand::Health => {
                    get_json(&client, &endpoint, "/v1/health", &request_id).await?
                }
                VaultCommand::Ceremony {
                    command: CeremonyCommand::Inspect,
                } => get_json(&client, &endpoint, "/v1/admin/ceremony", &request_id).await?,
            }
        }
        Command::Quorum {
            command: QuorumCommand::Status,
        } => {
            let endpoint = endpoint(cli.endpoint.as_deref(), "KEROSENE_NODE_ENDPOINT")?;
            get_json(&client, &endpoint, "/v1/readiness", &request_id).await?
        }
        Command::Compatibility {
            command: CompatibilityCommand::Check,
        } => json!({
            "compatible": true,
            "discovery_contract_version": DISCOVERY_CONTRACT_VERSION,
            "request_id": request_id
        }),
        Command::Artifact {
            command: ArtifactCommand::Verify { path, sha256 },
        } => artifact_verify(&path, sha256.as_deref())?,
        Command::Membership { command } => membership(command).await?,
        Command::Doctor => {
            let endpoint = endpoint(cli.endpoint.as_deref(), "KEROSENE_NODE_ENDPOINT")?;
            let live = get_json(&client, &endpoint, "/live", &request_id).await?;
            let readiness = get_json(&client, &endpoint, "/v1/readiness", &request_id).await?;
            json!({"healthy": true, "live": live, "readiness": readiness})
        }
    };
    print_value(cli.output, &value)
}

async fn membership(command: MembershipCommand) -> Result<Value> {
    match command {
        MembershipCommand::Create(args) => {
            let members: Vec<ManifestMember> = read_json(&args.members)?;
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
            write_private_json(&args.output, &manifest)?;
            Ok(
                json!({"created": true, "manifest_hash": canonical_hash(&manifest), "path": args.output}),
            )
        }
        MembershipCommand::Sign(args) => {
            let mut manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let secret = read_secret(&args.identity)?;
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
            write_private_json(&args.output, &manifest)?;
            Ok(
                json!({"signed": true, "manifest_hash": canonical_hash(&manifest), "path": args.output}),
            )
        }
        MembershipCommand::Assemble(args) => {
            let mut manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let expected = manifest.signing_bytes();
            for path in args.signed_manifests {
                let signed: MembershipManifestV1 = read_json(&path)?;
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
            write_private_json(&args.output, &manifest)?;
            Ok(json!({
                "assembled": true,
                "signature_count": manifest.signatures.len(),
                "manifest_hash": canonical_hash(&manifest),
                "path": args.output
            }))
        }
        MembershipCommand::Verify(args) => {
            let manifest: MembershipManifestV1 = read_json(&args.manifest)?;
            let bundle: GenesisTrustBundleV1 = read_json(&args.trust_bundle)?;
            let mut verifier = MembershipVerifier::new(&bundle, manifest.plane)?;
            verifier.accept(manifest.clone())?;
            Ok(json!({"valid": true, "manifest_hash": canonical_hash(&manifest)}))
        }
        MembershipCommand::Publish(args) => {
            let manifest: MembershipManifestV1 = read_json(&args.manifest)?;
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
    }
}

fn admin_client(
    timeout: u64,
    identity_pem: Option<&Path>,
    ca: Option<&Path>,
    socks5h: Option<&str>,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(timeout));
    if identity_pem.is_some() != ca.is_some() {
        bail!("--identity-pem and --ca must be provided together");
    }
    if let (Some(identity_pem), Some(ca)) = (identity_pem, ca) {
        builder = builder
            .https_only(true)
            .identity(reqwest::Identity::from_pem(&fs::read(identity_pem)?)?)
            .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(ca)?)?);
    }
    if let Some(proxy) = socks5h {
        if !proxy.starts_with("socks5h://") {
            bail!("proxy must use socks5h:// so DNS is resolved through Tor");
        }
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    Ok(builder.build()?)
}

async fn get_json(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    request_id: &str,
) -> Result<Value> {
    Ok(client
        .get(format!("{}{}", base.trim_end_matches('/'), path))
        .header("X-Request-Id", request_id)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn endpoint(cli: Option<&str>, env_name: &str) -> Result<String> {
    cli.map(str::to_owned)
        .or_else(|| std::env::var(env_name).ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("--endpoint or {env_name} is required"))
}

fn request_id(value: Option<String>) -> String {
    value.unwrap_or_else(|| format!("rsctl-{}", std::process::id()))
}

fn artifact_verify(path: &Path, expected: Option<&str>) -> Result<Value> {
    let digest = hex::encode(Sha256::digest(fs::read(path)?));
    if expected.is_some_and(|value| !value.eq_ignore_ascii_case(&digest)) {
        bail!("artifact SHA-256 mismatch");
    }
    Ok(json!({"valid": true, "sha256": digest, "path": path}))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn read_secret(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("identity key permissions must not grant group or other access");
        }
    }
    let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("identity key must contain 32 bytes"))
}

fn write_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    options.open(path)?.write_all(&bytes)?;
    Ok(())
}

fn print_value(output: Output, value: &Value) -> Result<()> {
    match output {
        Output::Text | Output::JsonPretty => println!("{}", serde_json::to_string_pretty(value)?),
        Output::Json => println!("{}", serde_json::to_string(value)?),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_digest_is_verified() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact");
        fs::write(&path, b"kerosene").unwrap();
        let digest = hex::encode(Sha256::digest(b"kerosene"));

        assert!(artifact_verify(&path, Some(&digest)).is_ok());
        assert!(artifact_verify(&path, Some(&"00".repeat(32))).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn identity_key_rejects_group_access() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity");
        fs::write(&path, "00".repeat(32)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        assert!(read_secret(&path).is_err());
    }
}
