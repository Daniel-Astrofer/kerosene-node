use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::Value;

mod artifact;
mod compat;
mod doctor;
mod membership;
mod node;
mod quorum;
mod vault;

#[derive(Parser)]
#[command(
    name = "kerosene-rsctl",
    version,
    about = "Kerosene infrastructure administration client"
)]
pub(crate) struct Cli {
    #[arg(long, global = true, value_enum, default_value = "text")]
    pub(crate) output: Output,
    #[arg(long, global = true, default_value_t = 10)]
    pub(crate) timeout: u64,
    #[arg(long, global = true)]
    pub(crate) endpoint: Option<String>,
    #[arg(long, global = true)]
    pub(crate) profile: Option<String>,
    #[arg(long, global = true)]
    pub(crate) identity_pem: Option<PathBuf>,
    #[arg(long, global = true)]
    pub(crate) ca: Option<PathBuf>,
    #[arg(long, global = true)]
    pub(crate) socks5h: Option<String>,
    #[arg(long, global = true)]
    pub(crate) request_id: Option<String>,
    #[arg(long, global = true)]
    pub(crate) verbose: bool,
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Output {
    Text,
    Json,
    JsonPretty,
}

#[derive(Subcommand)]
pub(crate) enum Command {
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
pub(crate) enum NodeCommand {
    Status,
    Peers,
    Membership {
        #[command(subcommand)]
        command: NodeMembershipCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum NodeMembershipCommand {
    List,
}

#[derive(Subcommand)]
pub(crate) enum VaultCommand {
    Status,
    Health,
    Ceremony {
        #[command(subcommand)]
        command: CeremonyCommand,
    },
}

#[derive(Subcommand)]
pub(crate) enum CeremonyCommand {
    Inspect,
}

#[derive(Subcommand)]
pub(crate) enum QuorumCommand {
    Status,
}

#[derive(Subcommand)]
pub(crate) enum ArtifactCommand {
    Verify {
        path: PathBuf,
        #[arg(long)]
        sha256: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum CompatibilityCommand {
    Check,
}

#[derive(Clone, Subcommand)]
pub(crate) enum MembershipCommand {
    Create(CreateManifest),
    Sign(SignManifest),
    Assemble(AssembleManifest),
    Verify(VerifyManifest),
    Publish(PublishManifest),
}

#[derive(Clone, Args)]
pub(crate) struct CreateManifest {
    #[arg(long)]
    pub(crate) network: String,
    #[arg(long, value_enum)]
    pub(crate) plane: Plane,
    #[arg(long)]
    pub(crate) epoch: u64,
    #[arg(long)]
    pub(crate) threshold: u16,
    #[arg(long)]
    pub(crate) members: PathBuf,
    #[arg(long)]
    pub(crate) output: PathBuf,
    #[arg(long, default_value_t = false)]
    pub(crate) joint: bool,
    #[arg(
        long,
        default_value = "0000000000000000000000000000000000000000000000000000000000000000"
    )]
    pub(crate) previous_manifest_hash: String,
    #[arg(long)]
    pub(crate) next_epoch: Option<u64>,
}

#[derive(Clone, Args)]
pub(crate) struct SignManifest {
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long)]
    pub(crate) identity: PathBuf,
    #[arg(long)]
    pub(crate) output: PathBuf,
}

#[derive(Clone, Args)]
pub(crate) struct AssembleManifest {
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long = "signed-manifest", required = true)]
    pub(crate) signed_manifests: Vec<PathBuf>,
    #[arg(long)]
    pub(crate) output: PathBuf,
}

#[derive(Clone, Args)]
pub(crate) struct VerifyManifest {
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long)]
    pub(crate) trust_bundle: PathBuf,
}

#[derive(Clone, Args)]
pub(crate) struct PublishManifest {
    #[arg(long)]
    pub(crate) manifest: PathBuf,
    #[arg(long)]
    pub(crate) endpoint: String,
    #[arg(long)]
    pub(crate) identity_pem: PathBuf,
    #[arg(long)]
    pub(crate) ca: PathBuf,
    #[arg(long)]
    pub(crate) socks5h: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Plane {
    Bank,
    Vault,
}

impl From<Plane> for kerosene_contracts::DiscoveryPlane {
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

    let value = match &cli.command {
        Command::Node { command } => node::handle_node(command, &cli, &request_id).await?,
        Command::Vault { command } => vault::handle_vault(command, &cli, &request_id).await?,
        Command::Quorum { command } => quorum::handle_quorum(command, &cli, &request_id).await?,
        Command::Compatibility { command } => {
            compat::handle_compatibility(command, &cli, &request_id).await?
        }
        Command::Artifact { command } => artifact::handle_artifact(command).await?,
        Command::Membership { command } => membership::handle_membership(command.clone()).await?,
        Command::Doctor => doctor::handle_doctor(&cli, &request_id).await?,
    };

    // Redact sensitive data before output
    let mut output = value;
    kerosene_rsctl_client::redact::redact_value(&mut output);

    print_value(cli.output, &output)
}

pub(crate) fn endpoint(cli: Option<&str>, env_name: &str) -> Result<String> {
    cli.map(str::to_owned)
        .or_else(|| std::env::var(env_name).ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow!("--endpoint or {env_name} is required"))
}

pub(crate) fn request_id(value: Option<String>) -> String {
    value.unwrap_or_else(|| format!("rsctl-{}", std::process::id()))
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

pub(crate) fn read_secret(path: &Path) -> Result<[u8; 32]> {
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

pub(crate) fn write_private_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
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

    #[test]
    fn request_id_default_is_set() {
        let id = request_id(None);
        assert!(id.starts_with("rsctl-"));
    }

    #[test]
    fn request_id_uses_provided_value() {
        let id = request_id(Some("custom-id".into()));
        assert_eq!(id, "custom-id");
    }
}
