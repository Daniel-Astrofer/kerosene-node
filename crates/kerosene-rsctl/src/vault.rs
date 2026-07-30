use anyhow::Result;
use serde_json::Value;

use kerosene_rsctl_client::{MockVaultClient, VaultClient};

pub async fn handle_vault(
    command: &super::VaultCommand,
    _cli: &super::Cli,
    request_id: &str,
) -> Result<Value> {
    // Use the mock vault client for now.
    // When issue #10 is complete, this will be replaced by UnixVaultClient.
    let client = MockVaultClient::new();

    match command {
        super::VaultCommand::Status => client.status(request_id).await.map_err(Into::into),
        super::VaultCommand::Health => client.health(request_id).await.map_err(Into::into),
        super::VaultCommand::Ceremony {
            command: super::CeremonyCommand::Inspect,
        } => client.ceremony_inspect(request_id).await.map_err(Into::into),
    }
}
