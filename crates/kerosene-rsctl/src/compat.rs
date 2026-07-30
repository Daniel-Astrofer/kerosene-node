use anyhow::Result;
use serde_json::Value;

use kerosene_rsctl_client::CompatibilityClient;

pub async fn handle_compatibility(
    command: &super::CompatibilityCommand,
    cli: &super::Cli,
    request_id: &str,
) -> Result<Value> {
    match command {
        super::CompatibilityCommand::Check => {
            let endpoint =
                crate::endpoint(cli.endpoint.as_deref(), "KEROSENE_NODE_ENDPOINT")?;
            let compat = CompatibilityClient::new(endpoint, cli.timeout);
            compat.check(request_id).await.map_err(Into::into)
        }
    }
}
