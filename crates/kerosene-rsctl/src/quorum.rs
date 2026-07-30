use anyhow::Result;
use serde_json::Value;

use kerosene_rsctl_client::NodeClient;

pub async fn handle_quorum(
    command: &super::QuorumCommand,
    cli: &super::Cli,
    request_id: &str,
) -> Result<Value> {
    match command {
        super::QuorumCommand::Status => {
            let endpoint = crate::endpoint(cli.endpoint.as_deref(), "KEROSENE_NODE_ENDPOINT")?;
            let client = NodeClient::new(
                endpoint,
                cli.timeout,
                cli.identity_pem.as_deref(),
                cli.ca.as_deref(),
                cli.socks5h.as_deref(),
                None,
            )?;
            client.status(request_id).await.map_err(Into::into)
        }
    }
}
