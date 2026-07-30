use anyhow::Result;
use serde_json::Value;

use kerosene_rsctl_client::NodeClient;

pub async fn handle_node(
    command: &super::NodeCommand,
    cli: &super::Cli,
    request_id: &str,
) -> Result<Value> {
    let endpoint = crate::endpoint(cli.endpoint.as_deref(), "KEROSENE_NODE_ENDPOINT")?;
    let client = NodeClient::new(
        endpoint,
        cli.timeout,
        cli.identity_pem.as_deref(),
        cli.ca.as_deref(),
        cli.socks5h.as_deref(),
        None,
    )?;

    match command {
        super::NodeCommand::Status => client.status(request_id).await.map_err(Into::into),
        super::NodeCommand::Peers => client.peers(request_id).await.map_err(Into::into),
        super::NodeCommand::Membership {
            command: super::NodeMembershipCommand::List,
        } => client.membership_list(request_id).await.map_err(Into::into),
    }
}
