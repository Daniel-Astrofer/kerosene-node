use anyhow::Result;
use serde_json::{json, Value};

use kerosene_rsctl_client::NodeClient;

pub async fn handle_doctor(cli: &super::Cli, request_id: &str) -> Result<Value> {
    let endpoint = crate::endpoint(cli.endpoint.as_deref(), "KEROSENE_NODE_ENDPOINT")?;
    let client = NodeClient::new(
        endpoint,
        cli.timeout,
        cli.identity_pem.as_deref(),
        cli.ca.as_deref(),
        cli.socks5h.as_deref(),
        None,
    )?;

    let live = client.live(request_id).await?;
    let readiness = client.status(request_id).await?;
    Ok(json!({"healthy": true, "live": live, "readiness": readiness}))
}
