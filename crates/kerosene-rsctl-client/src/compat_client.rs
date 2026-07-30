use kerosene_contracts::DISCOVERY_CONTRACT_VERSION;
use serde_json::{json, Value};

use crate::error::ClientError;

/// Protocol version compatibility checker.
///
/// Contacts a node endpoint to verify that the protocol versions
/// are compatible between client and server.
pub struct CompatibilityClient {
    node_endpoint: String,
    timeout_secs: u64,
}

impl CompatibilityClient {
    pub fn new(node_endpoint: String, timeout_secs: u64) -> Self {
        Self {
            node_endpoint,
            timeout_secs,
        }
    }

    /// Check compatibility with the configured node endpoint.
    ///
    /// Returns a JSON value with compatibility information:
    /// - `compatible`: whether versions are compatible
    /// - `discovery_contract_version`: the client's version
    /// - `node_discovery_version`: the node's version (if reachable)
    /// - `request_id`: the request identifier
    pub async fn check(&self, request_id: &str) -> Result<Value, ClientError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .build()?;

        let url = format!(
            "{}/v1/compatibility",
            self.node_endpoint.trim_end_matches('/')
        );

        let node_version = match client
            .get(&url)
            .header("X-Request-Id", request_id)
            .send()
            .await
        {
            Ok(resp) => match resp.json::<Value>().await {
                Ok(versions) => versions
                    .get("discovery_contract_version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                Err(_) => "unreachable".to_string(),
            },
            Err(_) => "unreachable".to_string(),
        };

        Ok(json!({
            "compatible": node_version == DISCOVERY_CONTRACT_VERSION || node_version == "unreachable",
            "discovery_contract_version": DISCOVERY_CONTRACT_VERSION,
            "node_discovery_version": node_version,
            "request_id": request_id,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_version_is_available() {
        assert!(!DISCOVERY_CONTRACT_VERSION.is_empty());
    }

    #[tokio::test]
    async fn check_returns_self_version_on_connection_error() {
        let client = CompatibilityClient::new("http://127.0.0.1:1".to_string(), 2);
        let result = client.check("test-request").await;
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(
            value["discovery_contract_version"],
            DISCOVERY_CONTRACT_VERSION
        );
        assert_eq!(value["node_discovery_version"], "unreachable");
    }
}
