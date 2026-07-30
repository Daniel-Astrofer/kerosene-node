pub mod client;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Bridge to the KFE (Kerosene Financial Engine) Java service.
///
/// The KFE is a Java service that handles financial rule validation,
/// block preparation, and state persistence. This bridge communicates
/// with the KFE over a Unix domain socket using JSON-RPC style messages.
#[derive(Debug, Clone)]
pub struct KfeBridge {
    client: client::UnixSocketClient,
}

/// Response from a KFE `check_transaction` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckTxResponse {
    pub allowed: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub gas_estimate: u64,
}

/// Response from a KFE `prepare_block` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareBlockResponse {
    pub valid_tx_indices: Vec<usize>,
    #[serde(default)]
    pub state_root: Option<String>,
    #[serde(default)]
    pub error: String,
}

/// Response from a KFE `commit_state` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitStateResponse {
    pub state_root: String,
    #[serde(default)]
    pub error: String,
}

/// Errors originating from the KFE bridge.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("KFE connection error: {0}")]
    Connection(String),

    #[error("KFE request timed out")]
    Timeout,

    #[error("KFE returned error: {0}")]
    KfeError(String),

    #[error("invalid response from KFE: {0}")]
    InvalidResponse(String),
}

impl KfeBridge {
    /// Create a new KFE bridge connected to the given Unix socket path.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            client: client::UnixSocketClient::new(socket_path.into()),
        }
    }

    /// Validate a transaction against KFE financial rules.
    ///
    /// This delegates to the KFE Java service which has access to the
    /// full financial rule engine.
    pub async fn check_transaction(
        &self,
        tx_json: &str,
    ) -> Result<CheckTxResponse, BridgeError> {
        let request = serde_json::json!({
            "method": "check_transaction",
            "params": {
                "transaction": tx_json,
            },
            "id": 1,
        });

        let response = self
            .client
            .call(request.to_string())
            .await
            .map_err(|e| BridgeError::Connection(e.to_string()))?;

        let parsed: CheckTxResponse =
            serde_json::from_str(&response).map_err(|e| BridgeError::InvalidResponse(e.to_string()))?;

        if !parsed.allowed {
            return Err(BridgeError::KfeError(parsed.reason));
        }

        Ok(parsed)
    }

    /// Prepare a block by delegating block-building logic to the KFE.
    ///
    /// The KFE determines which transactions are valid for financial rules,
    /// orders them appropriately, and returns the filtered list.
    pub async fn prepare_block(
        &self,
        txs_json: &str,
        height: u64,
    ) -> Result<PrepareBlockResponse, BridgeError> {
        let request = serde_json::json!({
            "method": "prepare_block",
            "params": {
                "transactions": txs_json,
                "height": height,
            },
            "id": 1,
        });

        let response = self
            .client
            .call(request.to_string())
            .await
            .map_err(|e| BridgeError::Connection(e.to_string()))?;

        serde_json::from_str(&response)
            .map_err(|e| BridgeError::InvalidResponse(e.to_string()))
    }

    /// Commit the current state to the KFE's persistent store.
    ///
    /// Returns the state root hash from the KFE.
    pub async fn commit_state(
        &self,
        state_json: &str,
        height: u64,
    ) -> Result<CommitStateResponse, BridgeError> {
        let request = serde_json::json!({
            "method": "commit_state",
            "params": {
                "state": state_json,
                "height": height,
            },
            "id": 1,
        });

        let response = self
            .client
            .call(request.to_string())
            .await
            .map_err(|e| BridgeError::Connection(e.to_string()))?;

        serde_json::from_str(&response)
            .map_err(|e| BridgeError::InvalidResponse(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_constructs() {
        let bridge = KfeBridge::new("/tmp/kfe.sock");
        assert_eq!(bridge.client.socket_path(), "/tmp/kfe.sock");
    }

    #[test]
    fn check_tx_response_parsing() {
        let json = r#"{"allowed": true, "reason": "", "gas_estimate": 50000}"#;
        let resp: CheckTxResponse = serde_json::from_str(json).unwrap();
        assert!(resp.allowed);
        assert_eq!(resp.gas_estimate, 50000);
    }

    #[test]
    fn check_tx_response_rejected() {
        let json = r#"{"allowed": false, "reason": "insufficient funds", "gas_estimate": 0}"#;
        let resp: CheckTxResponse = serde_json::from_str(json).unwrap();
        assert!(!resp.allowed);
        assert_eq!(resp.reason, "insufficient funds");
    }

    #[test]
    fn prepare_block_response_parsing() {
        let json = r#"{"valid_tx_indices": [0, 2, 3], "state_root": "abc123"}"#;
        let resp: PrepareBlockResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.valid_tx_indices, vec![0, 2, 3]);
        assert_eq!(resp.state_root, Some("abc123".into()));
    }

    #[test]
    fn commit_state_response_parsing() {
        let json = r#"{"state_root": "def456"}"#;
        let resp: CommitStateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.state_root, "def456");
    }
}
