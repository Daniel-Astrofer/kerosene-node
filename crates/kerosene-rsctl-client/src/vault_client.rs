use std::path::PathBuf;

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::error::ClientError;

/// Trait for the vault Admin API client.
///
/// The real implementation communicates over a Unix domain socket.
/// A mock implementation is provided for testing and for development
/// before the vault Admin API (issue #10) is complete.
#[async_trait]
pub trait VaultClient: Send + Sync {
    /// Vault operational status.
    async fn status(&self, request_id: &str) -> Result<Value, ClientError>;

    /// Vault health check.
    async fn health(&self, request_id: &str) -> Result<Value, ClientError>;

    /// Inspect ceremony state (no secret material).
    async fn ceremony_inspect(&self, request_id: &str) -> Result<Value, ClientError>;
}

/// Mock vault client for testing and development.
///
/// Returns simulated responses without any real vault connection.
pub struct MockVaultClient {
    healthy: bool,
    status_value: Value,
    health_value: Value,
    ceremony_value: Value,
}

impl Default for MockVaultClient {
    fn default() -> Self {
        Self {
            healthy: true,
            status_value: json!({
                "vault_status": "operational",
                "uptime_seconds": 3600,
                "sealed": false,
                "active_ceremony": null,
            }),
            health_value: json!({
                "healthy": true,
                "disk_ok": true,
                "memory_ok": true,
            }),
            ceremony_value: json!({
                "ceremony_active": false,
                "ceremony_phase": null,
                "participants_ready": 0,
                "threshold": 0,
            }),
        }
    }
}

impl MockVaultClient {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub fn with_healthy(mut self, healthy: bool) -> Self {
        self.healthy = healthy;
        self
    }
}

#[async_trait]
impl VaultClient for MockVaultClient {
    async fn status(&self, request_id: &str) -> Result<Value, ClientError> {
        let mut value = self.status_value.clone();
        if let Some(obj) = value.as_object_mut() {
            obj.insert("request_id".into(), json!(request_id));
        }
        if !self.healthy {
            return Err(ClientError::ConnectionRefused(
                "vault is not reachable".into(),
            ));
        }
        Ok(value)
    }

    async fn health(&self, request_id: &str) -> Result<Value, ClientError> {
        let mut value = self.health_value.clone();
        if let Some(obj) = value.as_object_mut() {
            obj.insert("request_id".into(), json!(request_id));
        }
        if !self.healthy {
            return Err(ClientError::ConnectionRefused(
                "vault is not reachable".into(),
            ));
        }
        Ok(value)
    }

    async fn ceremony_inspect(&self, request_id: &str) -> Result<Value, ClientError> {
        let mut value = self.ceremony_value.clone();
        if let Some(obj) = value.as_object_mut() {
            obj.insert("request_id".into(), json!(request_id));
        }
        if !self.healthy {
            return Err(ClientError::ConnectionRefused(
                "vault is not reachable".into(),
            ));
        }
        Ok(value)
    }
}

/// Real vault client that communicates over a Unix domain socket.
///
/// This will be fully implemented in issue #10 when the vault Admin API
/// server is available. For now, it returns a "not implemented" error.
pub struct UnixVaultClient {
    socket_path: PathBuf,
    #[allow(dead_code)]
    timeout_secs: u64,
}

impl UnixVaultClient {
    pub fn new(socket_path: PathBuf, timeout_secs: u64) -> Self {
        Self {
            socket_path,
            timeout_secs,
        }
    }
}

#[async_trait]
impl VaultClient for UnixVaultClient {
    async fn status(&self, _request_id: &str) -> Result<Value, ClientError> {
        Err(ClientError::NotImplemented(format!(
            "Unix socket vault client for {} is not yet wired; see issue #10",
            self.socket_path.display()
        )))
    }

    async fn health(&self, _request_id: &str) -> Result<Value, ClientError> {
        Err(ClientError::NotImplemented(format!(
            "Unix socket vault client for {} is not yet wired; see issue #10",
            self.socket_path.display()
        )))
    }

    async fn ceremony_inspect(&self, _request_id: &str) -> Result<Value, ClientError> {
        Err(ClientError::NotImplemented(format!(
            "Unix socket vault client for {} is not yet wired; see issue #10",
            self.socket_path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_vault_status_returns_operational() {
        let client = MockVaultClient::new();
        let result = client.status("test-request").await.unwrap();
        assert_eq!(result["vault_status"], "operational");
        assert_eq!(result["request_id"], "test-request");
    }

    #[tokio::test]
    async fn mock_vault_health_returns_healthy() {
        let client = MockVaultClient::new();
        let result = client.health("test-request").await.unwrap();
        assert_eq!(result["healthy"], true);
    }

    #[tokio::test]
    async fn mock_vault_ceremony_inspect_returns_inactive() {
        let client = MockVaultClient::new();
        let result = client.ceremony_inspect("test-request").await.unwrap();
        assert_eq!(result["ceremony_active"], false);
    }

    #[tokio::test]
    async fn mock_vault_unhealthy_returns_error() {
        let client = MockVaultClient::new().with_healthy(false);
        assert!(client.status("test-request").await.is_err());
        assert!(client.health("test-request").await.is_err());
        assert!(client.ceremony_inspect("test-request").await.is_err());
    }
}
