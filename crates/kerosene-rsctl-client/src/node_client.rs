use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::{Certificate, Client, Identity, Proxy};
use serde_json::Value;
use tracing::info;

use crate::error::ClientError;

/// HTTP client for the kerosene-node Admin API.
///
/// Supports mTLS authentication, Tor SOCKS5H proxying, and
/// Unix domain socket connections.
#[derive(Debug)]
pub struct NodeClient {
    client: Client,
    endpoint: String,
    #[allow(dead_code)]
    unix_socket: Option<PathBuf>,
}

impl NodeClient {
    /// Create a new `NodeClient` with the given configuration.
    ///
    /// When `identity_pem` and `ca` are both provided, mTLS is configured.
    /// When `socks5h` is provided, all traffic is routed through the proxy.
    /// When `unix_socket` is provided, connections use Unix domain sockets.
    pub fn new(
        endpoint: String,
        timeout_secs: u64,
        identity_pem: Option<&Path>,
        ca: Option<&Path>,
        socks5h: Option<&str>,
        unix_socket: Option<PathBuf>,
    ) -> Result<Self, ClientError> {
        let mut builder = Client::builder().timeout(Duration::from_secs(timeout_secs));

        if identity_pem.is_some() != ca.is_some() {
            return Err(ClientError::Config(
                "--identity-pem and --ca must be provided together".into(),
            ));
        }

        if let (Some(identity_pem), Some(ca)) = (identity_pem, ca) {
            builder = builder
                .https_only(true)
                .identity(Identity::from_pem(&fs::read(identity_pem)?)?)
                .add_root_certificate(Certificate::from_pem(&fs::read(ca)?)?);
        }

        if let Some(proxy) = socks5h {
            if !proxy.starts_with("socks5h://") {
                return Err(ClientError::Config(
                    "proxy must use socks5h:// so DNS is resolved through Tor".into(),
                ));
            }
            builder = builder.proxy(Proxy::all(proxy)?);
        }

        Ok(Self {
            client: builder.build()?,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            unix_socket,
        })
    }

    /// Get a builder for more ergonomic construction.
    pub fn builder() -> NodeClientBuilder {
        NodeClientBuilder::default()
    }

    async fn get(&self, path: &str, request_id: &str) -> Result<Value, ClientError> {
        let url = format!("{}{}", self.endpoint, path);
        info!(
            url = %url,
            request_id = %request_id,
            "GET request"
        );
        let response = self
            .client
            .get(&url)
            .header("X-Request-Id", request_id)
            .send()
            .await
            .map_err(classify_error)?;

        Ok(response.error_for_status()?.json().await?)
    }

    /// Node health / readiness status.
    pub async fn status(&self, request_id: &str) -> Result<Value, ClientError> {
        self.get("/v1/readiness", request_id).await
    }

    /// List discovered peers.
    pub async fn peers(&self, request_id: &str) -> Result<Value, ClientError> {
        self.get("/v1/discovery/peers", request_id).await
    }

    /// List membership manifests (current active).
    pub async fn membership_list(&self, request_id: &str) -> Result<Value, ClientError> {
        self.get("/v1/membership/current", request_id).await
    }

    /// Publish a membership manifest to the node.
    pub async fn publish_manifest(
        &self,
        manifest: &Value,
        request_id: &str,
    ) -> Result<Value, ClientError> {
        let url = format!("{}/v1/membership", self.endpoint);
        info!(
            url = %url,
            request_id = %request_id,
            "POST manifest"
        );
        let response = self
            .client
            .post(&url)
            .header("X-Request-Id", request_id)
            .json(manifest)
            .send()
            .await
            .map_err(classify_error)?;
        Ok(response.error_for_status()?.json().await?)
    }

    /// Liveness check.
    pub async fn live(&self, request_id: &str) -> Result<Value, ClientError> {
        self.get("/live", request_id).await
    }
}

fn classify_error(error: reqwest::Error) -> ClientError {
    if error.is_timeout() {
        return ClientError::Timeout(error.to_string());
    }
    if error.is_connect() {
        return ClientError::ConnectionRefused(error.to_string());
    }
    ClientError::Http(error)
}

/// Builder for `NodeClient`.
#[derive(Default)]
pub struct NodeClientBuilder {
    endpoint: Option<String>,
    timeout_secs: Option<u64>,
    identity_pem: Option<PathBuf>,
    ca: Option<PathBuf>,
    socks5h: Option<String>,
    unix_socket: Option<PathBuf>,
}

impl NodeClientBuilder {
    pub fn endpoint(mut self, value: String) -> Self {
        self.endpoint = Some(value);
        self
    }

    pub fn timeout_secs(mut self, value: u64) -> Self {
        self.timeout_secs = Some(value);
        self
    }

    pub fn identity_pem(mut self, value: PathBuf) -> Self {
        self.identity_pem = Some(value);
        self
    }

    pub fn ca(mut self, value: PathBuf) -> Self {
        self.ca = Some(value);
        self
    }

    pub fn socks5h(mut self, value: String) -> Self {
        self.socks5h = Some(value);
        self
    }

    pub fn unix_socket(mut self, value: PathBuf) -> Self {
        self.unix_socket = Some(value);
        self
    }

    pub fn build(self) -> Result<NodeClient, ClientError> {
        let endpoint = self.endpoint.ok_or_else(|| {
            ClientError::Config("endpoint is required to build NodeClient".into())
        })?;
        NodeClient::new(
            endpoint,
            self.timeout_secs.unwrap_or(10),
            self.identity_pem.as_deref(),
            self.ca.as_deref(),
            self.socks5h.as_deref(),
            self.unix_socket,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builder_requires_endpoint() {
        let result = NodeClientBuilder::default().build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("endpoint is required"));
    }

    #[test]
    fn builder_succeeds_with_endpoint() {
        let result = NodeClientBuilder::default()
            .endpoint("http://127.0.0.1:8080".into())
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn mismatched_tls_flags_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        fs::write(&cert_path, b"fake cert").unwrap();

        let result = NodeClient::new(
            "http://127.0.0.1:8080".into(),
            10,
            Some(&cert_path),
            None,
            None,
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("must be provided together"), "got: {err}");
    }

    #[tokio::test]
    async fn connection_refused_error() {
        let client = NodeClient::new("http://127.0.0.1:1".into(), 2, None, None, None, None);
        assert!(client.is_ok());
        let result = client.unwrap().status("test").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ClientError::ConnectionRefused(_)),
            "got: {err}"
        );
    }

    #[test]
    fn redacted_json_contains_no_secrets() {
        let mut value = json!({"identity": "supersecret", "name": "test"});
        crate::redact::redact_value(&mut value);
        assert_eq!(value["identity"], "<REDACTED>");
        assert_eq!(value["name"], "test");
    }
}
