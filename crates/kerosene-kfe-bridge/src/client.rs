use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

/// A Unix domain socket client for communicating with the KFE Java service.
///
/// Uses JSON-RPC style message exchange over a Unix socket.
/// Each message is a single line of JSON terminated by a newline.
#[derive(Debug, Clone)]
pub struct UnixSocketClient {
    socket_path: String,
    /// Connection timeout in milliseconds.
    connect_timeout_ms: u64,
    /// Request timeout in milliseconds.
    request_timeout_ms: u64,
    /// Maximum number of reconnection attempts.
    max_retries: u32,
}

impl UnixSocketClient {
    /// Create a new client connecting to the given Unix socket path.
    pub fn new(socket_path: String) -> Self {
        Self {
            socket_path,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
            max_retries: 3,
        }
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Send a JSON-RPC request and receive the response.
    ///
    /// This establishes a new connection for each call and reads a
    /// single line response. The connection is closed after each call.
    pub async fn call(&self, request: String) -> Result<String, ClientError> {
        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            match self.try_call(&request).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = Some(e);
                    if attempt < self.max_retries {
                        tokio::time::sleep(Duration::from_millis(100 * 2u64.saturating_pow(attempt))).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or(ClientError::Connection("max retries exceeded".into())))
    }

    async fn try_call(&self, request: &str) -> Result<String, ClientError> {
        if !Path::new(&self.socket_path).exists() {
            return Err(ClientError::Connection(format!(
                "socket not found: {}",
                self.socket_path
            )));
        }

        let stream = timeout(
            Duration::from_millis(self.connect_timeout_ms),
            UnixStream::connect(&self.socket_path),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|e| ClientError::Connection(e.to_string()))?;

        let (reader, mut writer) = stream.into_split();

        // Send request with newline terminator
        let mut request_bytes = request.as_bytes().to_vec();
        request_bytes.push(b'\n');
        writer
            .write_all(&request_bytes)
            .await
            .map_err(|e| ClientError::Connection(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| ClientError::Connection(e.to_string()))?;

        // Read response line
        let mut buf_reader = BufReader::new(reader);
        let mut response = String::new();

        timeout(Duration::from_millis(self.request_timeout_ms), async {
            buf_reader
                .read_line(&mut response)
                .await
                .map_err(|e| ClientError::Connection(e.to_string()))?;
            Ok::<_, ClientError>(())
        })
        .await
        .map_err(|_| ClientError::Timeout)??;

        if response.is_empty() {
            return Err(ClientError::Connection("empty response from KFE".into()));
        }

        Ok(response.trim().to_string())
    }
}

/// Errors from the Unix socket client.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connection error: {0}")]
    Connection(String),

    #[error("request timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    /// Helper: start a mock KFE server on a temp socket.
    async fn start_mock_server(socket_path: &str) -> tokio::net::UnixListener {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).unwrap();
        listener
    }

    #[tokio::test]
    async fn send_and_receive() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("kfe.sock");
        let socket_str = socket_path.to_str().unwrap().to_string();

        let listener = start_mock_server(&socket_str).await;
        let socket_str_clone = socket_str.clone();

        // Spawn mock server that echoes back a fixed response
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            stream.read(&mut buf).await.unwrap();
            let response = b"{\"allowed\": true}\n";
            stream.write_all(response).await.unwrap();
            stream.flush().await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        let client = UnixSocketClient::new(socket_str_clone);
        let response = client
            .call(r#"{"method": "check_transaction", "params": {}, "id": 1}"#.into())
            .await
            .unwrap();

        assert_eq!(response, r#"{"allowed": true}"#);
    }

    #[tokio::test]
    async fn socket_not_found() {
        let client = UnixSocketClient::new("/tmp/nonexistent-kfe-test.sock".into());
        let result = client
            .call(r#"{"method": "check_transaction"}"#.into())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn connection_timeout() {
        // Use a socket that exists but doesn't respond
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("hang.sock");
        let socket_str = socket_path.to_str().unwrap().to_string();

        let listener = start_mock_server(&socket_str).await;

        // Don't accept connections, just let the socket file exist

        let mut client = UnixSocketClient::new(socket_str);
        client.connect_timeout_ms = 100; // Very short timeout

        let result = client
            .call(r#"{"method": "check_transaction"}"#.into())
            .await;

        // Should fail due to connection timeout
        assert!(result.is_err());
    }
}
