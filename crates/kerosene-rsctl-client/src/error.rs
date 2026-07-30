use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Connection refused: {0}")]
    ConnectionRefused(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    #[error("Certificate not found: {0}")]
    CertificateNotFound(PathBuf),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("{0}")]
    Other(String),
}

impl From<String> for ClientError {
    fn from(value: String) -> Self {
        ClientError::Other(value)
    }
}
