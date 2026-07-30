//! kerosene-rsctl-client — HTTP and Unix-socket client library
//! for the kerosene infrastructure administration client.
//!
//! This crate provides:
//! - `NodeClient` — HTTP client for the kerosene-node API
//! - `VaultClient` trait + `MockVaultClient` — vault Admin API (issue #10)
//! - `CompatibilityClient` — protocol version compatibility checks
//! - `ClientError` — unified error type
//! - `redact` — sensitive data redaction utilities

pub mod compat_client;
pub mod error;
pub mod node_client;
pub mod redact;
pub mod vault_client;

pub use compat_client::CompatibilityClient;
pub use error::ClientError;
pub use node_client::{NodeClient, NodeClientBuilder};
pub use vault_client::{MockVaultClient, UnixVaultClient, VaultClient};
