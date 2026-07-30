use std::env;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::AppError;

/// ABCI server connection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum CometBftTransport {
    /// Connect over a Unix domain socket.
    Unix,
    /// Connect over TCP.
    Tcp,
}

/// Configuration for the CometBFT adapter.
#[derive(Debug, Clone)]
pub struct CometBftConfig {
    /// Address to listen on (Unix socket path or TCP addr).
    pub listen_addr: String,
    /// Transport mode.
    pub transport: CometBftTransport,
    /// Path to persist application state.
    pub state_path: PathBuf,
    /// Network ID for transaction validation.
    pub network_id: String,
    /// Maximum number of transactions per block.
    pub max_tx_per_block: u32,
}

impl CometBftConfig {
    /// Load configuration from environment variables.
    ///
    /// # Variables
    /// - `KEROSENE_ABCI_LISTEN_ADDR` — listen address (default: `/tmp/kerosene-abci.sock`)
    /// - `KEROSENE_ABCI_TRANSPORT` — `unix` or `tcp` (default: `unix`)
    /// - `KEROSENE_ABCI_STATE_PATH` — state persistence path (default: `data/abci-state`)
    /// - `KEROSENE_NETWORK_ID` — network identifier (required)
    /// - `KEROSENE_ABCI_MAX_TX_PER_BLOCK` — max tx per block (default: `1000`)
    pub fn from_env() -> Result<Self, AppError> {
        let listen_addr = env::var("KEROSENE_ABCI_LISTEN_ADDR")
            .unwrap_or_else(|_| "/tmp/kerosene-abci.sock".into());

        let transport = match env::var("KEROSENE_ABCI_TRANSPORT")
            .as_deref()
            .unwrap_or("unix")
        {
            "unix" => CometBftTransport::Unix,
            "tcp" => CometBftTransport::Tcp,
            other => {
                return Err(AppError::Config(format!(
                    "unknown KEROSENE_ABCI_TRANSPORT={other}; expected 'unix' or 'tcp'"
                )));
            }
        };

        let state_path = PathBuf::from(
            env::var("KEROSENE_ABCI_STATE_PATH").unwrap_or_else(|_| "data/abci-state".into()),
        );

        let network_id =
            env::var("KEROSENE_NETWORK_ID").map_err(|_| AppError::Config("KEROSENE_NETWORK_ID is required".into()))?;

        let max_tx_per_block = env::var("KEROSENE_ABCI_MAX_TX_PER_BLOCK")
            .ok()
            .map(|v| v.parse::<u32>())
            .transpose()
            .map_err(|e| AppError::Config(format!("invalid KEROSENE_ABCI_MAX_TX_PER_BLOCK: {e}")))?
            .unwrap_or(1000);

        Ok(Self {
            listen_addr,
            transport,
            state_path,
            network_id,
            max_tx_per_block,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        temp_env::with_vars_unset([
            "KEROSENE_ABCI_LISTEN_ADDR",
            "KEROSENE_ABCI_TRANSPORT",
            "KEROSENE_ABCI_STATE_PATH",
            "KEROSENE_NETWORK_ID",
            "KEROSENE_ABCI_MAX_TX_PER_BLOCK",
        ], || {
            let result = CometBftConfig::from_env();
            assert!(result.is_err(), "should fail without NETWORK_ID");
        });
    }

    #[test]
    fn config_with_network_id() {
        temp_env::with_vars([
            ("KEROSENE_NETWORK_ID", Some("testnet-1")),
            ("KEROSENE_ABCI_LISTEN_ADDR", Some("/tmp/test.sock")),
            ("KEROSENE_ABCI_TRANSPORT", Some("unix")),
        ], || {
            let config = CometBftConfig::from_env().unwrap();
            assert_eq!(config.network_id, "testnet-1");
            assert_eq!(config.listen_addr, "/tmp/test.sock");
            assert_eq!(config.transport, CometBftTransport::Unix);
            assert_eq!(config.max_tx_per_block, 1000);
        });
    }

    #[test]
    fn config_tcp_transport() {
        temp_env::with_vars([
            ("KEROSENE_NETWORK_ID", Some("testnet-1")),
            ("KEROSENE_ABCI_TRANSPORT", Some("tcp")),
            ("KEROSENE_ABCI_LISTEN_ADDR", Some("127.0.0.1:26658")),
        ], || {
            let config = CometBftConfig::from_env().unwrap();
            assert_eq!(config.transport, CometBftTransport::Tcp);
            assert_eq!(config.listen_addr, "127.0.0.1:26658");
        });
    }

    #[test]
    fn config_invalid_transport() {
        temp_env::with_vars([
            ("KEROSENE_NETWORK_ID", Some("testnet-1")),
            ("KEROSENE_ABCI_TRANSPORT", Some("quic")),
        ], || {
            let err = CometBftConfig::from_env().unwrap_err();
            assert!(err.to_string().contains("unknown"));
        });
    }
}

/// Helper module for test env var management.
///
/// Provides a simple way to temporarily set env vars for testing.
/// In production, we'd use the `temp_env` crate, but this inline
/// approach avoids adding a dev dependency.
#[cfg(test)]
mod temp_env {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static TEST_ENV: Mutex<Option<HashMap<String, Option<String>>>> = Mutex::new(None);

    pub fn with_vars(vars: Vec<(&str, Option<&str>)>, f: impl FnOnce()) {
        let previous = std::env::vars().collect::<HashMap<_, _>>();
        // Clear
        for (key, _) in &previous {
            std::env::remove_var(key);
        }
        // Set test vars
        for (key, value) in &vars {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        f();
        // Restore
        std::env::vars().for_each(|(k, _)| std::env::remove_var(k));
        for (key, value) in &previous {
            std::env::set_var(key, value);
        }
    }

    pub fn with_vars_unset(names: &[&str], f: impl FnOnce()) {
        let previous = std::env::vars().collect::<HashMap<_, _>>();
        for name in names {
            std::env::remove_var(name);
        }
        f();
        std::env::vars().for_each(|(k, _)| std::env::remove_var(k));
        for (key, value) in &previous {
            std::env::set_var(key, value);
        }
    }
}
