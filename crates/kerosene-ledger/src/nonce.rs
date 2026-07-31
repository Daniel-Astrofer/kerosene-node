use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::LedgerError;

// ---------------------------------------------------------------------------
// NonceChecker trait (async)
// ---------------------------------------------------------------------------

/// Interface for checking and recording nonces (anti-replay).
///
/// Vaults and the KFE use this to ensure that a settlement authorization
/// nonce has not been seen before, preventing replay attacks.
#[async_trait]
pub trait NonceChecker: Send + Sync {
    /// Returns `true` if the nonce has already been consumed.
    async fn is_consumed(&self, nonce: &str) -> Result<bool, LedgerError>;

    /// Mark a nonce as consumed (returns an error if already consumed).
    async fn mark_consumed(&self, nonce: &str) -> Result<(), LedgerError>;
}

// ---------------------------------------------------------------------------
// InMemoryNonceChecker
// ---------------------------------------------------------------------------

/// In-memory implementation of `NonceChecker` backed by a `HashSet`.
///
/// Used for testing and single-node deployments. Not durable across restarts.
pub struct InMemoryNonceChecker {
    consumed: Mutex<HashSet<String>>,
}

impl InMemoryNonceChecker {
    /// Creates a new empty nonce checker.
    pub fn new() -> Self {
        Self {
            consumed: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for InMemoryNonceChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NonceChecker for InMemoryNonceChecker {
    async fn is_consumed(&self, nonce: &str) -> Result<bool, LedgerError> {
        let inner = self.consumed.lock().unwrap();
        Ok(inner.contains(nonce))
    }

    async fn mark_consumed(&self, nonce: &str) -> Result<(), LedgerError> {
        let mut inner = self.consumed.lock().unwrap();
        if inner.contains(nonce) {
            return Err(LedgerError::AuthorizationInvalid(format!(
                "nonce already consumed: {}",
                nonce
            )));
        }
        inner.insert(nonce.to_string());
        Ok(())
    }
}

/// Sync wrapper for `InMemoryNonceChecker` that can be used by
/// `VaultAuthorizationVerifier` for synchronous verification.
impl crate::settlement::NonceChecker for InMemoryNonceChecker {
    fn is_consumed_sync(&self, nonce: &str) -> bool {
        let inner = self.consumed.lock().unwrap();
        inner.contains(nonce)
    }

    fn mark_consumed_sync(&self, nonce: &str) {
        let mut inner = self.consumed.lock().unwrap();
        inner.insert(nonce.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settlement::NonceChecker as SyncNonceChecker;

    #[tokio::test]
    async fn fresh_nonce_is_not_consumed() {
        let nc = InMemoryNonceChecker::new();
        assert!(!nc.is_consumed("nonce-1").await.unwrap());
    }

    #[tokio::test]
    async fn mark_consumed_works() {
        let nc = InMemoryNonceChecker::new();
        nc.mark_consumed("nonce-1").await.unwrap();
        assert!(nc.is_consumed("nonce-1").await.unwrap());
    }

    #[tokio::test]
    async fn double_consumption_returns_error() {
        let nc = InMemoryNonceChecker::new();
        nc.mark_consumed("nonce-1").await.unwrap();
        let err = nc.mark_consumed("nonce-1").await.unwrap_err();
        assert!(matches!(err, LedgerError::AuthorizationInvalid(_)));
    }

    #[tokio::test]
    async fn different_nonces_are_independent() {
        let nc = InMemoryNonceChecker::new();
        nc.mark_consumed("nonce-1").await.unwrap();
        assert!(!nc.is_consumed("nonce-2").await.unwrap());
        assert!(nc.is_consumed("nonce-1").await.unwrap());
    }

    #[tokio::test]
    async fn sync_check_matches_async() {
        let nc = InMemoryNonceChecker::new();
        nc.mark_consumed("nonce-1").await.unwrap();
        assert!(nc.is_consumed_sync("nonce-1"));
        assert!(!nc.is_consumed_sync("nonce-2"));
    }
}
