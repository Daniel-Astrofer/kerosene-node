use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::error::AppError;

/// A versioned key-value store used as the ABCI application state machine.
///
/// Each key has an associated version (monotonic counter) and value.
/// The state supports snapshot/restore for crash recovery and
/// computes an AppHash as the SHA-256 root of the entire state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    /// Internal versioned KV store.
    store: BTreeMap<String, VersionedValue>,
    /// Monotonic block height.
    height: u64,
    /// Monotonic app version (increments on each commit).
    app_version: u64,
}

/// A value with its version metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionedValue {
    value: Vec<u8>,
    version: u64,
}

impl AppState {
    /// Create an empty application state at height 0.
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
            height: 0,
            app_version: 0,
        }
    }

    /// Apply a state mutation (set a key-value pair) at the current height.
    ///
    /// Returns the previous value if the key existed.
    pub fn apply(&mut self, key: impl Into<String>, value: impl Into<Vec<u8>>) -> Option<Vec<u8>> {
        let key = key.into();
        let value = value.into();
        let previous = self.store.get(&key).map(|v| v.value.clone());
        self.store.insert(
            key,
            VersionedValue {
                value,
                version: self.app_version,
            },
        );
        previous
    }

    /// Apply a batch of state mutations atomically.
    pub fn apply_batch(&mut self, entries: Vec<(String, Vec<u8>)>) {
        for (key, value) in entries {
            self.store.insert(
                key,
                VersionedValue {
                    value,
                    version: self.app_version,
                },
            );
        }
    }

    /// Get a value by key.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.store.get(key).map(|v| v.value.as_slice())
    }

    /// Check if a key exists.
    pub fn has(&self, key: &str) -> bool {
        self.store.contains_key(key)
    }

    /// Remove a key from the store.
    pub fn delete(&mut self, key: &str) -> Option<Vec<u8>> {
        self.store.remove(key).map(|v| v.value)
    }

    /// Compute the AppHash = SHA-256 over the canonical encoding of the
    /// entire key-value store sorted by key.
    ///
    /// The encoding is: for each (key, value) pair in BTree order,
    /// hash the concatenation: SHA-256(key_len || key || value_len || value),
    /// then combine all hashes with another SHA-256.
    pub fn root_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for (key, vv) in &self.store {
            let key_bytes = key.as_bytes();
            let key_len = key_bytes.len() as u64;
            let val_len = vv.value.len() as u64;
            hasher.update(key_len.to_le_bytes());
            hasher.update(key_bytes);
            hasher.update(val_len.to_le_bytes());
            hasher.update(&vv.value);
        }
        let mut result = [0u8; 32];
        result.copy_from_slice(&hasher.finalize());
        result
    }

    /// Take a serializable snapshot of the current state.
    pub fn snapshot(&self) -> Result<Vec<u8>, AppError> {
        serde_json::to_vec(self).map_err(|e| AppError::State(e.to_string()))
    }

    /// Restore state from a previously-taken snapshot.
    pub fn restore(data: &[u8]) -> Result<Self, AppError> {
        serde_json::from_slice(data).map_err(|e| AppError::State(e.to_string()))
    }

    /// Current block height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Set the current block height.
    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    /// Current app version.
    pub fn app_version(&self) -> u64 {
        self.app_version
    }

    /// Increment the app version (called on Commit).
    pub fn increment_version(&mut self) {
        self.app_version += 1;
    }

    /// Number of key-value pairs in the store.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Get all state entries for debugging/inspection.
    pub fn entries(&self) -> Vec<(&str, &[u8], u64)> {
        self.store
            .iter()
            .map(|(k, vv)| (k.as_str(), vv.value.as_slice(), vv.version))
            .collect()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_root_hash_is_deterministic() {
        let state = AppState::new();
        let hash1 = state.root_hash();
        let hash2 = AppState::new().root_hash();
        assert_eq!(hash1, hash2);
        // Empty hash should not be all zeros
        assert!(hash1.iter().any(|&b| b != 0));
    }

    #[test]
    fn apply_and_retrieve() {
        let mut state = AppState::new();
        assert!(state.is_empty());
        state.apply("alice", b"100");
        assert_eq!(state.get("alice"), Some(b"100" as &[u8]));
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn overwrite_returns_previous() {
        let mut state = AppState::new();
        state.apply("key1", b"v1");
        let prev = state.apply("key1", b"v2");
        assert_eq!(prev, Some(b"v1".to_vec()));
        assert_eq!(state.get("key1"), Some(b"v2" as &[u8]));
    }

    #[test]
    fn delete_removes_key() {
        let mut state = AppState::new();
        state.apply("key1", b"value");
        assert!(state.has("key1"));
        let deleted = state.delete("key1");
        assert_eq!(deleted, Some(b"value".to_vec()));
        assert!(!state.has("key1"));
    }

    #[test]
    fn root_hash_changes_after_mutation() {
        let mut state = AppState::new();
        let hash_before = state.root_hash();
        state.apply("key", b"value");
        let hash_after = state.root_hash();
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn deterministic_root_hash() {
        let mut s1 = AppState::new();
        s1.apply("a", b"1");
        s1.apply("b", b"2");

        let mut s2 = AppState::new();
        s2.apply("a", b"1");
        s2.apply("b", b"2");

        assert_eq!(s1.root_hash(), s2.root_hash());
    }

    #[test]
    fn snapshot_and_restore_roundtrip() {
        let mut state = AppState::new();
        state.apply("alice", b"100");
        state.apply("bob", b"200");
        state.set_height(42);
        state.increment_version();

        let snapshot = state.snapshot().unwrap();
        let restored = AppState::restore(&snapshot).unwrap();

        assert_eq!(restored.get("alice"), Some(b"100" as &[u8]));
        assert_eq!(restored.get("bob"), Some(b"200" as &[u8]));
        assert_eq!(restored.height(), 42);
        assert_eq!(restored.app_version(), 1);
        assert_eq!(restored.root_hash(), state.root_hash());
    }

    #[test]
    fn apply_batch_atomic() {
        let mut state = AppState::new();
        state.apply_batch(vec![
            ("x".into(), b"10".to_vec()),
            ("y".into(), b"20".to_vec()),
        ]);
        assert_eq!(state.len(), 2);
        assert_eq!(state.get("x"), Some(b"10" as &[u8]));
        assert_eq!(state.get("y"), Some(b"20" as &[u8]));
    }

    #[test]
    fn ordered_entries() {
        let mut state = AppState::new();
        state.apply("z", b"3");
        state.apply("a", b"1");
        state.apply("m", b"2");

        let entries = state.entries();
        let keys: Vec<&str> = entries.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(keys, vec!["a", "m", "z"]);
    }
}
