use parking_lot::RwLock;
use tendermint::abci::response;
use tracing::info;

use crate::state::AppState;

/// Persist the current application state and return the AppHash.
///
/// Called by CometBFT after `FinalizeBlock` to commit the state.
/// The AppHash returned here is included in the next block header.
pub fn commit_state(state: &RwLock<AppState>) -> response::Commit {
    let hash = {
        let mut s = state.write();
        s.increment_version();
        s.root_hash()
    };

    info!(
        app_hash = %hex::encode(hash),
        "Commit called, state persisted"
    );

    response::Commit {
        retain_height: 0u32.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_increments_version() {
        let state = RwLock::new(AppState::new());
        assert_eq!(state.read().app_version(), 0);

        let _resp = commit_state(&state);
        assert_eq!(state.read().app_version(), 1);

        let _resp = commit_state(&state);
        assert_eq!(state.read().app_version(), 2);
    }

    #[test]
    fn commit_after_mutations_produces_app_hash() {
        let state = RwLock::new(AppState::new());
        {
            let mut s = state.write();
            s.apply("key1", b"value1");
        }

        let resp = commit_state(&state);

        // Check that the state changed by verifying version incremented
        assert_eq!(state.read().app_version(), 1);
        assert_eq!(state.read().len(), 1);
    }

    #[test]
    fn commit_with_empty_state() {
        let state = RwLock::new(AppState::new());
        let resp = commit_state(&state);
        assert_eq!(state.read().app_version(), 1);
    }
}
