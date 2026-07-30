use serde::{Deserialize, Serialize};

use crate::double_entry::AccountBalance;

/// A versioned snapshot of all account balances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBalanceState {
    /// Monotonically increasing version number.
    pub version: u64,
    /// All account balances at this version.
    pub balances: Vec<AccountBalance>,
}
