use serde::{Deserialize, Serialize};

/// Classifies an account within the double-entry chart of accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccountClass {
    Asset,
    Liability,
    Equity,
    Expense,
    Revenue,
}

/// Canonical chart of accounts for the Kerosene platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StandardAccount {
    /// BTC under Kerosene custodial control (hot + cold aggregated)
    AssetCustodiedBtc,
    /// BTC in cold storage
    AssetColdBtc,
    /// BTC in hot wallet
    AssetHotBtc,
    /// Liabilities owed to platform users
    LiabilityUserBalances,
    /// Withdrawals that have been requested but not yet settled
    LiabilityPendingWithdrawals,
    /// Internal reserves set aside for operational purposes
    LiabilityInternalReserved,
    /// Platform equity / retained earnings
    EquityPlatform,
    /// Bitcoin miner fees paid out
    ExpenseMinerFees,
    /// Platform fees collected from users
    RevenuePlatformFees,
}

impl StandardAccount {
    /// Returns the accounting class for this standard account.
    pub fn class(&self) -> AccountClass {
        match self {
            Self::AssetCustodiedBtc | Self::AssetColdBtc | Self::AssetHotBtc => {
                AccountClass::Asset
            }
            Self::LiabilityUserBalances
            | Self::LiabilityPendingWithdrawals
            | Self::LiabilityInternalReserved => AccountClass::Liability,
            Self::EquityPlatform => AccountClass::Equity,
            Self::ExpenseMinerFees => AccountClass::Expense,
            Self::RevenuePlatformFees => AccountClass::Revenue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_classification() {
        assert_eq!(
            StandardAccount::AssetCustodiedBtc.class(),
            AccountClass::Asset
        );
        assert_eq!(StandardAccount::AssetColdBtc.class(), AccountClass::Asset);
        assert_eq!(StandardAccount::AssetHotBtc.class(), AccountClass::Asset);
        assert_eq!(
            StandardAccount::LiabilityUserBalances.class(),
            AccountClass::Liability
        );
        assert_eq!(
            StandardAccount::LiabilityPendingWithdrawals.class(),
            AccountClass::Liability
        );
        assert_eq!(
            StandardAccount::LiabilityInternalReserved.class(),
            AccountClass::Liability
        );
        assert_eq!(StandardAccount::EquityPlatform.class(), AccountClass::Equity);
        assert_eq!(
            StandardAccount::ExpenseMinerFees.class(),
            AccountClass::Expense
        );
        assert_eq!(
            StandardAccount::RevenuePlatformFees.class(),
            AccountClass::Revenue
        );
    }
}
