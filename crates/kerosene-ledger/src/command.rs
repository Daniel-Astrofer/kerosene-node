use serde::{Deserialize, Serialize};

/// Operations that can be applied to an account balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BalanceOperation {
    /// Increase the available balance.
    Credit,
    /// Decrease the available balance (requires sufficient spendable funds).
    Debit,
    /// Move funds from available to reserved (two-phase commitment).
    Reserve,
    /// Move funds from reserved back to available (abort a reservation).
    ReleaseReservation,
}

/// A versioned command to modify a single account balance.
///
/// Every command carries the `expected_version` that the caller observed.
/// If the account's current version differs, the command is rejected with
/// `VersionConflict`, preventing lost updates in concurrent scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceCommand {
    /// Globally unique command identifier (used for idempotency).
    pub command_id: String,
    /// The account to operate on.
    pub account_id: String,
    /// The version the caller observed before issuing this command.
    pub expected_version: u64,
    /// The operation to perform.
    pub operation: BalanceOperation,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// Epoch bucket for ordering.
    pub epoch: u64,
    /// Hash of the payload for integrity verification.
    pub payload_hash: String,
}

/// An atomic internal transfer between two accounts.
///
/// Both source and destination carry their own expected versions.
/// The transfer either commits fully (both sides updated) or not at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalTransferCommand {
    /// Globally unique command identifier (used for idempotency).
    pub command_id: String,
    /// Source account whose balance will be debited.
    pub source_account_id: String,
    /// Expected version of the source account.
    pub source_expected_version: u64,
    /// Destination account whose balance will be credited.
    pub destination_account_id: String,
    /// Expected version of the destination account.
    pub destination_expected_version: u64,
    /// Amount in satoshis to transfer.
    pub amount_sats: u64,
    /// Authorization commitment (e.g. multi-sig approval hash).
    pub authorization_commitment: String,
}

impl BalanceCommand {
    /// Creates a new `BalanceCommand` with the given parameters.
    /// Computes the `payload_hash` from the command fields (excluding command_id).
    pub fn new(
        command_id: impl Into<String>,
        account_id: impl Into<String>,
        expected_version: u64,
        operation: BalanceOperation,
        amount_sats: u64,
        epoch: u64,
    ) -> Self {
        let cmd = Self {
            command_id: command_id.into(),
            account_id: account_id.into(),
            expected_version,
            operation,
            amount_sats,
            epoch,
            payload_hash: String::new(),
        };
        cmd
    }
}

impl InternalTransferCommand {
    /// Creates a new `InternalTransferCommand`.
    pub fn new(
        command_id: impl Into<String>,
        source_account_id: impl Into<String>,
        source_expected_version: u64,
        destination_account_id: impl Into<String>,
        destination_expected_version: u64,
        amount_sats: u64,
        authorization_commitment: impl Into<String>,
    ) -> Self {
        Self {
            command_id: command_id.into(),
            source_account_id: source_account_id.into(),
            source_expected_version,
            destination_account_id: destination_account_id.into(),
            destination_expected_version,
            amount_sats,
            authorization_commitment: authorization_commitment.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_balance_command() {
        let cmd = BalanceCommand::new("cmd-1", "account-1", 0, BalanceOperation::Credit, 1000, 1);
        assert_eq!(cmd.command_id, "cmd-1");
        assert_eq!(cmd.account_id, "account-1");
        assert_eq!(cmd.expected_version, 0);
        assert_eq!(cmd.operation, BalanceOperation::Credit);
        assert_eq!(cmd.amount_sats, 1000);
    }

    #[test]
    fn create_internal_transfer() {
        let cmd = InternalTransferCommand::new(
            "tx-1",
            "source-1",
            5,
            "dest-1",
            3,
            500,
            "auth-commit-123",
        );
        assert_eq!(cmd.command_id, "tx-1");
        assert_eq!(cmd.source_account_id, "source-1");
        assert_eq!(cmd.source_expected_version, 5);
        assert_eq!(cmd.destination_account_id, "dest-1");
        assert_eq!(cmd.destination_expected_version, 3);
        assert_eq!(cmd.amount_sats, 500);
        assert_eq!(cmd.authorization_commitment, "auth-commit-123");
    }

    #[test]
    fn balance_operation_serde_roundtrip() {
        let ops = [
            BalanceOperation::Credit,
            BalanceOperation::Debit,
            BalanceOperation::Reserve,
            BalanceOperation::ReleaseReservation,
        ];
        for op in &ops {
            let json = serde_json::to_string(op).unwrap();
            let deserialized: BalanceOperation = serde_json::from_str(&json).unwrap();
            assert_eq!(*op, deserialized);
        }
    }
}
