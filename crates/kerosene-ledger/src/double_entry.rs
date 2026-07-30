use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::account::{AccountClass, StandardAccount};
use crate::error::LedgerError;

/// A single debit or credit posting against a standard account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Posting {
    pub account: StandardAccount,
    pub amount_sats: u64,
}

/// A journal entry — the core unit of the double-entry ledger.
///
/// Every entry is recorded with a monotonically increasing sequence number
/// and is chained to the previous entry via `entry_hash` / `previous_entry_hash`.
///
/// # Hash chain
///
/// ```text
/// material = "{sequence}|{description}|{debits_hash}|{credits_hash}|{prev_hash}|{timestamp}"
/// entry_hash = SHA-256(material)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Unique entry identifier (used for idempotency).
    pub entry_id: String,
    /// Global monotonically increasing sequence number.
    pub sequence: u64,
    /// Human-readable description of the entry.
    pub description: String,
    /// Debit postings.
    pub debits: Vec<Posting>,
    /// Credit postings.
    pub credits: Vec<Posting>,
    /// Time bucket for ordering (e.g. unix epoch seconds / slot).
    pub timestamp_bucket: u64,
    /// SHA-256 hash of this entry's material.
    pub entry_hash: String,
    /// Hash of the previous entry in the chain (`None` for genesis).
    pub previous_entry_hash: Option<String>,
}

impl JournalEntry {
    /// Computes the SHA-256 entry hash from the entry's fields and the
    /// previous entry hash (if any).
    pub fn compute_entry_hash(
        sequence: u64,
        description: &str,
        debits: &[Posting],
        credits: &[Posting],
        timestamp_bucket: u64,
        previous_entry_hash: Option<&str>,
    ) -> String {
        let mut hasher = Sha256::new();
        let debits_hash = Self::hash_postings(debits);
        let credits_hash = Self::hash_postings(credits);
        let prev = previous_entry_hash.unwrap_or("");
        let material = format!(
            "{sequence}|{description}|{debits_hash}|{credits_hash}|{prev}|{timestamp_bucket}"
        );
        hasher.update(material.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Computes a SHA-256 hash of a slice of postings.
    fn hash_postings(postings: &[Posting]) -> String {
        let mut hasher = Sha256::new();
        for p in postings {
            let account_repr = format!("{:?}", p.account);
            hasher.update(account_repr.as_bytes());
            hasher.update(b":");
            hasher.update(p.amount_sats.to_le_bytes());
            hasher.update(b",");
        }
        hex::encode(hasher.finalize())
    }
}

/// Balance of a single account in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBalance {
    /// The account.
    pub account: StandardAccount,
    /// The accounting class of this account.
    pub class: AccountClass,
    /// Total debits posted to this account (in sats).
    pub total_debits_sats: u128,
    /// Total credits posted to this account (in sats).
    pub total_credits_sats: u128,
    /// Net balance: `total_debits - total_credits`.
    /// Positive = debit balance, Negative = credit balance.
    pub net_balance_sats: i128,
}

/// Receipt returned after successfully posting a journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalReceipt {
    /// Assigned sequence number.
    pub sequence: u64,
    /// Hash of the newly posted entry.
    pub entry_hash: String,
    /// Hash of the previous entry (`None` for genesis).
    pub previous_entry_hash: Option<String>,
    /// Updated account balances after this entry.
    pub account_balances: Vec<AccountBalance>,
    /// SHA-256 hash of the full trial balance after this entry.
    pub trial_balance_hash: String,
}

// ---------------------------------------------------------------------------
// LedgerPort — abstract ledger interface
// ---------------------------------------------------------------------------

/// Port trait for the double-entry ledger.
#[async_trait]
pub trait LedgerPort: Send + Sync {
    /// Post a new journal entry (validates and commits).
    async fn post_entry(&self, entry: JournalEntry) -> Result<JournalReceipt, LedgerError>;

    /// Get the current balance for a specific account.
    async fn account_balance(
        &self,
        account: StandardAccount,
    ) -> Result<AccountBalance, LedgerError>;

    /// Get all account balances (trial balance).
    async fn trial_balance(&self) -> Result<Vec<AccountBalance>, LedgerError>;

    /// Get an entry by its sequence number.
    async fn get_entry(&self, sequence: u64) -> Result<Option<JournalEntry>, LedgerError>;

    /// Get the current entry count.
    async fn entry_count(&self) -> Result<u64, LedgerError>;

    /// Get the hash of the most recent entry (head of the chain).
    async fn head_hash(&self) -> Result<Option<String>, LedgerError>;
}

// ---------------------------------------------------------------------------
// InMemoryLedger — in-memory implementation for testing
// ---------------------------------------------------------------------------

struct InMemoryLedgerInner {
    entries: Vec<JournalEntry>,
    balances: HashMap<StandardAccount, AccountBalance>,
    receipts: HashMap<String, JournalReceipt>, // entry_id → receipt (idempotency)
}

/// An in-memory double-entry ledger backed by a `Vec<JournalEntry>`.
///
/// All operations are synchronous and guarded by a `std::sync::Mutex`.
/// This adapter is intended for testing and single-node scenarios.
pub struct InMemoryLedger {
    inner: Mutex<InMemoryLedgerInner>,
}

impl InMemoryLedger {
    /// Creates a new empty in-memory ledger.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InMemoryLedgerInner {
                entries: Vec::new(),
                balances: Self::initial_balances(),
                receipts: HashMap::new(),
            }),
        }
    }

    /// Initialises a zero-balance map for every standard account.
    fn initial_balances() -> HashMap<StandardAccount, AccountBalance> {
        StandardAccount::ALL
            .iter()
            .map(|&acc| {
                let class = acc.class();
                (
                    acc,
                    AccountBalance {
                        account: acc,
                        class,
                        total_debits_sats: 0,
                        total_credits_sats: 0,
                        net_balance_sats: 0,
                    },
                )
            })
            .collect()
    }

    /// Computes a SHA-256 hash of the full trial balance.
    fn compute_trial_balance_hash(
        balances: &HashMap<StandardAccount, AccountBalance>,
    ) -> String {
        let mut hasher = Sha256::new();
        let mut accounts: Vec<_> = balances.keys().collect();
        accounts.sort_by_key(|a| *a);
        for acc in accounts {
            if let Some(bal) = balances.get(acc) {
                let line = format!(
                    "{:?}|{}|{}|{}",
                    acc, bal.total_debits_sats, bal.total_credits_sats, bal.net_balance_sats
                );
                hasher.update(line.as_bytes());
                hasher.update(b"\n");
            }
        }
        hex::encode(hasher.finalize())
    }
}

impl Default for InMemoryLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LedgerPort for InMemoryLedger {
    async fn post_entry(&self, entry: JournalEntry) -> Result<JournalReceipt, LedgerError> {
        let mut inner = self.inner.lock().unwrap();

        // --- Idempotency: return existing receipt if entry_id already seen ---
        if let Some(existing) = inner.receipts.get(&entry.entry_id) {
            return Ok(existing.clone());
        }

        // --- Validation ---

        // 1. At least one debit and one credit
        if entry.debits.is_empty() || entry.credits.is_empty() {
            return Err(LedgerError::EmptyEntry);
        }

        // 2. Sum of debits == sum of credits
        let debits_sum: u128 = entry.debits.iter().map(|p| p.amount_sats as u128).sum();
        let credits_sum: u128 = entry.credits.iter().map(|p| p.amount_sats as u128).sum();
        if debits_sum != credits_sum {
            return Err(LedgerError::UnbalancedEntry {
                debits_sum,
                credits_sum,
            });
        }

        let expected_seq = inner.entries.len() as u64;

        // 3. Sequence gap check
        if entry.sequence != expected_seq {
            return Err(LedgerError::SequenceGap {
                expected: expected_seq,
                got: entry.sequence,
            });
        }

        // 4. Duplicate sequence (redundant after gap check but kept for clarity)
        if entry.sequence < expected_seq {
            return Err(LedgerError::DuplicateSequence(entry.sequence));
        }

        // 5. Compute hash and chain
        let prev_hash = inner
            .entries
            .last()
            .map(|e| e.entry_hash.as_str());
        let computed_hash = JournalEntry::compute_entry_hash(
            entry.sequence,
            &entry.description,
            &entry.debits,
            &entry.credits,
            entry.timestamp_bucket,
            prev_hash,
        );

        // Validate the caller-supplied hash matches
        if entry.entry_hash != computed_hash {
            return Err(LedgerError::InvalidHash(computed_hash));
        }

        // 6. Check previous_entry_hash matches
        match (prev_hash, entry.previous_entry_hash.as_deref()) {
            (Some(expected_prev), Some(given_prev)) if given_prev != expected_prev => {
                return Err(LedgerError::InvalidHash(format!(
                    "previous_entry_hash mismatch: expected {expected_prev}, got {given_prev}"
                )));
            }
            (None, Some(_)) => {
                return Err(LedgerError::InvalidHash(
                    "genesis entry should have previous_entry_hash = None".into(),
                ));
            }
            (Some(_), None) => {
                return Err(LedgerError::InvalidHash(
                    "non-genesis entry must have a previous_entry_hash".into(),
                ));
            }
            _ => {}
        }

        // --- Apply postings to balances ---

        // Apply debits (increase debit balances)
        for posting in &entry.debits {
            let bal = inner
                .balances
                .get_mut(&posting.account)
                .ok_or(LedgerError::AccountNotFound(posting.account))?;
            let amount = posting.amount_sats as u128;
            bal.total_debits_sats = bal
                .total_debits_sats
                .checked_add(amount)
                .ok_or(LedgerError::BalanceOverflow {
                    account: posting.account,
                })?;
            bal.net_balance_sats = (bal.total_debits_sats as i128)
                .checked_sub(bal.total_credits_sats as i128)
                .ok_or(LedgerError::BalanceOverflow {
                    account: posting.account,
                })?;
        }

        // Apply credits (increase credit balances)
        for posting in &entry.credits {
            let bal = inner
                .balances
                .get_mut(&posting.account)
                .ok_or(LedgerError::AccountNotFound(posting.account))?;
            let amount = posting.amount_sats as u128;
            bal.total_credits_sats = bal
                .total_credits_sats
                .checked_add(amount)
                .ok_or(LedgerError::BalanceOverflow {
                    account: posting.account,
                })?;
            bal.net_balance_sats = (bal.total_debits_sats as i128)
                .checked_sub(bal.total_credits_sats as i128)
                .ok_or(LedgerError::BalanceOverflow {
                    account: posting.account,
                })?;
        }

        // 7. Check negative balances per account class
        for bal in inner.balances.values() {
            match bal.class {
                AccountClass::Asset | AccountClass::Expense => {
                    // Must have debit balance (net >= 0)
                    if bal.net_balance_sats < 0 {
                        return Err(LedgerError::NegativeBalance {
                            account: bal.account,
                            balance: bal.net_balance_sats,
                        });
                    }
                }
                AccountClass::Liability | AccountClass::Equity | AccountClass::Revenue => {
                    // Must have credit balance (net <= 0)
                    if bal.net_balance_sats > 0 {
                        return Err(LedgerError::NegativeBalance {
                            account: bal.account,
                            balance: bal.net_balance_sats,
                        });
                    }
                }
            }
        }

        // --- Commit the entry ---
        inner.entries.push(entry.clone());

        let account_balances: Vec<AccountBalance> = {
            let mut accounts: Vec<_> = inner.balances.values().cloned().collect();
            accounts.sort_by_key(|b| b.account);
            accounts
        };

        let trial_balance_hash = Self::compute_trial_balance_hash(&inner.balances);

        let receipt = JournalReceipt {
            sequence: entry.sequence,
            entry_hash: entry.entry_hash.clone(),
            previous_entry_hash: entry.previous_entry_hash.clone(),
            account_balances: account_balances.clone(),
            trial_balance_hash,
        };

        inner.receipts.insert(entry.entry_id.clone(), receipt.clone());

        Ok(receipt)
    }

    async fn account_balance(
        &self,
        account: StandardAccount,
    ) -> Result<AccountBalance, LedgerError> {
        let inner = self.inner.lock().unwrap();
        inner
            .balances
            .get(&account)
            .cloned()
            .ok_or(LedgerError::AccountNotFound(account))
    }

    async fn trial_balance(&self) -> Result<Vec<AccountBalance>, LedgerError> {
        let inner = self.inner.lock().unwrap();
        let mut accounts: Vec<_> = inner.balances.values().cloned().collect();
        accounts.sort_by_key(|b| b.account);
        Ok(accounts)
    }

    async fn get_entry(&self, sequence: u64) -> Result<Option<JournalEntry>, LedgerError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.entries.get(sequence as usize).cloned())
    }

    async fn entry_count(&self) -> Result<u64, LedgerError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.entries.len() as u64)
    }

    async fn head_hash(&self) -> Result<Option<String>, LedgerError> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.entries.last().map(|e| e.entry_hash.clone()))
    }
}

// Provide a static list of all standard accounts for iteration.
impl StandardAccount {
    /// All variants of `StandardAccount`.
    pub const ALL: [StandardAccount; 9] = [
        StandardAccount::AssetCustodiedBtc,
        StandardAccount::AssetColdBtc,
        StandardAccount::AssetHotBtc,
        StandardAccount::LiabilityUserBalances,
        StandardAccount::LiabilityPendingWithdrawals,
        StandardAccount::LiabilityInternalReserved,
        StandardAccount::EquityPlatform,
        StandardAccount::ExpenseMinerFees,
        StandardAccount::RevenuePlatformFees,
    ];
}
