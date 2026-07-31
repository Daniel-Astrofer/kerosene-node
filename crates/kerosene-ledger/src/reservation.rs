use serde::{Deserialize, Serialize};

/// States in the two-phase reservation lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReservationState {
    /// Reservation has been prepared (funds earmarked but not committed).
    Prepared,
    /// Reservation has been committed via quorum.
    Committed,
    /// Reservation has been consumed (external settlement succeeded).
    Consumed,
    /// Reservation has been released (external settlement failed / aborted).
    Released,
    /// Reservation has expired (time window elapsed).
    Expired,
}

/// A two-phase reservation for withdrawals and settlements.
///
/// Flow:
/// 1. Create reservation command → commit via quorum
/// 2. Reduce available_sats, increase reserved_sats
/// 3. Begin external settlement (KFE/PSBT/FROST)
/// 4. Consume reservation on success (zero out reserved)
/// 5. Release or expire on failure (restore available)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    /// Unique identifier for this reservation.
    pub reservation_id: String,
    /// The account against which the reservation is held.
    pub account_id: String,
    /// Amount in satoshis reserved.
    pub amount_sats: u64,
    /// Current state in the reservation lifecycle.
    pub state: ReservationState,
    /// Time bucket when the reservation was created.
    pub created_at_bucket: u64,
    /// Time bucket after which the reservation expires.
    pub expires_at_bucket: u64,
    /// Sequence number of the journal entry that committed this reservation.
    pub committed_sequence: u64,
    /// Authorization commitment (e.g. multi-sig approval hash).
    pub authorization_commitment: String,
}

impl Reservation {
    /// Creates a new reservation in the `Prepared` state.
    pub fn new(
        reservation_id: impl Into<String>,
        account_id: impl Into<String>,
        amount_sats: u64,
        created_at_bucket: u64,
        expires_at_bucket: u64,
        authorization_commitment: impl Into<String>,
    ) -> Self {
        Self {
            reservation_id: reservation_id.into(),
            account_id: account_id.into(),
            amount_sats,
            state: ReservationState::Prepared,
            created_at_bucket,
            expires_at_bucket,
            committed_sequence: 0,
            authorization_commitment: authorization_commitment.into(),
        }
    }

    /// Returns `true` if the reservation is in a terminal state (consumed,
    /// released, or expired).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            ReservationState::Consumed | ReservationState::Released | ReservationState::Expired
        )
    }

    /// Returns `true` if the reservation is expired given the current bucket.
    pub fn is_expired(&self, current_bucket: u64) -> bool {
        current_bucket >= self.expires_at_bucket
            && !matches!(self.state, ReservationState::Consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_reservation_in_prepared_state() {
        let r = Reservation::new("res-1", "account-1", 1000, 10, 20, "auth-1");
        assert_eq!(r.reservation_id, "res-1");
        assert_eq!(r.account_id, "account-1");
        assert_eq!(r.amount_sats, 1000);
        assert_eq!(r.state, ReservationState::Prepared);
        assert_eq!(r.created_at_bucket, 10);
        assert_eq!(r.expires_at_bucket, 20);
        assert_eq!(r.committed_sequence, 0);
    }

    #[test]
    fn terminal_state_detection() {
        let mut r = Reservation::new("res-1", "a", 100, 0, 10, "auth");
        assert!(!r.is_terminal());
        r.state = ReservationState::Committed;
        assert!(!r.is_terminal());
        r.state = ReservationState::Consumed;
        assert!(r.is_terminal());
        r.state = ReservationState::Released;
        assert!(r.is_terminal());
        r.state = ReservationState::Expired;
        assert!(r.is_terminal());
    }

    #[test]
    fn expired_detection_consumed_not_expired() {
        let r = Reservation {
            state: ReservationState::Consumed,
            expires_at_bucket: 10,
            ..Reservation::new("r", "a", 100, 0, 10, "auth")
        };
        // Consumed reservations are never "expired" regardless of bucket
        assert!(!r.is_expired(100));
    }

    #[test]
    fn not_expired_before_expiry() {
        let r = Reservation::new("r", "a", 100, 0, 10, "auth");
        assert!(!r.is_expired(5));
    }

    #[test]
    fn expired_after_expiry_bucket() {
        let r = Reservation::new("r", "a", 100, 0, 10, "auth");
        assert!(r.is_expired(10));
        assert!(r.is_expired(15));
    }

    #[test]
    fn reservation_serde_roundtrip() {
        let r = Reservation::new("res-1", "account-1", 1000, 10, 20, "auth-1");
        let json = serde_json::to_string(&r).unwrap();
        let deserialized: Reservation = serde_json::from_str(&json).unwrap();
        assert_eq!(r, deserialized);
    }
}
