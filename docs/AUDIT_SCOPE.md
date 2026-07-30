# External audit scope

This document defines the scope for an independent cryptographic and protocol
audit of the Kerosene node discovery and membership subsystem. Every finding
must be resolved before a mainnet promotion can be approved.

## Audit boundary

The audit covers the following crates and the wire protocols they implement:

| Crate | Role |
|---|---|
| `kerosene-identity-core` | Root Ed25519 identity generation, persistence, PeerHello signing/verification |
| `kerosene-discovery` | Tor/mTLS handshake flow, challenge-response, peer authentication, persistent peer store |
| `kerosene-membership` | `GenesisTrustBundleV1` verification, manifest hash-chain, OLD→JOINT→NEW transition, signature threshold enforcement |
| `kerosene-contracts` (pinned commit) | Wire type definitions: `PeerHelloV1`, `AdmissionRequestV1`, `MembershipManifestV1`, `GenesisTrustBundleV1`, canonical encoding |

## 1. Protocol review

### 1.1 PeerHelloV1

- Contract version, network ID, and discovery plane are bound into the signed
  transcript — confirm none can be silently substituted across contexts.
- The challenge is a single-use 32-byte random value (via `OsRng`), issued and
  consumed by `ChallengeStore`. Verify the UTC timestamp + TTL enforcement
  cannot be bypassed or rolled back.
- `issued_at_epoch_ms` is checked against `max_clock_skew_ms` bidirectionally
  (`abs_diff`). Confirm no overflow or wrap-around path can bypass the check.
- The endpoint is validated as an HTTPS v3 onion before signing, and
  re-validated on receipt. Confirm no canonicalization mismatch exists between
  the two validation sites.
- `member_id` is recomputed from `SHA-256(networkId || rootPublicKey)` during
  verification. Confirm the derivation is consistent and cannot collide across
  networks.

### 1.2 AdmissionRequestV1

- Binds sponsor, candidate, candidate key, and network. Verify sponsor
  membership is independently proven (not self-attested).
- Signature covers the full canonical encoding. Confirm no fields are omitted
  or accidentally unconstrained.
- The admission request alone does not authorize roster changes — it must be
  followed by a signed manifest transition. Verify the protocol enforces this
  sequencing.

### 1.3 MembershipManifestV1

- Hash chain: `previous_manifest_hash` must equal `SHA-256(canonical(parent))`.
  Verify this is deterministic and cannot be shortcut.
- Epochs are strictly monotonically increasing per chain. Initial epoch must be
  > 0 and point to `"0".repeat(64)` as the root sentinel.
- `MembershipPhase::Stable` must not have `next_epoch` set.
- `MembershipPhase::Joint` must have `next_epoch > epoch`.
- Transition rule: `Stable → Joint → Stable`. A `Stable → Stable` change that
  alters the roster must be rejected (requires `JointConsensusRequired`).
- Signature threshold: the minimum of `(threshold_old, threshold_new)` does not
  apply — each phase requires its own threshold. Verify:
  - Stable manifest after genesis: genesis threshold signers from genesis members.
  - Joint manifest: both old-threshold (old members) AND new-threshold (new members).
  - New stable manifest: new-threshold (new members).

## 2. Cryptography review

### 2.1 Ed25519 signatures

- Identity key generation: `OsRng` + `ed25519-dalek` — verify no weak-RNG path.
- `PeerHelloV1` is signed via `signing_bytes()` canonical encoding.
- Manifest signatures are independently verified via `ed25519-dalek::Verifier`.
- Key material is hex-encoded for transport. Verify encoding/decoding is
  consistent and rejects invalid lengths.
- Verify `zeroize` is applied to secret key bytes after loading on all code
  paths (success and error).

### 2.2 SHA-256 hash chains

- `canonical_hash(manifest)` uses domain-separated canonical JSON encoding.
- Verify no two distinct manifests can produce the same hash (canonicalization
  collision resistance).
- Genesis sentinel hash is `"0".repeat(64)`. Verify this cannot collide with a
  real manifest hash.

### 2.3 Domain-separated canonical encoding

- `CanonicalSignable` trait produces deterministic signing bytes.
- Verify field ordering is fixed and no metadata is appended outside the
  signed payload.
- Verify `signing_bytes()` includes all semantically relevant fields and does
  not include fields that vary per-hop (e.g. relay metadata).

## 3. Discovery review

### 3.1 Tor handshake

- Challenge: issued as GET `/v1/discovery/challenge`, consumed by POST
  `/v1/discovery/hello`. Verify a challenge obtained on one endpoint cannot be
  replayed on another.
- `socks5h` is mandatory — verify no path uses `socks5` (local DNS) or direct
  TCP.
- mTLS: inbound requires a client certificate validated against the configured
  CA. Outbound uses a configured client identity. Verify certs cannot be
  substituted at the application layer.
- Self-connection prevention: `PeerAuthenticator.authenticate` does not check
  the local member ID — the caller (`discovery` module) must enforce this.
  Verify the check exists at the correct layer.

### 3.2 Challenge-response

- `ChallengeStore.issue` inserts a random 32-byte hex challenge with a TTL.
- `consume` uses a single `retain + remove` — verify no race or double-consume
  is possible under concurrent calls (the Mutex protects this).
- TTL is clamped to `max(1, value)`. Verify a TTL of 0 cannot disable expiry.
- Expired challenges are lazily purged on `consume`. Verify this is not a
  denial vector (challenge map is per-peer-store, bounded by active exchanges).

### 3.3 Peer authentication

- `PeerAuthenticator.authenticate` checks, in order:
  1. contract version, network, plane (`ScopeMismatch`)
  2. clock skew (`ClockSkew`)
  3. onion endpoint validity (`InvalidEndpoint`)
  4. signature + member ID binding (`Identity`)
  5. challenge consumption (`ChallengeRejected`)
  6. membership roster check (`NotMember`)
- Verify the order creates no oracle: a failed step does not reveal more
  information than necessary (e.g. challenge consumption happens *after*
  signature verification, so a bad-signature peer never learns whether their
  challenge was valid).

## 4. Membership review

### 4.1 OLD → JOINT → NEW transition

- Entry from genesis: first manifest must be `Stable`, epoch > 0, hash points
  to sentinel, signed by genesis threshold.
- From Stable: either a no-op Stable (same roster, confirmed) or a Joint with
  proposed new roster.
- From Joint: only a Stable with identical roster to the Joint.
- Verify all other transitions (`Joint → Joint`, `Stable → Stable` with roster
  change, epoch skips) are rejected.

### 4.2 Threshold enforcement

- Genesis threshold: `0 < threshold <= member_count`.
- Manifest threshold: verified the same way.
- Joint threshold: both old-roster threshold AND new-roster threshold must sign.
- Verify signatures from members outside the authorized set are ignored (not
  counted toward threshold, not treated as invalid-veto).

### 4.3 Hash chain continuity

- `canonical_hash(current) == next.previous_manifest_hash` is verified on every
  `accept()`.
- After restart: `MembershipVerifier::restore` replays all persisted manifests
  through `accept()`. Verify a corrupted or reordered manifest list fails
  closed.

## 5. Operational review

- Identity file permissions: `0o600` on Unix. Verify no world-readable fallback.
- Peer-store atomic writes: temporary-file + rename. Verify no partial write
  can leave a corrupt database that passes JSON deserialization.
- Verified membership is used before discovery authentication. Verify the
  bootstrapping path (no manifests yet → genesis) cannot be confused with a
  post-genesis state.

## Deliverables

The auditor must produce:

1. A numbered findings report with severity (critical / high / medium / low /
   informational).
2. For each finding: location (file:line), description, exploit scenario, and
   remediation recommendation.
3. A summary of the protocol's security posture and residual risks.
4. A separate re-audit report if any critical or high findings are remediated
   after the initial audit.
