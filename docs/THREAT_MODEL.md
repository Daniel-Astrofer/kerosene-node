# Threat model

## Protected assets

- root identity private key;
- authenticated membership and manifest history;
- network/plane separation;
- state-root integrity;
- quorum and financial-readiness decisions.

Vault shares and transaction signing are outside this process.

## Trust boundaries

- Tor provides address privacy and remote name resolution, not peer authority.
- mTLS protects the transport, but membership is established by root-key
  signatures from the versioned trust bundle and manifests.
- Discovery inputs are untrusted until onion syntax, network, plane, root key,
  signature, challenge, timestamp and membership all verify.
- Persisted endpoints are hints only. They do not survive as live votes.

## Implemented controls

- v3 onion HTTPS endpoints only; clearnet, userinfo, query strings and local
  service DNS are rejected;
- `socks5h` is mandatory so DNS is resolved by Tor;
- mutual TLS is mandatory for inbound and configured outbound production paths;
- signed, single-use, expiring challenges prevent replay;
- self-connections and cross-plane handshakes cannot increase quorum;
- member IDs bind network and root public key;
- manifests reject forks, replay, duplicate signers and insufficient quorum;
- membership changes require OLD -> JOINT -> NEW;
- active peer TTL and current-roster filtering protect readiness;
- lifecycle transitions cannot be skipped;
- root identity files use owner-only permissions;
- identity key material is zeroized on load (both success and error code paths)
  via the `zeroize` crate.

## Key rotation

### Identity key (Ed25519 root key)

The root identity key is permanent and network-bound. It is not rotated as a
matter of routine maintenance.

**When rotation is required:**
- Confirmed compromise or suspected leak of the private key.
- Operator loses access to the key and has no backup.
- A post-quantum migration replaces Ed25519 (see below).

**Procedure:**
1. The affected member generates a new Ed25519 key pair out of band (offline
   machine, `kerosene-node-keygen`).
2. An admission request for the new key is signed by a sponsor and submitted.
3. A joint manifest is published adding the new key and removing the old key
   in a single `OLD → JOINT → NEW` transition.
4. The manifest is signed by the old threshold (including the compromised key,
   if still usable, or an alternative path if not).
5. After the new stable manifest is confirmed, the old key is revoked and
   the node is restarted with the new identity file.
6. If the compromised key cannot sign the transition (e.g. it was stolen and
   is now controlled by an adversary), the procedure requires a governance
   intervention: a super-majority of remaining trusted operators sign an
   emergency manifest that replaces the compromised roster entry.

**Timeline:**
- Key rotation via the standard OLD→JOINT→NEW path: ~1 hour (ceremony time).
- Emergency rotation (compromised key refuses to cooperate): requires
  governance process, typically 24–48 hours for threshold reconfiguration.

**Emergency fallback without the old key:**
If the old threshold cannot be met because the compromised key is adversarial,
the canonical chain must be abandoned and a new genesis bundle issued. All
nodes restart with the new trust bundle. This is a last resort and constitutes
a network reset.

### TLS certificates

TLS certificates (server cert, client cert, client CA) are rotated on a
fixed schedule:

| Certificate | Lifetime | Rotation trigger | Grace period |
|---|---|---|---|
| Server certificate | 1 year | Auto-renew at 30 days before expiry | 24 hours |
| Client identity | 1 year | Auto-renew at 30 days before expiry | 24 hours |
| Client CA | 5 years | Manual renewal 60 days before expiry | 7 days |

TLS rotation does not affect membership, identity, or discovery state. It is a
transport-layer change only. The node must be restarted (or the TLS listener
hot-reloaded) after certificate replacement.

### Genesis trust bundle

The genesis bundle is not rotated. Membership changes are expressed via signed
manifests. If the genesis bundle itself is compromised, the network must be
restarted with a new bundle (see emergency fallback above).

## Post-quantum considerations

### Current status

Kerosene uses Ed25519 for all cryptographic operations:
- Identity signing and verification (`ed25519-dalek`).
- Manifest signing and verification.
- No post-quantum algorithms are implemented.

Ed25519 provides 128-bit security against classical adversaries but is broken
by a sufficiently large quantum computer (Shor's algorithm).

### Migration path

When a post-quantum (PQ) migration becomes necessary:

1. **Protocol version bump**: `DISCOVERY_CONTRACT_VERSION` is incremented.
   New nodes can advertise PQ-signed PeerHelloV2 (or equivalent).
2. **Dual-signing period**: During transition, manifests include both an
   Ed25519 signature and a PQ signature (e.g. ML-DSA, SLH-DSA). Thresholds
   are computed as "N of M Ed25519 AND N of M PQ".
3. **Full migration**: After all members have PQ-capable keys, the
   `GenesisTrustBundleV2` or a manifest drops Ed25519 requirements.
4. **Fallback**: Nodes that cannot verify PQ signatures fall back to Ed25519
   during the dual-signing period but log a warning.

No PQ algorithm is mandated or implemented in this repository. The crate
structure is designed to allow a new `kerosene-identity-pq` crate with a
compatible `CanonicalSignable` trait without modifying discovery or membership
core logic.

### Timeline

An active PQ migration is not required for mainnet. The threat model assumes
a classical adversary. The migration path must be implemented before any known
quantum threat materializes (currently estimated at 2030+ for sufficiently
large fault-tolerant quantum computers).

## Implementation gaps identified during review

The following gaps were identified during the pre-mainnet implementation review
(ISSUE node#6) and must be addressed before mainnet:

| Gap | Component | Severity | Mitigation |
|---|---|---|---|
| No built-in rate limiting on challenge issuance | Discovery | Medium | Deployment infrastructure must rate-limit `/v1/discovery/challenge`. A periodic eviction sweep in `ChallengeStore` is recommended. |
| No built-in rate limiting on manifest ingestion | Membership | Medium | Deployment infrastructure must rate-limit `/v1/membership/current` and mirror feeds. |
| No explicit recursion/ depth limit on JSON deserialization | All (serde_json) | Low | `serde_json` defaults may allow deep nesting. Consider `serde_stacker` for production. |
| Self-connection check is in the caller, not in `PeerAuthenticator` | Discovery | Low | The `discovery` module's handshake handler rejects local member IDs; this is tested but not enforced at the authenticator layer. |
| Challenge map has no active eviction (only lazy on `consume`) | Discovery | Low | Under sustained challenge-request flooding, un-consumed challenges accumulate in memory. Add a periodic `retain` sweep. |

## Residual risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Compromise of enough membership roots to authorize a malicious roster | Low | Critical | Offline root-key storage, threshold signing ceremony, independent monitoring |
| Compromised host memory can expose the node identity while the process runs | Medium | High | mlock() identity pages if available; HSM or TPM integration (future) |
| Tor or peer flooding can degrade availability | Medium | Medium | Upstream rate limiting, connection limits, resource monitoring |
| Local disk exhaustion can prevent atomic persistence | Low | Medium | Disk usage monitoring, separate partition for peer-store |
| Wall-clock manipulation beyond the configured window can deny handshakes | Low | Low | NTP monitoring, alert on clock skew; use of multiple time sources |
| CometBFT/ABCI consensus failure due to misconfigured validator set | Low | Critical | Covered by CometBFT operational procedures, not Kerosene protocol |
| Challenge-store memory exhaustion under flooding | Low | Medium | Add periodic eviction sweep (see implementation gaps above) |
| TLS certificate expiry causes connectivity loss | Medium | Medium | Automated renewal, expiry monitoring and alerting |
| Split-brain due to concurrent manifest signing | Low | High | Serial signing ceremony, automated hash cross-check (`kerosene-rsctl membership audit`) |
| Key compromise during rotation window | Low | High | Out-of-band key generation, minimal rotation window duration |

Rate limiting, host hardening, independent monitoring and offline root-key
procedures must be applied by deployment infrastructure. These are not
enforced by the Kerosene protocol.
