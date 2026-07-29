# Architecture

`kerosene-node` keeps five independent decisions separate:

1. **Identity** proves control of a network-bound Ed25519 root key.
2. **Discovery** finds onion endpoints but grants no authority.
3. **Membership** verifies signed, hash-chained rosters.
4. **Readiness** reports local/member/quorum/financial capability independently.
5. **Authority** is only available after the required lifecycle and live quorum.

`memberId = SHA-256(networkId || rootPublicKey)`. Network addresses are HTTPS
v3 onion services; clearnet publication and local DNS service discovery are
rejected.

## Planes

Bank discovery and Vault discovery use different trust roots, manifests,
thresholds and handshakes. A valid Bank peer cannot satisfy a Vault quorum, and
the inverse is also true. Any authenticated peer can transport a manifest, but
only its valid root signatures and hash-chain make it authoritative.

## Progressive lifecycle

```text
CREATED
  -> IDENTITY_READY
  -> TRANSPORT_READY
  -> DISCOVERING
  -> AUTHENTICATED
  -> MEMBER_VERIFIED
  -> SYNCING
  -> STATE_VERIFIED
  -> ELIGIBLE
  -> ACTIVE
```

Transitions cannot be skipped. Persisted peers are discovery hints after a
restart, never proof that they are live. `ACTIVE` requires a verified state and
current live quorum.

## Discovery order

Each discovery cycle rebuilds and deduplicates the candidate list:

1. previous successful connections;
2. endpoints in the current verified manifest;
3. configured genesis endpoints;
4. configured signed-mirror transport endpoints;
5. endpoints learned from previously authenticated peers.

Before any peer is admitted, both sides exchange a single-use challenge and a
signed `KEROSENE_PEER_HELLO_V1`. The transcript binds contract version,
network, plane, member ID, root key, endpoint, challenge and timestamp. HTTPS
uses Tor remote DNS resolution (`socks5h`) and mutual TLS.

## Membership

The `GenesisTrustBundleV1` establishes independent Bank and Vault roots and
thresholds. Manifests are deterministic, signed and hash-chained. A roster
change cannot move directly between stable sets:

```text
OLD stable -> JOINT(old + proposed new) -> NEW stable
```

The joint entry requires both the old threshold and the proposed new threshold.
Replays, forks, wrong epochs, duplicate signers and direct membership changes
fail closed.

## Persistence

The peer-store owns:

- `peers.db`;
- `endpoints.db`;
- `successful-connections.db`;
- `membership-manifests.db`;
- `lifecycle.db`.

Writes use a temporary file and atomic rename. These files contain public peer
metadata, not Vault shares, macaroons, signing material or user data. The root
identity key is stored separately with owner-only permissions.

## Consensus boundary

The synchronization crate defines deterministic state-root verification and an
adapter trait. CometBFT remains an external consensus process and its pinned
compatibility and ABCI implementation belong to issue #2. Discovery and
membership do not claim consensus finality.
