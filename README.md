# Kerosene Node

Rust runtime for Kerosene identity, Tor-only peer discovery, authenticated
membership, progressive startup and state verification.

The Bank and Vault discovery planes are independent. A single Core node or a
single Vault node can start locally without pretending to have quorum:

- `local_ready`: identity, mTLS listener and local state are available;
- `member_ready`: the local root key belongs to the verified roster;
- `quorum_ready`: enough currently live members of the same plane exist;
- `financial_ready`: the node is active after state verification and live
  same-plane quorum.

An isolated member reports `ACTIVE_LOCAL_WAITING_FOR_PEERS`. It stays
operational for local administration and discovery, but cannot exercise
financial authority.

## Workspace

```text
crates/
├── kerosene-identity-core  # persistent Ed25519 root identity
├── kerosene-discovery      # Tor/mTLS handshake and persistent peer store
├── kerosene-membership     # signed manifests and OLD -> JOINT -> NEW
├── kerosene-sync           # lifecycle and state-root verification traits
└── kerosene-node           # HTTPS API and discovery runtime
└── kerosene-rsctl          # operator CLI; no embedded authority
```

Wire types come from a commit-pinned `kerosene-contracts` dependency.
CometBFT/ABCI consensus is intentionally tracked separately in
[issue #2](https://github.com/Daniel-Astrofer/kerosene-node/issues/2); this
repository does not substitute a fake consensus engine.

## Run

Production startup requires a v3 onion endpoint, Tor `socks5h`, a
`GenesisTrustBundleV1`, a server certificate/key and a CA used to require client
certificates. See [operations](docs/OPERATIONS.md) for the complete environment
contract and progressive bootstrap procedure.

```bash
cargo run --locked --features production -p kerosene-node
```

## Verify

```bash
cargo fmt --all -- --check
cargo check --workspace --features production
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Security assumptions and release gates are documented in
[THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[PRODUCTION_GATES.md](docs/PRODUCTION_GATES.md).

## Administrative CLI

`kerosene-rsctl` provides read-only health, peers, membership, quorum,
compatibility and artifact diagnostics. It also supports an offline
create/sign/verify/publish membership ceremony. Private identity files must be
mode `0600`; secrets are never accepted as inline command arguments.

```bash
cargo run -p kerosene-rsctl -- node status \
  --endpoint https://example.onion:8800 --output json-pretty
cargo run -p kerosene-rsctl -- membership verify \
  --manifest signed.json --trust-bundle genesis.json
```
