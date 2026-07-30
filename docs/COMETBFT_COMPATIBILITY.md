# CometBFT compatibility

This document records the fixed CometBFT version for the current release and
documents ABCI compatibility, known breaking changes, and the upgrade
procedure.

## Fixed version

| Component | Version | Source |
|---|---|---|
| CometBFT | v0.38.x | CometBFT releases |
| ABCI | v0.38.x (RFC 696 / protobuf) | `tower-abci` v0.19 |
| Tendermint-rs | 0.40.x | `tendermint` / `tendermint-proto` crates |
| Adapter crate | `kerosene-cometbft-adapter` | This workspace |

The dependency versions are pinned in `Cargo.toml`:

```toml
tendermint = "0.40"
tendermint-proto = "0.40"
tower-abci = "0.19"
```

## ABCI compatibility (v0.38.x)

The `kerosene-cometbft-adapter` crate implements the following ABCI v0.38
methods:

| ABCI method | Implemented | Notes |
|---|---|---|
| `Echo` | Yes | Passthrough |
| `Flush` | Yes | Passthrough |
| `Info` | Yes | Returns app version, height, app hash |
| `InitChain` | Yes | Initializes state, returns app hash |
| `Query` | Yes | Key-value query |
| `CheckTx` | Yes | Validates transaction format, Ed25519 signature, nonce uniqueness |
| `FinalizeBlock` | Yes | Executes transactions, applies to state |
| `Commit` | Yes | Computes and returns AppHash (SHA-256 state root) |
| `PrepareProposal` | Yes | Passthrough (returns txs unchanged) |
| `ProcessProposal` | Yes | Always accepts |
| `ExtendVote` | Yes | Returns empty vote extension |
| `VerifyVoteExtension` | Yes | Always accepts |
| `ListSnapshots` | No | Returns empty list |
| `OfferSnapshot` | No | No-op |
| `LoadSnapshotChunk` | No | No-op |
| `ApplySnapshotChunk` | No | No-op |

### Transport

The adapter supports both Unix domain sockets and TCP:

```bash
KEROSENE_ABCI_TRANSPORT=unix   # default
KEROSENE_ABCI_LISTEN_ADDR=/tmp/kerosene-abci.sock  # default

KEROSENE_ABCI_TRANSPORT=tcp
KEROSENE_ABCI_LISTEN_ADDR=127.0.0.1:26658
```

### Service splitting

`tower-abci v0.38` splits the single ABCI service into four category
services (consensus, mempool, info, snapshot) with the following concurrency
limits:

| Service | Buffer | Concurrency |
|---|---|---|
| Consensus | 1 | 1 |
| Mempool | 100 | 10 |
| Info | 10 | 5 |
| Snapshot | 1 | 1 |

Consensus service is serialized (buffer 1, concurrency 1) because the ABCI
application is not thread-safe for consensus operations.

## Breaking changes to watch for

### CometBFT v0.38.x → v0.39+

If upgrading CometBFT beyond v0.38.x, the following changes affect the
adapter:

- **ABCI v1.0 / v0.39**: `BeginBlock` and `EndBlock` are removed; all logic
  moves to `FinalizeBlock`. The adapter already uses `FinalizeBlock` only,
  so this change is compatible, but the `tower-abci` dependency must be
  updated.
- **Proposal methods**: `PrepareProposal` and `ProcessProposal` signatures
  may change. The adapter currently passes through all txs and always accepts
  — verify compatibility.
- **Vote extensions**: v0.38.0 introduced vote extensions. The adapter
  returns empty extensions. Future versions may require non-empty extensions.
- **Snapshots**: v0.38+ supports state sync snapshots. The adapter returns
  empty lists. Snapshot support must be implemented before state sync is
  needed.

### Tendermint-rs 0.40.x

- The `tendermint` crate v0.40 may change `AppHash`, `Height`, and `Code`
  types. The adapter currently converts between internal and `tendermint`
  types explicitly — these conversions must be updated if the types change.
- `tendermint-proto` v0.40 matches `tendermint` v0.40. Both must be upgraded
  together.

### tower-abci 0.19

- `tower-abci` v0.19 targets CometBFT v0.38.x. Upgrading tower-abci requires
  matching support for the target CometBFT version.
- The `split::service` function partitions the app into four services. Its
  signature may change in future versions.

## Upgrade procedure

### Minor/patch upgrade (within v0.38.x)

1. Update the CometBFT binary to the new patch version.
2. Verify no breaking changes in the release notes.
3. Run the existing test suite:
   ```bash
   cargo test --workspace --all-features
   ```
4. Run the progressive bootstrap integration test:
   ```bash
   cargo test --package kerosene-node --test progressive_bootstrap
   ```
5. Verify on a staging network before production.

### Minor version upgrade (e.g. v0.38 → v0.39)

1. Audit the new CometBFT release notes for all ABCI changes.
2. Update `tendermint`, `tendermint-proto`, and `tower-abci` dependencies in
   `Cargo.toml`.
3. Run `cargo update` and commit the updated `Cargo.lock`.
4. Fix any compilation errors from changed types.
5. Run `cargo test --workspace --all-features`.
6. Run full load test suite (`ops/LOAD_TEST_PLAN.md`).
7. Run split-brain recovery drill (`ops/SPLIT_BRAIN_RECOVERY.md`).
8. Deploy to staging, then production.

### Major version upgrade (e.g. v0.38 → v1.0)

1. Full protocol audit of ABCI changes.
2. Potentially create a new adapter crate (`kerosene-cometbft-v2-adapter`) if
   the changes are not backward compatible.
3. Dual-run on staging with both old and new adapters.
4. Migrate after one full epoch of consistent behavior.

## Compatibility tests

The CI workflow (`.github/workflows/security.yml`) includes a
`compatibility` job that uses a shared `compatibility-ci.yml` workflow. This
job must verify:

- CometBFT binary version matches the expected version.
- ABCI handshake succeeds (Info response is valid).
- Echo + Flush cycle works.
- InitChain + FinalizeBlock + Commit produces a valid AppHash.
- CheckTx rejects malformed transactions.

Test the compatibility:

```bash
# Start the ABCI application
cargo run --release -p kerosene-cometbft-adapter --bin kerosene-abci &

# Use a test harness or CometBFT's built-in kvstore test
cometbft test --abci-addr unix:///tmp/kerosene-abci.sock
```
