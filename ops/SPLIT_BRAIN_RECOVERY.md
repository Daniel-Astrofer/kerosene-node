# Split-brain detection and recovery

A split-brain occurs when two (or more) subsets of the Kerosene network
independently produce conflicting membership manifests, resulting in divergent
hash chains and incompatible rosters. Because Kerosene uses the CometBFT
consensus engine, a split brain also manifests as consensus failure — nodes
cannot agree on blocks because they operate from different membership sets.

## Symptoms

### Consensus-level symptoms

- CometBFT consensus rounds repeatedly fail to commit.
- Different nodes report different `AppHash` values after the same block
  height.
- `/ready-quorum` returns 503 despite enough peers being reachable
  (because quorum is calculated per-manifest, and different nodes compute
  different thresholds).
- `kerosene-rsctl node status` shows healthy `/live` and `/ready-local` but
  inconsistent member counts across nodes.

### Membership-level symptoms

- Querying `/v1/membership/current` from different nodes returns manifests
  with different `canonical_hash` values.
- Manifest hash chains diverge after a specific epoch number.
- Conflicting membership manifests have the same epoch but different hashes
  (a fork).
- A node reports that a remote peer's manifest hash does not match its own
  chain.

### Discovery-level symptoms

- A node repeatedly connects to peers but cannot synchronize manifests.
- Peers that should be current members are reported as non-members.
- Successful handshakes complete, but membership verification fails with
  `HashChain` or `EpochTransition`.

## Detection procedure

### Step 1: Identify the fork point

Query all reachable nodes for their current manifest:

```bash
for node in node-a.onion node-b.onion node-c.onion; do
  echo "=== $node ==="
  curl -s https://$node:8800/v1/membership/current \
    --cert ... --key ... --cacert ... \
    | jq '{epoch: .epoch, hash: (.previous_manifest_hash[0:16] + "...")}'
done
```

If different nodes report manifests with the same `epoch` but different
`previous_manifest_hash`, a fork at `epoch - 1` is confirmed.

### Step 2: Trace the divergence

Retrieve the full manifest history from conflicting nodes:

```bash
# Node A's chain
curl -s https://node-a.onion:8800/v1/membership/history > node-a-chain.json

# Node B's chain
curl -s https://node-b.onion:8800/v1/membership/history > node-b-chain.json
```

Compare the two chains epoch by epoch:

```bash
diff <(jq -c '.[] | {epoch, previous_manifest_hash}' node-a-chain.json) \
     <(jq -c '.[] | {epoch, previous_manifest_hash}' node-b-chain.json)
```

The first epoch where the hashes differ is the fork point.

### Step 3: Determine the canonical chain

The canonical chain is the one that:

1. Has the highest epoch number (most recent manifest).
2. Has valid hash chain continuity from genesis (verify with
   `MembershipVerifier::restore`).
3. Has valid threshold signatures on every link in the chain.
4. (If applicable) Is consistent with CometBFT's committed block height.

Verify candidate chains:

```bash
cargo run -p kerosene-rsctl -- membership verify \
  --manifest candidate-chain.json \
  --trust-bundle /path/to/genesis-trust-bundle.json
```

If both chains fail verification, the network may be under active attack.
Proceed to quarantine (Step 4a).

## Recovery

### Step 4a: Quarantine — non-canonical partition

Isolate nodes on the non-canonical chain:

1. Block their onion endpoints at the network firewall or Tor configuration.
2. Remove their endpoints from `successful-connections.db` on canonical nodes.
3. Notify operators of the non-canonical nodes.
4. Do NOT publish any new manifest from the non-canonical side.

On the non-canonical nodes:

```bash
# Stop the kerosene process
# Back up the peer-store and identity key
cp -r peer-store peer-store.split-brain-backup

# Clear manifest database (quarantine the fork)
echo '[]' > peer-store/membership-manifests.db
```

### Step 4b: Rejoin — non-canonical to canonical

On the non-canonical node, after quarantine:

1. Restart the node with at least one canonical genesis endpoint in
   `KEROSENE_GENESIS_ENDPOINTS` (or a canonical peer's endpoint).
2. The node's `PersistentPeerStore` starts fresh (or from genesis manifests).
3. Discovery connects to the canonical peer; the handshake succeeds.
4. The node fetches the current canonical manifest.
5. `MembershipVerifier::restore` replays the canonical chain. If the node's
   own identity is in the roster, `ready-member` returns 200.
6. The node re-enters quorum with the canonical partition.

If the non-canonical node has pending state that needs to be replayed
(CometBFT blocks), the operator must manually replay or discard those blocks
before rejoining.

### Step 4c: Determine root cause

After recovery, investigate:

- Was the fork caused by a bug in manifest signing (two different signer
  subsets producing valid manifests at the same epoch)?
- Was the fork caused by a clock skew allowing simultaneous valid-but-
  different manifest proposals?
- Was the fork caused by a race condition in `MembershipVerifier::accept`?
- Was the fork caused by operator error (two operators independently signing
  manifests)?

Document the root cause and update the threat model before declaring the
network healthy.

## Prevention

### Pre-signed manifest serialization

Manifests should be produced through a serial ceremony, not concurrently:

1. One operator prepares the proposed manifest.
2. All signers sign the same canonical bytes.
3. The manifest is published only after all required signatures are collected.
4. A new manifest is published only after the previous one is confirmed by all
   nodes.

### Monitoring

- Alert on any `/v1/membership/current` hash divergence across nodes.
- Monitor `canonical_hash` as a metric in the health dashboard.
- Record the signing time; if two manifests for the same epoch appear within
  the clock skew window, trigger an immediate investigation.

### Automated checks

The `kerosene-rsctl` suite:

```bash
# Cross-check manifest hash across all known peers
cargo run -p kerosene-rsctl -- membership audit \
  --endpoints https://node-a.onion:8800,https://node-b.onion:8800

# Verify chain continuity locally
cargo run -p kerosene-rsctl -- membership verify \
  --manifest /path/to/peer-store/membership-manifests.db \
  --trust-bundle /path/to/genesis-trust-bundle.json
```

## When to declare an incident

Declare a security incident if any of the following is true:

- A fork was caused by an adversary gaining threshold signing capability.
- The fork persisted longer than `KEROSENE_CHALLENGE_TTL_MS` without
  detection.
- Non-canonical nodes processed financial transactions.
- The root cause is unknown after 4 hours of investigation.
