# Load test plan — discovery and membership

This plan defines the load test procedure for the Kerosene discovery subsystem
and membership verification under sustained traffic.

## Target metrics

| Metric | Target | Measurement method |
|---|---|---|
| Handshake throughput | ≥ 1000 complete handshakes/sec | Count authenticated peers / test duration |
| p95 challenge-to-hello latency | ≤ 200 ms | Per-handshake timing on client |
| p95 manifest fetch latency | ≤ 100 ms | Per-request timing on client |
| p95 Ed25519 verify latency | ≤ 1 ms | Instrumented in `PeerAuthenticator::authenticate` |
| CPU per handshake | ≤ 5 ms of CPU time | `perf stat` or `/proc/pid/stat` |
| Memory per authenticated peer | ≤ 1 KB | RSS delta / peer count |
| Network I/O per handshake | ≤ 2 KB sent + 2 KB received | `tcpdump` or instrumented I/O counters |
| Error rate | ≤ 0.1 % | 5xx responses / total requests |

## Hardware specification

### Baseline test environment (minimum)

| Component | Specification |
|---|---|
| Nodes | 4 peer nodes + 1 load generator |
| CPU | 2 vCPUs per node (x86_64, ~2.5 GHz) |
| RAM | 4 GB per node |
| Disk | 20 GB SSD per node |
| Network | 1 Gbps interconnect (same data center preferred) |
| Tor | Local Tor daemon per node; no external Tor network |

### Production-equivalent environment (recommended)

| Component | Specification |
|---|---|
| Nodes | 10 peer nodes + 1 load generator |
| CPU | 4 vCPUs per node (x86_64, ~3.0 GHz) |
| RAM | 8 GB per node |
| Disk | 50 GB NVMe per node |
| Network | 10 Gbps interconnect |
| Tor | Dedicated Tor instance per node with onion service |

## Setup

### Node configuration

All nodes use:

```bash
KEROSENE_CHALLENGE_TTL_MS=30000
KEROSENE_PEER_LIVE_WINDOW_MS=90000
KEROSENE_DISCOVERY_INTERVAL_MS=15000
```

The load generator is a separate machine running `curl` or a custom HTTP
client that replays PeerHello exchanges.

### Test network topology

```
[Load Generator] -- HTTPS/Tor/mTLS --> [Node A]
                                       [Node B]
                                       [Node C]
                                       [Node D]
```

All nodes are in the same discovery plane (Bank). The load generator
impersonates distinct member identities (one per simulated peer), pre-loaded
into the genesis trust bundle so membership verification succeeds.

### Load generation script

A test script should:

1. Generate N distinct Ed25519 key pairs.
2. Add them to the trust bundle before the test (or use a small set of allowed
   member IDs that each simulated peer cycles through).
3. For each simulated handshake:
   a. GET `/v1/discovery/challenge` from a target node.
   b. Construct and sign a `PeerHelloV1`.
   c. POST `/v1/discovery/hello` with the hello and a response challenge.
   d. Record timing, success/failure, and response size.

## Test procedures

### Test 1: Ramp-up

Gradually increase the handshake rate and measure success rate.

1. Start at 10 handshakes/sec for 60 seconds.
2. Increase to 50/sec for 60 seconds.
3. Increase to 100/sec for 60 seconds.
4. Increase to 500/sec for 60 seconds.
5. Increase to 1000/sec for 60 seconds.
6. Hold at 1000/sec for 300 seconds.

**Pass criteria**: Error rate stays below 0.1% at each step. p95 latency
stays below 200 ms at 1000/sec.

### Test 2: Sustained load

Run at 1000 handshakes/sec for 1 hour.

**Pass criteria**: No degradation in throughput or latency over the hour.
Memory and CPU usage are stable (no monotonic growth). Zero crashes.

### Test 3: Spike test

1. Start at 0 handshakes/sec.
2. Immediately jump to 2000 handshakes/sec.
3. Hold for 30 seconds.
4. Drop back to 100/sec for 60 seconds.
5. Repeat three times.

**Pass criteria**: No crash or unrecoverable error. Recovery to steady-state
latency within 10 seconds of returning to 100/sec.

### Test 4: Resource exhaustion — challenge store

1. Rapidly request challenges from a single node (10,000 GET requests in 1
   second).
2. Then attempt legitimate handshakes with valid challenges.

**Pass criteria**: Legitimate handshakes succeed. Memory usage from the
challenge map does not exceed 50 MB.

### Test 5: Concurrent manifest verification

1. Load generator sends 100 concurrent manifest proposals to a node.
2. Each proposal is a valid `MembershipManifestV1` with correct signatures.

**Pass criteria**: All valid manifests are processed within 10 seconds. CPU
usage returns to baseline after processing. No manifests are silently dropped.

### Test 6: Large roster

1. Create a manifest with 100 members (maximum reasonable roster size).
2. Verify the manifest on each node under load.
3. Measure verification time.

**Pass criteria**: Manifest verification completes in under 5 seconds on a
2 vCPU node.

## Success criteria

All of the following must be true for the load test to pass:

1. Throughput: ≥ 1000 handshakes/sec sustained for 1 hour.
2. Latency: p95 challenge-to-hello ≤ 200 ms at target throughput.
3. Stability: No monotonic memory growth over 1 hour (RSS delta < 10%).
4. Error rate: < 0.1% at all load levels.
5. No crashes or panics under any test.
6. Recovery: System returns to baseline within 30 seconds after spike.

## Results documentation

For each test run, record:

- Date, commit SHA, and test environment details.
- Raw throughput and latency measurements (CSV or JSON).
- CPU/memory/network profiles (from `top`, `perf`, `tcpdump`, or equivalent).
- Any errors, warnings, or anomalies.
- A comparison against the previous test run.

## Non-goals

This plan does not cover:

- CometBFT consensus throughput (separate test plan).
- Vault quorum signing performance (separate test plan).
- Network partition tolerance (covered in `ops/SPLIT_BRAIN_RECOVERY.md`).
- Long-term (multi-day) soak testing (future work).
