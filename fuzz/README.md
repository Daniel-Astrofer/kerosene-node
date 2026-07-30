# Fuzzing campaign

This directory contains `cargo-fuzz` targets for the Kerosene discovery and
membership wire protocols. Fuzzing is a mandatory pre-mainnet gate; a release
must not be promoted without a sustained campaign covering all defined targets.

## Prerequisites

```bash
# Install nightly toolchain (required by cargo-fuzz)
rustup toolchain install nightly --profile minimal

# Install cargo-fuzz
cargo +nightly install cargo-fuzz --locked
```

## Available targets

| Target | Crate input | What it exercises |
|---|---|---|
| `peer_hello` | `PeerHelloV1` JSON | Deserialization, canonical encoding (`signing_bytes`) |
| `admission_request` | `AdmissionRequestV1` JSON | Deserialization, canonical encoding (`signing_bytes`) |

## Running a fuzz campaign

### Basic usage

```bash
cd fuzz/
cargo +nightly fuzz run peer_hello
cargo +nightly fuzz run admission_request
```

### With duration or iteration limits

```bash
# Run for 60 seconds
cargo +nightly fuzz run peer_hello -- -max_total_time=60

# Run for 1 million iterations
cargo +nightly fuzz run peer_hello -- -runs=1000000

# Run with a specific corpus directory
cargo +nightly fuzz run peer_hello -- corpus/peer_hello/
```

### CI integration

The `.github/workflows/fuzz.yml` workflow compiles all targets on every PR
that modifies fuzz, discovery, or membership code, and runs a weekly scheduled
campaign. The CI job only verifies compilation — a sustained campaign must run
in a dedicated environment.

## Campaign duration recommendations

| Campaign type | Minimum | Recommended | Notes |
|---|---|---|---|
| Pre-release | 24 CPU-hours per target | 72 CPU-hours | Run across 4+ parallel workers |
| Weekly CI | 1 CPU-hour per target | 4 CPU-hours | Catch regressions quickly |
| Post-merge for protocol changes | 8 CPU-hours per target | 24 CPU-hours | New code paths need deeper coverage |

Use `-jobs=N` to parallelize across N cores:

```bash
cargo +nightly fuzz run peer_hello -- -jobs=8 -workers=8 -max_total_time=86400
```

### How to interpret crash findings

When `cargo-fuzz` finds a crash, it writes the crashing input to
`fuzz/artifacts/<target>/<sha1-hash>`. To reproduce and diagnose:

```bash
# Reproduce the crash
cargo +nightly fuzz run peer_hello fuzz/artifacts/peer_hello/<crash-file>

# Examine the input
xxd fuzz/artifacts/peer_hello/<crash-file>

# Pipe through the target binary for debugging
cargo +nightly fuzz run peer_hello fuzz/artifacts/peer_hello/<crash-file> -- -runs=0
```

Common findings and their interpretation:

| Observation | Likely cause | Action |
|---|---|---|
| Panic in `serde_json::from_slice` | Invalid UTF-8 or structural JSON issue | Review deserialization constraints; add `#[serde(deny_unknown_fields)]` if missing |
| Panic in `signing_bytes` | Arithmetic overflow or allocation failure | Review `CanonicalSignable` implementation for unwrap/expect on user data |
| Slowdown / timeout | Algorithmic complexity (e.g. quadratic blowup in large inputs) | Review field size limits; add input size pre-checks |
| Stack overflow | Deeply nested JSON structure | Add recursion depth limits or use `serde_stacker` |
| OOM | Unbounded allocation from large input | Reject inputs exceeding `MAX_SERIALIZED_SIZE` |

All findings must be triaged before a release. A panic in `signing_bytes`
means a malformed wire message could crash a node — this is a **critical**
severity finding.

## How to add a new target

1. Create a new file in `fuzz/fuzz_targets/<name>.rs`:

```rust
#![no_main]

use kerosene_contracts::{YourType, CanonicalSignable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<YourType>(data) {
        std::hint::black_box(value.signing_bytes());
    }
});
```

2. Register the target in `fuzz/Cargo.toml`:

```toml
[[bin]]
name = "your_target"
path = "fuzz_targets/your_target.rs"
test = false
doc = false
bench = false
```

3. Add the dependency if `YourType` comes from a different crate.
4. Run `cargo +nightly fuzz build` to verify compilation.
5. Run `cargo +nightly fuzz run your_target -- -runs=1000` to verify the target
   runs without immediate crashes on the initial seed corpus.

## Target coverage gaps (future work)

The current targets only exercise deserialization + canonical encoding.
Full protocol fuzzing should also include:

- `MembershipManifestV1` — deserialization + `signing_bytes` + `canonical_hash`
- `GenesisTrustBundleV1` — deserialization + structure validation
- Combined walkthrough: deserialize → sign → verify for a full
  `PeerHelloV1` handshake (tests the verify side with corrupted inputs)
- Manifest chain: feed sequences of manifests into
  `MembershipVerifier::accept` with adversarial ordering
- Endpoint validation: random strings fed to `validate_onion_endpoint`

When adding these targets, increase the campaign to the "Recommended"
duration.
