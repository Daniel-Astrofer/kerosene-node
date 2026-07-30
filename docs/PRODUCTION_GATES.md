# Production gates

The implementation and CI are necessary but not sufficient for mainnet. A
release must not be promoted until evidence exists for every gate below.

## Gate status

| # | Gate | Status | Evidence | Owner |
|---|---|---|---|---|
| 1 | Independent cryptographic and protocol audit | **SCOPE DEFINED** | `docs/AUDIT_SCOPE.md` | External auditor |
| 2 | Infrastructure penetration test over the Tor/mTLS boundary | **PLAN DEFINED** | `docs/PENTEST_PLAN.md` | Security team |
| 3 | Continuous fuzzing of peer hello and membership/admission inputs | **TARGETS + CI** | `fuzz/`, `fuzz/README.md`, `.github/workflows/fuzz.yml` | Engineering |
| 4 | Reviewed threat model and key-rotation procedure | **DOCUMENTED** | `docs/THREAT_MODEL.md` (updated with key rotation, PQ, gaps) | Security team |
| 5 | Tested bootstrap, isolation, recovery and joint-membership runbooks | **DOCUMENTED** | `ops/COLD_START.md`, `ops/SPLIT_BRAIN_RECOVERY.md` | Ops team |
| 6 | Network partition, replay, fork and endpoint-spoofing exercises | **DOCUMENTED** | `docs/PENTEST_PLAN.md` (scenarios 3–6, 11) | Security team |
| 7 | Sustained discovery/membership load and resource-exhaustion test | **PLAN DEFINED** | `ops/LOAD_TEST_PLAN.md` | Engineering |
| 8 | Reproducible build, SBOM, provenance and signed release artifact | **PLAN DEFINED** | `docs/REPRODUCIBLE_BUILDS.md` | Engineering |
| 9 | Pinned CometBFT compatibility | **DOCUMENTED** | `docs/COMETBFT_COMPATIBILITY.md`, `crates/kerosene-cometbft-adapter/` | Engineering |

## Legend

| Status | Meaning |
|---|---|
| **SCOPE DEFINED** | Audit scope is documented but the audit has not been performed |
| **PLAN DEFINED** | Test plan exists but the test has not been executed |
| **DOCUMENTED** | Procedure or analysis exists and is ready for use |
| **TARGETS + CI** | Fuzz targets exist and compile in CI; sustained campaign pending |
| **COMPLETED** | Evidence exists that the gate is satisfied |
| **NOT STARTED** | No work has been done |

## Gate requirements

### 1. Independent cryptographic and protocol audit

An external auditor must review the protocol, cryptography, discovery and
membership implementation. The auditor must produce a numbered findings
report, and all critical and high findings must be remediated before the
release.

### 2. Infrastructure penetration test

A security team must execute the scenarios in `docs/PENTEST_PLAN.md` against
a live multi-node Kerosene network over Tor/mTLS. Each scenario must be
documented with pass/fail and evidence.

### 3. Continuous fuzzing

The fuzz targets in `fuzz/` must be run for at least 24 CPU-hours per target
before release. A weekly scheduled CI campaign (`fuzz.yml`) runs a shorter
check. Crash findings must be triaged before release.

### 4. Threat model and key rotation

The threat model must be reviewed and signed off. Key rotation procedures
must be tested on a staging network. Residual risks must be accepted by the
operator.

### 5. Runbooks

Cold start and split-brain recovery procedures must be tested on a staging
network at least once before mainnet. The test must be documented with
screenshots, timestamps, and pass/fail.

### 6. Network partition exercises

The pentest scenarios covering partition, replay, fork and endpoint-spoofing
must be executed and documented.

### 7. Load and resource-exhaustion test

The load test plan must be executed. The system must sustain 1000
handshakes/sec for 1 hour with p95 latency below 200 ms, zero crashes, and
no monotonic memory growth.

### 8. Reproducible builds

Two independent builds from the same commit must produce byte-identical
binaries. SHA-256SUMS, Sigstore signatures, SPDX SBOM and GitHub attestation
provenance must be published with each release.

### 9. CometBFT compatibility

The pinned CometBFT version must be compatible with the ABCI adapter. The
upgrade procedure must be followed for any future version change. A
compatibility CI job runs on every PR.

## How to promote

1. Each gate must have an associated issue or PR with evidence attached.
2. The evidence must be reviewed by a second engineer or security team member.
3. After all gates are COMPLETED, a release candidate tag is created.
4. The release candidate undergoes a 7-day observation period on staging.
5. After the observation period, the release is promoted to mainnet.

## Non-gates

The following are intentionally NOT production gates:

- Vault threshold signing performance (covered by Vault-specific testing).
- Multi-region deployment testing (covered by operations procedures).
- Browser-based or mobile client compatibility.
