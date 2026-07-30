# Reproducible builds and artifact signing

This document defines the build reproducibility plan for the Kerosene node.
Every release artifact must be independently verifiable as byte-for-byte
identical when built from the same source commit.

## Pinned toolchain

The workspace pins the Rust toolchain via `rust-version` in
`Cargo.toml`:

```toml
[workspace.package]
rust-version = "1.88"
```

All CI and release builds use exactly this toolchain version:

```bash
rustup toolchain install 1.88 --profile minimal
cargo +1.88 build --release --locked
```

The `+1.88` selector ensures the correct compiler version regardless of the
default toolchain. The CI configuration in `.github/workflows/security.yml`
already uses `rustup toolchain install 1.88 --profile minimal` and runs
`cargo +1.88 test`.

## Locked builds

All release builds must use `--locked` to enforce `Cargo.lock` fidelity:

```bash
cargo build --release --locked
```

`Cargo.lock` is committed to the repository. Verify it is up to date:

```bash
cargo check --locked
```

If the lock file needs updating, run `cargo update` in a dedicated commit,
never as part of a feature change.

## Build steps for a reproducible artifact

### 1. Prepare the build environment

Use the same operating system and architecture as the target deployment.
Recommended: `ubuntu:24.04` or `debian:bookworm` Docker image, same kernel
version family.

```dockerfile
FROM debian:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl build-essential pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain 1.88
ENV PATH="/root/.cargo/bin:${PATH}"

COPY . /build
WORKDIR /build
RUN cargo build --release --locked
```

### 2. Build

```bash
cargo build --release --locked -p kerosene-node
cargo build --release --locked -p kerosene-rsctl
```

The binaries are at `target/release/kerosene-node` and
`target/release/kerosene-rsctl`.

### 3. Verify reproducibility

Build twice from the same commit in the same environment and compare:

```bash
mkdir /tmp/build-a /tmp/build-b

# First build
cargo build --release --locked --target-dir /tmp/build-a

# Second build
cargo build --release --locked --target-dir /tmp/build-b

# Compare binaries
sha256sum /tmp/build-a/release/kerosene-node \
          /tmp/build-b/release/kerosene-node

diff /tmp/build-a/release/kerosene-node \
     /tmp/build-b/release/kerosene-node
```

If the binaries differ, investigate:
- Embedded build timestamps (use `SOURCE_DATE_EPOCH` to pin).
- File paths in debug info (build from the same absolute path, or strip
  debuginfo).
- Compiler version variations (ensure exact same toolchain).
- Dependency versions (ensure `Cargo.lock` is identical).

## SHA-256SUMS generation

After a reproducible build is confirmed, generate checksums:

```bash
cd target/release/
sha256sum kerosene-node kerosene-rsctl > SHA-256SUMS
cat SHA-256SUMS
```

The `SHA-256SUMS` file is published alongside the release artifacts.

## Sigstore keyless signing (cosign)

Sign the checksums file and binaries using Sigstore keyless signing:

```bash
# Install cosign
go install github.com/sigstore/cosign/v2/cmd/cosign@latest

# Sign the checksums file (keyless — uses OIDC)
cosign sign-blob --bundle kerosene-node-SHA-256SUMS.bundle \
  SHA-256SUMS

# Sign individual binaries
cosign sign-blob --bundle kerosene-node.bundle \
  target/release/kerosene-node

cosign sign-blob --bundle kerosene-rsctl.bundle \
  target/release/kerosene-rsctl
```

The `.bundle` files contain the signature and the Rekor transparency log
entry. They must be published alongside the release artifacts.

### Verify signatures

```bash
cosign verify-blob --bundle kerosene-node-SHA-256SUMS.bundle \
  --certificate-identity-regexp '.*@astrofer\.com' \
  --certificate-oidc-issuer https://github.com/login/oauth \
  SHA-256SUMS
```

## SBOM generation (SPDX)

Generate a Software Bill of Materials using `cargo-cyclonedx` or `cargo-spdx`:

```bash
# Using cargo-cyclonedx
cargo install cargo-cyclonedx
cargo cyclonedx --all --format json

# Using cargo-spdx (simpler, SPDX native)
cargo install cargo-spdx
cargo spdx
```

The SBOM file (`kerosene-node.spdx.json` or similar) is published alongside
the release artifacts. It contains all direct and transitive dependencies
with their licenses and versions.

## GitHub attestation build provenance

Use GitHub Attestations to link the build artifact to the source commit:

```yaml
# In the release workflow
- name: Generate build provenance
  uses: actions/attest-build-provenance@v1
  with:
    subject-path: |
      target/release/kerosene-node
      target/release/kerosene-rsctl
      SHA-256SUMS
```

This attaches a signed SLSA provenance statement to each artifact, proving
it was built from a specific commit on a specific workflow run.

## Release checklist

Before publishing a release:

- [ ] All CI checks pass on the tagged commit.
- [ ] `cargo check --locked` succeeds.
- [ ] Toolchain is `rustc 1.88.x` (match `rust-version`).
- [ ] Two independent builds produce identical SHA-256 hashes.
- [ ] SHA-256SUMS file is generated.
- [ ] Cosign keyless signatures are created and verified.
- [ ] SBOM is generated and verified.
- [ ] GitHub attestation provenance is attached.
- [ ] All artifacts (binaries, SHA-256SUMS, .bundle files, SBOM) are
      uploaded to the release.
- [ ] A third party independently verifies reproducibility from the published
      source.
