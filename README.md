# Kerosene Node

Planned Rust infrastructure node for Kerosene.

## Scope

- server identity and attestation;
- CometBFT/ABCI application;
- discovery and authenticated membership;
- snapshots, catch-up, state sync and state roots;
- KFE bridge and Vault directory;
- Tor-aware peer transport.

The implementation has not yet landed on `Kerosene/main`. This repository is
created as the independent release boundary and intentionally contains no fake
consensus implementation.

See [issue #30](https://github.com/Daniel-Astrofer/Kerosene/issues/30) for the
implementation roadmap.
