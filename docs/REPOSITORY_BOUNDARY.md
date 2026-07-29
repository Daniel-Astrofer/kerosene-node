# Repository boundary

This repository is the canonical source for Kerosene node identity, discovery,
membership, synchronization and consensus integration.

Node consumes versioned protocols from `kerosene-contracts` and uses fake Core
and Vault adapters in CI. It must not read source files from the archived
monorepo or another service repository.
