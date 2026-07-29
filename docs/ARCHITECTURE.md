# Architecture boundary

`kerosene-node` is the Kerosene server identity and consensus boundary. It will
host the ABCI application while CometBFT remains a separate consensus engine.

Planned crates:

```text
kerosene-identity-core/
kerosene-node/
kerosene-discovery/
kerosene-membership/
kerosene-sync/
tor-peer-adapter/
```

The repository will use a versioned compatibility matrix for CometBFT and
`kerosene-contracts`. Startup must be progressive: local identity and transport
can become ready without claiming membership, quorum or financial authority.
