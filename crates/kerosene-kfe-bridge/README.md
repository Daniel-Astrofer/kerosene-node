# kerosene-kfe-bridge

Unix socket bridge to the KFE (Kerosene Financial Engine) Java service.

This crate provides an async client for communicating with the KFE Java service
over a Unix domain socket using JSON-RPC style messages.

## Usage

```rust
use kerosene_kfe_bridge::KfeBridge;

let bridge = KfeBridge::new("/var/run/kfe.sock");
let result = bridge.check_transaction(tx_json).await?;
```

## API Methods

- `check_transaction`: Validate a transaction against financial rules
- `prepare_block`: Prepare a block with financial validation
- `commit_state`: Persist state and return state root
