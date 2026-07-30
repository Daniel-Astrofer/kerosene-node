# kerosene-cometbft-adapter

ABCI application adapter for the Kerosene node, implementing the CometBFT consensus engine interface.

## Architecture

This crate implements the ABCI (Application BlockChain Interface) for Kerosene using
the `tower-abci` library. It acts as the state machine that CometBFT drives through
consensus.

### Key Components

- **AbciApp**: The main Tower Service that processes all ABCI requests
- **AppState**: Versioned key-value store with SHA-256 root hash computation
- **CheckTx**: Transaction validation (format, nonce, Ed25519 signature)
- **FinalizeBlock**: Block execution against the state machine
- **Commit**: State persistence and AppHash computation

### Transaction Format

Transactions are JSON-encoded with the following structure:
```json
{
  "command": "set",
  "key": "some_key",
  "value": "some_value",
  "nonce": 12345,
  "public_key": "hex_encoded_ed25519_pk",
  "signature": "hex_encoded_ed25519_sig"
}
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KEROSENE_ABCI_LISTEN_ADDR` | `/tmp/kerosene-abci.sock` | Listen address |
| `KEROSENE_ABCI_TRANSPORT` | `unix` | Transport: `unix` or `tcp` |
| `KEROSENE_ABCI_STATE_PATH` | `data/abci-state` | State persistence path |
| `KEROSENE_NETWORK_ID` | (required) | Network identifier |
| `KEROSENE_ABCI_MAX_TX_PER_BLOCK` | `1000` | Max transactions per block |
