# Threat model

## Protected assets

- root identity private key;
- authenticated membership and manifest history;
- network/plane separation;
- state-root integrity;
- quorum and financial-readiness decisions.

Vault shares and transaction signing are outside this process.

## Trust boundaries

- Tor provides address privacy and remote name resolution, not peer authority.
- mTLS protects the transport, but membership is established by root-key
  signatures from the versioned trust bundle and manifests.
- Discovery inputs are untrusted until onion syntax, network, plane, root key,
  signature, challenge, timestamp and membership all verify.
- Persisted endpoints are hints only. They do not survive as live votes.

## Implemented controls

- v3 onion HTTPS endpoints only; clearnet, userinfo, query strings and local
  service DNS are rejected;
- `socks5h` is mandatory so DNS is resolved by Tor;
- mutual TLS is mandatory for inbound and configured outbound production paths;
- signed, single-use, expiring challenges prevent replay;
- self-connections and cross-plane handshakes cannot increase quorum;
- member IDs bind network and root public key;
- manifests reject forks, replay, duplicate signers and insufficient quorum;
- membership changes require OLD -> JOINT -> NEW;
- active peer TTL and current-roster filtering protect readiness;
- lifecycle transitions cannot be skipped;
- root identity files use owner-only permissions.

## Residual risks

- compromise of enough membership roots can authorize a malicious roster;
- compromised host memory can expose the node identity while the process runs;
- Tor or peer flooding can degrade availability;
- local disk exhaustion/corruption can prevent atomic persistence;
- wall-clock manipulation beyond the configured window can deny handshakes;
- CometBFT/ABCI safety is not covered until issue #2 is delivered.

Rate limiting, host hardening, independent monitoring and offline root-key
procedures must be applied by deployment infrastructure.
