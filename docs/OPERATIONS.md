# Operations

## Required configuration

| Variable | Meaning |
| --- | --- |
| `KEROSENE_NETWORK_ID` | Exact network identifier bound into identities |
| `KEROSENE_DISCOVERY_PLANE` | `bank` or `vault` |
| `KEROSENE_NODE_ONION_ENDPOINT` | Published `https://<56-char-v3>.onion` URL |
| `KEROSENE_GENESIS_TRUST_BUNDLE` | Path to `GenesisTrustBundleV1` JSON |
| `KEROSENE_TLS_CERT_PATH` | Server certificate with the onion hostname SAN |
| `KEROSENE_TLS_KEY_PATH` | Server TLS private key |
| `KEROSENE_TLS_CLIENT_CA_PATH` | CA used for mandatory inbound client mTLS |
| `KEROSENE_TOR_SOCKS_PROXY` | Tor proxy using `socks5h://host:port` |

Optional configuration:

| Variable | Default | Meaning |
| --- | --- | --- |
| `KEROSENE_NODE_LISTEN_ADDR` | `127.0.0.1:8800` | Protected local bind for the onion service |
| `KEROSENE_IDENTITY_KEY_PATH` | `peer-store/identity.key` | Persistent root identity |
| `KEROSENE_PEER_STORE` | `peer-store` | Persistent discovery state |
| `KEROSENE_TLS_CLIENT_IDENTITY_PEM` | none | PEM containing outbound mTLS certificate and key |
| `KEROSENE_GENESIS_ENDPOINTS` | none | Comma-separated initial onion endpoints |
| `KEROSENE_DISCOVERY_MIRRORS` | none | Comma-separated onion manifest mirrors |
| `KEROSENE_DISCOVERY_OBSERVER` | false | Fetch manifests without becoming a member |
| `KEROSENE_CHALLENGE_TTL_MS` | `30000` | Hello challenge and clock-skew window |
| `KEROSENE_PEER_LIVE_WINDOW_MS` | `90000` | Peer liveness validity |
| `KEROSENE_DISCOVERY_INTERVAL_MS` | `15000` | Discovery retry interval |

`KEROSENE_DISCOVERY_SEEDS` is accepted temporarily as a compatibility alias for
`KEROSENE_GENESIS_ENDPOINTS`. New deployments should use the new name.
`KEROSENE_CLEARNET_PUBLISH=true` is always rejected.

## First Core

1. Install and start Tor with a v3 onion service forwarding to the protected
   listen address.
2. Provision the network trust bundle and mTLS material out of band.
3. Start one `bank` node with no discovery endpoints.
4. Verify `/live`, `/ready-local` and `/ready-member`.
5. Expect `/ready-quorum` and `/ready-financial` to return HTTP 503 until the
   corresponding requirements are met.

The first node is useful for administration and onboarding but does not invent
quorum.

## Add a Vault

Start a separate process with `KEROSENE_DISCOVERY_PLANE=vault`, its own Vault
identity, peer-store and onion service. Give it Vault-plane genesis endpoints.
A Bank/Core endpoint cannot authenticate on this plane. With a 2-of-3 Vault
policy, one Vault remains `ACTIVE_LOCAL_WAITING_FOR_PEERS`; two verified and
currently live Vault members can reach quorum.

This node runtime never loads FROST shares and never makes a Vault signer
automatically deployable.

## Admission and removal

An `AdmissionRequestV1` proves that a candidate controls its proposed root key
and names a sponsor; it is not an authorization. Operators verify the request
out of band, then publish a signed `joint` manifest containing the proposed
roster. The old threshold and proposed new threshold must both sign it. A later
stable manifest activates exactly that roster.

Removal uses the same OLD -> JOINT -> NEW sequence. Do not delete a peer from
local endpoint files as a substitute for membership removal. During emergency
containment, block its transport separately while the signed roster transition
is completed.

## Health endpoints

| Endpoint | HTTP 200 means |
| --- | --- |
| `/live` | Process serves requests |
| `/ready-local` | Local startup completed |
| `/ready-member` | Local identity is in the verified roster |
| `/ready-quorum` | Current same-plane live threshold exists |
| `/ready-financial` | Node has verified state, eligibility and same-plane live quorum |

Do not map `/live` to financial traffic. Orchestrators should use the most
specific readiness endpoint required by the workload.

## Recovery

Back up the trust bundle, identity key and peer-store independently. On restart,
the node restores manifests and lifecycle but deliberately discards liveness.
It reconnects using previous successful endpoints first. If the peer-store is
lost, bootstrap again from configured genesis endpoints or mirrors. Never copy
another member's identity key.
