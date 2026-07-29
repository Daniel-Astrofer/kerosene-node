# Agent rules

- Keep consensus deterministic and independently testable.
- Treat identity, discovery, membership and readiness as distinct states.
- Pin CometBFT compatibility explicitly.
- Use fake KFE/Vault adapters in CI; never use production credentials.
- Protocol changes must consume versioned `kerosene-contracts` artifacts.
- Add Rust CI when the first crate is introduced.
