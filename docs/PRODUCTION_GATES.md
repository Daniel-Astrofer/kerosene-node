# Production gates

The implementation and CI are necessary but not sufficient for mainnet. A
release must not be promoted until evidence exists for every gate below:

- independent cryptographic and protocol audit;
- infrastructure penetration test over the Tor/mTLS boundary;
- continuous fuzzing of peer hello and membership/admission inputs;
- reviewed threat model and key-rotation procedure;
- tested bootstrap, isolation, recovery and joint-membership runbooks;
- network partition, replay, fork and endpoint-spoofing exercises;
- sustained discovery/membership load and resource-exhaustion test;
- reproducible build, SBOM, provenance and signed release artifact;
- pinned CometBFT compatibility after issue #2 is implemented.

CI covers formatting, production compilation, Clippy, unit tests and
progressive bootstrap/security integration tests. External audit, penetration
test and mainnet load evidence cannot be replaced by a passing GitHub Action.
