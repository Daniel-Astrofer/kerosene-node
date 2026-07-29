FROM rust:1.88-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --locked --release --features production -p kerosene-node

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 kerosene
COPY --from=builder /build/target/release/kerosene-node /usr/local/bin/kerosene-node
USER 10001:10001
EXPOSE 8800
ENTRYPOINT ["/usr/local/bin/kerosene-node"]
