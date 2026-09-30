FROM rust:1-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --release -p sealbook-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 sealbook

COPY --from=builder /src/target/release/sealbook-server /usr/local/bin/sealbook-server

RUN mkdir -p /data && chown sealbook:sealbook /data

USER sealbook
WORKDIR /data

ENV SEALBOOK_BIND=0.0.0.0:8443 \
    SEALBOOK_DATA_DIR=/data

VOLUME ["/data"]
EXPOSE 8443

# The server speaks TLS 1.3 with X25519MLKEM768 only, which the curl and wget in
# this base image cannot negotiate, so they would report a healthy server as
# unhealthy. The binary carries its own probe instead.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/sealbook-server", "--health-check"]

ENTRYPOINT ["/usr/local/bin/sealbook-server"]