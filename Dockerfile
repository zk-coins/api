# Multi-stage Docker build for the zkCoins public REST API layer.
#
# Toolchain pin: `rust-toolchain` at the repo root
# (`channel = "nightly-2026-06-18"`). rustup respects that file and installs
# the right channel when cargo is first invoked — no manual `rustup install`.
#
# Build:
#   docker build -t zkcoins/api:local .
#
# Run (no defaults baked into the image — every required var must be set):
#   docker run -p 8080:8080 \
#     -e ZKCOINS_BIND_ADDR=0.0.0.0:8080 \
#     -e ZKCOINS_KERNEL_ADDR=http://node:50051 \
#     -e ZKCOINS_FEATURES=wallet,explorer \
#     -e ZKCOINS_PUBLIC_HOST= \
#     -v api_blossom:/data/blossom \
#     zkcoins/api:local
#
# ---------------------------------------------------------------------------
# Boot environment (from src/config.rs + src/main.rs — fail-closed; no image
# defaults for bind/kernel/store). Names, meaning, requiredness:
#
# Pflicht (Variable muss gesetzt sein; leerer Wert wo vermerkt erlaubt):
#
#   ZKCOINS_BIND_ADDR
#     HTTP listen address as `host:port` (parsed as SocketAddr).
#     Required, non-empty. Empty or garbage → start error (ConfigError).
#     Codestelle: src/config.rs ENV_BIND / require_present; bind in
#     src/main.rs TcpListener::bind(config.bind_addr).
#     Convention for local stack / EXPOSE: 0.0.0.0:8080 (not hard-coded
#     in the binary — only in operator env).
#
#   ZKCOINS_KERNEL_ADDR
#     Kernel gRPC target URI (opaque non-empty string, tonic Endpoint).
#     Required, non-empty. Bad URI → start error at connect_lazy.
#     Codestelle: src/config.rs ENV_KERNEL; dial src/kernel/client.rs
#     KernelClient::connect_lazy / src/main.rs connect_lazy.
#
#   ZKCOINS_FEATURES
#     Comma-separated subset of §6.1 closed feature set:
#     wallet, explorer, publisher, lightning_bridge, mail_bridge.
#     Variable required; empty string = all features off (allowed).
#     Unknown token → start error. Codestelle: src/config.rs ENV_FEATURES.
#
#   ZKCOINS_PUBLIC_HOST
#     Comma-separated authoritative hostnames for §5.1 chan_bind.
#     Variable required; empty string allowed (then OwnershipProof auth
#     fails loud — no silent localhost). Never from HTTP Host header.
#     Codestelle: src/config.rs ENV_PUBLIC_HOST.
#
# Optional Blossom surface (§7.4) — all-or-nothing:
#
#   ZKCOINS_BLOSSOM_STORE
#     Filesystem root for the content-addressed store.
#     Absent ⇒ Blossom routes unmounted, three discovery keys unadvertised.
#     Present-but-empty ⇒ start error (no /tmp default).
#     Codestelle: src/config.rs ENV_BLOSSOM_STORE / parse_blossom_config.
#
#   When ZKCOINS_BLOSSOM_STORE is set, these companions become Pflicht:
#
#   ZKCOINS_BLOSSOM_MAX_BLOB_BYTES
#     Advertised upload size limit; strict decimal u64, must be > 0.
#     Codestelle: src/config.rs ENV_BLOSSOM_MAX_BLOB_BYTES.
#
#   ZKCOINS_BLOSSOM_ALLOWED_OPS
#     Comma-separated lowercase-hex 32-byte op pubkeys allowed to upload.
#     Variable required when store is set; empty string allowed
#     (surface up, every upload 403). Codestelle: ENV_BLOSSOM_ALLOWED_OPS.
#
# Optional (logging only — not process config):
#
#   RUST_LOG
#     tracing-subscriber EnvFilter. Unset ⇒ "info" in main::init_tracing
#     (src/main.rs). Not a silent fallback for bind/kernel/store.
# ---------------------------------------------------------------------------

FROM rust:bookworm AS builder
WORKDIR /app

# kernel-proto/build.rs → tonic_build::configure().compile_protos(...)
# needs `protoc` on PATH at compile time (see kernel-proto/build.rs).
# Pin: Debian bookworm package protobuf-compiler 3.21.12-3
# (https://packages.debian.org/bookworm/protobuf-compiler) — not unversioned
# `latest` and not a floating upstream tag.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        protobuf-compiler=3.21.12-3+deb12u1 \
    && rm -rf /var/lib/apt/lists/* \
    && protoc --version

# Copy just the toolchain file first so rustup can fetch the right
# channel before the slow source copy. Layer-caches across source-only changes.
COPY rust-toolchain ./
RUN rustup show

COPY . .

RUN cargo build --release -p api

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 zkcoins \
    && useradd --system --uid 10001 --gid zkcoins \
        --home-dir /data --create-home --shell /usr/sbin/nologin zkcoins \
    # Pre-create the Blossom store dir owned by the runtime user so a fresh
    # named volume mounted at /data/blossom inherits writable ownership
    # (Docker seeds a new volume from the image path; without this the mount
    # is root-owned and the non-root process gets EACCES on blob writes).
    && mkdir -p /data/blossom \
    && chown zkcoins:zkcoins /data/blossom

COPY --from=builder /app/target/release/api /usr/local/bin/zkcoins-api

# No ZKCOINS_* defaults in the image — boot fails closed without operator env.
ENV RUST_LOG=info
WORKDIR /data
USER zkcoins:zkcoins

# Documented local-stack port (ZKCOINS_BIND_ADDR=0.0.0.0:8080). The binary
# binds only the address from env (src/main.rs); this is not a code default.
EXPOSE 8080

ENTRYPOINT ["zkcoins-api"]
