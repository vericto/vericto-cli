# Thin container image for the `vericto` CLI (§9, Phase 1).
#
# Two stages: build a fully static musl binary, then drop it into a distroless
# "static" base. The result is a tiny image with no shell and no package manager
# — just the binary and CA certificates. rustls (see Cargo.toml) means there is
# no system OpenSSL dependency, so `FROM scratch`-class bases work.
#
# Build:  docker build -t ghcr.io/vericto/vericto-cli:latest .
# Run:    docker run --rm -e VERICTO_API_KEY ghcr.io/vericto/vericto-cli:latest \
#             check migrations/*.sql
#
# The release pipeline (cargo-dist) publishes the prebuilt binaries; this image
# is a convenience wrapper for CI runners that prefer an image step.

# ── Build stage: static musl binary ─────────────────────────────────────────
# A Debian builder cross-compiling to `<arch>-unknown-linux-musl` (since
# 1.9.0, for offline mode). It used to be `rust:*-alpine`, which targets musl natively,
# but the embedded engine's pg_query runs bindgen, which loads libclang at
# build time, and Alpine's static build scripts cannot load a shared library
# ("Dynamic loading not supported"). Here build scripts are ordinary glibc
# binaries and the final link is still fully static against musl. `clang`
# brings the compiler headers bindgen needs (`stdbool.h`); libclang-dev alone
# does not. The target comes from `uname -m`, so the Dockerfile stays
# architecture-agnostic for `docker buildx --platform linux/amd64,linux/arm64`.
# Base images are pinned by digest (multi-arch index) as well as tag, so a
# re-pushed tag cannot change what is built; Dependabot (docker) bumps them.
FROM rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools libclang-dev clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# Cache dependencies: copy manifests first, then the sources. A source change
# doesn't re-fetch the whole dependency graph.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the release binary (LTO etc. from [profile.release]).
RUN T="$(uname -m)-unknown-linux-musl" \
    && rustup target add "$T" \
    && cargo build --release --locked --target "$T" \
    && cp "target/$T/release/vericto" /vericto

# ── Runtime stage: distroless static ────────────────────────────────────────
# `static` includes CA certificates + tzdata but no shell/libc — minimal attack
# surface for a binary that runs inside CI holding credentials (§6.1).
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /vericto /usr/local/bin/vericto
# The license, its notices and the third-party licenses ship with the image,
# where distroless keeps package docs. The label is set here too, so a local
# `docker build` carries it, not only the image docker.yml publishes.
COPY LICENSE NOTICE THIRD_PARTY_LICENSES /usr/share/doc/vericto/
LABEL org.opencontainers.image.licenses="FSL-1.1-ALv2"
# The image is for CI runners, and a container does not see the runner's `CI`
# variable unless it is passed in. Without this, a pipeline whose
# VERICTO_API_KEY secret went missing (`-e VERICTO_API_KEY` passes nothing)
# would check offline with the standard rules instead of failing with exit 3.
# Pass `--offline` to choose offline mode, or `-e CI=` to run it as a local
# tool with automatic offline mode.
ENV CI=true
# So `docker run <image> check ...` works without repeating the binary name.
ENTRYPOINT ["/usr/local/bin/vericto"]
