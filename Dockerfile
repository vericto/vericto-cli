# Thin container image for the `vericto` CLI (§9, Phase 1).
#
# Two stages: build a fully static musl binary, then drop it into a distroless
# "static" base. The result is a tiny image with no shell and no package manager
# — just the binary and CA certificates. rustls (see Cargo.toml) means there is
# no system OpenSSL dependency, so `FROM scratch`-class bases work.
#
# Build:  docker build -t ghcr.io/donkan168/vericto-cli:latest .
# Run:    docker run --rm -e VERICTO_API_KEY ghcr.io/donkan168/vericto-cli:latest \
#             check migrations/*.sql
#
# The release pipeline (cargo-dist) publishes the prebuilt binaries; this image
# is a convenience wrapper for CI runners that prefer an image step.

# ── Build stage: static musl binary ─────────────────────────────────────────
# `rust:*-alpine` targets `*-unknown-linux-musl` natively, so a plain
# `cargo build` yields a static musl binary for the image's architecture — no
# `--target` needed. That keeps this Dockerfile architecture-agnostic, so
# `docker buildx --platform linux/amd64,linux/arm64` builds each arch natively.
FROM rust:1.88-alpine AS build
# musl-dev provides the C runtime bits some crates' build scripts expect; the
# final link is still fully static against musl.
RUN apk add --no-cache musl-dev
WORKDIR /src

# Cache dependencies: copy manifests first, then the sources. A source change
# doesn't re-fetch the whole dependency graph.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the release binary (LTO etc. from [profile.release]).
RUN cargo build --release --locked \
    && cp target/release/vericto /vericto

# ── Runtime stage: distroless static ────────────────────────────────────────
# `static` includes CA certificates + tzdata but no shell/libc — minimal attack
# surface for a binary that runs inside CI holding credentials (§6.1).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /vericto /usr/local/bin/vericto
# So `docker run <image> check ...` works without repeating the binary name.
ENTRYPOINT ["/usr/local/bin/vericto"]
