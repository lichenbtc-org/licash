# The hub service, with the prover of its statement (r0/host) on x86-64.
# Build from the repository root:
#   docker build -f apps/hub/Dockerfile -t licash-hub .
# --platform linux/arm64 or linux/arm/v7 cross-compiles (apps/image-build.sh),
# without a prover: such a hub responds to no contested exit on a network
# with genuine proofs (see docs/hub.md).
ARG TARGETARCH

FROM --platform=$BUILDPLATFORM rust:1-slim-trixie AS build
ARG TARGETPLATFORM
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/apps/target,sharing=locked \
    apps/image-build.sh licash-hub-service:licash-hub

# The prover: its CPU build, and its CUDA build, which the CPU build proves
# through when the container is given a GPU (CUDA 12.4: NVIDIA drivers 550
# and newer), for the GPU generations of CUDA_ARCHS (Turing on). With RISC
# Zero's Groth16 setup and native prover, from its prover image, and the
# programs contracts open under (r0/programs).
FROM nvidia/cuda:12.4.1-devel-ubuntu22.04 AS prover-amd64
ARG CUDA_ARCHS="75 80 86 89"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl build-essential pkg-config clang protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_STRIP=true
WORKDIR /src
COPY . .
RUN --mount=type=cache,id=licash-r0-registry,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,id=licash-r0-target,target=/src/r0/host/target,sharing=locked \
    set -eu; \
    # Built again whatever the cached target's times: a source edited while
    # an earlier build ran is older than what that build left.
    find r0/host/src crates/licash/src crates/licash-chain/src crates/licash-hp/src crates/licash-statement/src -name '*.rs' -exec touch {} +; \
    flags=; for a in $CUDA_ARCHS; do flags="$flags -gencode arch=compute_$a,code=sm_$a"; done; \
    newest=${CUDA_ARCHS##* }; \
    export NVCC_APPEND_FLAGS="$flags -gencode arch=compute_$newest,code=compute_$newest"; \
    cargo build --locked --release --manifest-path r0/host/Cargo.toml --features cuda --target-dir r0/host/target/cuda; \
    unset NVCC_APPEND_FLAGS; \
    cargo build --locked --release --manifest-path r0/host/Cargo.toml; \
    share=/opt/r0/share/licash-r0; \
    mkdir -p /opt/r0/bin "$share/programs" "$share/groth16"; \
    cp r0/host/target/release/licash-r0 /opt/r0/bin/; \
    cp r0/host/target/cuda/release/licash-r0 /opt/r0/bin/licash-r0-cuda; \
    cp r0/host/licash-r0-remote /opt/r0/bin/; \
    cp r0/programs/*.bin "$share/programs/"; \
    cp r0/host/bench.bin "$share/"
COPY --from=risczero/risc0-groth16-prover:v2026-10-20.1@sha256:e8c2068fb34bbc41447255aa980a89cbb7d6e5a80c0d66041264431f2a955e47 \
    /usr/local/bin/stark_verify /usr/local/bin/prover \
    /app/stark_verify.dat /app/stark_verify.cs /app/stark_verify_final.pk.dmp \
    /opt/r0/share/licash-r0/groth16/

# No prover on ARM: RISC Zero's Groth16 prover is x86-64 only.
FROM --platform=$BUILDPLATFORM debian:trixie-slim AS prover-none
RUN mkdir -p /opt/r0
FROM prover-none AS prover-arm64
FROM prover-none AS prover-arm
FROM prover-${TARGETARCH} AS prover

FROM debian:trixie-slim AS runtime
# Root certificates, for notifications and Esplora over HTTPS; GMP, for the
# Groth16 witness generator; SSH, to the machines that prove segments too
# (`licash-r0-remote`, docs/r0.md).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgmp10 openssh-client \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin licash \
    && mkdir -p /data && chown licash /data && chmod 700 /data
COPY --from=build /usr/local/bin/licash-hub /usr/local/bin/licash-hub
USER 10001
# The GPU's compute, when the container is given one (--gpus).
ENV LICASH_HUB_DATA=/data LICASH_HUB_LISTEN=0.0.0.0:8338 NVIDIA_DRIVER_CAPABILITIES=compute,utility
VOLUME /data
EXPOSE 8338
# Unhealthy once the hub halts (see docs/hub.md).
HEALTHCHECK --interval=30s --timeout=5s \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${LICASH_HUB_LISTEN##*:} && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && head -n1 <&3 | grep -q ' 200 '"]
ENTRYPOINT ["licash-hub"]
CMD ["run"]

# The hub's standby (docs/hub.md, "The standby"), `--target standby`: with
# Litestream, which restores its ledger from the hub's replica at each
# start (apps/hub/standby.sh). x86-64 and arm64, as Litestream's image.
FROM runtime AS standby
COPY --from=prover /opt/r0/ /usr/local/
COPY --from=litestream/litestream:0.5.18@sha256:513bff62a88fc0c86c73d27333c41c54c89fe890a7c32a551600adff9309b11b \
    /usr/local/bin/litestream /usr/local/bin/litestream
COPY --chmod=755 apps/hub/standby.sh /usr/local/bin/licash-hub-standby
# Its starts are routine (each restore): told only of its alerts.
ENV LICASH_HUB_NOTIFY_KINDS=alert,reorg
ENTRYPOINT ["licash-hub-standby"]
CMD ["run"]

FROM runtime AS production
COPY --from=prover /opt/r0/ /usr/local/
