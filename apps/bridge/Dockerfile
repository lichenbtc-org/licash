# The NWC bridge. Build from the repository root:
#   docker build -f apps/bridge/Dockerfile -t licash-bridge .
# --platform linux/arm64 or linux/arm/v7 cross-compiles (apps/image-build.sh).
FROM --platform=$BUILDPLATFORM rust:1-slim-trixie AS build
ARG TARGETPLATFORM
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/apps/target,sharing=locked \
    apps/image-build.sh licash-bridge:licash-bridge

FROM debian:trixie-slim
# Root certificates, for its hub and relays over HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin licash \
    && mkdir -p /data && chown licash /data && chmod 700 /data
COPY --from=build /usr/local/bin/licash-bridge /usr/local/bin/
USER 10001
ENV LICASH_BRIDGE_DATA=/data LICASH_BRIDGE_LISTEN=0.0.0.0:8090
VOLUME /data
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${LICASH_BRIDGE_LISTEN##*:} && printf 'GET /health HTTP/1.0\\r\\n\\r\\n' >&3 && head -n1 <&3 | grep -q ' 200 '"]
ENTRYPOINT ["licash-bridge"]
CMD ["run"]
