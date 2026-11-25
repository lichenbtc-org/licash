# A Licash contract witness. Build from the repository root:
#   docker build -f apps/witness/Dockerfile -t licash-witness .
# --platform linux/arm64 or linux/arm/v7 cross-compiles (apps/image-build.sh).
FROM --platform=$BUILDPLATFORM rust:1-slim-trixie AS build
ARG TARGETPLATFORM
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/apps/target,sharing=locked \
    apps/image-build.sh licash-witness:licash-witness

FROM debian:trixie-slim
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin licash \
    && mkdir -p /data && chown licash /data && chmod 700 /data
COPY --from=build /usr/local/bin/licash-witness /usr/local/bin/
USER 10001
ENV LICASH_WITNESS_DATA=/data LICASH_WITNESS_LISTEN=0.0.0.0:8339
VOLUME /data
EXPOSE 8339
HEALTHCHECK --interval=30s --timeout=5s \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${LICASH_WITNESS_LISTEN##*:}"]
ENTRYPOINT ["licash-witness"]
CMD ["run"]
