# The hub's feed of its standbys (standby-sync.sh): rsync over SSH, on the
# private network to them.
FROM debian:trixie-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends rsync openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=755 standby-sync.sh /usr/local/bin/standby-sync
COPY --chmod=755 healthy.sh /usr/local/bin/standby-sync-healthy
# The hub's user, to read its data.
USER 10001:10001
ENV HOME=/stage
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s CMD ["standby-sync-healthy"]
ENTRYPOINT ["standby-sync"]
