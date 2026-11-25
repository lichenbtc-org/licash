#!/usr/bin/env bash
# litestream-compatible launcher for the hub service's tests: each
# invocation runs `litestream ARGS` in one throwaway container of the
# pinned image, the tests' temporary directory mounted at its own path, so
# that the paths a test gives mean the same inside.
set -euo pipefail

root="${LICASH_LITESTREAM_ROOT:-${TMPDIR:?TMPDIR names the directory to mount}}"
# The same version is used in CI. Override only to test another version.
image="${LICASH_LITESTREAM_IMAGE:-litestream/litestream:0.5.18}"
name="licash-litestream-$$"
user="$(id -u):$(id -g)"
# In rootless Docker the container's root is the invoking host user.
if docker info --format '{{json .SecurityOptions}}' | grep -q 'name=rootless'; then
    user='0:0'
fi
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# In the background, so that a signal stops it at once rather than once
# it exits by itself.
docker run --rm --init --name "$name" \
    --user "$user" \
    --volume "$root:$root:z" \
    "$image" "$@" &
wait $!
