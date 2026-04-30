#!/bin/sh
# run.sh — outer driver for the Phase 1 Docker integration test.
# Builds the binary for linux/amd64, copies it into ./test/integration,
# builds the systemd-Debian-12 image, runs it as PID-1 systemd, then
# execs run-inside.sh which executes the actual install + probe
# checklist.
#
# Usage:    test/integration/run.sh
# Cleanup:  the script always tears down the container on exit.
#
# Knobs:
#   IMAGE_TAG   defaults to xray-aio-integration:latest
#   CONTAINER   defaults to xray-aio-integration
#   FQDN        defaults to xray-aio.test (passed through to run-inside)
set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
IMAGE_TAG="${IMAGE_TAG:-xray-aio-integration:latest}"
CONTAINER="${CONTAINER:-xray-aio-integration}"
FQDN="${FQDN:-xray-aio.test}"

cleanup() {
    if [ "${KEEP_CONTAINER:-0}" != '1' ]; then
        docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    fi
    rm -f "$SCRIPT_DIR/xray-aio"
}
trap cleanup EXIT

echo '=== build linux/amd64 binary ===' >&2
(cd "$REPO_ROOT" && \
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' \
    -o "$SCRIPT_DIR/xray-aio" ./cmd/xray-aio)

echo '=== docker build ===' >&2
docker build -t "$IMAGE_TAG" "$SCRIPT_DIR" >&2

echo '=== docker run (privileged systemd PID 1) ===' >&2
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
# `--cgroupns=host` is required for systemd PID-1 on cgroup v2 hosts:
# the default private cgroup namespace mounts /sys/fs/cgroup as a
# read-only namespace root that systemd refuses to take over. Pairs
# with the --privileged flag and the --tmpfs /run mounts.
docker run -d \
    --name "$CONTAINER" \
    --privileged \
    --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -e FQDN="$FQDN" \
    "$IMAGE_TAG" >/dev/null

echo '=== wait for systemd multi-user.target ===' >&2
for _ in $(seq 1 30); do
    if docker exec "$CONTAINER" systemctl is-system-running --wait 2>/dev/null \
        | grep -qE '^(running|degraded)$'; then
        break
    fi
    sleep 1
done

echo '=== run integration script ===' >&2
docker exec -e FQDN="$FQDN" "$CONTAINER" /run-inside.sh
