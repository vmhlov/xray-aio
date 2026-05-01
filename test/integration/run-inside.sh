#!/bin/sh
# run-inside.sh — exercises the install+probe path inside a debian:12
# systemd container. Invoked by run.sh via `docker exec`.
#
# What we assert (mirroring the production E2E §7 checklist, minus the
# parts that need a real domain + LE certificate):
#
#   1. `xray-aio install` returns 0 (sysuser creation, config write,
#      systemd start all succeed).
#   2. Both xray-aio-{xray,naive}.service report active.
#   3. `xray-aio install` is idempotent — re-run returns 0 without
#      `systemctl stop` (preflight detects own listeners as held).
#   4. The subscription endpoint at https://<fqdn>:8444/sub/<token>/
#      returns HTTP 200 (Caddy `tls internal` cert; client uses -k).
#   5. The proxy gate works: forwarded request without auth returns 0
#      (probe_resistance silently rejects); with the right basic_auth
#      Caddy CONNECTs through to https://example.com.
#
# Uses `tls internal` (passing --email "" forces it) so we never touch
# the public ACME servers and the test runs offline-against-LE. We
# DO need internet for transport binary downloads + the example.com
# upstream; both are fine on GitHub Actions runners.

set -eu

FQDN="${FQDN:-xray-aio.test}"
STATE=/etc/xray-aio/state.json

log() { printf '\n=== %s ===\n' "$*" >&2; }

log 'first install'
xray-aio install \
    --profile home-stealth \
    --domain "$FQDN" \
    --email ''

log 'services active after first install'
systemctl is-active xray-aio-xray.service
systemctl is-active xray-aio-naive.service

log 'state.json was written'
test -f "$STATE"

# Phase-1.7 token + naive creds end up here; orchestrator tests use the
# same shape (internal/orchestrator/state.go). The state file has the
# raw orchestrator slice base64-decoded into .transports._orchestrator
# (a JSON value), so two jq invocations are needed: first to extract
# the bucket, second to walk it.
ORCH=$(jq -r '.transports._orchestrator' "$STATE")
test -n "$ORCH" && test "$ORCH" != null
TOKEN=$(printf '%s' "$ORCH" | jq -r '.subscription.token')
USER=$(printf '%s' "$ORCH" | jq -r '.naive.username')
PASS=$(printf '%s' "$ORCH" | jq -r '.naive.password')
test -n "$TOKEN" && test "$TOKEN" != null
test -n "$USER" && test "$USER" != null
test -n "$PASS" && test "$PASS" != null

# Caddy needs ~5–10s after systemd start to issue the `tls internal`
# cert and bind :8444. Poll until the subscription endpoint responds
# instead of guessing with a fixed sleep.
log 'wait for caddy on :8444'
for _ in $(seq 1 30); do
    if curl -sk --resolve "$FQDN:8444:127.0.0.1" \
        -o /dev/null -w '%{http_code}' \
        "https://$FQDN:8444/sub/$TOKEN/" | grep -q '^200$'; then
        break
    fi
    sleep 1
done

log 'subscription endpoint :8444/sub/<token>/ → 200'
curl -sk --resolve "$FQDN:8444:127.0.0.1" --fail \
    "https://$FQDN:8444/sub/$TOKEN/" >/dev/null

log 'subscription endpoint NOT reachable on :8443 (isolation)'
code=$(curl -sk --resolve "$FQDN:8443:127.0.0.1" \
    -o /dev/null -w '%{http_code}' \
    "https://$FQDN:8443/sub/$TOKEN/")
test "$code" = '404'

log 'proxy without auth → 000 (probe_resistance silent reject)'
code=$(curl -sk --resolve "$FQDN:8444:127.0.0.1" \
    -o /dev/null -w '%{http_code}' \
    --proxy "https://$FQDN:8444" \
    --proxy-insecure \
    https://example.com/) || code='000'
# curl exits non-zero → variable assignment fallback. We expect 000.
test "$code" = '000' || { echo "expected 000, got $code" >&2; exit 1; }

log 'proxy with valid basic_auth → 200 (real upstream)'
code=$(curl -sk --resolve "$FQDN:8444:127.0.0.1" \
    -o /dev/null -w '%{http_code}' \
    --proxy "https://$USER:$PASS@$FQDN:8444" \
    --proxy-insecure \
    https://example.com/)
test "$code" = '200'

log 'idempotent install (no systemctl stop)'
xray-aio install \
    --profile home-stealth \
    --domain "$FQDN" \
    --email ''
systemctl is-active xray-aio-xray.service
systemctl is-active xray-aio-naive.service

# Token + creds must survive a re-install.
TOKEN2=$(jq -r '.transports._orchestrator.subscription.token' "$STATE")
USER2=$(jq -r '.transports._orchestrator.naive.username' "$STATE")
PASS2=$(jq -r '.transports._orchestrator.naive.password' "$STATE")
test "$TOKEN" = "$TOKEN2"
test "$USER" = "$USER2"
test "$PASS" = "$PASS2"

log 'home-mobile smoke: cross-profile re-install must be rejected'
# Cross-profile guard from orchestrator/install.go: state.json tied to
# home-stealth must reject an install for home-mobile with a clear
# error so operators do not silently lose state. This runs entirely
# from cached state — no extra binaries downloaded, no services
# restarted — so it is safe to chain after the home-stealth checklist.
if xray-aio install --profile home-mobile --domain "$FQDN" --email '' 2>/tmp/cross.err; then
    echo 'expected cross-profile install to fail' >&2
    cat /tmp/cross.err >&2
    exit 1
fi
grep -q 'state holds profile' /tmp/cross.err

log 'integration test passed'
