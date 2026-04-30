# Phase 1 Docker integration test

End-to-end exercise of the `home-stealth` install path against a
privileged Debian 12 container running systemd as PID 1. Catches
regressions that the unit tests cannot — anything that breaks once
the binary runs `systemctl enable --now`, fetches Caddy/Xray
upstreams, or hits Caddy's `tls internal` cert path.

## What it asserts

1. `xray-aio install` exits 0 (sysuser, config, systemd start).
2. Both `xray-aio-{xray,naive}.service` are active afterwards.
3. `state.json` has the expected `subscription.token` + `naive.username/password`.
4. `https://<fqdn>:8444/sub/<token>/` returns 200 (Caddy `tls internal`).
5. `https://<fqdn>:8443/sub/<token>/` returns 404 (selfsteal isolation).
6. Forward-proxy without auth → 000 (probe_resistance silent reject).
7. Forward-proxy with `username:password` from state → 200 (real example.com upstream).
8. Re-running `xray-aio install` with the same domain returns 0 without `systemctl stop`, and preserves the token + naive creds.

Steps 1, 2, 8 cover the regressions from PR #10 (missing system users),
#13/#14 (idempotent preflight). Steps 5, 6, 7 cover the regressions
from PR #11 (Caddy directive reorder), #12 (host-matcher rejecting
HTTP/1.1 CONNECT).

## Running locally

```sh
make integration
```

Requires Docker. The script builds a `linux/amd64` binary, copies it
into a Debian 12 + systemd image, runs the container privileged with
`--cgroupns=host` (mandatory on cgroup v2 hosts for systemd PID-1),
exec's the in-container script, then tears the container down.

End-to-end on a warm Docker cache: ~25 s. First run pulls
`debian:12-slim` and installs `systemd`, `ca-certificates`, `curl`,
`jq` — adds another ~20 s.

## Knobs

| Env var       | Default                        | What it does                          |
|---------------|--------------------------------|---------------------------------------|
| `IMAGE_TAG`   | `xray-aio-integration:latest`  | Docker image tag                      |
| `CONTAINER`   | `xray-aio-integration`         | Docker container name                 |
| `FQDN`        | `xray-aio.test`                | `--domain` passed to `xray-aio install` |
| `KEEP_CONTAINER` | unset (cleanup on exit)     | If `1`, leaves the container running for inspection |

## CI

Wired into `.github/workflows/ci.yml` as the `integration` job.
Depends on `build` succeeding so a regression in cross-build is
caught first; the integration job itself runs `make integration`
on `ubuntu-latest`, which has Docker + privileged + cgroup v2
available out of the box.
