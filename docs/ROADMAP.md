# Roadmap

## Phase 0 — скелет (этот PR)

- репозиторий, лицензия, Go-проект (`go.mod`, Makefile)
- CLI-каркас на cobra: `install / status / update / rotate / uninstall / preflight`
- `state` пакет с атомарной записью `state.json`
- `transport` пакет с регистром транспортов и контрактом `Transport`
- `preflight` пакет с детектом дистрибутива
- `version` пакет (`-ldflags` инъекция)
- CI: `gofmt`, `go vet`, `go test -race`, `go build` под `linux/amd64,linux/arm64`
- `docs/architecture.md`, `docs/ROADMAP.md`

**Definition of done:** `make ci` зелёный, `bin/xray-aio --help` показывает все команды, `bin/xray-aio preflight` работает.

## Phase 1 — TCP-стек MVP (`home-stealth`)

- `internal/tls/` — установка Caddy + ACME через TLS-ALPN-01
- `internal/transport/xray/` — VLESS REALITY (Vision + XHTTP) + selfsteal
- `internal/transport/naive/` — Caddy forwardproxy@naive (порт от Caddy)
- `internal/subscribe/` — HMAC-token подписка, выдача QR/конфигов через `xray-aio status --subscribe`
- `internal/preflight/` — порты 80/443 (TCP), kernel ≥ 5.4 (BBR), IPv4/IPv6
- интеграционный тест в Docker (Debian 12)
- `xray-aio install --profile home-stealth --domain ...` — рабочий

## Phase 2 — расширение транспортов

PR на каждый, изолированно:
- `transport/hysteria2`
- `transport/amneziawg`
- `transport/mtproto` (вынос из autoXRAY/test/)
- `transport/trojan`
- `transport/shadowsocks` (опционально, как fallback)

## Phase 3 — UX / надёжность

- TUI (whiptail / promptui) для интерактива
- health-probes (TLS, JA3 expected, UDP/443, packet loss)
- auto-rotate `xray-aio rotate`
- pin-версии и `xray-aio update --to-latest|--to-vX.Y.Z`
- `transport/singbox` как альтернативное ядро

## Phase 4 — Cloudflare

- `internal/cloudflare/tunnel/` — установка cloudflared + `tunnel create`
- `internal/cloudflare/worker/` — деплой готового JS-Worker через CF API (без `wrangler` как зависимости)
- доки по выбору режима

## Phase 5 — RU→EU bridge + кластеризация

- `internal/bridge/` — две ноды, REALITY-XHTTP цепочка
- координация state.json между нодами через подписку обновлений

## Phase 6 — релиз

- semver, тег `v1.0.0`, GitHub Release с бинарями (linux amd64/arm64)
- `install.sh` обёртка
- README на ru+en
