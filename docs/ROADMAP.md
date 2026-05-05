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

- 1.1 ✅ `internal/preflight/` — порты 80/443 (TCP), kernel ≥ 5.4 (BBR), IPv4/IPv6, DNS
- 1.2 ✅ Caddy + ACME (HTTP-01) — реализовано в `internal/transport/naive/`, см. 1.7
- 1.3 ✅ `internal/transport/xray/` — VLESS REALITY (Vision + XHTTP)
- 1.4 ✅ `internal/transport/naive/` — Caddy forwardproxy@naive
- 1.5 ✅ `internal/subscribe/` — HMAC-token подписка, рендер VLESS/Naive URI, landing-page
- 1.6 ✅ `internal/orchestrator/` — `xray-aio install --profile home-stealth --domain ...` end-to-end (REALITY+Naive)
- 1.7 ✅ unified Caddy — selfsteal + Naive forward_proxy в одном Caddy-инстансе под общим ACME-аккаунтом и cert-store; REALITY-upstream приземляется на selfsteal-сайт с настоящим LE-сертификатом
- интеграционный тест в Docker (Debian 12)

## Phase 2 — расширение транспортов

PR на каждый, изолированно:
- 2.1 ✅ `transport/hysteria2` — пакет (#17)
- 2.1b ✅ orchestrator-wiring — профиль `home-mobile` (REALITY+naive+selfsteal+hy2),
  CLI-флаги `--hysteria2-port` / `--hysteria2-masquerade`, hy2:// URI в подписке
- 2.2 ✅ `transport/amneziawg` — пакет + preflight + sha256-verified releases,
  профиль `home-vpn-mobile` (REALITY+naive+hy2+AmneziaWG), .conf + QR в подписке (#26–#35)
- 2.3 ✅ `transport/mtproto` — пакет telemt (Fake-TLS / EE-MTProxy),
  sha256-verified binary из github.com/telemt/telemt, registry-registration
- 2.3b `transport/mtproto` orchestrator-wiring — CLI-флаги, tg:// URI
  в подписке, preflight-коллизии по :8883/TCP, профиль-включение
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
