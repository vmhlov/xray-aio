# xray-aio — архитектура

> Согласовано с владельцем `vmhlov` 2026-04-29. Это документ-спецификация,
> от которой пишется код. Любое отклонение оформляется отдельным PR с
> правкой этого документа.

---

## 1. Что строим

**xray-aio** — оркестратор bypass-транспортов: один Go-бинарь, который
ставит и держит на VPS набор современных протоколов обхода блокировок,
без БД и GUI. Преемник
[`vmhlov/autoXRAY`](https://github.com/vmhlov/autoXRAY) (bash, 2200+
строк → Go, модульно).

Ядра (Xray-core, sing-box, Caddy + naive, Hysteria 2, AmneziaWG, mtg)
запускаются как отдельные процессы под systemd. xray-aio их не
линкует — он только конфигурирует, пускает, опрашивает и отзывает.

---

## 2. Зафиксированные решения

| # | Решение | Значение |
|---|---|---|
| 1 | Язык orchestrator | **Go 1.22** |
| 2 | TLS-frontend | **Caddy** (ACME из коробки, HTTP/3, naive-плагин) |
| 3 | Совместимость со старыми autoXRAY-подписками | **нет** (breaking) |
| 4 | Telegram-нотификатор | **выкинут** |
| 5 | Cloudflare-интеграция | **оба варианта**, дефолт = Tunnel (cloudflared) |
| 6 | Имя продукта | **xray-aio** |
| 7 | Лицензия | **MIT** |

---

## 3. Сравнительная таблица транспортов (зачем они нам)

Колонки: **WL-RF** = выживает под whitelist в РФ, **JA3** = стойкость к
TLS-fingerprint, **CDN** = можно фронтить через Cloudflare,
**Maturity** = зрелость 2026.

| Транспорт | WL-RF | JA3 | CDN | Maturity | Когда применять |
|---|---|---|---|---|---|
| VLESS REALITY (Vision/RAW) | 🟢 selfsteal | 🟢 | ❌ | 🟢 | дефолт `home-stealth` |
| VLESS REALITY + XHTTP | 🟢 | 🟢 | ❌ | 🟡 | защита от ML-детекта |
| VLESS TLS + XHTTP | 🟢 (свой домен) | 🟢 | 🟢 (CF) | 🟢 | CDN-fronting |
| VLESS WS / gRPC + TLS | 🟢 | 🟢 | 🟢 | 🟢 | за CF, мобилки |
| Trojan TLS | 🟢 | 🟢 | 🟢 | 🟢 | дублёр VLESS |
| Hysteria 2 | 🔴 (UDP) | 🟢 | ❌ | 🟢 | дом-провайдер без drop UDP |
| TUIC v5 | 🔴 | 🟢 | ❌ | 🟡 | альтернатива Hysteria 2 |
| MASQUE / WARP | 🟡 (CF в WL) | 🟢 | 🟢 | 🟡 | outbound через WARP |
| AmneziaWG | 🔴 (UDP) | 🟢 | ❌ | 🟢 | домашний WG-аналог |
| NaïveProxy | 🟢 | 🟢 | ❌ | 🟢 | альтернатива VLESS |
| Shadowsocks-2022 | 🟡 | 🔴 | 🟡 | 🟢 | резерв |
| MTProto FakeTLS | 🟢 | 🟢 | ❌ | 🟢 | Telegram only |
| SSH-туннель | 🟢 | 🟢 | ❌ | 🟢 | админ / fallback |

**Вывод:** дефолтный профиль ставит TCP-стек (REALITY+naive). UDP-стек
(Hysteria 2, AmneziaWG) — опционально, в профилях `home-mobile` и
`paranoid`.

---

## 4. Профили

| Профиль | Состав |
|---|---|
| `home-stealth` (default) | VLESS REALITY (Vision) + naive forward_proxy + selfsteal под единым Caddy с ACME HTTP-01 |
| `home-mobile` | `home-stealth` + Hysteria 2 |
| `home-cdn` | VLESS WS/gRPC + Trojan WS за CF |
| `bridge-ru-eu` | Российская нода → ЕС-нода через REALITY-XHTTP |
| `paranoid` | всё перечисленное + AmneziaWG + MTProto FakeTLS |

Профили — это пресеты `state.json`. Каждый транспорт можно включить
вручную через `xray-aio install --transport=<name>`.

---

## 5. Структура кода

```
xray-aio/
├── cmd/xray-aio/main.go         cobra CLI
├── internal/
│   ├── version/                 build metadata (-ldflags)
│   ├── log/                     slog wrapper
│   ├── state/                   state.json load/save (atomic)
│   ├── preflight/               OS/distro/ports/DNS checks
│   ├── transport/               Transport interface + registry
│   │   ├── xray/                VLESS REALITY/XHTTP/TLS/WS/gRPC (Phase 1)
│   │   ├── singbox/             sing-box backend (alt)          (Phase 3)
│   │   ├── naive/               Caddy forwardproxy@naive        (Phase 2)
│   │   ├── hysteria2/           apernet/hysteria                (Phase 2)
│   │   ├── amneziawg/                                            (Phase 2)
│   │   ├── mtproto/             mtg fake-TLS                    (Phase 2)
│   │   └── trojan/                                               (Phase 3)
│   ├── orchestrator/            install/status coordinator      (Phase 1.6)
│   ├── bridge/                  RU→EU bridge profile            (Phase 5)
│   ├── subscribe/               подпись HMAC, выдача конфигов   (Phase 1.5)
│   ├── cloudflare/
│   │   ├── tunnel/              cloudflared (default CF mode)   (Phase 4)
│   │   └── worker/              CF Worker via API               (Phase 4)
│   └── warp/                    WARP-cli outbound               (Phase 1)
├── docs/
│   ├── architecture.md          (этот файл)
│   ├── ROADMAP.md
│   └── transports/<name>.md     по странице на транспорт         (по мере)
├── .github/workflows/ci.yml     gofmt/vet/test/build/golangci
├── Makefile
├── go.mod
├── README.md
└── LICENSE                      MIT
```

---

## 6. Контракт `Transport`

```go
type Transport interface {
    Name() string
    Install(ctx, opts Options) error
    Start(ctx) error
    Stop(ctx) error
    Status(ctx) (Status, error)
    Probe(ctx) (ProbeResult, error)
    Uninstall(ctx) error
}
```

- **Idempotency** — `Install` можно дёргать сколько угодно, не должно
  ломать уже запущенные сервисы.
- **State** — каждый транспорт хранит свою конфигурацию в
  `state.Transports["<name>"]` как `json.RawMessage`. Схема — приватная
  структура внутри пакета транспорта.
- **Probe** — встроенный health-check (TLS handshake, JA3-сравнение,
  curl на свой sub-path, etc), результат — в stdout и в `state.json`.

---

## 7. State

`/etc/xray-aio/state.json` (perm `0600`):

```json
{
  "schema": 1,
  "created_at": "2026-04-29T08:00:00Z",
  "updated_at": "2026-04-29T08:00:00Z",
  "profile": "home-stealth",
  "domain": "example.com",
  "transports": {
    "xray-reality":      { "...": "..." },
    "naive":             { "...": "..." },
    "hysteria2":         null,
    "cloudflare-tunnel": null
  }
}
```

Атомарная запись через `write tmp` + `rename`. Конкретные структуры
транспортных секций описывает каждый пакет.

---

## 8. Команды CLI

| Команда | Поведение |
|---|---|
| `xray-aio preflight` | проверка ОС, дистрибутива, портов, DNS, kernel, BBR |
| `xray-aio install --profile=...` | preflight → установка транспортов профиля → пробы |
| `xray-aio status` | читает state.json, показывает PID/health каждого транспорта |
| `xray-aio update` | обновление пинов транспортных бинарей |
| `xray-aio rotate` | новые UUID/keys/paths без переустановки бинарей |
| `xray-aio uninstall` | systemctl disable, rm бинарей и конфигов, чистка state.json |
| `xray-aio cloudflare tunnel ...` | управление cloudflared (Phase 4) |
| `xray-aio cloudflare worker ...` | управление CF Workers (Phase 4) |

---

## 9. Что НЕ входит

- мульти-юзер панель (это Marzban/Remnawave/3x-ui)
- свой VPN-клиент (остаются Happ/v2rayTun/sing-box/NekoBox)
- биллинг/закупка VPS
- любые попытки атаки на ТСПУ/CF/чужую инфраструктуру
- Telegram-интеграция (вычеркнута)

---

## 10. Источники

- `habr.com/articles/1027276/` — белые списки (L3+L7), 6 способов обхода
- `habr.com/articles/903358/` — XTLS REALITY, технический разбор
- `habr.com/articles/992240/` — Xray-core, вызовы 2026 года
- `habr.com/articles/1009542/` — JA3/JA4 fingerprint и переход на XHTTP
- `habr.com/articles/1008554/` — Hysteria 2 и Salamander/Brutal
- `habr.com/articles/972172/` — MASQUE / RFC 9484
- `habr.com/articles/1018964/` — sing-box знакомство
- `habr.com/articles/839656/` — VLESS vs Shadowsocks
- `habr.com/articles/841460/` — zapret / nfqws на клиенте
- `habr.com/articles/845114/` — GoodbyeDPI
- `github.com/openlibrecommunity/twl` — еженедельный datasets whitelist
- `github.com/XTLS/Xray-core/discussions/5969` — продвинутые SNI-spoofing
- `github.com/vmhlov/autoXRAY` — предшественник
- `github.com/vmhlov/naive-proxy` — рабочий naive-стенд (за основу `naive`-транспорта)
