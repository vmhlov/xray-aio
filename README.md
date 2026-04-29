# xray-aio

> All-in-one bypass-aggregator: один бинарь, один конфиг, любой транспорт.
> Преемник [autoXRAY](https://github.com/vmhlov/autoXRAY) с переписанной на Go архитектурой.

**Статус:** Phase 0 — скелет проекта. К релизу не готов. См. [docs/architecture.md](./docs/architecture.md) и [docs/ROADMAP.md](./docs/ROADMAP.md).

## Цель

Развернуть на VPS набор современных bypass-транспортов одной командой, с разумными значениями по умолчанию, без GUI и без БД. Покрытие — то, что реально работает в 2026 году под whitelist-фильтрацией:

- VLESS REALITY (Vision / RAW / XHTTP)
- VLESS TLS (XHTTP / WS / gRPC)
- NaïveProxy (Caddy + forwardproxy@naive)
- Hysteria2 (QUIC / Brutal / Salamander)
- AmneziaWG
- MTProto FakeTLS
- RU → EU bridge
- Cloudflare Tunnel / Worker (опционально)

Ядра запускаются как отдельные процессы (Xray, sing-box, Caddy, hysteria, amneziawg, mtg) — `xray-aio` их оркестрирует, не линкует.

## Установка (план — пока не работает)

```
curl -fsSL https://raw.githubusercontent.com/vmhlov/xray-aio/main/install.sh | bash -s -- \
    --profile home-stealth \
    --domain example.com
```

## Лицензия

MIT — см. [LICENSE](./LICENSE).
