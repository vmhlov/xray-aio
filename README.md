# xray-aio

> All-in-one bypass-aggregator: один бинарь, один конфиг, любой транспорт.
> Преемник [autoXRAY](https://github.com/vmhlov/autoXRAY) с переписанной на Go архитектурой.

**Статус:** Phase 1 ✅ — `home-stealth` (VLESS REALITY + NaïveProxy под общим Caddy/LE) ставится и тестируется на проде. Phase 2 (расширение транспортов) в работе. См. [docs/architecture.md](./docs/architecture.md) и [docs/ROADMAP.md](./docs/ROADMAP.md).

## Цель

Развернуть на VPS набор современных bypass-транспортов одной командой, с разумными значениями по умолчанию, без GUI и без БД. Покрытие — то, что реально работает в 2026 году под whitelist-фильтрацией:

- VLESS REALITY (Vision / RAW / XHTTP) — Phase 1 ✅
- NaïveProxy (Caddy + forwardproxy@naive) — Phase 1 ✅
- Hysteria2 (QUIC / Brutal / Salamander) — Phase 2
- AmneziaWG — Phase 2
- MTProto FakeTLS — Phase 2
- Trojan — Phase 2
- VLESS TLS (XHTTP / WS / gRPC) — Phase 3
- RU → EU bridge — Phase 5
- Cloudflare Tunnel / Worker (опционально) — Phase 4

Ядра запускаются как отдельные процессы (Xray, sing-box, Caddy, hysteria, amneziawg, mtg) — `xray-aio` их оркестрирует, не линкует.

## Установка (Phase 1: home-stealth)

Требования:
- Debian 11/12 или совместимая `systemd`-based Linux x86_64/arm64.
- Запуск под root.
- Свободные порты `tcp/80` (ACME HTTP-01), `tcp/443` (REALITY), `tcp/8443` (selfsteal loopback), `tcp/8444` (NaïveProxy).
- DNS: A-запись на ваш домен указывает на этот VPS, пропагирована на публичные резолверы.

Сборка из исходников:

```sh
git clone https://github.com/vmhlov/xray-aio.git
cd xray-aio
make build           # → bin/xray-aio
sudo install -m 0755 bin/xray-aio /usr/local/bin/
```

Прогон preflight-проверок:

```sh
sudo xray-aio preflight
```

Установка профиля `home-stealth`:

```sh
sudo xray-aio install \
    --profile home-stealth \
    --domain example.com \
    --email you@example.com
```

Команда:

1. Создаёт системные пользователи `caddy` и `xray` (идемпотентно).
2. Скачивает и устанавливает Xray-core и Caddy с naive-плагином.
3. Генерирует REALITY-ключи, Naïve-credentials, HMAC-токен подписки.
4. Пишет конфиги (`/etc/xray-aio/`), systemd-юниты (`/etc/systemd/system/`), статический selfsteal-сайт (`/var/lib/xray-aio/selfsteal/`), public-сайт + лендинг подписки (`/var/lib/xray-aio/naive-selfsteal/sub/<token>/`).
5. Запускает `xray-aio-xray.service` и `xray-aio-naive.service`, ждёт LE-сертификат.
6. Печатает URL подписки.

Пример вывода (успех):

```
profile: home-stealth
domain:  example.com

subscription URL (give to client):
  https://example.com:8444/sub/<token>/
bundle written: /var/lib/xray-aio/naive-selfsteal/sub/<token>
```

Команда **идемпотентна**: повторный запуск с тем же `--domain` сохраняет существующий state (REALITY-ключи, токен, basic_auth) и только обновляет конфиги/юниты. Останавливать сервисы вручную не нужно — preflight видит наши собственные слушатели и не считает их конфликтом.

## Клиенты

В лендинге подписки (`https://<domain>:8444/sub/<token>/`) сгенерированы ссылки в формате `vless://…` (REALITY, Vision flow) и `naive+https://…`. Импортируйте их в:

- **NekoBox / NekoRay** (Windows/Android/macOS) — оба URI работают
- **sing-box** — VLESS REALITY URI работает напрямую
- **Hiddify** (iOS/macOS/Android) — оба URI
- **v2rayN / v2rayNG** — VLESS REALITY URI
- **NaïveProxy CLI** — `naive+https://…` URI

## Команды

```
xray-aio install      # установить профиль
xray-aio status       # показать статус сервисов и health-probe
xray-aio preflight    # только проверка окружения
xray-aio update       # (Phase 3) обновить версии транспортов
xray-aio rotate       # (Phase 3) ротировать ключи/токены
xray-aio uninstall    # (Phase 3) снять всё, что установил install
```

## Лицензия

MIT — см. [LICENSE](./LICENSE).
