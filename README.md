# code_checker

## Telegram proxy

Для отправки алертов через proxy задайте:

- `USE_TELEGRAM_PROXY=true`
- `TELEGRAM_PROXY_URL`
- `TELEGRAM_PROXY_AUTH_SECRET`
- `TELEGRAM_PROXY_CREDS`
- `TELEGRAM_PROXY_TIMEOUT_SEC` (опционально, по умолчанию `15`)

При `USE_TELEGRAM_PROXY=false` используется старый путь `BOT_TOKEN/CHAT_ID`.

## Proxy fallback

`PROXY_URLS` задаётся в порядке приоритета: сначала используется первый proxy,
при ошибке запроса — следующий. Для двух proxy порядок такой: `proxy-1 -> proxy-2`.

Fallback включён по умолчанию. Его можно явно отключить через
`PROXY_FALLBACK_ENABLED=false`.

Чтобы запросы всегда шли через proxy, задайте `PROXY_DIRECT_PERCENT=0`.

## Proxy bypass для отдельных доменов

Чтобы отдельные домены проверялись напрямую, без proxy и без fallback через proxy,
задайте `PROXY_BYPASS_DOMAINS` через запятую, точку с запятой или перенос строки.

Для временной проверки MTS:

```text
PROXY_BYPASS_DOMAINS=mts-home-online.ru
```

Остальные домены продолжают использовать обычную proxy-логику.

## Jenkins schedule

Для запуска один раз в час в настройках Jenkins job:

- удалите trigger `Build after other projects are built` и любые downstream/upstream triggers;
- оставьте только `Build periodically` с cron-выражением `H * * * *`;
- для proxy-режима задайте `PROXIES_ENABLED=true`, `PROXY_DIRECT_PERCENT=0` и передайте два адреса в `PROXY_URLS` в нужном порядке.
