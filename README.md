# code_checker

## Telegram proxy

Для отправки алертов через proxy задайте:

- `USE_TELEGRAM_PROXY=true`
- `TELEGRAM_PROXY_URL`
- `TELEGRAM_PROXY_AUTH_SECRET`
- `TELEGRAM_PROXY_CREDS`
- `TELEGRAM_PROXY_TIMEOUT_SEC` (опционально, по умолчанию `15`)

При `USE_TELEGRAM_PROXY=false` используется старый путь `BOT_TOKEN/CHAT_ID`.
