import json
from datetime import date
import requests
import os
import html

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("CHAT_ID", "").strip()
USE_TELEGRAM_PROXY = os.getenv("USE_TELEGRAM_PROXY", "false").lower() in {"1", "true", "yes", "y", "on"}
TELEGRAM_PROXY_URL = os.getenv("TELEGRAM_PROXY_URL", "").strip()
TELEGRAM_PROXY_AUTH_SECRET = os.getenv("TELEGRAM_PROXY_AUTH_SECRET", "").strip()
TELEGRAM_PROXY_CREDS = os.getenv("TELEGRAM_PROXY_CREDS", "").strip()
try:
    TELEGRAM_PROXY_TIMEOUT_SEC = float(os.getenv("TELEGRAM_PROXY_TIMEOUT_SEC", "15"))
except Exception:
    TELEGRAM_PROXY_TIMEOUT_SEC = 15.0
STATS_FILE = "/root/data/stats.json"


def _send_message(msg: str) -> None:
    if USE_TELEGRAM_PROXY:
        missing = []
        if not TELEGRAM_PROXY_URL:
            missing.append("TELEGRAM_PROXY_URL")
        if not TELEGRAM_PROXY_AUTH_SECRET:
            missing.append("TELEGRAM_PROXY_AUTH_SECRET")
        if not TELEGRAM_PROXY_CREDS:
            missing.append("TELEGRAM_PROXY_CREDS")
        if missing:
            print(f"[telegram][proxy] Missing required env vars: {', '.join(missing)}")
            return
        try:
            requests.post(
                TELEGRAM_PROXY_URL,
                headers={
                    "Content-Type": "application/json",
                    "X-Authentication": TELEGRAM_PROXY_AUTH_SECRET,
                },
                json={
                    "title": html.escape("Run summary"),
                    "text": html.escape(msg),
                    "creds": TELEGRAM_PROXY_CREDS,
                    "parse_mode": "HTML",
                    "disable_notification": False,
                },
                timeout=TELEGRAM_PROXY_TIMEOUT_SEC,
            )
        except Exception as exc:
            print(f"[telegram][proxy] failed to send summary: {exc}")
        return

    if not BOT_TOKEN or not CHAT_ID:
        print("[telegram] BOT_TOKEN/CHAT_ID missing")
        return
    requests.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data={"chat_id": CHAT_ID, "text": msg},
        timeout=10,
    )


def send_report():
    today = str(date.today())
    if not os.path.exists(STATS_FILE):
        msg = f"📊 Отчет за {today}: статистики нет"
    else:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        stats = data.get(today, {"success": 0, "fail": 0})
        msg = f"📊 Отчет за {today}:\n✅ Успешно: {stats['success']}\n❌ Ошибок: {stats['fail']}"

    _send_message(msg)


if __name__ == "__main__":
    send_report()
