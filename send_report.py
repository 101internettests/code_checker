import json
from datetime import date
import requests
import os
import html

TELEGRAM_PROXY_URL = os.getenv("TELEGRAM_PROXY_URL", "").strip()
TELEGRAM_PROXY_AUTH_SECRET = os.getenv("TELEGRAM_PROXY_AUTH_SECRET", "").strip()
TELEGRAM_PROXY_CREDS = os.getenv("TELEGRAM_PROXY_CREDS", "").strip()
try:
    TELEGRAM_PROXY_TIMEOUT_SEC = float(os.getenv("TELEGRAM_PROXY_TIMEOUT_SEC", "15"))
except Exception:
    TELEGRAM_PROXY_TIMEOUT_SEC = 15.0
STATS_FILE = "/root/data/stats.json"


def _send_message(msg: str) -> None:
    # Proxy-only transport for summary notifications.
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
        response = requests.post(
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
        if getattr(response, "status_code", 200) >= 400:
            body = (getattr(response, "text", "") or "").strip().replace("\n", " ")
            print(f"[telegram][proxy] send failed: status={response.status_code} body={body[:180]}")
    except Exception as exc:
        print(f"[telegram][proxy] failed to send summary: {exc}")


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
