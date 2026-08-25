import json
from datetime import datetime
import requests
import os
import html
from zoneinfo import ZoneInfo

TELEGRAM_PROXY_URL = os.getenv("TELEGRAM_PROXY_URL", "").strip()
TELEGRAM_PROXY_AUTH_SECRET = os.getenv("TELEGRAM_PROXY_AUTH_SECRET", "").strip()
TELEGRAM_PROXY_CREDS = os.getenv("TELEGRAM_PROXY_CREDS", "").strip()
try:
    TELEGRAM_PROXY_TIMEOUT_SEC = float(os.getenv("TELEGRAM_PROXY_TIMEOUT_SEC", "15"))
except Exception:
    TELEGRAM_PROXY_TIMEOUT_SEC = 15.0
STATS_FILE = os.getenv("STATS_FILE", "/var/lib/jenkins/stats.json").strip()
TIMEZONE = os.getenv("TZ", "Europe/Moscow").strip()


def _today() -> str:
    try:
        return datetime.now(ZoneInfo(TIMEZONE)).strftime("%Y-%m-%d")
    except Exception:
        return datetime.now().strftime("%Y-%m-%d")


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
    today = _today()
    if not os.path.exists(STATS_FILE):
        msg = f"📊 Отчет за {today}: статистики нет"
    else:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        stats = data.get(today, {})
        success = int(stats.get("success", 0))
        # run_check.py uses "failure"; "fail" is kept for old stats files.
        failure = int(stats.get("failure", stats.get("fail", 0)))
        runs = int(stats.get("runs", success + failure))
        failed_pages = int(stats.get("failed_pages", 0))
        ssl_issues = int(stats.get("ssl_issues_sites", 0))
        if not stats:
            msg = f"📊 Отчет за {today}: данных за день нет"
        else:
            msg = (
                f"📊 Отчет за {today}\n"
                f"Прогонов: {runs}\n"
                f"✅ Успешных: {success}\n"
                f"❌ С ошибками: {failure}\n"
                f"Ошибок страниц: {failed_pages}\n"
                f"SSL-проблем: {ssl_issues}"
            )

    _send_message(msg)


if __name__ == "__main__":
    send_report()
