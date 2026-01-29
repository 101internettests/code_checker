import json
from datetime import date
import requests
import os

# Read required tokens from env (fail fast if missing)
BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]

# Allow overriding stats path via env to match run_check configuration
STATS_FILE = os.environ.get("STATS_FILE", "/root/data/stats.json")


def _format_report_for_day(day: str, payload: dict) -> str:
    entry = payload.get(day)
    if not isinstance(entry, dict):
        return f"📊 Отчет за {day}: статистики нет"

    success = int(entry.get("success", 0))
    failure = int(entry.get("failure", entry.get("fail", 0)))  # backward-compat if old key present
    total_pages = int(entry.get("total_pages", 0))
    failed_pages = int(entry.get("failed_pages", 0))
    ssl_sites = int(entry.get("ssl_issues_sites", 0))
    runs = int(entry.get("runs", 0))
    last_ts = entry.get("last_timestamp", "—")

    # Prefer stored summary if present, otherwise construct
    summary = entry.get("summary") or f"Сводка: успешно {success}, неуспешно {failure}"

    lines = [
        f"📊 Отчет за {day}",
        summary,
        f"Всего страниц: {total_pages}",
        f"Проблемных страниц: {failed_pages}",
        f"SSL-проблем на сайтах: {ssl_sites}",
        f"Прогонов: {runs}",
        f"Последний запуск: {last_ts}",
    ]
    return "\n".join(lines)


def send_report():
    today = str(date.today())

    if not os.path.exists(STATS_FILE):
        msg = f"📊 Отчет за {today}: статистики нет"
    else:
        try:
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
        msg = _format_report_for_day(today, data)

    requests.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data={"chat_id": CHAT_ID, "text": msg}
    )


if __name__ == "__main__":
    send_report()