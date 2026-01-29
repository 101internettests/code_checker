import json
from datetime import date
import requests
import os

BOT_TOKEN = os.environ["BOT_TOKEN"]
CHAT_ID = os.environ["CHAT_ID"]
STATS_FILE = "/root/data/stats.json"


def send_report():
    today = str(date.today())
    if not os.path.exists(STATS_FILE):
        msg = f"📊 Отчет за {today}: статистики нет"
    else:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        stats = data.get(today, {"success": 0, "fail": 0})
        msg = f"📊 Отчет за {today}:\n✅ Успешно: {stats['success']}\n❌ Ошибок: {stats['fail']}"

    requests.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data={"chat_id": CHAT_ID, "text": msg}
    )


if __name__ == "__main__":
    send_report()