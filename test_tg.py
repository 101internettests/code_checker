import os
from datetime import datetime

import requests
from dotenv import load_dotenv


def main():
    load_dotenv(override=True)
    bot_token = os.getenv("BOT_TOKEN", "").strip()
    chat_id = os.getenv("CHAT_ID", "").strip()

    if not bot_token or not chat_id:
        print("ERROR: BOT_TOKEN or CHAT_ID not set in .env")
        raise SystemExit(1)

    text = f"Test from code_checker at {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}"

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=10
        )
        print("status:", resp.status_code)
        print("body:", resp.text)
        if not resp.ok:
            raise SystemExit(2)
    except Exception as e:
        print("ERROR sending telegram message:", e)
        raise SystemExit(3)


if __name__ == "__main__":
    main()
