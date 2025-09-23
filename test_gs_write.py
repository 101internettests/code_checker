import os
from datetime import datetime

import gspread
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv


def main():
    load_dotenv(override=True)

    spreadsheet_id = os.getenv("SPREADSHEET_ID", "").strip()
    gsa_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", "").strip()

    if not spreadsheet_id:
        print("ERROR: SPREADSHEET_ID is not set in .env")
        raise SystemExit(1)
    if not gsa_json or not os.path.exists(gsa_json):
        print("ERROR: GOOGLE_SERVICE_ACCOUNT_JSON is not set or file not found")
        raise SystemExit(1)

    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive",
    ]
    creds = Credentials.from_service_account_file(gsa_json, scopes=scopes)
    gc = gspread.authorize(creds)

    sh = gc.open_by_key(spreadsheet_id)

    today_title = "Лист 1"
    try:
        ws = sh.worksheet(today_title)
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=today_title, rows=1, cols=20)
        ws.append_row(["timestamp", "site", "http_full", "http_status", "response_ms", "result", "notes"], value_input_option="RAW")

    now_str = datetime.now().strftime("%d.%m.%Y %H:%M")
    ws.append_row([now_str, "TEST", "https://test.example.com/page", "", "", "TEST_WRITE", "ping"], value_input_option="RAW")

    print(f"OK: test row appended to sheet '{today_title}' in spreadsheet {spreadsheet_id}")


if __name__ == "__main__":
    main()
