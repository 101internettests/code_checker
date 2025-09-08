import os
import ssl
import socket
import time
import logging
from datetime import datetime
from zoneinfo import ZoneInfo
from typing import List, Dict, Tuple, Optional

import requests
import pandas as pd
import gspread
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
import tldextract
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress warnings when verify=False is used intentionally to fetch status codes despite SSL issues
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


# --------------- Configuration ---------------
DEFAULT_TIMEOUT_SECONDS = 10
DEFAULT_TZ = os.environ.get("TZ", "Europe/Moscow")


# --------------- Logging ---------------
LOGS_DIR = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, "availability.log"), encoding="utf-8"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# --------------- Env ---------------
def load_config() -> dict:
    # Do NOT override existing env (e.g., Jenkins), local .env only fills missing values
    load_dotenv(override=False)

    config = {
        "urls_file": os.getenv("URLS_FILE", ""),
        "url_column_name": os.getenv("URL_COLUMN_NAME", "url"),
        "timeout_seconds": int(os.getenv("TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))),
        "ssl_check_mode": os.getenv("SSL_CHECK_MODE", "base"),  # base|per_host
        "spreadsheet_id": os.getenv("SPREADSHEET_ID", ""),
        "gsa_json": os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON", ""),
        "bot_token": os.getenv("BOT_TOKEN", ""),
        "chat_id": os.getenv("CHAT_ID", ""),
        "alerts_enabled": os.getenv("ALERTS_ENABLED", "true").lower() in {"1", "true", "yes"},
        "timezone": os.getenv("TZ", DEFAULT_TZ),
        # daily: один лист на дату; per_run: новый лист на каждый запуск (по умолчанию)
        "sheet_mode": os.getenv("SHEET_MODE", "per_run").strip().lower(),
        # отправлять ли сообщение об успешной проверке
        "success_alerts_enabled": os.getenv("SUCCESS_ALERTS_ENABLED", "true").lower() in {"1", "true", "yes"}
    }

    missing = []
    for key in ["urls_file", "spreadsheet_id", "gsa_json"]:
        if not config[key]:
            missing.append(key)
    if missing:
        logger.warning("Missing required envs for Google Sheets or URL list: %s", ", ".join(missing))

    # Helpful log to verify which chat id is used in CI
    try:
        logger.info(
            "Config: ALERTS_ENABLED=%s SUCCESS_ALERTS_ENABLED=%s SHEET_MODE=%s CHAT_ID=%s",
            config["alerts_enabled"], config.get("success_alerts_enabled", True), config.get("sheet_mode"), config.get("chat_id")
        )
    except Exception:
        pass

    return config


# --------------- Helpers ---------------
def now_local_str(tz_name: str) -> str:
    dt = datetime.now(ZoneInfo(tz_name)).replace(microsecond=0)
    return dt.strftime("%d.%m.%Y %H:%M")


def sheet_name_for_today(tz_name: str) -> str:
    dt = datetime.now(ZoneInfo(tz_name))
    return dt.strftime("%Y-%m-%d")


def sheet_name_for_run(tz_name: str) -> str:
    dt = datetime.now(ZoneInfo(tz_name))
    # Use date + time with seconds to ensure uniqueness per run; avoid ':' in sheet title
    return dt.strftime("%Y-%m-%d_%H-%M-%S")


def format_duration(seconds: float) -> str:
    total_seconds = int(round(seconds))
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    secs = total_seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def extract_site_domain(url: str) -> Tuple[str, str]:
    """
    Returns (site_base_domain, host).
    site_base_domain is registrable domain like example.com
    host is hostname like moskva.example.com
    """
    parsed = tldextract.extract(url)
    registered_domain = f"{parsed.domain}.{parsed.suffix}" if parsed.suffix else parsed.domain
    host = url.split("//")[-1].split("/")[0]
    return registered_domain, host


# --------------- SSL Check ---------------
def check_ssl_valid(domain: str, timeout: int = 10) -> Tuple[bool, Optional[str]]:
    """Check SSL certificate validity for a domain on 443.
    Returns (is_valid, detail_message).
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return False, "SSL: сертификат не получен"
                not_after = cert.get("notAfter")
                if not_after:
                    # Example format: 'Jun 15 08:12:23 2026 GMT'
                    expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    if expiry_dt <= datetime.utcnow():
                        return False, f"SSL: сертификат истёк {expiry_dt} UTC"
                # If handshake succeeded and not expired, we consider valid
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, f"SSL: ошибка верификации сертификата: {e}"
    except Exception as e:
        return False, f"SSL: ошибка соединения: {e}"


# --------------- HTTP Request ---------------
def request_with_timing(url: str, timeout: int, verify_ssl: bool = True) -> Tuple[Optional[int], float, Optional[str]]:
    """
    Returns (status_code, response_ms, error_message)
    status_code is None on network/timeout error
    """
    start = time.perf_counter()
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify_ssl)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return resp.status_code, elapsed_ms, None
    except requests.Timeout:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return None, elapsed_ms, "timeout"
    except requests.RequestException as e:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return None, elapsed_ms, str(e)


# --------------- Google Sheets ---------------
def get_gspread_client(gsa_json_path: str) -> gspread.Client:
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ]
    creds = Credentials.from_service_account_file(gsa_json_path, scopes=scopes)
    return gspread.authorize(creds)


def ensure_worksheet(gc: gspread.Client, spreadsheet_id: str, title: str) -> gspread.Worksheet:
    sh = gc.open_by_key(spreadsheet_id)
    try:
        ws = sh.worksheet(title)
        return ws
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=title, rows=1, cols=20)
        header = [
            "timestamp",
            "site",
            "page",
            "http_status",
            "response_ms",
            "result",
            "notes"
        ]
        ws.append_row(header, value_input_option="RAW")
        return ws


def append_rows(ws: gspread.Worksheet, rows: List[List[str]]):
    if not rows:
        return
    ws.append_rows(rows, value_input_option="RAW")


# --------------- Telegram ---------------
def send_telegram_message(bot_token: str, chat_id: str, text: str):
    if not bot_token or not chat_id:
        logger.warning("Telegram not configured: BOT_TOKEN/CHAT_ID missing")
        return
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=10
        )
        if not resp.ok:
            logger.error("Telegram API error: status=%s body=%s", resp.status_code, resp.text)
    except Exception as e:
        logger.error("Failed to send Telegram message: %s", e)


# --------------- Core Logic ---------------
def read_url_list(file_path: str, url_column_name: str) -> List[str]:
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"URLS file not found: {file_path}")
    df = pd.read_excel(file_path)
    cols_lower = {c.lower(): c for c in df.columns}
    col = cols_lower.get(url_column_name.lower()) or cols_lower.get("url")
    if not col:
        # Fallback to first column
        col = df.columns[0]
    urls = [str(u).strip() for u in df[col].dropna().tolist() if str(u).strip()]
    return urls


def group_urls_by_site(urls: List[str]) -> Dict[str, List[str]]:
    groups: Dict[str, List[str]] = {}
    for u in urls:
        site, _ = extract_site_domain(u)
        if not site:
            continue
        groups.setdefault(site, []).append(u)
    return groups


def run_for_site(site: str, urls: List[str], cfg: dict, gc: Optional[gspread.Client], ws: Optional[gspread.Worksheet]):
    tz = cfg["timezone"]
    timestamp = now_local_str(tz)

    # SSL check
    ssl_valid = True
    ssl_detail = None
    if cfg["ssl_check_mode"] == "per_host":
        unique_hosts = {extract_site_domain(u)[1] for u in urls}
        for host in unique_hosts:
            ok, detail = check_ssl_valid(host)
            if not ok:
                ssl_valid, ssl_detail = False, detail
                break
    else:
        ok, detail = check_ssl_valid(site)
        if not ok:
            ssl_valid, ssl_detail = False, detail

    rows_to_append: List[List[str]] = []

    # If SSL invalid, alert but continue to perform HTTP checks; mark rows with note
    ssl_note: Optional[str] = None
    if not ssl_valid:
        logger.error("[%s] SSL invalid: %s", site, ssl_detail)
        if cfg["alerts_enabled"]:
            msg = (
                f"🚨 [ALERT] Проблема с SSL сертификатом 🔒\n"
                f"Сайт: {site}\n"
                f"Описание: {ssl_detail or 'сертификат недействителен'}\n"
                f"Время проверки: {timestamp}"
            )
            send_telegram_message(cfg["bot_token"], cfg["chat_id"], msg)
        ssl_note = ssl_detail or "сертификат недействителен"

    # HTTP checks
    results = []  # list of tuples (url, host, status, ms, err)
    for u in urls:
        # If SSL is invalid, bypass verification to still get HTTP status codes
        status, ms, err = request_with_timing(
            u,
            cfg["timeout_seconds"],
            verify_ssl=ssl_valid  # True normally, False if SSL invalid
        )
        _, host = extract_site_domain(u)
        results.append((u, host, status, ms, err))

    # Append to sheet
    for (_u, host, status, ms, err) in results:
        if status is None:
            res = "TIMEOUT" if (err == "timeout") else "NETWORK_ERROR"
            note = err or ""
            if ssl_note:
                note = (note + ("; " if note else "")) + f"SSL_INVALID: {ssl_note}"
            rows_to_append.append([
                timestamp, site, host, "", f"{ms:.0f}", res, note
            ])
        else:
            res = "OK" if (200 <= status < 400) else ("ERROR_404" if status == 404 else ("ERROR_5XX" if 500 <= status < 600 else "ERROR"))
            note = f"SSL_INVALID: {ssl_note}" if ssl_note else ""
            rows_to_append.append([
                timestamp, site, host, str(status), f"{ms:.0f}", res, note
            ])

    if ws:
        append_rows(ws, rows_to_append)

    # Alerts
    statuses = [s for (_u, _h, s, _ms, _e) in results]
    status_non_none = [s for s in statuses if s is not None]

    all_404 = bool(status_non_none) and all(s == 404 for s in status_non_none) and len(status_non_none) == len(results)
    all_5xx = bool(status_non_none) and all(500 <= s < 600 for s in status_non_none) and len(status_non_none) == len(results)
    count_404 = sum(1 for s in status_non_none if s == 404)
    count_5xx = sum(1 for s in status_non_none if 500 <= s < 600)

    # Immediate alerts per conditions
    if cfg["alerts_enabled"]:
        if all_404:
            msg = (
                f"🛑 [CRITICAL] Ошибка доступа ко всем страницам на лендинге\n"
                f"Сайт: {site}\n"
                f"Страниц с ошибкой 404: {count_404} из {len(results)}\n"
                f"Время проверки: {timestamp}"
            )
            send_telegram_message(cfg["bot_token"], cfg["chat_id"], msg)
        elif all_5xx:
            msg = (
                f"🛑 [CRITICAL] Сайт {site} недоступен\n"
                f"Страниц с ошибкой 5хх: {count_5xx} из {len(results)}\n"
                f"Время проверки: {timestamp}"
            )
            send_telegram_message(cfg["bot_token"], cfg["chat_id"], msg)
        else:
            for (_u, host, status, _ms, _e) in results:
                if status == 404:
                    text = (
                        f"⚠️ [ALERT] Ошибка доступа к страницам\n"
                        f"Сайт: {site}\n"
                        f"Страница: {host}\n"
                        f"Тип ошибки: 404\n"
                        f"Время проверки: {timestamp}"
                    )
                    send_telegram_message(cfg["bot_token"], cfg["chat_id"], text)
                elif status is not None and 500 <= status < 600:
                    text = (
                        f"🚨 [ALERT] Ошибка доступа к страницам\n"
                        f"Сайт: {site}\n"
                        f"Страница: {host}\n"
                        f"Тип ошибки: {status}\n"
                        f"Время проверки: {timestamp}"
                    )
                    send_telegram_message(cfg["bot_token"], cfg["chat_id"], text)

    num_ok = sum(1 for (_u, _h, status, _ms, _e) in results if status is not None and 200 <= status < 400)
    return {"num_pages": len(results), "num_ok": num_ok}


def main():
    cfg = load_config()

    if not cfg["urls_file"]:
        logger.error("URLS_FILE is not set in .env")
        return

    try:
        urls = read_url_list(cfg["urls_file"], cfg["url_column_name"])
    except Exception as e:
        logger.exception("Failed to read URL list: %s", e)
        return

    if not urls:
        logger.warning("No URLs to check")
        return

    groups = group_urls_by_site(urls)
    logger.info("Loaded %d URLs across %d sites", len(urls), len(groups))

    gc = None
    ws = None
    if cfg["spreadsheet_id"] and cfg["gsa_json"] and os.path.exists(cfg["gsa_json"]):
        try:
            gc = get_gspread_client(cfg["gsa_json"])
            sheet_title = (
                sheet_name_for_run(cfg["timezone"]) if cfg.get("sheet_mode") == "per_run"
                else sheet_name_for_today(cfg["timezone"])
            )
            ws = ensure_worksheet(gc, cfg["spreadsheet_id"], sheet_title)
        except Exception as e:
            logger.exception("Failed to init Google Sheets client: %s", e)
            gc = None
            ws = None
    else:
        logger.warning("Google Sheets not configured or credentials missing")

    total_pages = 0
    total_ok = 0
    run_start = time.perf_counter()
    for site, site_urls in groups.items():
        logger.info("Checking site: %s (%d pages)", site, len(site_urls))
        try:
            result = run_for_site(site, site_urls, cfg, gc, ws)
            if isinstance(result, dict):
                total_pages += int(result.get("num_pages", 0))
                total_ok += int(result.get("num_ok", 0))
        except Exception as e:
            logger.exception("Unexpected error while processing site %s: %s", site, e)

    # Success after whole run if no errors
    if cfg["alerts_enabled"] and cfg.get("success_alerts_enabled", True):
        if total_pages > 0 and total_ok == total_pages:
            run_timestamp = now_local_str(cfg["timezone"])
            duration = time.perf_counter() - run_start
            ok_msg = (
                f"✅ Проверка пройдена\n"
                f"Проверено ссылок: {total_pages}\n"
                f"Время проверки: {run_timestamp}\n"
                f"Длительность: {format_duration(duration)}"
            )
            send_telegram_message(cfg["bot_token"], cfg["chat_id"], ok_msg)


if __name__ == "__main__":
    main()
