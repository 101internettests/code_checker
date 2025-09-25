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
import json
from pathlib import Path

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
        "success_alerts_enabled": os.getenv("SUCCESS_ALERTS_ENABLED", "true").lower() in {"1", "true", "yes"},
        # путь до stats.json (если задан, пишем сводку)
        "stats_file": os.getenv("STATS_FILE", "").strip(),
        # путь для хранения состояния алертов между прогонами
        "alert_state_file": os.getenv("ALERT_STATE_FILE", "").strip()
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


# --------------- Alert State (persistent) ---------------
def _state_key(site: str, page: Optional[str], error_type: str) -> str:
    # error_type: ssl_site | http_5xx | http_404 | timeout
    page_part = page or ""
    return f"{site}||{page_part}||{error_type}"


def load_alert_state(path: str) -> Dict[str, dict]:
    if not path:
        return {}
    try:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.error("Failed to load alert state %s: %s", path, e)
        return {}


def save_alert_state(path: str, state: Dict[str, dict]):
    if not path:
        return
    try:
        p = Path(path)
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error("Failed to save alert state %s: %s", path, e)


def should_notify(consecutive_runs: int, last_step: int) -> Tuple[bool, Optional[int]]:
    # Notify on thresholds 1,4,12,50
    thresholds = [1, 4, 12, 50]
    for t in thresholds:
        if consecutive_runs == t and last_step < t:
            return True, t
    return False, None


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
        # Ensure header has response_time column in the desired position
        try:
            desired_header = [
                "timestamp",
                "site",
                "http_full",
                "http_status",
                "response_ms",
                "response_time",
                "result",
                "notes"
            ]
            current = ws.row_values(1)
            current_norm = [c.strip() for c in current]
            if current_norm[:len(desired_header)] != desired_header:
                ws.update('A1:H1', [desired_header])
        except Exception:
            pass
        return ws
    except gspread.WorksheetNotFound:
        ws = sh.add_worksheet(title=title, rows=1, cols=20)
        header = [
            "timestamp",
            "site",
            "http_full",
            "http_status",
            "response_ms",
            "response_time",
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
    state = load_alert_state(cfg.get("alert_state_file", ""))

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
    errors_404: List[str] = []
    errors_5xx: List[Tuple[str, int]] = []
    errors_timeout: List[str] = []
    errors_network: List[str] = []
    errors_other: List[Tuple[str, int]] = []

    # If SSL invalid, alert but continue to perform HTTP checks; mark rows with note
    ssl_note: Optional[str] = None
    ssl_invalid_flag = False
    if not ssl_valid:
        logger.error("[%s] SSL invalid: %s", site, ssl_detail)
        ssl_note = ssl_detail or "сертификат недействителен"
        ssl_invalid_flag = True
        # Запишем отдельную строку о проблеме SSL в хранилище (Google Sheets)
        # чтобы было видно SSL-ошибки, а не только HTTP-коды
        rows_to_append.append([
            timestamp,  # timestamp
            site,       # site
            site,       # http_full (для SSL-ошибки фиксируем базовый домен)
            "",         # http_status
            "",         # response_ms
            "",         # response_time (sec)
            "SERT_INVALID",  # result
            ssl_note or ""
        ])

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

    # Append to sheet (only errors) and collect aggregation
    for (_u, host, status, ms, err) in results:
        if status is None:
            res = "TIMEOUT" if (err == "timeout") else "NETWORK_ERROR"
            note = err or ""
            if ssl_note:
                note = (note + ("; " if note else "")) + f"SERT_INVALID: {ssl_note}"
            rows_to_append.append([
                timestamp, site, _u, "", f"{ms:.0f}", f"{ms/1000.0:.3f}", res, note
            ])
            if err == "timeout":
                errors_timeout.append(_u)
            else:
                errors_network.append(_u)
        else:
            is_ok = 200 <= status < 400
            res = "OK" if is_ok else ("ERROR_404" if status == 404 else ("ERROR_5XX" if 500 <= status < 600 else "ERROR"))
            if not is_ok:
                note = f"SERT_INVALID: {ssl_note}" if ssl_note else ""
                rows_to_append.append([
                    timestamp, site, _u, str(status), f"{ms:.0f}", f"{ms/1000.0:.3f}", res, note
                ])
                if status == 404:
                    errors_404.append(_u)
                elif 500 <= status < 600:
                    errors_5xx.append((_u, status))
                else:
                    errors_other.append((_u, status))

    if ws:
        append_rows(ws, rows_to_append)

    # ---------- Alerts & state logic (per URL) ----------
    if cfg["alerts_enabled"]:
        # SSL site-level
        if ssl_invalid_flag:
            key = _state_key(site, None, "ssl_site")
            st = state.get(key, {"active": False, "consecutive_runs": 0, "first_seen": timestamp, "last_notified_step": 0})
            st["consecutive_runs"] = int(st.get("consecutive_runs", 0)) + 1
            st["active"] = True
            notify, step = should_notify(st["consecutive_runs"], int(st.get("last_notified_step", 0)))
            if notify:
                parts = [
                    "❌ [ALERT] Ошибка SSL сертификата",
                    f"Сайт: {site}",
                    f"Время проверки: {timestamp}"
                ]
                if step in (4, 12, 50):
                    parts.append(f"Повторный прогон ошибки: {step} (ошибка все еще актуальна)")
                    if step in (12, 50):
                        parts.insert(2, f"Время первой фиксации ошибки: {st.get('first_seen', timestamp)}")
                        parts.insert(3, f"Сколько прогонов подряд падает: {step}")
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
                st["last_notified_step"] = step
            state[key] = st
        else:
            # SSL recovered
            key = _state_key(site, None, "ssl_site")
            st = state.get(key)
            if st and st.get("active"):
                parts = [
                    "✅ [ALERT] Проблема с SSL сертификатом восстановлена🔒",
                    f"Сайт: {site}",
                    f"Время проверки: {timestamp}"
                ]
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
                st["active"] = False
                st["consecutive_runs"] = 0
                st["last_notified_step"] = 0
                state[key] = st

        # Build per-URL error sets
        pages_5xx = [(u, code) for (u, code) in errors_5xx]
        pages_404 = [u for u in errors_404]
        pages_timeout = [u for u in errors_timeout]

        # ---------- Recovery detection before updating state ----------
        current_5xx_set = {u for (u, _c) in pages_5xx}
        current_404_set = set(pages_404)
        current_timeout_set = set(pages_timeout)

        prev_active_5xx = set()
        prev_active_404 = set()
        prev_active_timeout = set()
        for k, st_old in list(state.items()):
            try:
                site_k, page_k, et_k = k.split("||", 2)
            except ValueError:
                continue
            if site_k != site or not st_old or not st_old.get("active"):
                continue
            if et_k == "http_5xx":
                prev_active_5xx.add(page_k)
            elif et_k == "http_404":
                prev_active_404.add(page_k)
            elif et_k == "timeout":
                prev_active_timeout.add(page_k)

        recovered_5xx = sorted(list(prev_active_5xx - current_5xx_set)) if prev_active_5xx else []
        recovered_404 = sorted(list(prev_active_404 - current_404_set)) if prev_active_404 else []
        recovered_timeout = sorted(list(prev_active_timeout - current_timeout_set)) if prev_active_timeout else []

        # Send recovery alerts per spec and clear state entries
        # 5xx recoveries
        if recovered_5xx:
            if len(prev_active_5xx) == len(urls) and len(recovered_5xx) == len(urls):
                parts = [
                    "✅ [ALERT] Лендинг снова доступен",
                    f"Все страницы сайта {site} вернули код 200",
                    f"Время проверки: {timestamp}"
                ]
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            elif len(recovered_5xx) > 5:
                parts = [
                    "✅ [ALERT] Страницы снова доступны",
                    f"Сайт: {site}",
                    f"{len(recovered_5xx)} страниц сайта вернули код 200",
                    f"Время проверки: {timestamp}"
                ]
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            else:
                for url_ok in recovered_5xx:
                    _s, host_ok = extract_site_domain(url_ok)
                    parts = [
                        "✅ [ALERT] Страница снова доступна",
                        f"Сайт: {site}",
                        f"Страница: {host_ok}",
                        "Код: 200",
                        f"Время проверки: {timestamp}"
                    ]
                    send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            # clear state
            for url_ok in recovered_5xx:
                key_del = _state_key(site, url_ok, "http_5xx")
                if key_del in state:
                    del state[key_del]

        # 404 recoveries
        if recovered_404:
            if len(prev_active_404) == len(urls) and len(recovered_404) == len(urls):
                parts = [
                    "✅ [ALERT] Лендинг снова доступен",
                    f"Все страницы сайта {site} вернули код 200",
                    f"Время проверки: {timestamp}"
                ]
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            elif len(recovered_404) > 5:
                parts = [
                    "✅ [ALERT] Страницы снова доступны",
                    f"Сайт: {site}",
                    f"{len(recovered_404)} страниц сайта вернули код 200",
                    f"Время проверки: {timestamp}"
                ]
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            else:
                for url_ok in recovered_404:
                    _s, host_ok = extract_site_domain(url_ok)
                    parts = [
                        "✅ [ALERT] Страница снова доступна",
                        f"Сайт: {site}",
                        f"Страница: {host_ok}",
                        "Код: 200",
                        f"Время проверки: {timestamp}"
                    ]
                    send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            # clear state
            for url_ok in recovered_404:
                key_del = _state_key(site, url_ok, "http_404")
                if key_del in state:
                    del state[key_del]

        # Timeout recoveries (grouped list)
        if recovered_timeout:
            parts = [
                f"✅ [ALERT] Ожидание ответа страниц на сайте {site} вернулось к нормальным значениям",
                "",
                f"Страницы ({len(recovered_timeout)}):"
            ]
            for url_ok in recovered_timeout:
                parts.append(f"- {url_ok}")
            parts.append("")
            parts.append(f"Время проверки: {timestamp}")
            send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            for url_ok in recovered_timeout:
                key_del = _state_key(site, url_ok, "timeout")
                if key_del in state:
                    del state[key_del]

        # Helper to update page state (without immediate send). We accumulate pages that hit threshold this run.
        triggered_5xx: List[Tuple[str, str, int, str]] = []  # (url, code_label, step, first_seen)
        triggered_404: List[Tuple[str, int, str]] = []  # (url, step, first_seen)
        triggered_timeout: List[Tuple[str, int, str]] = []  # (url, step, first_seen)

        def update_page_error(url: str, error_type: str, code_label: Optional[str] = None):
            k = _state_key(site, url, error_type)
            stp = state.get(k, {"active": False, "consecutive_runs": 0, "first_seen": timestamp, "last_notified_step": 0})
            stp["consecutive_runs"] = int(stp.get("consecutive_runs", 0)) + 1
            stp["active"] = True
            stp["last_status_code"] = code_label
            notify, step = should_notify(stp["consecutive_runs"], int(stp.get("last_notified_step", 0)))
            if notify:
                if error_type == "http_5xx":
                    triggered_5xx.append((url, code_label or "5xx", step, stp.get('first_seen', timestamp)))
                elif error_type == "http_404":
                    triggered_404.append((url, step, stp.get('first_seen', timestamp)))
                elif error_type == "timeout":
                    triggered_timeout.append((url, step, stp.get('first_seen', timestamp)))
                stp["last_notified_step"] = step
            state[k] = stp

        # Update per-page errors (per-URL accounting)
        for u, code in pages_5xx:
            update_page_error(u, "http_5xx", code_label=str(code))
        for u in pages_404:
            update_page_error(u, "http_404")
        for u in pages_timeout:
            update_page_error(u, "timeout")

        # Group-level summaries when count > 5 or all pages affected (built on per-URL states)
        num_5xx = len(pages_5xx)
        num_404 = len(pages_404)
        total_site_pages = len(urls)
        all_5xx = (num_5xx == total_site_pages and total_site_pages > 0)
        all_404 = (num_404 == total_site_pages and total_site_pages > 0)

        # Trigger group messages only if any page just hit a threshold this run
        def any_page_hit_threshold(pages: List[str], error_type: str) -> bool:
            for url in pages:
                k = _state_key(site, url, error_type)
                stl = state.get(k)
                if not stl:
                    continue
                last_step = int(stl.get("last_notified_step", 0))
                consec = int(stl.get("consecutive_runs", 0))
                want, _ = should_notify(consec, last_step)
                if want:
                    return True
            return False

        # 5xx group messages
        if num_5xx > 5 or all_5xx:
            if triggered_5xx:
                if all_5xx:
                    parts = [
                        f"[CRITICAL] Сайт {site} недоступен",
                        "Все страницы вернули ошибку 5хх",
                        f"Время проверки: {timestamp}"
                    ]
                else:
                    parts = [
                        "❌ [ALERT] Ошибка доступа к страницам",
                        f"Сайт: {site}",
                        f"{num_5xx} страниц сайта вернули ошибку 5хх",
                        f"Время проверки: {timestamp}"
                    ]
                rep_steps = [s for (_u, _c, s, _fs) in triggered_5xx if s in (4, 12, 50)]
                if rep_steps:
                    stepv = rep_steps[0]
                    parts.append(f"Повторный прогон ошибки: {stepv} (ошибка все еще актуальна)")
                    if stepv in (12, 50):
                        firsts = [fs for (_u, _c, s, fs) in triggered_5xx if s == stepv and fs]
                        first_seen_val = firsts[0] if firsts else timestamp
                        parts.insert(2, f"Время первой фиксации ошибки: {first_seen_val}")
                        parts.insert(3, f"Сколько прогонов подряд падает: {stepv}")
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
        elif 0 < num_5xx <= 5:
            if triggered_5xx:
                # Send one message per page as per spec
                for (url, code_label, step, first_seen_val) in triggered_5xx:
                    _site, host = extract_site_domain(url)
                    parts = [
                        "❌ [ALERT] Ошибка доступа к страницам",
                        f"Сайт: {site}",
                        f"Страница: {host}",
                        f"Тип ошибки: {code_label}",
                        f"Время проверки: {timestamp}"
                    ]
                    if step in (4, 12, 50):
                        parts.append(f"Повторный прогон ошибки: {step} (ошибка все еще актуальна)")
                        if step in (12, 50):
                            parts.insert(2, f"Время первой фиксации ошибки: {first_seen_val}")
                            parts.insert(3, f"Сколько прогонов подряд падает: {step}")
                    send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))

        # 404 group messages
        if num_404 > 5 or all_404:
            if triggered_404:
                if all_404:
                    parts = [
                        "[CRITICAL] Ошибка доступа ко всем страницам на лендинге",
                        f"Все страницы сайта {site} вернули ошибку 404",
                        f"Время проверки: {timestamp}"
                    ]
                else:
                    parts = [
                        "❌ [ALERT] Ошибка доступа к страницам",
                        f"Сайт: {site}",
                        f"{num_404} страниц сайта вернули ошибку 404",
                        f"Время проверки: {timestamp}"
                    ]
                rep_steps = [s for (_u, s, _fs) in triggered_404 if s in (4, 12, 50)]
                if rep_steps:
                    stepv = rep_steps[0]
                    parts.append(f"Повторный прогон ошибки: {stepv} (ошибка все еще актуальна)")
                    if stepv in (12, 50):
                        firsts = [fs for (_u, s, fs) in triggered_404 if s == stepv and fs]
                        first_seen_val = firsts[0] if firsts else timestamp
                        parts.insert(2, f"Время первой фиксации ошибки: {first_seen_val}")
                        parts.insert(3, f"Сколько прогонов подряд падает: {stepv}")
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
        elif 0 < num_404 <= 5:
            if triggered_404:
                for (url, step, first_seen_val) in triggered_404:
                    _site, host = extract_site_domain(url)
                    parts = [
                        "❌ [ALERT] Ошибка доступа к страницам",
                        f"Сайт: {site}",
                        f"Страница: {host}",
                        "Тип ошибки: 404",
                        f"Время проверки: {timestamp}"
                    ]
                    if step in (4, 12, 50):
                        parts.append(f"Повторный прогон ошибки: {step} (ошибка все еще актуальна)")
                        if step in (12, 50):
                            parts.insert(2, f"Время первой фиксации ошибки: {first_seen_val}")
                            parts.insert(3, f"Сколько прогонов подряд падает: {step}")
                    send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))

        # Timeouts grouped
        if triggered_timeout:
            parts = [
                f"❌ [ALERT] Ошибки на сайте {site}",
                "",
                f"Таймауты ({len(triggered_timeout)}):"
            ]
            for (url, _step, _fs) in triggered_timeout:
                parts.append(f"- {url}")
            rep_steps = [s for (_u, s, _fs) in triggered_timeout if s in (4, 12, 50)]
            if rep_steps:
                stepv = rep_steps[0]
                parts.append("")
                parts.append(f"Повторный прогон ошибки: {stepv} (ошибка все еще актуальна)")
                if stepv in (12, 50):
                    firsts = [fs for (_u, s, fs) in triggered_timeout if s == stepv and fs]
                    first_seen_val = firsts[0] if firsts else timestamp
                    parts.insert(2, f"Время первой фиксации ошибки: {first_seen_val}")
                    parts.insert(3, f"Сколько прогонов подряд падает: {stepv}")
            parts.append("")
            parts.append(f"Время проверки: {timestamp}")
            send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))

    # Save alert state (after all updates and notifications)
    save_alert_state(cfg.get("alert_state_file", ""), state)

    num_ok = sum(1 for (_u, _h, status, _ms, _e) in results if status is not None and 200 <= status < 400)
    # неуспехи учитываем только для 404 и 5xx (как по условиям алертов)
    num_failed = sum(1 for (_u, _h, status, _ms, _e) in results if (status == 404) or (status is not None and 500 <= status < 600))
    return {"num_pages": len(results), "num_ok": num_ok, "num_failed": num_failed, "ssl_invalid": ssl_invalid_flag}


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
    # Ensure alert state file exists or create empty
    if cfg.get("alert_state_file"):
        st_path = Path(cfg["alert_state_file"]).expanduser()
        if st_path.parent and not st_path.parent.exists():
            st_path.parent.mkdir(parents=True, exist_ok=True)
        if not st_path.exists():
            save_alert_state(str(st_path), {})
    logger.info("Loaded %d URLs across %d sites", len(urls), len(groups))

    gc = None
    ws = None
    if cfg["spreadsheet_id"] and cfg["gsa_json"] and os.path.exists(cfg["gsa_json"]):
        try:
            gc = get_gspread_client(cfg["gsa_json"])
            sheet_title = "Лист 1"
            ws = ensure_worksheet(gc, cfg["spreadsheet_id"], sheet_title)
        except Exception as e:
            logger.exception("Failed to init Google Sheets client: %s", e)
            gc = None
            ws = None
    else:
        logger.warning("Google Sheets not configured or credentials missing")

    total_pages = 0
    total_ok = 0
    total_failed_pages = 0
    ssl_issues_sites = 0
    run_start = time.perf_counter()
    for site, site_urls in groups.items():
        logger.info("Checking site: %s (%d pages)", site, len(site_urls))
        try:
            result = run_for_site(site, site_urls, cfg, gc, ws)
            if isinstance(result, dict):
                total_pages += int(result.get("num_pages", 0))
                total_ok += int(result.get("num_ok", 0))
                total_failed_pages += int(result.get("num_failed", 0))
                ssl_issues_sites += 1 if result.get("ssl_invalid") else 0
        except Exception as e:
            logger.exception("Unexpected error while processing site %s: %s", site, e)

    # Success after whole run if no errors (controlled only by SUCCESS_ALERTS_ENABLED)
    if cfg.get("success_alerts_enabled", True):
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

    # Write stats.json if configured (aggregate per day, do not overwrite)
    if cfg.get("stats_file"):
        run_timestamp = now_local_str(cfg["timezone"])
        # A run is successful if there were NO SSL issues and NO 404/5xx across all pages
        success_run = 1 if (int(ssl_issues_sites) == 0 and int(total_failed_pages) == 0) else 0
        failure_run = 1 - success_run
        run_date = datetime.now(ZoneInfo(cfg["timezone"]))\
            .strftime("%Y-%m-%d")
        try:
            stats_path = Path(cfg["stats_file"])
            if stats_path.parent and not stats_path.parent.exists():
                stats_path.parent.mkdir(parents=True, exist_ok=True)
            # Load existing stats (aggregate per date)
            if stats_path.exists():
                try:
                    with open(stats_path, "r", encoding="utf-8") as f:
                        stats_obj = json.load(f)
                except Exception:
                    stats_obj = {}
            else:
                stats_obj = {}

            if not isinstance(stats_obj, dict):
                stats_obj = {}

            entry = stats_obj.get(run_date, {}) if isinstance(stats_obj.get(run_date, {}), dict) else {}
            # Aggregate runs per day
            entry_success = int(entry.get("success", 0)) + success_run
            entry_failure = int(entry.get("failure", 0)) + failure_run
            entry_total_pages = int(entry.get("total_pages", 0)) + int(total_pages)
            entry_failed_pages = int(entry.get("failed_pages", 0)) + int(total_failed_pages)
            entry_ssl_issues_sites = int(entry.get("ssl_issues_sites", 0)) + int(ssl_issues_sites)
            entry_runs = int(entry.get("runs", 0)) + 1

            entry.update({
                "summary": f"Сводка: успешно {entry_success}, неуспешно {entry_failure}",
                "success": entry_success,
                "failure": entry_failure,
                "total_pages": entry_total_pages,
                "failed_pages": entry_failed_pages,
                "ssl_issues_sites": entry_ssl_issues_sites,
                "runs": entry_runs,
                "last_timestamp": run_timestamp
            })

            stats_obj[run_date] = entry

            with open(stats_path, "w", encoding="utf-8") as f:
                json.dump(stats_obj, f, ensure_ascii=False, indent=2)
            logger.info("Stats updated for %s in %s: %s", run_date, stats_path, entry["summary"])
        except Exception as e:
            logger.error("Failed to write stats file %s: %s", cfg["stats_file"], e)


if __name__ == "__main__":
    main()
