import os
import random
import ssl
import socket
import time
import html
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
DEFAULT_TIMEOUT_SECONDS = 20
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
_PROXY_MISSING_ENV_LOGGED = False


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
        "use_telegram_proxy": os.getenv("USE_TELEGRAM_PROXY", "false").lower() in {"1", "true", "yes"},
        "telegram_proxy_url": os.getenv("TELEGRAM_PROXY_URL", "").strip(),
        "telegram_proxy_auth_secret": os.getenv("TELEGRAM_PROXY_AUTH_SECRET", "").strip(),
        "telegram_proxy_creds": os.getenv("TELEGRAM_PROXY_CREDS", "").strip(),
        "telegram_proxy_timeout_sec": os.getenv("TELEGRAM_PROXY_TIMEOUT_SEC", "15").strip(),
        "alerts_enabled": os.getenv("ALERTS_ENABLED", "true").lower() in {"1", "true", "yes"},
        "timezone": os.getenv("TZ", DEFAULT_TZ),
        # daily: один лист на дату; per_run: новый лист на каждый запуск (по умолчанию)
        "sheet_mode": os.getenv("SHEET_MODE", "per_run").strip().lower(),
        # отправлять ли сообщение об успешной проверке
        "success_alerts_enabled": os.getenv("SUCCESS_ALERTS_ENABLED", "true").lower() in {"1", "true", "yes"},
        # путь до stats.json (если задан, пишем сводку)
        "stats_file": os.getenv("STATS_FILE", "").strip(),
        # путь для хранения состояния алертов между прогонами
        "alert_state_file": os.getenv("ALERT_STATE_FILE", "").strip(),
        # Proxy settings: enable and provide comma/semicolon/newline-separated list of full proxy URLs
        # Example item: http://USER:PASS@185.126.86.225:8000
        "proxies_enabled": os.getenv("PROXIES_ENABLED", "false").lower() in {"1", "true", "yes"},
        "proxy_urls_raw": os.getenv("PROXY_URLS", ""),
        # Percentage (0..100) of requests to send directly (without proxy) when proxies are enabled
        "proxy_direct_percent": os.getenv("PROXY_DIRECT_PERCENT", "0"),
        # Content validation: treat 200 responses as errors if body contains any of these substrings
        # Example: "Fatal error;Uncaught Exception"
        "content_error_substrings_raw": os.getenv("CONTENT_ERROR_SUBSTRINGS", "Fatal error")
    }

    # Normalize proxy URLs list
    raw_list = config.get("proxy_urls_raw", "")
    if raw_list:
        # split by common separators and strip blanks
        parts = []
        for sep in ["\n", ";", ",", " "]:
            if sep in raw_list:
                raw_list = raw_list.replace(sep, "\n")
        parts = [p.strip() for p in raw_list.split("\n") if p.strip()]
    else:
        parts = []
    config["proxy_urls"] = parts

    # Normalize direct percent
    try:
        direct_percent = int(str(config.get("proxy_direct_percent", "0")).strip())
    except Exception:
        direct_percent = 0
    if direct_percent < 0:
        direct_percent = 0
    if direct_percent > 100:
        direct_percent = 100
    config["proxy_direct_percent"] = direct_percent

    # Parse content error substrings list
    raw_content = str(config.get("content_error_substrings_raw", "")).strip()
    if raw_content:
        tmp = raw_content
        for sep in ["\n", ";", ","]:
            if sep in tmp:
                tmp = tmp.replace(sep, "\n")
        content_list = [p.strip() for p in tmp.split("\n") if p.strip()]
    else:
        content_list = []
    config["content_error_substrings"] = content_list

    missing = []
    for key in ["urls_file", "spreadsheet_id", "gsa_json"]:
        if not config[key]:
            missing.append(key)
    if missing:
        logger.warning("Missing required envs for Google Sheets or URL list: %s", ", ".join(missing))

    # Helpful log to verify which chat id is used in CI
    try:
        config["telegram_proxy_timeout_sec"] = float(config.get("telegram_proxy_timeout_sec", "15"))
    except Exception:
        config["telegram_proxy_timeout_sec"] = 15.0

    try:
        logger.info(
            "Config: ALERTS_ENABLED=%s SUCCESS_ALERTS_ENABLED=%s SHEET_MODE=%s CHAT_ID=%s USE_TELEGRAM_PROXY=%s",
            config["alerts_enabled"],
            config.get("success_alerts_enabled", True),
            config.get("sheet_mode"),
            config.get("chat_id"),
            config.get("use_telegram_proxy", False),
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


def _select_random_proxy(proxy_urls: List[str]) -> Optional[Dict[str, str]]:
    if not proxy_urls:
        return None
    proxy_url = random.choice(proxy_urls)
    # Provide same proxy for http and https schemes
    return {"http": proxy_url, "https": proxy_url}


def _proxy_label(proxy_url: str) -> str:
    try:
        # Hide credentials; show only host:port
        hostport = proxy_url.split("@")[ -1 ]
        return hostport
    except Exception:
        return "proxy"


def _should_use_direct(direct_percent: int) -> bool:
    if direct_percent <= 0:
        return False
    if direct_percent >= 100:
        return True
    return (random.random() * 100.0) < float(direct_percent)


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
def check_ssl_valid(domain: str, timeout: int = 30) -> Tuple[bool, Optional[str]]:
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
def request_with_timing(url: str, timeout: int, verify_ssl: bool = True, proxies: Optional[Dict[str, str]] = None) -> Tuple[Optional[int], float, Optional[str], Optional[str]]:
    """
    Returns (status_code, response_ms, error_message, text_snippet)
    status_code is None on network/timeout error
    """
    start = time.perf_counter()
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify_ssl, proxies=proxies)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        # Limit response text to avoid huge memory usage
        text_snippet: Optional[str]
        try:
            text_snippet = resp.text[:8192]
        except Exception:
            text_snippet = None
        return resp.status_code, elapsed_ms, None, text_snippet
    except requests.Timeout:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return None, elapsed_ms, "timeout", None
    except requests.RequestException as e:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return None, elapsed_ms, str(e), None


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
def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def send_telegram_message(
    bot_token: str,
    chat_id: str,
    text: str,
    *,
    use_telegram_proxy: Optional[bool] = None,
    telegram_proxy_url: Optional[str] = None,
    telegram_proxy_auth_secret: Optional[str] = None,
    telegram_proxy_creds: Optional[str] = None,
    telegram_proxy_timeout_sec: Optional[float] = None,
):
    global _PROXY_MISSING_ENV_LOGGED

    use_proxy = _env_bool("USE_TELEGRAM_PROXY", False) if use_telegram_proxy is None else bool(use_telegram_proxy)
    if telegram_proxy_timeout_sec is None:
        try:
            timeout = float(os.getenv("TELEGRAM_PROXY_TIMEOUT_SEC", "15"))
        except Exception:
            timeout = 15.0
    else:
        timeout = float(telegram_proxy_timeout_sec)

    if use_proxy:
        proxy_url = (telegram_proxy_url or os.getenv("TELEGRAM_PROXY_URL") or "").strip()
        auth_secret = (telegram_proxy_auth_secret or os.getenv("TELEGRAM_PROXY_AUTH_SECRET") or "").strip()
        creds = (telegram_proxy_creds or os.getenv("TELEGRAM_PROXY_CREDS") or "").strip()

        missing = []
        if not proxy_url:
            missing.append("TELEGRAM_PROXY_URL")
        if not auth_secret:
            missing.append("TELEGRAM_PROXY_AUTH_SECRET")
        if not creds:
            missing.append("TELEGRAM_PROXY_CREDS")

        if missing:
            if not _PROXY_MISSING_ENV_LOGGED:
                logger.error("Telegram proxy missing required env vars: %s", ", ".join(missing))
                _PROXY_MISSING_ENV_LOGGED = True
            return

        try:
            resp = requests.post(
                proxy_url,
                headers={
                    "Content-Type": "application/json",
                    "X-Authentication": auth_secret,
                },
                json={
                    "title": html.escape("Runtime alert"),
                    "text": html.escape(text),
                    "creds": creds,
                    "parse_mode": "HTML",
                    "disable_notification": False,
                },
                timeout=timeout,
            )
            if not resp.ok:
                logger.error("Telegram proxy error: status=%s body=%s", resp.status_code, (resp.text or "")[:180])
            return
        except requests.Timeout:
            logger.error("Telegram proxy timeout after %ss", timeout)
            return
        except requests.RequestException as e:
            logger.error("Telegram proxy transport error: %s", e)
            return
        except Exception as e:
            logger.error("Telegram proxy unexpected error: %s", e)
            return

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
    content_error_substrings = [s.lower() for s in cfg.get("content_error_substrings", [])]

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
        # Base mode: try apex and www-variant; consider valid if any passes
        domains_to_try = [site]
        if site.startswith("www."):
            apex = site[4:]
            if apex:
                domains_to_try.append(apex)
        else:
            domains_to_try.append(f"www.{site}")

        check_results: List[Tuple[str, bool, Optional[str]]] = []
        ssl_valid = False
        for dom in domains_to_try:
            ok, detail = check_ssl_valid(dom)
            check_results.append((dom, ok, detail))
            if ok:
                ssl_valid = True
                break
        if not ssl_valid:
            # Aggregate details for both attempts to aid troubleshooting
            details_joined = "; ".join([
                f"{d}: {det or 'unknown error'}" for (d, ok, det) in check_results if not ok
            ])
            ssl_detail = details_joined or "SSL: сертификат недействителен"

    rows_to_append: List[List[str]] = []
    errors_404: List[str] = []
    errors_5xx: List[Tuple[str, int]] = []
    errors_timeout: List[str] = []
    errors_network: List[str] = []
    errors_other: List[Tuple[str, int]] = []
    errors_content: List[Tuple[str, str]] = []  # (url, content_note)

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
    results = []  # list of tuples (url, host, status, ms, err, content_error, content_note)
    for u in urls:
        # If SSL is invalid, bypass verification to still get HTTP status codes
        proxies = None
        if cfg.get("proxies_enabled") and cfg.get("proxy_urls"):
            if _should_use_direct(int(cfg.get("proxy_direct_percent", 0))):
                logger.info("Using direct connection for %s", u)
            else:
                proxies = _select_random_proxy(cfg["proxy_urls"]) or None
                if proxies and isinstance(proxies, dict) and proxies.get("http"):
                    try:
                        label = _proxy_label(proxies.get("http", ""))
                        logger.info("Using proxy %s for %s", label, u)
                    except Exception:
                        pass

        status, ms, err, body_text = request_with_timing(
            u,
            cfg["timeout_seconds"],
            verify_ssl=ssl_valid,  # True normally, False if SSL invalid
            proxies=proxies
        )

        # If got an error (timeout, network, or non-2xx/3xx), confirm via proxy from PROXY_URLS
        def _is_ok(sc: Optional[int]) -> bool:
            return sc is not None and 200 <= sc < 400

        if not _is_ok(status) and cfg.get("proxy_urls"):
            confirm_proxies = _select_random_proxy(cfg["proxy_urls"]) or None
            if confirm_proxies and isinstance(confirm_proxies, dict) and confirm_proxies.get("http"):
                try:
                    label2 = _proxy_label(confirm_proxies.get("http", ""))
                    logger.info("Confirm via proxy %s for %s", label2, u)
                except Exception:
                    pass
            c_status, c_ms, c_err, c_body_text = request_with_timing(
                u,
                cfg["timeout_seconds"],
                verify_ssl=ssl_valid,
                proxies=confirm_proxies
            )
            if _is_ok(c_status):
                # Suppress error – treat as success
                status, ms, err, body_text = c_status, c_ms, c_err, c_body_text
                logger.info("Suppressed error after confirm via proxy for %s", u)
            else:
                # Error confirmed – keep confirmed result
                status, ms, err, body_text = c_status, c_ms, c_err, c_body_text
                logger.info("Error confirmed after confirm via proxy for %s", u)

        _, host = extract_site_domain(u)
        # Content validation for successful statuses
        content_error = False
        content_note = None
        if status is not None and 200 <= status < 400 and body_text and content_error_substrings:
            bt_lower = body_text.lower()
            matched = [s for s in content_error_substrings if s in bt_lower]
            if matched:
                content_error = True
                if len(matched) == 1:
                    content_note = f"CONTENT_ERROR: contains '{matched[0]}'"
                else:
                    content_note = f"CONTENT_ERROR: contains {', '.join([repr(m) for m in matched])}"
        results.append((u, host, status, ms, err, content_error, content_note or ""))

    # Append to sheet (only errors) and collect aggregation
    for (_u, host, status, ms, err, content_error, content_note) in results:
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
            is_ok = (200 <= status < 400) and (not content_error)
            if not is_ok and content_error and (200 <= status < 400):
                res = "ERROR_CONTENT"
            else:
                res = "OK" if is_ok else ("ERROR_404" if status == 404 else ("ERROR_5XX" if 500 <= status < 600 else "ERROR"))
            if not is_ok:
                note_parts = []
                if ssl_note:
                    note_parts.append(f"SERT_INVALID: {ssl_note}")
                if content_error and content_note:
                    note_parts.append(content_note)
                note = "; ".join(note_parts)
                rows_to_append.append([
                    timestamp, site, _u, str(status), f"{ms:.0f}", f"{ms/1000.0:.3f}", res, note
                ])
                if status == 404:
                    errors_404.append(_u)
                elif 500 <= status < 600:
                    errors_5xx.append((_u, status))
                else:
                    if content_error:
                        errors_content.append((_u, content_note or "CONTENT_ERROR"))
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
        pages_content = [(u, note) for (u, note) in errors_content]

        # ---------- Recovery detection before updating state ----------
        current_5xx_set = {u for (u, _c) in pages_5xx}
        current_404_set = set(pages_404)
        current_timeout_set = set(pages_timeout)

        prev_active_5xx = set()
        prev_active_404 = set()
        prev_active_timeout = set()
        prev_active_content = set()
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
            elif et_k == "content_error":
                prev_active_content.add(page_k)

        recovered_5xx = sorted(list(prev_active_5xx - current_5xx_set)) if prev_active_5xx else []
        recovered_404 = sorted(list(prev_active_404 - current_404_set)) if prev_active_404 else []
        recovered_timeout = sorted(list(prev_active_timeout - current_timeout_set)) if prev_active_timeout else []
        current_content_set = {u for (u, _n) in pages_content}
        recovered_content = sorted(list(prev_active_content - current_content_set)) if prev_active_content else []

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

        # Content error recoveries
        if recovered_content:
            if len(prev_active_content) > 5 and len(recovered_content) > 5:
                parts = [
                    "✅ [ALERT] Проблемы контента устранены",
                    f"Сайт: {site}",
                    f"{len(recovered_content)} страниц больше не содержат запрещённый текст",
                    f"Время проверки: {timestamp}"
                ]
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            else:
                for url_ok in recovered_content:
                    _s, host_ok = extract_site_domain(url_ok)
                    parts = [
                        "✅ [ALERT] Проблема контента устранена",
                        f"Сайт: {site}",
                        f"Страница: {host_ok}",
                        f"Время проверки: {timestamp}"
                    ]
                    send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
            for url_ok in recovered_content:
                key_del = _state_key(site, url_ok, "content_error")
                if key_del in state:
                    del state[key_del]

        # Helper to update page state (without immediate send). We accumulate pages that hit threshold this run.
        triggered_5xx: List[Tuple[str, str, int, str]] = []  # (url, code_label, step, first_seen)
        triggered_404: List[Tuple[str, int, str]] = []  # (url, step, first_seen)
        triggered_timeout: List[Tuple[str, int, str]] = []  # (url, step, first_seen)
        triggered_content: List[Tuple[str, str, int, str]] = []  # (url, note, step, first_seen)

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
                elif error_type == "content_error":
                    triggered_content.append((url, code_label or "CONTENT_ERROR", step, stp.get('first_seen', timestamp)))
                stp["last_notified_step"] = step
            state[k] = stp

        # Update per-page errors (per-URL accounting)
        for u, code in pages_5xx:
            update_page_error(u, "http_5xx", code_label=str(code))
        for u in pages_404:
            update_page_error(u, "http_404")
        for u in pages_timeout:
            update_page_error(u, "timeout")
        for (u, note) in pages_content:
            update_page_error(u, "content_error", code_label=note)

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

        # Content errors grouped / per page
        num_content = len(pages_content)
        if num_content > 5:
            if triggered_content:
                parts = [
                    "❌ [ALERT] Ошибка контента на страницах",
                    f"Сайт: {site}",
                    f"{num_content} страниц содержат запрещённый текст",
                    f"Время проверки: {timestamp}"
                ]
                rep_steps = [s for (_u, _note, s, _fs) in triggered_content if s in (4, 12, 50)]
                if rep_steps:
                    stepv = rep_steps[0]
                    parts.append(f"Повторный прогон ошибки: {stepv} (ошибка все еще актуальна)")
                send_telegram_message(cfg["bot_token"], cfg["chat_id"], "\n".join(parts))
        elif 0 < num_content <= 5:
            if triggered_content:
                for (url, note, step, first_seen_val) in triggered_content:
                    _site, host = extract_site_domain(url)
                    parts = [
                        "❌ [ALERT] Ошибка контента на странице",
                        f"Сайт: {site}",
                        f"Страница: {host}",
                        "Детали: Контент сайта недоступен",
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

    num_ok = sum(
        1
        for (_u, _h, status, _ms, _e, content_error, _cn) in results
        if (status is not None and 200 <= status < 400 and not content_error)
    )
    # неуспехи учитываем только для 404 и 5xx (как по условиям алертов)
    num_failed = sum(
        1
        for (_u, _h, status, _ms, _e, _ce, _cn) in results
        if (status == 404) or (status is not None and 500 <= status < 600)
    )
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
        # A run is successful if ALL pages are OK (same rule as for success Telegram) and no SSL issues
        success_run = 1 if (int(total_pages) > 0 and int(total_ok) == int(total_pages) and int(ssl_issues_sites) == 0) else 0
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
            # Count failed pages in this run as total_pages - total_ok (includes timeouts/network/non-OK)
            failed_pages_this_run = max(0, int(total_pages) - int(total_ok))
            entry_failed_pages = int(entry.get("failed_pages", 0)) + failed_pages_this_run
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

