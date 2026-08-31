from telethon import TelegramClient
from config_loader import get_int, get_str
from paths import SESSIONS_DIR

api_id = get_int("TELEGRAM_API_ID", 0)
api_hash = get_str("TELEGRAM_API_HASH", "") or ""

async def main():
    if not api_id or not api_hash:
        raise SystemExit("Set TELEGRAM_API_ID and TELEGRAM_API_HASH before listing groups.")
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    session_name = str(SESSIONS_DIR / get_str("TELEGRAM_USER_SESSION_NAME", "user_scraper_session"))
    async with TelegramClient(session_name, api_id, api_hash) as client:
        print("\n--- YOUR GROUPS AND IDS ---")
        async for dialog in client.iter_dialogs():
            if dialog.is_group or dialog.is_channel:
                print(f"NAME: {dialog.name} | ID: {dialog.id}")
        print("---------------------------\n")

import asyncio
asyncio.run(main())
