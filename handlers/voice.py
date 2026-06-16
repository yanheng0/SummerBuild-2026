import logging
from telegram import Update
from telegram.ext import ContextTypes
from services.reka_client import scan_voice
from services.utils.formatter import format_verdict

logger = logging.getLogger(__name__)

async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Send a "processing" message immediately
    status_msg = await update.message.reply_text("🔍 Analysing your voice message... Please wait.")

    try:
        voice = update.message.voice
        file = await voice.get_file()
        data = await file.download_as_bytearray()
        caption = update.message.caption or ""

        result = await scan_voice(bytes(data), caption)
        context.user_data['last_analysis'] = result  # store for /report

        reply = format_verdict(result)
        await status_msg.edit_text(reply, parse_mode="HTML")
    except Exception as e:
        logger.error(f"Voice scan failed: {e}")
        await status_msg.edit_text("⚠️ Voice analysis temporarily unavailable. Please try again later.")