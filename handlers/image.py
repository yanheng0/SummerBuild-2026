import logging
from telegram import Update
from telegram.ext import ContextTypes
from services.reka_client import scan_image
from services.utils.formatter import format_verdict

logger = logging.getLogger(__name__)

async def handle_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Send a "processing" message immediately
    status_msg = await update.message.reply_text("🔍 Analysing your image... Please wait.")

    try:
        photo = update.message.photo[-1]
        file = await photo.get_file()
        data = await file.download_as_bytearray()
        caption = update.message.caption or ""

        result = await scan_image(bytes(data), caption)
        context.user_data['last_analysis'] = result  # store for /report

        reply = format_verdict(result)
        await status_msg.edit_text(reply, parse_mode="HTML")
    except Exception as e:
        logger.error(f"Image scan failed: {e}")
        await status_msg.edit_text("⚠️ Image analysis temporarily unavailable. Please try again later.")