from telegram import Update
from telegram.ext import ContextTypes
import logging
from services.reka_client import scan_text
from services.utils.formatter import format_verdict

logger = logging.getLogger(__name__)

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_message = update.message.text
    # Send a "processing" message
    status_msg = await update.message.reply_text("🔍 Analysing your message... Please wait.")
    try:
        result = await scan_text(user_message)
        context.user_data['last_analysis'] = result
        reply = format_verdict(result)
        # Edit the status message with the final verdict
        await status_msg.edit_text(reply, parse_mode="HTML")
    except Exception as e:
        logger.error(f"Text scan failed: {e}")
        await status_msg.edit_text("⚠️ Analysis temporarily unavailable. Please try again later.")