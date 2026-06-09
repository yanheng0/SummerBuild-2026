import logging

from telegram import Update
from telegram.ext import ContextTypes

from services.reka_client import scan_text
from services.utils.formatter import format_text_verdict

log = logging.getLogger(__name__)


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    text = msg.text

    status = await msg.reply_text("Analysing text — please wait…")

    try:
        raw = await scan_text(text)
        await status.edit_text(format_text_verdict(raw))

    except Exception as e:
        log.exception("text handler failed")
        await status.edit_text(
            f"Sorry, something went wrong analysing that message.\n\n"
            f"Error: `{type(e).__name__}: {e}`"
        )
