import logging

from telegram import Update
from telegram.ext import ContextTypes

from services.reka_client import scan_image
from services.utils.formatter import format_image_verdict

from datetime import datetime, timezone

log = logging.getLogger(__name__)


async def handle_image(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    photo = msg.photo[-1]  # largest size

    status = await msg.reply_text("Analysing image — please wait…")

    try:
        tg_file = await context.bot.get_file(photo.file_id)
        image_bytes = await tg_file.download_as_bytearray()

        raw = await scan_image(bytes(image_bytes))
        await status.edit_text(format_image_verdict(raw))

        # Persist raw JSON result so /report can generate a police report from it
        context.user_data["last_analysis"] = raw
        context.user_data["last_analysis_time"] = datetime.now(timezone.utc).strftime(
            "%d %B %Y, %I:%M %p UTC"
        )
 
        formatted = format_image_verdict(raw)
        await status.edit_text(
            formatted + "\n\n💡 Use /report to generate a draft police report."
        )

    except Exception as e:
        log.exception("image handler failed")
        await status.edit_text(
            f"Sorry, something went wrong analysing that image.\n\n"
            f"Error: `{type(e).__name__}: {e}`"
        )
