import logging
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes
from services.reka_client import scan_image, MAX_IMAGE_BYTES
from services.utils.formatter_button import format_verdict_button

logger = logging.getLogger(__name__)

async def handle_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Send a "processing" message immediately
    status_msg = await update.message.reply_text("🔍 Analysing your image... Please wait.")

    try:
        photo = update.message.photo[-1]
        # Check the size *before* downloading — Telegram tells us the file
        # size on each PhotoSize, so we can fail fast on a file we know is
        # too big and avoid the network round-trip.
        if photo.file_size and photo.file_size > MAX_IMAGE_BYTES:
            await status_msg.edit_text(
                f"⚠️ Image is {photo.file_size / 1024 / 1024:.1f} MB, "
                f"but the limit is {MAX_IMAGE_BYTES // 1024 // 1024} MB.\n\n"
                "Please send a smaller image (or compress it before sending)."
            )
            return

        file = await photo.get_file()
        data = bytes(await file.download_as_bytearray())

        # Belt-and-braces: re-check the *downloaded* size, in case
        # Telegram's file_size field was missing or wrong. Without this,
        # an oversize download would reach scan_image and raise a generic
        # ValueError that gets swallowed into the "temporarily unavailable"
        # message.
        if len(data) > MAX_IMAGE_BYTES:
            await status_msg.edit_text(
                f"⚠️ Image is {len(data) / 1024 / 1024:.1f} MB, "
                f"but the limit is {MAX_IMAGE_BYTES // 1024 // 1024} MB.\n\n"
                "Please send a smaller image."
            )
            return

        caption = update.message.caption or ""

        result = await scan_image(data, caption)
        context.user_data['last_analysis'] = result  # store for /report

        reply, reply_markup = format_verdict_button(result)

        await status_msg.edit_text(reply, parse_mode="HTML", reply_markup=reply_markup)
    except Exception as e:
        logger.error(f"Image scan failed: {e}")
        await status_msg.edit_text("⚠️ Image analysis temporarily unavailable. Please try again later.")
