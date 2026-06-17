import logging
from telegram import Update
from telegram.ext import ContextTypes
from services.audio_converter import convert_to_wav
from services.reka_client import scan_voice, MAX_AUDIO_BYTES
from services.utils.formatter_button import format_verdict_button

logger = logging.getLogger(__name__)

async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Send a "processing" message immediately
    status_msg = await update.message.reply_text("🔍 Analysing your audio... Please wait.")

    try:
        # Handle both voice notes and audio files
        voice = update.message.voice
        audio = update.message.audio

        # Determine which type we're processing and get the file object
        if voice:
            file_obj = voice
            file_type = "voice note"
        elif audio:
            file_obj = audio
            file_type = "audio file"
        else:
            # Neither voice nor audio - this shouldn't happen with proper filters
            await status_msg.edit_text("⚠️ No audio content found.")
            return

        # Check the size *before* downloading — Telegram tells us the file
        # size on the message object, so we can fail fast and avoid the
        # download + conversion on a file we know is too big.
        # file_size is None for some edge cases, so guard.
        if file_obj.file_size and file_obj.file_size > MAX_AUDIO_BYTES:
            await status_msg.edit_text(
                f"⚠️ {file_type.capitalize()} is {file_obj.file_size / 1024 / 1024:.1f} MB, "
                f"but the limit is {MAX_AUDIO_BYTES // 1024 // 1024} MB.\n\n"
                "Please send a shorter clip (under ~2 minutes is usually safe)."
            )
            return

        file = await file_obj.get_file()
        data = bytes(await file.download_as_bytearray())

        # Belt-and-braces: re-check the *downloaded* size, in case Telegram's
        # file_size field was missing or wrong. Without this, an oversize
        # download would reach scan_voice and raise a generic ValueError
        # that gets swallowed into the "temporarily unavailable" message.
        if len(data) > MAX_AUDIO_BYTES:
            await status_msg.edit_text(
                f"⚠️ {file_type.capitalize()} is {len(data) / 1024 / 1024:.1f} MB, "
                f"but the limit is {MAX_AUDIO_BYTES // 1024 // 1024} MB.\n\n"
                "Please send a shorter clip."
            )
            return

        caption = update.message.caption or ""

        # Convert to WAV for Reka analysis (handles OGG/Opus voice notes and various audio formats)
        wav_bytes = convert_to_wav(data)

        result = await scan_voice(wav_bytes, caption)
        context.user_data['last_analysis'] = result  # store for /report

        reply, reply_markup = format_verdict_button(result)
        await status_msg.edit_text(reply, parse_mode="HTML", reply_markup=reply_markup)
    except Exception as e:
        logger.error(f"Audio scan failed: {e}")
        await status_msg.edit_text("⚠️ Audio analysis temporarily unavailable. Please try again later.")
