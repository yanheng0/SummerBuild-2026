import logging
from telegram import Update
from telegram.ext import ContextTypes
from services.audio_converter import convert_to_wav
from services.reka_client import scan_voice, MAX_AUDIO_BYTES
from services.utils.formatter import format_verdict

logger = logging.getLogger(__name__)

async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # Send a "processing" message immediately
    status_msg = await update.message.reply_text("🔍 Analysing your voice message... Please wait.")

    try:
        voice = update.message.voice
        # Check the size *before* downloading — Telegram tells us the file
        # size on the message object, so we can fail fast and avoid the
        # download + ffmpeg conversion on a file we know is too big.
        # file_size is None for some edge cases, so guard.
        if voice.file_size and voice.file_size > MAX_AUDIO_BYTES:
            await status_msg.edit_text(
                f"⚠️ Voice note is {voice.file_size / 1024 / 1024:.1f} MB, "
                f"but the limit is {MAX_AUDIO_BYTES // 1024 // 1024} MB.\n\n"
                "Please send a shorter clip (under ~2 minutes is usually safe)."
            )
            return

        file = await voice.get_file()
        data = bytes(await file.download_as_bytearray())

        # Belt-and-braces: re-check the *downloaded* size, in case Telegram's
        # file_size field was missing or wrong. Without this, an oversize
        # download would reach scan_voice and raise a generic ValueError
        # that gets swallowed into the "temporarily unavailable" message.
        if len(data) > MAX_AUDIO_BYTES:
            await status_msg.edit_text(
                f"⚠️ Voice note is {len(data) / 1024 / 1024:.1f} MB, "
                f"but the limit is {MAX_AUDIO_BYTES // 1024 // 1024} MB.\n\n"
                "Please send a shorter clip."
            )
            return

        caption = update.message.caption or ""

        # Telegram voice notes are OGG/Opus; Reka's audio_url expects WAV.
        # Convert before sending so the model actually hears the audio
        # (without this step, Reka gets an unreadable blob and returns a
        # canned low-confidence verdict that doesn't reflect the clip).
        wav_bytes = convert_to_wav(data)

        result = await scan_voice(wav_bytes, caption)
        context.user_data['last_analysis'] = result  # store for /report

        reply = format_verdict(result)
        await status_msg.edit_text(reply, parse_mode="HTML")
    except Exception as e:
        logger.error(f"Voice scan failed: {e}")
        await status_msg.edit_text("⚠️ Voice analysis temporarily unavailable. Please try again later.")
