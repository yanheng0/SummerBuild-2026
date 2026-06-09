import logging

from telegram import Update
from telegram.ext import ContextTypes

from services.audio_converter import convert_to_wav
from services.reka_client import scan_voice
from services.utils.formatter import format_voice_verdict

log = logging.getLogger(__name__)


async def handle_voice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    voice = msg.voice or msg.audio

    if voice.duration < 3:
        await msg.reply_text(
            "Clip too short to analyse reliably. "
            "Please send at least 5 seconds of audio."
        )
        return

    status = await msg.reply_text("Analysing voice — please wait…")

    try:
        tg_file = await context.bot.get_file(voice.file_id)
        ogg_bytes = await tg_file.download_as_bytearray()
        wav_bytes = convert_to_wav(bytes(ogg_bytes))

        raw = await scan_voice(wav_bytes)
        await status.edit_text(format_voice_verdict(raw))

    except Exception as e:
        log.exception("voice handler failed")
        await status.edit_text(
            f"Sorry, something went wrong analysing that audio.\n\n"
            f"Error: `{type(e).__name__}: {e}`"
        )
