import logging

from telegram import Update
from telegram.ext import ContextTypes

from services.audio_converter import convert_to_wav
from services.reka_client import scan_voice, scan_voice_core
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

        # Flash analysis
        raw_flash = await scan_voice(wav_bytes)
        flash_parsed = _parse_reka_response(raw_flash)
        conf = float(flash_parsed.get("confidence_score", 0))
        needs_core = 50 <= conf <= 70  # ambiguous range

        final_raw = raw_flash
        if needs_core:
            log.info(
                "Flash confidence %.2f triggers core analysis for voice",
                conf,
            )
            raw_core = await scan_voice_core(wav_bytes)
            core_parsed = _parse_reka_response(raw_core)
            # Choose higher risk verdict
            def risk(res):
                v = res.get("verdict", "SAFE").upper()
                return {"SAFE": 0, "SUSPICIOUS": 1, "HIGH_RISK": 2}.get(v, 0)
            if risk(core_parsed) > risk(flash_parsed):
                final_raw = raw_core

        await status.edit_text(format_voice_verdict(final_raw))

    except Exception as e:
        log.exception("voice handler failed")
        await status.edit_text(
            f"Sorry, something went wrong analysing that audio.\n\n"
            f"Error: `{type(e).__name__}: {e}`"
        )


def _parse_reka_response(raw: str) -> dict:
    """Parse Reka JSON response, fallback to safe default."""
    import json, re
    # Extract JSON object
    cleaned = re.sub(r"```(?:json)?|```", "", raw)
    cleaned = re.sub(r"^\s*json\s*$", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        cleaned = cleaned[start:end+1]
    try:
        data = json.loads(cleaned)
        # Ensure expected fields
        data.setdefault("verdict", "SAFE")
        data.setdefault("confidence_score", 0)
        data.setdefault("analysis_summary", "")
        data.setdefault("forensic_indicators", {
            "linguistic_flags": [],
            "visual_anomalies": [],
            "behavioral_contradictions": []
        })
        data.setdefault("extracted_entities", {
            "impersonated_target": None,
            "scammer_identifiers": [],
            "malicious_urls": []
        })
        data.setdefault("recommended_action", "FLAG_FOR_HUMAN_REVIEW")
        return data
    except Exception:
        # Fallback
        return {
            "verdict": "SAFE",
            "confidence_score": 0,
            "analysis_summary": raw.strip(),
            "forensic_indicators": {
                "linguistic_flags": [],
                "visual_anomalies": [],
                "behavioral_contradictions": []
            },
            "extracted_entities": {
                "impersonated_target": None,
                "scammer_identifiers": [],
                "malicious_urls": []
            },
            "recommended_action": "FLAG_FOR_HUMAN_REVIEW"
        }
