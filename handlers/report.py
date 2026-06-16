import json
import logging
from datetime import datetime

from telegram import Update, error
from telegram.ext import ContextTypes

from services.reka_client import generate_report

log = logging.getLogger(__name__)


async def handle_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_data = context.user_data or {}
    analysis = user_data.get("last_analysis")

    if not analysis:
        await update.message.reply_text(
            "⚠️ No analysis found.\n\n"
            "Please send an image or text first, then use /report to generate a police report."
        )
        return

    status = await update.message.reply_text("📋 Generating your draft police report…")

    try:
        # Convert dict to JSON string
        analysis_json = json.dumps(analysis, ensure_ascii=False)
        submitted_at = user_data.get("last_analysis_time", datetime.now().isoformat())
        report = await generate_report(analysis_json=analysis_json, submitted_at=submitted_at)

        # Use HTML for consistent formatting
        header = "📋 <b>DRAFT POLICE REPORT</b>\n━━━━━━━━━━━━━━━━━━━━━━\n\n"
        footer = (
            "\n\n━━━━━━━━━━━━━━━━━━━━━━\n"
            "<i>This is a draft. Please verify all details before submitting to SPF at "
            "<a href='https://www.police.gov.sg/e-services/lodge-police-report'>police.gov.sg</a> or call 24/7 ScamShield Helpline at 1799.</i>"
        )

        full_message = header + report + footer

        # Telegram hard limit is 4096 chars per message
        if len(full_message) <= 4096:
            try:
                await status.edit_text(full_message, parse_mode="HTML")
            except error.BadRequest as e:
                # If HTML formatting fails, fall back to plain text
                log.warning(f"HTML formatting failed, sending plain text: {e}")
                await status.edit_text(full_message, parse_mode=None)
        else:
            await status.delete()
            chunks = [full_message[i:i + 4096] for i in range(0, len(full_message), 4096)]
            for chunk in chunks:
                try:
                    await update.message.reply_text(chunk, parse_mode="HTML")
                except error.BadRequest:
                    await update.message.reply_text(chunk, parse_mode=None)

    except Exception as e:
        log.exception("report handler failed")
        await status.edit_text(
            f"❌ Sorry, something went wrong generating the report.\n\n"
            f"Error: `{type(e).__name__}: {e}`"
        )