import logging

from telegram import Update
from telegram.ext import ContextTypes

from services.reka_client import generate_report

log = logging.getLogger(__name__)


async def handle_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_data = context.user_data or {}
    analysis = user_data.get("last_analysis")

    if not analysis:
        await update.message.reply_text(
            "⚠️ No analysis found.\n\n"
            "Please send an image first, then use /report to generate a police report."
        )
        return

    status = await update.message.reply_text("📋 Generating your draft police report…")

    try:
        submitted_at = user_data.get("last_analysis_time", "an unknown time")
        report = await generate_report(analysis_json=analysis, submitted_at=submitted_at)

        header = "📋 *DRAFT POLICE REPORT*\n━━━━━━━━━━━━━━━━━━━━━━\n\n"
        footer = (
            "\n\n━━━━━━━━━━━━━━━━━━━━━━\n"
            "⚠️ _This is a draft. Please verify all details before submitting to SPF at "
            "[police.gov.sg](https://www.police.gov.sg/scamalert) or call 1800-255-0000._"
        )

        full_message = header + report + footer

        # Telegram hard limit is 4096 chars per message
        if len(full_message) <= 4096:
            await status.edit_text(full_message, parse_mode="Markdown")
        else:
            await status.delete()
            chunks = [full_message[i:i + 4096] for i in range(0, len(full_message), 4096)]
            for chunk in chunks:
                await update.message.reply_text(chunk, parse_mode="Markdown")

    except Exception as e:
        log.exception("report handler failed")
        await status.edit_text(
            f"❌ Sorry, something went wrong generating the report.\n\n"
            f"Error: `{type(e).__name__}: {e}`"
        )