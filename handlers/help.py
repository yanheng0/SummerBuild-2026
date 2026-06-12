from telegram import Update
from telegram.ext import ContextTypes

async def handle_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "🤖 *Available Commands*\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "/start — Welcome message\n"
        "/help — Show this help menu\n"
        "/report — Generate a draft police report from the last scan\n\n"
        "*What I can analyse:*\n"
        "🖼 *Image* — Send any image to scan for deepfakes or scam content\n"
        "🎙 *Voice* — Send a voice message to check for scam calls\n"
        "💬 *Text* — Send any message to check for scam patterns\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        "_Powered by Reka AI • Built for Singapore 🇸🇬_"
    )
    await update.message.reply_text(help_text, parse_mode="Markdown")