from telegram import Update
from telegram.ext import ContextTypes

async def handle_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        'Welcome to the ScamRadar Bot!\n\n'
        'Send me a voice note, audio file, image, or text message '
        'to check if it\'s AI-generated or part of a scam.'
    )