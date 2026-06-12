import logging
from dotenv import load_dotenv
import os

load_dotenv()
from telegram.ext import Application, MessageHandler, CommandHandler, filters
from handlers.voice import handle_voice
from handlers.image import handle_image
from handlers.text import handle_text
from handlers.start import handle_start

logging.basicConfig(level=logging.INFO)

def main():
    app = Application.builder().token(os.getenv('TELEGRAM_BOT_TOKEN')).build()
    app.add_handler(CommandHandler('start', handle_start))
    app.add_handler(MessageHandler(filters.VOICE, handle_voice))
    app.add_handler(MessageHandler(filters.AUDIO, handle_voice))
    app.add_handler(MessageHandler(filters.PHOTO, handle_image))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.run_polling()

if __name__ == '__main__':
    main()
