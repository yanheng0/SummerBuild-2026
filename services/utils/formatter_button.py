from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from services.utils.formatter import format_verdict

def format_verdict_button(result: dict) -> tuple[str, InlineKeyboardMarkup]:
    text = format_verdict(result)
    keyboard = [[InlineKeyboardButton("Draft a Police Report", callback_data="run_report")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    return text, reply_markup