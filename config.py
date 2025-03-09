import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
    COMMANDS_FILE = os.path.join(os.path.dirname(__file__), 'bot/commands.json')
    BLOCKED_WORDS_FILE = os.path.join('..', 'bot', 'blocked_words.json')
    BLOCKED_WORDS_EMBED_FILE = os.path.join('..', 'bot', 'blocked_word_embed.json')