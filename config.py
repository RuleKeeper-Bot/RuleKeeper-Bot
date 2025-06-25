import os
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Core Application Configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    HEAD_ADMIN_USERNAME = os.getenv('HEAD_ADMIN_USERNAME')
    HEAD_ADMIN_PASSWORD = os.getenv('HEAD_ADMIN_PASSWORD')
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')
    API_URL = os.getenv('API_URL', 'http://localhost:5003')
    
    # Discord OAuth Configuration
    DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
    DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
    
    # Database Configuration
    if getattr(sys, 'frozen', False):
        # Running as compiled binary: use the binary's directory
        base_dir = Path(sys.executable).parent
        DATABASE_PATH = str(base_dir / os.getenv('DATABASE_PATH', 'bot.db'))
    else:
        # Running as script: use the path as set in the environment or default
        DATABASE_PATH = os.getenv('DATABASE_PATH', 'bot.db')
    
    # Default Embed Colors
    DEFAULT_EMBED_COLORS = {
        'success': 0x00ff00,
        'error': 0xff0000,
        'warning': 0xffa500,
        'info': 0x0099ff
    }
    
    # Feature Toggles
    ENABLE_LEVELING = os.getenv('ENABLE_LEVELING', 'true').lower() == 'true'
    ENABLE_MODERATION = os.getenv('ENABLE_MODERATION', 'true').lower() == 'true'
    ENABLE_APPEALS = os.getenv('ENABLE_APPEALS', 'true').lower() == 'true'

    def __init__(self):
        # Initialize dynamic properties
        self.DISCORD_REDIRECT_URI = f"{self.FRONTEND_URL}/callback"

    @property
    def SQLALCHEMY_DATABASE_URI(self):
        return f"sqlite:///{self.DATABASE_PATH}"

    @property
    def PERMITTED_GUILDS(self):
        return os.getenv('PERMITTED_GUILDS', '').split(',')

    @staticmethod
    def verify_paths():
        db_path = Config.DATABASE_PATH
        if not os.path.exists(db_path):
            # If the file doesn't exist, create an empty file so SQLite can use it
            open(db_path, 'a').close()

# Instantiate the configuration
config = Config()