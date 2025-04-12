import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Core Application Configuration
    SECRET_KEY = os.getenv('SECRET_KEY')
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')
    API_URL = os.getenv('API_URL', 'http://localhost:5003')
    
    # Discord OAuth Configuration
    DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
    DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
    
    # Database Configuration
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

# Instantiate the configuration
config = Config()