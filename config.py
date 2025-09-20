import os
import sys
from pathlib import Path
from dotenv import load_dotenv
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        """
        No-op fallback for a debugging print function.
        
        Accepts any positional and keyword arguments and does nothing. Provided to preserve the signature of an optional `debug_print` implementation so callers can invoke it without conditional checks when a real debug facility is not available.
        """
        pass

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

    def __init__(self):
        """
        Initialize a Config instance.
        
        Sets dynamic configuration values derived from class attributes. Specifically, creates the instance attribute `DISCORD_REDIRECT_URI` by appending `/callback` to `FRONTEND_URL`.
        """
        debug_print(f"Entering Config.__init__", level="all")
        # Initialize dynamic properties
        self.DISCORD_REDIRECT_URI = f"{self.FRONTEND_URL}/callback"

    @property
    def SQLALCHEMY_DATABASE_URI(self):
        """
        Return the SQLAlchemy database URI for the configured SQLite database.
        
        Constructs and returns a SQLite connection URI using the instance's DATABASE_PATH (e.g. "sqlite:////path/to/db").
        Returns:
            str: A SQLite URI suitable for SQLAlchemy's `create_engine` or Flask `SQLALCHEMY_DATABASE_URI`.
        """
        debug_print(f"Accessing SQLALCHEMY_DATABASE_URI property")
        return f"sqlite:///{self.DATABASE_PATH}"

    @property
    def PERMITTED_GUILDS(self):
        """
        Return the list of permitted guild IDs from the PERMITTED_GUILDS environment variable.
        
        Reads the `PERMITTED_GUILDS` environment variable and splits it on commas, returning the resulting list of strings. If the variable is not set an empty string is used, producing [''] (i.e., a single empty string element). Values are returned as-is (no trimming or type conversion).
        """
        debug_print(f"Accessing PERMITTED_GUILDS property")
        return os.getenv('PERMITTED_GUILDS', '').split(',')

    @staticmethod
    def verify_paths():
        """
        Ensure the configured SQLite database file exists.
        
        If the file at Config.DATABASE_PATH does not exist, create an empty file so SQLite can open it.
        No return value.
        """
        debug_print(f"Calling Config.verify_paths()", level="all")
        db_path = Config.DATABASE_PATH
        if not os.path.exists(db_path):
            # If the file doesn't exist, create an empty file so SQLite can use it
            open(db_path, 'a').close()

# Instantiate the configuration
debug_print("Instantiating Config")
config = Config()