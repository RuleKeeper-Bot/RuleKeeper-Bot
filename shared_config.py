import os
from pathlib import Path

class Config:
    BASE_DIR = Path(__file__).parent  # Project root
    DATABASE_PATH = BASE_DIR / "bot" / "bot.db"
    
    @classmethod
    def verify_paths(cls):
        if not cls.DATABASE_PATH.exists():
            raise FileNotFoundError(f"Database not found at {cls.DATABASE_PATH}")