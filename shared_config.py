from config import Config
import os

def verify_paths():
    db_path = Config.DATABASE_PATH
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database not found at {db_path}")