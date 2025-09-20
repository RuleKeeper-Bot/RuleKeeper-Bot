import sqlite3
import os
import json
import time
import random
import string
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        """
        No-op placeholder for an optional debug logging function.
        
        This function accepts any positional and keyword arguments and intentionally does nothing.
        It's used as a fallback when a real `debug_print` implementation isn't available so callers
        can invoke `debug_print(...)` without conditional checks.
        """
        pass

BACKUPS_DIR = os.path.join(os.path.dirname(__file__))
BACKUPS_DB_PATH = os.path.join(BACKUPS_DIR, 'backups.db')
os.makedirs(BACKUPS_DIR, exist_ok=True)
def get_conn():
    """
    Return a sqlite3.Connection to the backups database with row_factory set to sqlite3.Row.
    
    The connection is opened to BACKUPS_DB_PATH (the database file will be created if it does not exist). Rows fetched from this connection behave like mappings (column-name access) thanks to sqlite3.Row.
    
    Returns:
        sqlite3.Connection: An open SQLite connection with row_factory configured.
    """
    debug_print("Called get_conn()", level="all")
    conn = sqlite3.connect(BACKUPS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initialize the backups database schema.
    
    Creates the required tables (`backups` and `schedules`) in the configured
    backups SQLite database if they do not already exist. This is idempotent
    and will not modify existing tables.
    
    Tables created:
    - backups: stores backup metadata with columns
        - id (TEXT PRIMARY KEY)
        - guild_id (TEXT)
        - created_at (INTEGER, UNIX timestamp)
        - file_path (TEXT)
        - scheduled (INTEGER, default 0)
        - share_id (TEXT, UNIQUE)
    - schedules: stores scheduled-backup definitions with columns
        - id (TEXT PRIMARY KEY)
        - guild_id (TEXT)
        - start_date (TEXT)
        - start_time (TEXT)
        - frequency_value (INTEGER)
        - frequency_unit (TEXT)
        - enabled (INTEGER, default 1)
        - timezone (TEXT, default 'UTC')
    
    Side effects:
    - May create or modify the backups database file on disk via get_conn().
    """
    debug_print("Called init_db()", level="all")
    with get_conn() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS backups (
                id TEXT PRIMARY KEY,
                guild_id TEXT,
                created_at INTEGER,
                file_path TEXT,
                scheduled INTEGER DEFAULT 0,
                share_id TEXT UNIQUE
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS schedules (
                id TEXT PRIMARY KEY,
                guild_id TEXT,
                start_date TEXT,
                start_time TEXT,
                frequency_value INTEGER,
                frequency_unit TEXT,
                enabled INTEGER DEFAULT 1,
                timezone TEXT DEFAULT 'UTC'
            )
        ''')

def add_backup(guild_id, file_path, scheduled=0):
    """
    Create a new backup record in the backups database and return its generated ID.
    
    Inserts a new row into the backups table with a generated 5-digit numeric `backup_id`, the current UNIX timestamp as `created_at`, the provided `file_path`, and the `scheduled` flag.
    
    Parameters:
        guild_id (str): Identifier of the guild the backup belongs to.
        file_path (str): Filesystem path where the backup file is stored.
        scheduled (int): Flag indicating whether the backup is scheduled (default 0).
    
    Returns:
        str: The generated 5-digit numeric backup ID.
    """
    debug_print(f"Called add_backup(guild_id={guild_id}, file_path={file_path}, scheduled={scheduled})", level="all")
    import time
    backup_id = ''.join(random.choices('0123456789', k=5))
    with get_conn() as conn:
        conn.execute(
            'INSERT INTO backups (id, guild_id, created_at, file_path, scheduled) VALUES (?, ?, ?, ?, ?)',
            (backup_id, guild_id, int(time.time()), file_path, scheduled)
        )
    return backup_id

def get_backups(guild_id):
    """
    Return all backup records for a guild, ordered by creation time (newest first).
    
    Parameters:
        guild_id (str): ID of the guild whose backups to fetch.
    
    Returns:
        list[sqlite3.Row]: Rows from the `backups` table for the given guild, ordered by `created_at` descending.
    """
    debug_print(f"Called get_backups(guild_id={guild_id})", level="all")
    with get_conn() as conn:
        return conn.execute(
            'SELECT * FROM backups WHERE guild_id = ? ORDER BY created_at DESC', (guild_id,)
        ).fetchall()

def get_backup(backup_id, guild_id):
    """
    Retrieve a single backup record by backup ID scoped to a specific guild.
    
    Parameters:
        backup_id (str): The backup's identifier.
        guild_id (str): The guild identifier to scope the lookup.
    
    Returns:
        sqlite3.Row | None: The matching row from the `backups` table as a Row (mapping-like) or None if not found.
    """
    debug_print(f"Called get_backup(backup_id={backup_id}, guild_id={guild_id})", level="all")
    with get_conn() as conn:
        return conn.execute(
            'SELECT * FROM backups WHERE id = ? AND guild_id = ?', (backup_id, guild_id)
        ).fetchone()

def generate_share_id(length=6):
    """
    Generate a random alphanumeric share identifier.
    
    Returns a string of length `length` composed of ASCII letters (both cases) and digits.
    The value is suitable for short, human-readable share IDs but is not guaranteed to be unique.
    Parameters:
        length (int): Number of characters to generate (default 6).
    
    Returns:
        str: Random alphanumeric string of the requested length.
    """
    debug_print(f"Called generate_share_id(length={length})", level="all")
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def set_backup_share_id(backup_id, guild_id):
    """
    Generate a random share ID, store it on the backup record, and return it.
    
    Generates an alphanumeric share identifier, updates the matching backup row (by id and guild_id) setting its `share_id` column to the generated value, and returns that share ID.
    
    Parameters:
        backup_id (str): Backup identifier to update.
        guild_id (str): Guild identifier that owns the backup.
    
    Returns:
        str: The generated share ID.
    
    Raises:
        sqlite3.IntegrityError: If the generated share ID conflicts with an existing unique `share_id` in the database.
    """
    debug_print(f"Called set_backup_share_id(backup_id={backup_id}, guild_id={guild_id})", level="all")
    share_id = generate_share_id()
    with get_conn() as conn:
        conn.execute(
            'UPDATE backups SET share_id = ? WHERE id = ? AND guild_id = ?',
            (share_id, backup_id, guild_id)
        )
    return share_id

def get_backup_by_share_id(share_id):
    """
    Retrieve a backup record by its public share ID.
    
    Parameters:
        share_id (str): The public share identifier associated with a backup.
    
    Returns:
        sqlite3.Row | None: The matching backup row (with columns as defined in the `backups` table) or None if no match is found.
    """
    debug_print(f"Called get_backup_by_share_id(share_id={share_id})", level="all")
    with get_conn() as conn:
        return conn.execute(
            'SELECT * FROM backups WHERE share_id = ?', (share_id,)
        ).fetchone()

def import_backup_file(file, guild_id):
    """
    Import an uploaded backup file: save it to disk, validate its JSON, and register a backup record.
    
    file: an uploaded file object that exposes a .save(path) method (e.g., Werkzeug/Flask FileStorage). The function saves the file to BACKUPS_DIR as "{guild_id}_{backup_id}.json", validates the file contents by loading JSON, and inserts a new row into the backups table with a generated 5-digit numeric id, the current UNIX timestamp, and scheduled=0.
    
    Parameters:
        file: uploaded file object with a .save(path) method.
        guild_id (str): ID of the guild to associate the backup with.
    
    Raises:
        json.JSONDecodeError: if the saved file is not valid JSON.
        OSError / IOError: on filesystem errors when saving or reading the file.
        sqlite3.Error: on database insertion errors.
    """
    debug_print(f"Called import_backup_file(file={file}, guild_id={guild_id})", level="all")
    # Save file to backups directory
    backup_id = ''.join(random.choices('0123456789', k=5))
    file_path = os.path.join(BACKUPS_DIR, f"{guild_id}_{backup_id}.json")
    file.save(file_path)
    # Optionally validate JSON structure here
    with open(file_path, 'r', encoding='utf-8') as f:
        json.load(f)  # Will raise if invalid
    # Register in DB
    with get_conn() as conn:
        conn.execute(
            'INSERT INTO backups (id, guild_id, created_at, file_path, scheduled) VALUES (?, ?, ?, ?, ?)',
            (backup_id, guild_id, int(time.time()), file_path, 0)
        )

def import_backup_file_from_bytes(file_bytes, guild_id):
    """
    Import a backup from raw bytes: save to disk, validate JSON, and record it in the backups database.
    
    Writes the provided bytes to a file named "<guild_id>_<backup_id>.json" inside the backups directory, validates the file contains valid JSON, and inserts a new row into the backups table with a generated 5-digit numeric backup id, the guild_id, current UNIX timestamp as created_at, the file path, and scheduled=0.
    
    Parameters:
        file_bytes (bytes): Raw file contents expected to be a JSON-formatted backup.
        guild_id (str): Identifier of the guild the backup belongs to.
    
    Raises:
        json.JSONDecodeError: If the written file is not valid JSON.
        OSError: If writing the file fails.
        sqlite3.Error: If inserting the backup record into the database fails.
    """
    debug_print(f"Called import_backup_file_from_bytes(file_bytes=<bytes>, guild_id={guild_id})", level="all")
    import time, json
    backup_id = ''.join(random.choices('0123456789', k=5))
    backup_dir = BACKUPS_DIR
    file_path = os.path.join(backup_dir, f"{guild_id}_{backup_id}.json")
    with open(file_path, 'wb') as f:
        f.write(file_bytes)
    # Optionally validate JSON structure here
    with open(file_path, 'r', encoding='utf-8') as f:
        json.load(f)  # Will raise if invalid
    with get_conn() as conn:
        conn.execute(
            'INSERT INTO backups (id, guild_id, created_at, file_path, scheduled) VALUES (?, ?, ?, ?, ?)',
            (backup_id, guild_id, int(time.time()), file_path, 0)
        )