import sqlite3
import os
import json
import time
import random
import string

BACKUPS_DIR = os.path.join(os.path.dirname(__file__))
BACKUPS_DB_PATH = os.path.join(BACKUPS_DIR, 'backups.db')

def get_conn():
    conn = sqlite3.connect(BACKUPS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
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
    import time
    backup_id = ''.join(random.choices('0123456789', k=5))
    with get_conn() as conn:
        conn.execute(
            'INSERT INTO backups (id, guild_id, created_at, file_path, scheduled) VALUES (?, ?, ?, ?, ?)',
            (backup_id, guild_id, int(time.time()), file_path, scheduled)
        )
    return backup_id

def get_backups(guild_id):
    with get_conn() as conn:
        return conn.execute(
            'SELECT * FROM backups WHERE guild_id = ? ORDER BY created_at DESC', (guild_id,)
        ).fetchall()

def get_backup(backup_id, guild_id):
    with get_conn() as conn:
        return conn.execute(
            'SELECT * FROM backups WHERE id = ? AND guild_id = ?', (backup_id, guild_id)
        ).fetchone()
    
def generate_share_id(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def set_backup_share_id(backup_id, guild_id):
    share_id = generate_share_id()
    with get_conn() as conn:
        conn.execute(
            'UPDATE backups SET share_id = ? WHERE id = ? AND guild_id = ?',
            (share_id, backup_id, guild_id)
        )
    return share_id

def get_backup_by_share_id(share_id):
    with get_conn() as conn:
        return conn.execute(
            'SELECT * FROM backups WHERE share_id = ?', (share_id,)
        ).fetchone()
    
def import_backup_file(file, guild_id):
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