import sqlite3
import json
import logging
import threading
import uuid
import time
from typing import Optional, List, Dict, Any
from config import Config
from shared.colors import red
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_path: str = str(Config.DATABASE_PATH)):
        debug_print(f"Entering Database.__init__ with db_path: {db_path}", level="all")
        self.db_path = db_path
        self.local = threading.local()
        self._verify_connection()
        self.conn.row_factory = sqlite3.Row
        
    def _verify_connection(self):
        debug_print(f"Entering _verify_connection", level="all")
        try:
            conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("SELECT 1")
            conn.close()
            debug_print(f"✅ Database connection verified at {self.db_path}")
        except Exception as e:
            debug_print(red(f"❌ Database connection failed: {str(e)}"))
            raise

    @property
    def conn(self):
        debug_print(f"Accessing conn property")
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            self._connect()
        return self.local.conn

    def _connect(self):
        debug_print(f"Entering _connect", level="all")
        self.local.conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        self.local.conn.row_factory = sqlite3.Row
        self.local.conn.execute("PRAGMA foreign_keys = ON")
        self.local.conn.execute("PRAGMA journal_mode=WAL;")
        logger.debug(f"Created new connection in thread {threading.get_ident()}")

    def close(self):
        debug_print(f"Entering close", level="all")
        if hasattr(self.local, 'conn') and self.local.conn:
            self.local.conn.close()
            self.local.conn = None
            logger.debug(f"Closed connection in thread {threading.get_ident()}")

    def execute_query(self, query: str, params=(), fetch: str = 'all', many: bool = False, retries: int = 5, retry_delay: float = 0.2):
        debug_print(f"Entering execute_query with query: {query}, params: {params}, fetch: {fetch}, many: {many}", level="all")
        last_exception = None
        for attempt in range(retries):
            try:
                conn = self.conn
                cursor = conn.cursor()

                if many:
                    cursor.executemany(query, params)
                else:
                    cursor.execute(query, params)

                result = None
                if fetch.lower() == 'all':
                    result = [dict(row) for row in cursor.fetchall()]
                elif fetch.lower() == 'one':
                    row = cursor.fetchone()
                    result = dict(row) if row else None

                if not query.strip().upper().startswith('SELECT'):
                    conn.commit()

                return result
            except sqlite3.OperationalError as e:
                if 'database is locked' in str(e):
                    logger.warning(f"Database is locked, retrying ({attempt+1}/{retries})...")
                    time.sleep(retry_delay)
                    last_exception = e
                    continue
                else:
                    logger.error(f"Database error: {str(e)}")
                    raise
            except sqlite3.Error as e:
                logger.error(f"Database error: {str(e)}")
                raise
        # If we exhausted retries
        logger.error(f"Database is locked after {retries} retries.")
        if last_exception:
            raise last_exception
        else:
            raise Exception("Database is locked and retries exhausted.")

    def initialize_db(self):
        debug_print(f"Entering initialize_db", level="all")
        try:
            self._connect()
            cursor = self.conn.cursor()

            # Tables creation with full schema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bot_admins (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
                
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admin_privileges (
                    username TEXT PRIMARY KEY,
                    can_manage_servers BOOLEAN DEFAULT 1,
                    can_edit_config BOOLEAN DEFAULT 1,
                    can_remove_bot BOOLEAN DEFAULT 0,
                    can_send_announcements BOOLEAN DEFAULT 1,
                    can_manage_settings BOOLEAN DEFAULT 0,
                    can_ban_users_guilds BOOLEAN DEFAULT 0,
                    FOREIGN KEY(username) REFERENCES bot_admins(username) ON DELETE CASCADE
                )''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_mfa (
                    user_id TEXT PRIMARY KEY,
                    email TEXT,
                    email_otp TEXT,
                    email_otp_expiry INTEGER,
                    totp_secret TEXT,
                    totp_last_used TEXT,
                    mfa_enabled INTEGER DEFAULT 0,
                    mfa_type TEXT,
                    security_questions TEXT,
                    sms_number TEXT,
                    sms_otp TEXT,
                    sms_otp_expiry INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mfa_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    attempt_time INTEGER,
                    method TEXT,
                    success INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )''')
    
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS guilds (
                    guild_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    icon TEXT,
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_synced REAL DEFAULT 0
                )''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT,
                    avatar_url TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_playlists (
                    playlist_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS playlist_tracks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    playlist_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT NOT NULL,
                    duration INTEGER,
                    thumbnail TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(playlist_id, url),
                    FOREIGN KEY(playlist_id) REFERENCES user_playlists(playlist_id) ON DELETE CASCADE
                )''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_permissions (
                    guild_id TEXT,
                    command_name TEXT,
                    allow_roles TEXT DEFAULT '[]',
                    allow_users TEXT DEFAULT '[]',
                    is_custom BOOLEAN DEFAULT 0,
                    PRIMARY KEY (guild_id, command_name)
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS log_config (
                    guild_id TEXT PRIMARY KEY,
                    log_channel_id TEXT,
                    log_config_update BOOLEAN DEFAULT 1,
                    message_delete BOOLEAN DEFAULT 1,
                    bulk_message_delete BOOLEAN DEFAULT 1,
                    message_edit BOOLEAN DEFAULT 1,
                    invite_create BOOLEAN DEFAULT 1,
                    invite_delete BOOLEAN DEFAULT 1,
                    member_role_add BOOLEAN DEFAULT 1,
                    member_role_remove BOOLEAN DEFAULT 1,
                    member_timeout BOOLEAN DEFAULT 1,
                    member_warn BOOLEAN DEFAULT 1,
                    member_unwarn BOOLEAN DEFAULT 1,
                    member_ban BOOLEAN DEFAULT 1,
                    member_unban BOOLEAN DEFAULT 1,
                    member_nickname_change BOOLEAN DEFAULT 1,
                    role_create BOOLEAN DEFAULT 1,
                    role_delete BOOLEAN DEFAULT 1,
                    role_update BOOLEAN DEFAULT 1,
                    channel_create BOOLEAN DEFAULT 1,
                    channel_delete BOOLEAN DEFAULT 1,
                    channel_update BOOLEAN DEFAULT 1,
                    emoji_create BOOLEAN DEFAULT 1,
                    emoji_name_change BOOLEAN DEFAULT 1,
                    emoji_delete BOOLEAN DEFAULT 1,
                    backup_created BOOLEAN DEFAULT 1,
                    backup_failed BOOLEAN DEFAULT 1,
                    backup_deleted BOOLEAN DEFAULT 1,
                    backup_restored BOOLEAN DEFAULT 1,
                    backup_restore_failed BOOLEAN DEFAULT 1,
                    backup_schedule_created BOOLEAN DEFAULT 1,
                    backup_schedule_deleted BOOLEAN DEFAULT 1,
                    excluded_users TEXT DEFAULT '[]',
                    excluded_roles TEXT DEFAULT '[]',
                    excluded_channels TEXT DEFAULT '[]',
                    log_bots BOOLEAN DEFAULT 1,
                    log_self BOOLEAN DEFAULT 0,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_words (
                    guild_id TEXT,
                    word TEXT,
                    PRIMARY KEY(guild_id, word),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_word_embeds (
                    guild_id TEXT PRIMARY KEY,
                    title TEXT DEFAULT 'Blocked Word Detected!',
                    description TEXT DEFAULT 'You have used a word that is not allowed.',
                    color INTEGER DEFAULT 16711680,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    guild_id TEXT,
                    command_name TEXT,
                    content TEXT,
                    description TEXT,
                    ephemeral BOOLEAN DEFAULT 1,
                    PRIMARY KEY(guild_id, command_name),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS level_config (
                    guild_id TEXT PRIMARY KEY,
                    cooldown INTEGER DEFAULT 60,
                    xp_min INTEGER DEFAULT 15,
                    xp_max INTEGER DEFAULT 25,
                    level_channel TEXT,
                    announce_level_up BOOLEAN DEFAULT 1,
                    excluded_channels TEXT DEFAULT '[]',
                    xp_boost_roles TEXT DEFAULT '{}',
                    embed_title TEXT DEFAULT '🎉 Level Up!',
                    embed_description TEXT DEFAULT '{user} has reached level **{level}**!',
                    embed_color INTEGER DEFAULT 16766720,
                    give_xp_to_bots BOOLEAN DEFAULT 0,
                    give_xp_to_self BOOLEAN DEFAULT 0,
                    cooldown_bypass_users TEXT DEFAULT '[]',
                    cooldown_bypass_roles TEXT DEFAULT '[]',
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS level_rewards (
                    guild_id TEXT,
                    level INTEGER,
                    role_id TEXT,
                    PRIMARY KEY(guild_id, level),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_levels (
                    guild_id TEXT,
                    user_id TEXT,
                    xp REAL DEFAULT 0,
                    level INTEGER DEFAULT 0,
                    username TEXT,
                    last_message TIMESTAMP DEFAULT 0,
                    PRIMARY KEY(guild_id, user_id),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS warnings (
                    guild_id TEXT,
                    user_id TEXT,
                    warning_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT NOT NULL,
                    action_type TEXT DEFAULT 'warn',
                    moderator_id TEXT,
                    PRIMARY KEY(guild_id, user_id, warning_id),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS warning_actions (
                    guild_id TEXT,
                    warning_count INTEGER,
                    action TEXT NOT NULL,
                    duration_seconds INTEGER DEFAULT NULL,
                    PRIMARY KEY (guild_id, warning_count),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')
                
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS welcome_config (
                    guild_id TEXT PRIMARY KEY,
                    enabled BOOLEAN DEFAULT 0,
                    channel_id TEXT,
                    message_type TEXT DEFAULT 'text',
                    message_content TEXT,
                    embed_title TEXT,
                    embed_description TEXT,
                    embed_color INTEGER DEFAULT 0x00FF00,
                    embed_thumbnail BOOLEAN DEFAULT 1,
                    show_server_icon BOOLEAN DEFAULT 0,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')
                
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS goodbye_config (
                    guild_id TEXT PRIMARY KEY,
                    enabled BOOLEAN DEFAULT 0,
                    channel_id TEXT,
                    message_type TEXT DEFAULT 'text',
                    message_content TEXT,
                    embed_title TEXT,
                    embed_description TEXT,
                    embed_color INTEGER DEFAULT 0xFF0000,
                    embed_thumbnail BOOLEAN DEFAULT 1,
                    show_server_icon BOOLEAN DEFAULT 0,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')
                
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS spam_detection_config (
                    guild_id TEXT PRIMARY KEY,
                    spam_threshold INTEGER DEFAULT 5,
                    spam_time_window INTEGER DEFAULT 10,
                    mention_threshold INTEGER DEFAULT 3,
                    mention_time_window INTEGER DEFAULT 30,
                    excluded_channels TEXT DEFAULT '[]',
                    excluded_roles TEXT DEFAULT '[]',
                    enabled BOOLEAN DEFAULT 1,
                    spam_strikes_before_warning INTEGER DEFAULT 1,
                    no_xp_duration INTEGER DEFAULT 60,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS autoroles (
                    guild_id TEXT,
                    role_id TEXT,
                    PRIMARY KEY (guild_id, role_id),
                    FOREIGN KEY (guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')
                
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    details TEXT,
                    changes TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id TEXT
                )''')
                
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS game_roles (
                    guild_id TEXT,
                    game_name TEXT,
                    role_id TEXT,
                    required_minutes INTEGER,
                    PRIMARY KEY(guild_id, game_name)
                )''')
                
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_game_time (
                    user_id TEXT,
                    guild_id TEXT,
                    game_name TEXT,
                    total_time INTEGER DEFAULT 0,
                    last_start INTEGER DEFAULT NULL,
                    PRIMARY KEY(user_id, guild_id, game_name)
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS twitch_announcements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    streamer_id TEXT NOT NULL,
                    message TEXT DEFAULT '@everyone {streamer} is live! {title} - {url}',
                    last_announced TIMESTAMP DEFAULT NULL,
                    role_id TEXT DEFAULT NULL,
                    created_by TEXT DEFAULT NULL,
                    last_live_status BOOLEAN DEFAULT 0,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS youtube_announcements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    announce_channel_id TEXT DEFAULT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    message TEXT DEFAULT '@everyone {streamer} uploaded: {title} - {url}',
                    last_video_id TEXT DEFAULT NULL,
                    role_id TEXT DEFAULT NULL,
                    created_by TEXT DEFAULT NULL,
                    live_stream BOOLEAN DEFAULT 0,
                    recent_video_ids TEXT DEFAULT '[]',
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS role_menus (
                    id TEXT PRIMARY KEY,
                    guild_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    message_id TEXT,
                    config TEXT NOT NULL,
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS custom_forms (
                    id TEXT PRIMARY KEY,
                    guild_id TEXT,
                    name TEXT,
                    description TEXT,
                    config TEXT,
                    is_template BOOLEAN DEFAULT 0,
                    template_source TEXT,
                    share_id TEXT UNIQUE,
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS form_submissions (
                    id TEXT PRIMARY KEY,
                    form_id TEXT,
                    guild_id TEXT,
                    user_id TEXT,
                    submission_data TEXT,
                    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(form_id) REFERENCES custom_forms(id) ON DELETE CASCADE,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS pending_role_changes (
                    user_id TEXT,
                    guild_id TEXT,
                    added_roles TEXT,
                    removed_roles TEXT,
                    expiration_time TIMESTAMP,
                    PRIMARY KEY (user_id, guild_id),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS announcement_config (
                    guild_id TEXT PRIMARY KEY,
                    channel_id TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    role_id TEXT,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS announcements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT,
                    channel_id TEXT,
                    message_content TEXT NOT NULL,
                    sent_by TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    message_id TEXT,
                    is_successful BOOLEAN DEFAULT 1,
                    error_message TEXT,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_birthdays (
                    guild_id TEXT,
                    user_id TEXT,
                    username TEXT,
                    birthday_month INTEGER NOT NULL,
                    birthday_day INTEGER NOT NULL,
                    birthday_year INTEGER DEFAULT NULL,
                    timezone TEXT DEFAULT 'UTC',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(guild_id, user_id),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS birthday_config (
                    guild_id TEXT PRIMARY KEY,
                    birthday_channel_id TEXT,
                    birthday_message TEXT DEFAULT '🎉 Happy Birthday {user}! 🎂 Hope you have a wonderful day!',
                    birthday_role_id TEXT DEFAULT NULL,
                    birthday_role_to_give_id TEXT DEFAULT NULL,
                    announce_birthdays BOOLEAN DEFAULT 1,
                    show_age BOOLEAN DEFAULT 1,
                    birthday_embed_enabled BOOLEAN DEFAULT 1,
                    birthday_embed_title TEXT DEFAULT '🎂 Birthday Alert!',
                    birthday_embed_color INTEGER DEFAULT 16766720,
                    public_calendar BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crafty_instances (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    api_url TEXT NOT NULL,
                    api_token TEXT NOT NULL,
                    description TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crafty_servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    crafty_instance_id INTEGER NOT NULL,
                    server_id TEXT NOT NULL,
                    server_name TEXT NOT NULL,
                    description TEXT,
                    port INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(crafty_instance_id) REFERENCES crafty_instances(id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crafty_permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    crafty_server_id INTEGER NOT NULL,
                    user_id TEXT,
                    role_id TEXT,
                    can_start BOOLEAN DEFAULT 0,
                    can_stop BOOLEAN DEFAULT 0,
                    can_restart BOOLEAN DEFAULT 0,
                    can_manage BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE,
                    FOREIGN KEY(crafty_server_id) REFERENCES crafty_servers(id) ON DELETE CASCADE,
                    CHECK((user_id IS NOT NULL AND role_id IS NULL) OR (user_id IS NULL AND role_id IS NOT NULL))
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cloudflare_config (
                    guild_id TEXT PRIMARY KEY,
                    api_token TEXT NOT NULL,
                    zone_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS minecraft_dns_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    crafty_server_id INTEGER NOT NULL,
                    hostname TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    priority INTEGER DEFAULT 0,
                    weight INTEGER DEFAULT 5,
                    record_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE,
                    FOREIGN KEY(crafty_server_id) REFERENCES crafty_servers(id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS minecraft_server_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    crafty_server_id INTEGER NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('start', 'stop', 'restart')),
                    start_date TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    frequency_value INTEGER NOT NULL,
                    frequency_unit TEXT NOT NULL CHECK(frequency_unit IN ('minutes', 'hours', 'days', 'weeks', 'months', 'years')),
                    timezone TEXT DEFAULT 'UTC',
                    enabled BOOLEAN DEFAULT 1,
                    check_player_count BOOLEAN DEFAULT 0,
                    min_idle_minutes INTEGER DEFAULT 5,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE,
                    FOREIGN KEY(crafty_server_id) REFERENCES crafty_servers(id) ON DELETE CASCADE
                )''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS minecraft_server_idle_tracking (
                    crafty_server_id INTEGER PRIMARY KEY,
                    idle_since_timestamp INTEGER,
                    last_checked_timestamp INTEGER DEFAULT 0,
                    FOREIGN KEY(crafty_server_id) REFERENCES crafty_servers(id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS minecraft_schedule_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schedule_id INTEGER NOT NULL,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL,
                    player_count INTEGER,
                    error_message TEXT,
                    FOREIGN KEY(schedule_id) REFERENCES minecraft_server_schedules(id) ON DELETE CASCADE
                )''')
            
            # Restore on rejoin settings
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS restore_settings (
                    guild_id TEXT PRIMARY KEY,
                    restore_roles BOOLEAN DEFAULT 1,
                    restore_xp BOOLEAN DEFAULT 1,
                    restore_nickname BOOLEAN DEFAULT 1,
                    excluded_roles TEXT DEFAULT '[]',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            # User data snapshots for restoration
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_restore_snapshots (
                    guild_id TEXT,
                    user_id TEXT,
                    roles TEXT,
                    xp REAL,
                    level INTEGER,
                    nickname TEXT,
                    left_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (guild_id, user_id),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS banned_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    reason TEXT NOT NULL,
                    banned_by TEXT NOT NULL,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_banned_ips_active 
                ON banned_ips(ip_address, is_active)
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS banned_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL UNIQUE,
                    username TEXT,
                    reason TEXT NOT NULL,
                    banned_by TEXT NOT NULL,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_banned_users_active 
                ON banned_users(user_id, is_active)
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS banned_guilds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL UNIQUE,
                    guild_name TEXT,
                    reason TEXT NOT NULL,
                    banned_by TEXT NOT NULL,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_banned_guilds_active 
                ON banned_guilds(guild_id, is_active)
            ''')
            
            self.conn.commit()
            logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {str(e)}")
            raise
        finally:
            self.close()
            
    # Bot Admin Methods
    def create_bot_admin(self, username: str, password_hash: str):
        debug_print(f"Entering create_bot_admin with username: {username}", level="all")
        self.execute_query(
            '''INSERT INTO bot_admins (username, password_hash)
            VALUES (?, ?)''',
            (username, password_hash)
        )

    def get_bot_admin(self, username: str) -> Optional[dict]:
        debug_print(f"Entering get_bot_admin with username: {username}", level="all")
        return self.execute_query(
            'SELECT * FROM bot_admins WHERE username = ?',
            (username,),
            fetch='one'
        )

    def delete_bot_admin(self, username: str):
        debug_print(f"Entering delete_bot_admin with username: {username}", level="all")
        self.execute_query(
            'DELETE FROM bot_admins WHERE username = ?',
            (username,)
        )
        
    def update_admin_privileges(self, username: str, privileges: dict):
        debug_print(f"Entering update_admin_privileges with username: {username}, privileges: {privileges}", level="all")
        self.execute_query(
            '''INSERT OR REPLACE INTO admin_privileges 
            (username, can_manage_servers, can_edit_config, can_remove_bot, can_send_announcements, can_manage_settings, can_ban_users_guilds)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (username, 
             privileges.get('manage_servers', False),
             privileges.get('edit_config', False),
             privileges.get('remove_bot', False),
             privileges.get('send_announcements', False),
             privileges.get('manage_settings', False),
             privileges.get('ban_users_guilds', False))
        )

    def get_admin_privileges(self, username: str) -> dict:
        debug_print(f"Entering get_admin_privileges with username: {username}", level="all")
        return self.execute_query(
            'SELECT * FROM admin_privileges WHERE username = ?',
            (username,),
            fetch='one'
        )

    # User Methods
    def get_or_create_user(self, user_id: str, username: str = None, avatar_url: str = None):
        debug_print(f"Entering get_or_create_user with user_id: {user_id}, username: {username}, avatar_url: {avatar_url}", level="all")
        self.execute_query(
            '''INSERT OR IGNORE INTO users 
            (user_id, username, avatar_url) 
            VALUES (?, ?, ?)''',
            (user_id, username, avatar_url)
        )
        if username or avatar_url:
            self.execute_query(
                '''UPDATE users 
                SET username = COALESCE(?, username), 
                    avatar_url = COALESCE(?, avatar_url),
                    last_updated = CURRENT_TIMESTAMP
                WHERE user_id = ?''',
                (username, avatar_url, user_id)
            )
        return self.execute_query(
            'SELECT * FROM users WHERE user_id = ?',
            (user_id,),
            fetch='one'
        )

    # Guild Methods
    def get_guild(self, guild_id: str) -> Optional[dict]:
        debug_print(f"Entering get_guild with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM guilds WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def add_guild(self, guild_id: str, name: str, owner_id: str, icon: str = None):
        debug_print(f"Entering add_guild with guild_id: {guild_id}, name: {name}, owner_id: {owner_id}, icon: {icon}", level="all")
        try:
            self.execute_query(
                '''INSERT OR IGNORE INTO guilds 
                (guild_id, name, owner_id, icon) 
                VALUES (?, ?, ?, ?)''',
                (guild_id, name, owner_id, icon)
            )
        except Exception as e:
            debug_print(red(f"❌ Database error adding guild: {str(e)}"))
            raise

    def remove_guild(self, guild_id: str):
        debug_print(f"Entering remove_guild with guild_id: {guild_id}", level="all")
        try:
            with self.conn:
                self.conn.execute('DELETE FROM guilds WHERE guild_id = ?', (guild_id,))
        except sqlite3.Error as e:
            debug_print(red(f"Database error removing guild: {str(e)}"))
            raise
        
    def get_all_guilds(self) -> list:
        debug_print(f"Entering get_all_guilds", level="all")
        return self.execute_query(
            'SELECT guild_id as id, name, icon FROM guilds',
            fetch='all'
        )
        
    # MFA: TOTP secret
    def set_totp_secret(self, user_id: str, secret: str):
        self.execute_query(
            'INSERT INTO user_mfa (user_id, totp_secret, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET totp_secret=excluded.totp_secret, updated_at=CURRENT_TIMESTAMP',
            (user_id, secret), fetch='none')

    def get_totp_secret(self, user_id: str) -> str:
        row = self.execute_query('SELECT totp_secret FROM user_mfa WHERE user_id = ?', (user_id,), fetch='one')
        return row['totp_secret'] if row and row['totp_secret'] else None

    # MFA: Email OTP
    def set_email_otp(self, user_id: str, email: str, otp: str, expiry: int):
        self.execute_query(
            'INSERT INTO user_mfa (user_id, email, email_otp, email_otp_expiry, updated_at) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET email=?, email_otp=?, email_otp_expiry=?, updated_at=CURRENT_TIMESTAMP',
            (user_id, email, otp, expiry, email, otp, expiry), fetch='none')

    def get_email_otp(self, user_id: str):
        row = self.execute_query('SELECT email_otp, email_otp_expiry, email FROM user_mfa WHERE user_id = ?', (user_id,), fetch='one')
        return row if row else None

    def clear_email_otp(self, user_id: str):
        self.execute_query('UPDATE user_mfa SET email_otp=NULL, email_otp_expiry=NULL WHERE user_id = ?', (user_id,), fetch='none')

    # MFA: Enable/disable TOTP
    def set_totp_enabled(self, user_id: str, enabled: bool):
        if enabled:
            # Enable TOTP - update mfa_enabled if this is the first MFA method
            self.execute_query(
                'INSERT INTO user_mfa (user_id, mfa_enabled, updated_at) VALUES (?, 1, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET mfa_enabled=1, updated_at=CURRENT_TIMESTAMP',
                (user_id,), fetch='none')
        else:
            # Disable TOTP by clearing the secret
            self.execute_query('UPDATE user_mfa SET totp_secret=NULL WHERE user_id = ?', (user_id,), fetch='none')
            # Check if any MFA methods are still enabled
            self._update_overall_mfa_status(user_id)

    # MFA: Enable/disable Email
    def set_email_mfa_enabled(self, user_id: str, enabled: bool):
        if enabled:
            # Enable email MFA - update mfa_enabled if this is the first MFA method
            self.execute_query(
                'INSERT INTO user_mfa (user_id, mfa_enabled, updated_at) VALUES (?, 1, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET mfa_enabled=1, updated_at=CURRENT_TIMESTAMP',
                (user_id,), fetch='none')
        else:
            # Disable email MFA by clearing email settings
            self.execute_query('UPDATE user_mfa SET email=NULL, email_otp=NULL, email_otp_expiry=NULL WHERE user_id = ?', (user_id,), fetch='none')
            # Check if any MFA methods are still enabled
            self._update_overall_mfa_status(user_id)

    # Helper method to update overall MFA status
    def _update_overall_mfa_status(self, user_id: str):
        row = self.execute_query('SELECT totp_secret, email FROM user_mfa WHERE user_id = ?', (user_id,), fetch='one')
        if row:
            has_totp = bool(row['totp_secret'])
            has_email = bool(row['email'])
            overall_enabled = has_totp or has_email
            self.execute_query('UPDATE user_mfa SET mfa_enabled=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=?', 
                             (1 if overall_enabled else 0, user_id), fetch='none')

    # MFA: Check which methods are enabled
    def get_mfa_methods(self, user_id: str) -> dict:
        row = self.execute_query('SELECT totp_secret, email, mfa_enabled FROM user_mfa WHERE user_id = ?', (user_id,), fetch='one')
        if not row:
            return {'totp_enabled': False, 'email_enabled': False, 'any_enabled': False}
        
        totp_enabled = bool(row['totp_secret'])
        email_enabled = bool(row['email'])
        return {
            'totp_enabled': totp_enabled,
            'email_enabled': email_enabled,
            'any_enabled': bool(row['mfa_enabled'])
        }

    def is_mfa_enabled(self, user_id: str) -> bool:
        row = self.execute_query('SELECT mfa_enabled FROM user_mfa WHERE user_id = ?', (user_id,), fetch='one')
        return bool(row and row['mfa_enabled'])

    # MFA: Disable all methods
    def disable_all_mfa(self, user_id: str):
        """Disable all MFA methods for a user"""
        self.execute_query(
            'UPDATE user_mfa SET mfa_enabled=0, totp_secret=NULL, email=NULL, email_otp=NULL, email_otp_expiry=NULL, updated_at=CURRENT_TIMESTAMP WHERE user_id=?', 
            (user_id,), fetch='none')

    # MFA: Log attempt
    def log_mfa_attempt(self, user_id: str, method: str, success: bool):
        self.execute_query('INSERT INTO mfa_attempts (user_id, attempt_time, method, success) VALUES (?, ?, ?, ?)', (user_id, int(time.time()), method, 1 if success else 0), fetch='none')

    # MFA: Rate limit check (max 5 attempts in 5 min)
    def is_mfa_rate_limited(self, user_id: str, method: str, window_sec: int = 300, max_attempts: int = 5) -> bool:
        since = int(time.time()) - window_sec
        rows = self.execute_query('SELECT COUNT(*) as cnt FROM mfa_attempts WHERE user_id = ? AND method = ? AND attempt_time > ?', (user_id, method, since), fetch='one')
        return rows and rows['cnt'] >= max_attempts
        
    # Playlist Methods
    def create_playlist(self, user_id: str, name: str) -> str:
        debug_print(f"Creating playlist for user {user_id} with name '{name}'", level="all")
        playlist_id = str(uuid.uuid4())
        self.execute_query(
            '''INSERT INTO user_playlists (playlist_id, user_id, name) VALUES (?, ?, ?)''',
            (playlist_id, user_id, name)
        )
        return playlist_id

    def edit_playlist(self, playlist_id: str, user_id: str, new_name: str):
        debug_print(f"Editing playlist {playlist_id} for user {user_id} to new name '{new_name}'", level="all")
        self.execute_query(
            '''UPDATE user_playlists SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE playlist_id = ? AND user_id = ?''',
            (new_name, playlist_id, user_id)
        )

    def delete_playlist(self, playlist_id: str, user_id: str):
        debug_print(f"Deleting playlist {playlist_id} for user {user_id}", level="all")
        self.execute_query(
            '''DELETE FROM user_playlists WHERE playlist_id = ? AND user_id = ?''',
            (playlist_id, user_id)
        )

    def get_user_playlists(self, user_id: str) -> list:
        debug_print(f"Getting playlists for user {user_id}", level="all")
        result = self.execute_query(
            '''SELECT * FROM user_playlists WHERE user_id = ? ORDER BY updated_at DESC, created_at DESC''',
            (user_id,),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []

    def get_playlist(self, playlist_id: str, user_id: str) -> dict:
        debug_print(f"Getting playlist {playlist_id} for user {user_id}", level="all")
        return self.execute_query(
            '''SELECT * FROM user_playlists WHERE playlist_id = ? AND user_id = ?''',
            (playlist_id, user_id),
            fetch='one'
        )

    def add_track_to_playlist(self, playlist_id: str, user_id: str, title: str, url: str, duration: int = None, thumbnail: str = None):
        debug_print(f"Adding track to playlist {playlist_id} for user {user_id}: {title} ({url})", level="all")
        self.execute_query(
            '''INSERT OR IGNORE INTO playlist_tracks (playlist_id, title, url, duration, thumbnail) VALUES (?, ?, ?, ?, ?)''',
            (playlist_id, title, url, duration, thumbnail)
        )

    def remove_track_from_playlist(self, playlist_id: str, user_id: str, url: str):
        debug_print(f"Removing track from playlist {playlist_id} for user {user_id}: {url}", level="all")
        self.execute_query(
            '''DELETE FROM playlist_tracks WHERE playlist_id = ? AND url = ?''',
            (playlist_id, url)
        )

    def get_playlist_tracks(self, playlist_id: str, user_id: str) -> list:
        debug_print(f"Getting tracks for playlist {playlist_id} for user {user_id}", level="all")
        result = self.execute_query(
            '''SELECT * FROM playlist_tracks WHERE playlist_id = ? ORDER BY added_at ASC''',
            (playlist_id,),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []
           
    # Command Methods
    def get_all_commands(self):
        debug_print(f"Entering get_all_commands", level="all")
        return self.execute_query(
            'SELECT * FROM commands',
            fetch='all'
        )

    def get_guild_commands(self, guild_id):
        debug_print(f"Entering get_guild_commands with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT * FROM commands WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return {row['command_name']: dict(row) for row in result} if result else {}
        
    def get_guild_commands_list(self, guild_id: str) -> list:
        debug_print(f"Entering get_guild_commands_list with guild_id: {guild_id}", level="all")
        """Get list of command dictionaries (safe for iteration)"""
        result = self.execute_query(
            'SELECT * FROM commands WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []

    def get_commands(self, guild_id: str) -> list:
        debug_print(f"Entering get_commands with guild_id: {guild_id}", level="all")
        """Get list of command dictionaries"""
        return self.execute_query(
            '''SELECT * FROM commands 
            WHERE guild_id = ? 
            AND command_name IS NOT NULL 
            AND content IS NOT NULL''',
            (guild_id,),
            fetch='all'
        )
        return {row['command_name']: dict(row) for row in result} if result else {}
        
    def get_command(self, guild_id: str, command_name: str) -> Optional[dict]:
        debug_print(f"Entering get_command with guild_id: {guild_id}, command_name: {command_name}", level="all")
        """Get a single command by name"""
        return self.execute_query(
            '''SELECT * FROM commands 
            WHERE guild_id = ? 
            AND command_name = ?''',
            (guild_id, command_name),
            fetch='one'
        )

    def add_command(self, guild_id: str, command_name: str, content: str, 
               description: str = "Custom command", ephemeral: bool = True):
        debug_print(f"Entering add_command with guild_id: {guild_id}, command_name: {command_name}, content: {content}, description: {description}, ephemeral: {ephemeral}", level="all")
        self.execute_query(
            '''INSERT INTO commands 
            (guild_id, command_name, content, description, ephemeral)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(guild_id, command_name) 
            DO UPDATE SET 
                content = excluded.content,
                description = excluded.description,
                ephemeral = excluded.ephemeral''',
            (guild_id, command_name, content, description, int(ephemeral)))

    def remove_command(self, guild_id: str, command_name: str):
        debug_print(f"Entering remove_command with guild_id: {guild_id}, command_name: {command_name}", level="all")
        self.execute_query(
            'DELETE FROM commands WHERE guild_id = ? AND command_name = ?',
            (guild_id, command_name)
        )

    def get_command_permissions(self, guild_id, command_name):
        debug_print(f"Entering get_command_permissions with guild_id: {guild_id}, command_name: {command_name}", level="all")
        row = self.execute_query(
            'SELECT * FROM command_permissions WHERE guild_id = ? AND command_name = ?',
            (guild_id, command_name),
            fetch='one'
        )
        if not row:
            return {
                "allow_roles": [],
                "allow_users": [],
                "is_custom": False
            }
        allow_roles = json.loads(row.get("allow_roles", "[]"))
        # Convert 'everyone' to actual guild_id for backend logic
        allow_roles = [guild_id if r == 'everyone' else r for r in allow_roles]
        return {
            "allow_roles": allow_roles,
            "allow_users": json.loads(row.get("allow_users", "[]")),
            "is_custom": bool(row.get("is_custom", 0))
        }

    def set_command_permissions(self, guild_id, command_name, allow_roles, allow_users, is_custom=False):
        debug_print(f"Entering set_command_permissions with guild_id: {guild_id}, command_name: {command_name}, allow_roles: {allow_roles}, allow_users: {allow_users}, is_custom: {is_custom}", level="all")
        # Convert actual guild_id to 'everyone' for storage if present
        allow_roles_db = [('everyone' if r == guild_id else r) for r in allow_roles]
        self.execute_query(
            '''INSERT OR REPLACE INTO command_permissions
            (guild_id, command_name, allow_roles, allow_users, is_custom)
            VALUES (?, ?, ?, ?, ?)''',
            (
                guild_id, command_name,
                json.dumps(allow_roles_db), json.dumps(allow_users),
                int(is_custom)
            )
        )

    # Log Config Methods
    def get_log_config(self, guild_id: str) -> dict:
        debug_print(f"Entering get_log_config with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM log_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def update_log_config(self, guild_id: str, **kwargs):
        debug_print(f"Entering update_log_config with guild_id: {guild_id}, kwargs: {kwargs}", level="all")
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id]
        self.execute_query(
            f'UPDATE log_config SET {columns} WHERE guild_id = ?',
            tuple(values)
        )
        
    # Welcome Message Method
    def get_welcome_config(self, guild_id: str) -> dict:
        debug_print(f"Entering get_welcome_config with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM welcome_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        
    # Goodbye Message Method
    def get_goodbye_config(self, guild_id: str) -> dict:
        debug_print(f"Entering get_goodbye_config with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM goodbye_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    # Blocked Words Methods
    def get_blocked_words(self, guild_id: str) -> List[str]:
        debug_print(f"Entering get_blocked_words with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT word FROM blocked_words WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [row['word'] for row in result] if result else []

    def add_blocked_word(self, guild_id: str, word: str):
        debug_print(f"Entering add_blocked_word with guild_id: {guild_id}, word: {word}", level="all")
        self.execute_query(
            'INSERT OR IGNORE INTO blocked_words (guild_id, word) VALUES (?, ?)',
            (guild_id, word)
        )

    def remove_blocked_word(self, guild_id: str, word: str):
        debug_print(f"Entering remove_blocked_word with guild_id: {guild_id}, word: {word}", level="all")
        self.execute_query(
            'DELETE FROM blocked_words WHERE guild_id = ? AND word = ?',
            (guild_id, word)
        )

    # Blocked Embed Methods
    def get_blocked_embed(self, guild_id: str) -> dict:
        debug_print(f"Entering get_blocked_embed with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM blocked_word_embeds WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def update_blocked_embed(self, guild_id: str, **kwargs):
        debug_print(f"Entering update_blocked_embed with guild_id: {guild_id}, kwargs: {kwargs}", level="all")
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id]
        self.execute_query(
            f'UPDATE blocked_word_embeds SET {columns} WHERE guild_id = ?',
            tuple(values)
        )

    # Level System Methods
    def get_level_config(self, guild_id: str) -> dict:
        debug_print(f"Entering get_level_config with guild_id: {guild_id}", level="all")
        config = self.execute_query(
            'SELECT * FROM level_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        
        if not config:
            return {}
            
        # Create completely fresh dictionary by copying values explicitly
        fresh_config = {
            'guild_id': str(config['guild_id']),
            'cooldown': int(config.get('cooldown', 60)),
            'xp_min': int(config.get('xp_min', 15)),
            'xp_max': int(config.get('xp_max', 25)),
            'level_channel': str(config.get('level_channel', '')),
            'announce_level_up': bool(config.get('announce_level_up', 1)),
            'embed_title': str(config.get('embed_title', '🎉 Level Up!')),
            'embed_description': str(config.get('embed_description', '{user} has reached level **{level}**!')),
            'embed_color': int(config.get('embed_color', 16766720)),
            'give_xp_to_bots': bool(config.get('give_xp_to_bots', 1)),
            'give_xp_to_self': bool(config.get('give_xp_to_self', 1))
        }
        
        try:
            # Handle excluded_channels
            excluded_channels = config.get('excluded_channels', '[]')
            if isinstance(excluded_channels, str):
                fresh_config['excluded_channels'] = json.loads(excluded_channels)
            else:
                fresh_config['excluded_channels'] = excluded_channels or []
            if not isinstance(fresh_config['excluded_channels'], list):
                fresh_config['excluded_channels'] = []

            # Handle xp_boost_roles with enhanced validation
            xp_boost = config.get('xp_boost_roles', '{}')
            
            # Convert bytes to string if needed
            if isinstance(xp_boost, bytes):
                xp_boost = xp_boost.decode('utf-8')
            
            # Clean JSON string
            if isinstance(xp_boost, str):
                xp_boost = xp_boost.strip().strip('"').replace("\\", "")
            
            # Parse JSON with type checking
            parsed_boost = {}
            if xp_boost:
                try:
                    temp = json.loads(xp_boost)
                    if isinstance(temp, dict):
                        parsed_boost = temp
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {str(e)}")
                    logger.error(f"Problematic JSON: {xp_boost}")

            # Validate and convert types
            valid_boosts = {}
            for key, value in parsed_boost.items():
                try:
                    valid_boosts[str(key)] = int(value)
                except (ValueError, TypeError):
                    continue
                
            fresh_config['xp_boost_roles'] = valid_boosts

            # Handle cooldown bypass roles
            bypass_roles = config.get('cooldown_bypass_roles', '[]')
            if isinstance(bypass_roles, str):
                try:
                    fresh_config['cooldown_bypass_roles'] = json.loads(bypass_roles)
                except json.JSONDecodeError:
                    fresh_config['cooldown_bypass_roles'] = []
            else:
                fresh_config['cooldown_bypass_roles'] = bypass_roles or []

            # Handle cooldown bypass users
            bypass_users = config.get('cooldown_bypass_users', '[]')
            if isinstance(bypass_users, str):
                try:
                    fresh_config['cooldown_bypass_users'] = json.loads(bypass_users)
                except json.JSONDecodeError:
                    fresh_config['cooldown_bypass_users'] = []
            else:
                fresh_config['cooldown_bypass_users'] = bypass_users or []

        except Exception as e:
            logger.error(f"Error parsing level config: {str(e)}")
            fresh_config['xp_boost_roles'] = {}
            fresh_config['excluded_channels'] = []
            fresh_config['cooldown_bypass_roles'] = []
            fresh_config['cooldown_bypass_users'] = []
            
        return fresh_config
            
    def update_level_config(self, guild_id: str, **kwargs):
        debug_print(f"Entering update_level_config with guild_id: {guild_id}, kwargs: {kwargs}", level="all")
        update_data = {}
        for key, value in kwargs.items():
            if key in ['xp_boost_roles', 'excluded_channels', 'cooldown_bypass_roles', 'cooldown_bypass_users']:
                if key == 'xp_boost_roles':
                    update_data[key] = json.dumps(value) if value else '{}'
                else:
                    update_data[key] = json.dumps(value) if value else '[]'
            elif key in ['give_xp_to_bots', 'give_xp_to_self']:
                update_data[key] = 1 if value else 0
            else:
                update_data[key] = value
        
        columns = ', '.join(f"{k} = ?" for k in update_data)
        values = list(update_data.values()) + [guild_id]
        
        self.execute_query(
            f'UPDATE level_config SET {columns} WHERE guild_id = ?',
            tuple(values)
        )

    def get_cooldown_bypass_roles(self, guild_id: str) -> list:
        """Get list of role IDs that bypass XP cooldown for a guild"""
        debug_print(f"Entering get_cooldown_bypass_roles with guild_id: {guild_id}", level="all")
        config = self.get_level_config(guild_id)
        return config.get('cooldown_bypass_roles', [])

    def get_cooldown_bypass_users(self, guild_id: str) -> list:
        """Get list of user IDs that bypass XP cooldown for a guild"""
        debug_print(f"Entering get_cooldown_bypass_users with guild_id: {guild_id}", level="all")
        config = self.get_level_config(guild_id)
        return config.get('cooldown_bypass_users', [])

    def add_cooldown_bypass_role(self, guild_id: str, role_id: str):
        """Add a role to the cooldown bypass list"""
        debug_print(f"Entering add_cooldown_bypass_role with guild_id: {guild_id}, role_id: {role_id}", level="all")
        bypass_roles = self.get_cooldown_bypass_roles(guild_id)
        if role_id not in bypass_roles:
            bypass_roles.append(role_id)
            self.update_level_config(guild_id, cooldown_bypass_roles=bypass_roles)

    def remove_cooldown_bypass_role(self, guild_id: str, role_id: str):
        """Remove a role from the cooldown bypass list"""
        debug_print(f"Entering remove_cooldown_bypass_role with guild_id: {guild_id}, role_id: {role_id}", level="all")
        bypass_roles = self.get_cooldown_bypass_roles(guild_id)
        if role_id in bypass_roles:
            bypass_roles.remove(role_id)
            self.update_level_config(guild_id, cooldown_bypass_roles=bypass_roles)

    def add_cooldown_bypass_user(self, guild_id: str, user_id: str):
        """Add a user to the cooldown bypass list"""
        debug_print(f"Entering add_cooldown_bypass_user with guild_id: {guild_id}, user_id: {user_id}", level="all")
        bypass_users = self.get_cooldown_bypass_users(guild_id)
        if user_id not in bypass_users:
            bypass_users.append(user_id)
            self.update_level_config(guild_id, cooldown_bypass_users=bypass_users)

    def remove_cooldown_bypass_user(self, guild_id: str, user_id: str):
        """Remove a user from the cooldown bypass list"""
        debug_print(f"Entering remove_cooldown_bypass_user with guild_id: {guild_id}, user_id: {user_id}", level="all")
        bypass_users = self.get_cooldown_bypass_users(guild_id)
        if user_id in bypass_users:
            bypass_users.remove(user_id)
            self.update_level_config(guild_id, cooldown_bypass_users=bypass_users)

    def has_cooldown_bypass(self, guild_id: str, user_id: str, user_roles: list) -> bool:
        """Check if a user bypasses the XP cooldown based on their roles or direct assignment"""
        debug_print(f"Entering has_cooldown_bypass with guild_id: {guild_id}, user_id: {user_id}", level="all")
        # Check direct user bypass
        if user_id in self.get_cooldown_bypass_users(guild_id):
            return True
        
        # Check role-based bypass
        bypass_roles = self.get_cooldown_bypass_roles(guild_id)
        for role_id in user_roles:
            if str(role_id) in bypass_roles:
                return True
        
        return False

    def get_level_rewards(self, guild_id: str) -> dict:
        debug_print(f"Entering get_level_rewards with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT level, role_id FROM level_rewards WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return {row['level']: row['role_id'] for row in result} if result else {}

    def add_level_reward(self, guild_id: str, level: int, role_id: str):
        debug_print(f"Entering add_level_reward with guild_id: {guild_id}, level: {level}, role_id: {role_id}", level="all")
        self.execute_query(
            '''INSERT OR REPLACE INTO level_rewards 
            (guild_id, level, role_id) VALUES (?, ?, ?)''',
            (guild_id, level, role_id)
        )

    def remove_level_reward(self, guild_id: str, level: int):
        debug_print(f"Entering remove_level_reward with guild_id: {guild_id}, level: {level}", level="all")
        self.execute_query(
            'DELETE FROM level_rewards WHERE guild_id = ? AND level = ?',
            (guild_id, level)
        )

    def get_user_level(self, guild_id: str, user_id: str) -> dict:
        debug_print(f"Entering get_user_level with guild_id: {guild_id}, user_id: {user_id}", level="all")
        return self.execute_query(
            'SELECT * FROM user_levels WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id),
            fetch='one'
        )

    def update_user_level(self, guild_id: str, user_id: str, **kwargs):
        debug_print(f"Entering update_user_level with guild_id: {guild_id}, user_id: {user_id}, kwargs: {kwargs}", level="all")
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id, user_id]
        self.execute_query(
            f'UPDATE user_levels SET {columns} WHERE guild_id = ? AND user_id = ?',
            tuple(values)
        )
        
    # Auto Roles Methods
    def get_autoroles(self, guild_id: str) -> List[str]:
        debug_print(f"Entering get_autoroles with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT role_id FROM autoroles WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [row['role_id'] for row in result] if result else []

    def update_autoroles(self, guild_id: str, role_ids: List[str]):
        debug_print(f"Entering update_autoroles with guild_id: {guild_id}, role_ids: {role_ids}", level="all")
        with self.conn:
            self.conn.execute('DELETE FROM autoroles WHERE guild_id = ?', (guild_id,))
            if role_ids:
                self.conn.executemany(
                    'INSERT INTO autoroles (guild_id, role_id) VALUES (?, ?)',
                    [(guild_id, rid) for rid in role_ids]
                )

    # Warning Methods
    def get_warnings(self, guild_id: str, user_id: str) -> list:
        debug_print(f"Entering get_warnings with guild_id: {guild_id}, user_id: {user_id}", level="all")
        return self.execute_query(
            '''SELECT w.*, u.username 
            FROM warnings w
            LEFT JOIN users u ON w.user_id = u.user_id
            WHERE w.guild_id = ? AND w.user_id = ? 
            ORDER BY timestamp DESC''',
            (guild_id, user_id),
            fetch='all'
        )

    def add_warning(self, guild_id: str, user_id: str, reason: str, moderator_id: str = None) -> str:
        debug_print(f"Entering add_warning with guild_id: {guild_id}, user_id: {user_id}, reason: {reason}, moderator_id: {moderator_id}", level="all")
        warning_id = str(uuid.uuid4())
        self.execute_query(
            '''INSERT INTO warnings 
            (guild_id, user_id, warning_id, reason, moderator_id) 
            VALUES (?, ?, ?, ?, ?)''',
            (guild_id, user_id, warning_id, reason, moderator_id)
        )
        return warning_id

    def remove_warning(self, guild_id: str, user_id: str, warning_id: str):
        debug_print(f"Entering remove_warning with guild_id: {guild_id}, user_id: {user_id}, warning_id: {warning_id}", level="all")
        self.execute_query(
            '''DELETE FROM warnings 
            WHERE guild_id = ? AND user_id = ? AND warning_id = ?''',
            (guild_id, user_id, warning_id)
        )
        
    def update_warning_reason(self, guild_id: str, user_id: str, warning_id: str, new_reason: str):
        debug_print(f"Entering update_warning_reason with guild_id: {guild_id}, user_id: {user_id}, warning_id: {warning_id}, new_reason: {new_reason}", level="all")
        self.execute_query(
            '''UPDATE warnings 
            SET reason = ? 
            WHERE guild_id = ? AND user_id = ? AND warning_id = ?''',
            (new_reason, guild_id, user_id, warning_id)
        )

    # Warning Actions Config
    def get_warning_actions(self, guild_id: str) -> list:
        debug_print(f"Entering get_warning_actions with guild_id: {guild_id}", level="all")
        """Returns a list of dicts sorted by warning_count ascending."""
        actions = self.execute_query(
            '''SELECT * FROM warning_actions WHERE guild_id = ? ORDER BY warning_count ASC''',
            (guild_id,),
            fetch='all'
        )
        return [dict(a) for a in actions] if actions else []

    def set_warning_action(self, guild_id: str, warning_count: int, action: str, duration_seconds: int = None):
        debug_print(f"Entering set_warning_action with guild_id: {guild_id}, warning_count: {warning_count}, action: {action}, duration_seconds: {duration_seconds}", level="all")
        """Upsert a warning action rule."""
        self.execute_query(
            '''INSERT OR REPLACE INTO warning_actions (guild_id, warning_count, action, duration_seconds)
               VALUES (?, ?, ?, ?)''',
            (guild_id, warning_count, action, duration_seconds)
        )

    def remove_warning_action(self, guild_id: str, warning_count: int):
        debug_print(f"Entering remove_warning_action with guild_id: {guild_id}, warning_count: {warning_count}", level="all")
        self.execute_query(
            '''DELETE FROM warning_actions WHERE guild_id = ? AND warning_count = ?''',
            (guild_id, warning_count)
        )
        
    # Spam config methods
    def get_spam_config(self, guild_id: str) -> dict:
        debug_print(f"Entering get_spam_config with guild_id: {guild_id}", level="all")
        default = {
            "spam_threshold": 5,
            "spam_time_window": 10,
            "mention_threshold": 3,
            "mention_time_window": 30,
            "excluded_channels": [],
            "excluded_roles": [],
            "enabled": True,
            "spam_strikes_before_warning": 1,
            "no_xp_duration": 60
        }
        config = self.execute_query(
            'SELECT * FROM spam_detection_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        if not config:
            return default
        config = dict(config)
        config["excluded_channels"] = json.loads(config.get("excluded_channels", "[]"))
        config["excluded_roles"] = json.loads(config.get("excluded_roles", "[]"))
        # Ensure no_xp_duration is present and int
        config["no_xp_duration"] = int(config.get("no_xp_duration", 60))
        return {**default, **config}

    def update_spam_config(self, guild_id: str, **kwargs):
        debug_print(f"Entering update_spam_config with guild_id: {guild_id}, kwargs: {kwargs}", level="all")
        # Ensure all possible columns are present with defaults
        full_data = {
            "spam_threshold": 5,
            "spam_time_window": 10,
            "mention_threshold": 3,
            "mention_time_window": 30,
            "excluded_channels": [],
            "excluded_roles": [],
            "enabled": True,
            "spam_strikes_before_warning": 1,
            "no_xp_duration": 60,
            **kwargs
        }
        # Convert list fields to JSON strings
        full_data["excluded_channels"] = json.dumps(full_data["excluded_channels"])
        full_data["excluded_roles"] = json.dumps(full_data["excluded_roles"])
        # Convert enabled to int for SQLite
        full_data["enabled"] = int(full_data.get("enabled", True))
        # Ensure no_xp_duration is int
        full_data["no_xp_duration"] = int(full_data.get("no_xp_duration", 60))

        columns = list(full_data.keys())
        values = list(full_data.values())
        self.execute_query(
            '''INSERT INTO spam_detection_config 
                (guild_id, ''' + ', '.join(columns) + ''')
                VALUES (?, ''' + ', '.join(['?']*len(columns)) + ''')
                ON CONFLICT(guild_id) DO UPDATE SET 
                ''' + ', '.join([f"{col} = excluded.{col}" for col in columns]),
            [guild_id] + values,
            many=False
        )
        
    # Auto Roles on Game Play Time
    def setup_game_roles_table(self):
        debug_print(f"Entering setup_game_roles_table", level="all")
        self.execute_query('''
            CREATE TABLE IF NOT EXISTS game_roles (
                guild_id TEXT,
                game_name TEXT,
                role_id TEXT,
                required_time INTEGER,
                PRIMARY KEY(guild_id, game_name)
            )''')
            
        self.execute_query('''
            CREATE TABLE IF NOT EXISTS user_game_time (
                user_id TEXT,
                guild_id TEXT,
                game_name TEXT,
                total_time INTEGER DEFAULT 0,
                last_start INTEGER DEFAULT 0,
                PRIMARY KEY(user_id, guild_id, game_name)
            )''')

    def get_game_roles(self, guild_id: str) -> list:
        debug_print(f"Entering get_game_roles with guild_id: {guild_id}")
        """Query with string guild_id"""
        return self.execute_query(
            'SELECT * FROM game_roles WHERE guild_id = ?',
            (str(guild_id),),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []

    def update_game_role(self, guild_id, game_name, role_id, required_time):
        debug_print(f"Entering update_game_role with guild_id: {guild_id}, game_name: {game_name}, role_id: {role_id}, required_time: {required_time}", level="all")
        self.execute_query(
            '''INSERT OR REPLACE INTO game_roles 
            (guild_id, game_name, role_id, required_minutes)
            VALUES (?, ?, ?, ?)''',
            (str(guild_id), game_name.lower(), str(role_id), required_time),
            fetch='all'
        )

    def delete_game_role(self, guild_id, game_name):
        debug_print(f"Entering delete_game_role with guild_id: {guild_id}, game_name: {game_name}", level="all")
        self.execute_query(
            'DELETE FROM game_roles WHERE guild_id = ? AND game_name = ?',
            (guild_id, game_name)
        )

    def update_game_time(self, user_id, guild_id, game_name, start_time):
        debug_print(f"Entering update_game_time with user_id: {user_id}, guild_id: {guild_id}, game_name: {game_name}, start_time: {start_time}", level="all")
        self.execute_query('''
            INSERT OR REPLACE INTO user_game_time 
            (user_id, guild_id, game_name, last_start)
            VALUES (?, ?, ?, ?)
        ''', (user_id, guild_id, game_name, start_time))

    def add_game_session(self, user_id, guild_id, game_name, session_duration):
        debug_print(f"Entering add_game_session with user_id: {user_id}, guild_id: {guild_id}, game_name: {game_name}, session_duration: {session_duration}", level="all")
        self.execute_query('''
            UPDATE user_game_time 
            SET total_time = total_time + ?
            WHERE user_id = ? AND guild_id = ? AND game_name = ?
        ''', (session_duration, user_id, guild_id, game_name))

    # Twitch Status
    def get_twitch_live_status(self, ann_id: int) -> bool:
        debug_print(f"Entering get_twitch_live_status with ann_id: {ann_id}", level="all")
        row = self.execute_query(
            'SELECT last_live_status FROM twitch_announcements WHERE id = ?',
            (ann_id,),
            fetch='one'
        )
        return bool(row['last_live_status']) if row and row['last_live_status'] is not None else False

    def set_twitch_live_status(self, ann_id: int, is_live: bool):
        debug_print(f"Entering set_twitch_live_status with ann_id: {ann_id}, is_live: {is_live}", level="all")
        self.execute_query(
            'UPDATE twitch_announcements SET last_live_status = ? WHERE id = ?',
            (int(is_live), ann_id)
        )

    # Pending Role Changes
    def get_pending_role_changes(self, user_id: str, guild_id: str) -> dict:
        debug_print(f"Entering get_pending_role_changes with user_id: {user_id}, guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM pending_role_changes WHERE user_id = ? AND guild_id = ?',
            (user_id, guild_id),
            fetch='one'
        )

    def clear_pending_role_changes(self, user_id: str, guild_id: str):
        debug_print(f"Entering clear_pending_role_changes with user_id: {user_id}, guild_id: {guild_id}", level="all")
        self.execute_query(
            'DELETE FROM pending_role_changes WHERE user_id = ? AND guild_id = ?',
            (user_id, guild_id)
        )

    # Announcement Methods
    def get_announcement_config(self, guild_id: str) -> dict:
        debug_print(f"Entering get_announcement_config with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT * FROM announcement_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        return result if result else {'guild_id': guild_id, 'channel_id': None, 'enabled': True, 'role_id': None}

    def set_announcement_config(self, guild_id: str, channel_id: str = None, enabled: bool = True, role_id: str = None):
        debug_print(f"Entering set_announcement_config with guild_id: {guild_id}, channel_id: {channel_id}, enabled: {enabled}, role_id: {role_id}", level="all")
        self.execute_query(
            '''INSERT OR REPLACE INTO announcement_config 
            (guild_id, channel_id, enabled, role_id) VALUES (?, ?, ?, ?)''',
            (guild_id, channel_id, enabled, role_id)
        )

    def log_announcement(self, guild_id: str, channel_id: str, message_content: str, sent_by: str, 
                        message_id: str = None, is_successful: bool = True, error_message: str = None):
        debug_print(f"Entering log_announcement with guild_id: {guild_id}, sent_by: {sent_by}", level="all")
        self.execute_query(
            '''INSERT INTO announcements 
            (guild_id, channel_id, message_content, sent_by, message_id, is_successful, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (guild_id, channel_id, message_content, sent_by, message_id, is_successful, error_message)
        )

    def get_announcement_history(self, guild_id: str = None, limit: int = 50) -> list:
        debug_print(f"Entering get_announcement_history with guild_id: {guild_id}, limit: {limit}", level="all")
        if guild_id:
            return self.execute_query(
                '''SELECT * FROM announcements WHERE guild_id = ? 
                ORDER BY sent_at DESC LIMIT ?''',
                (guild_id, limit),
                fetch='all'
            )
        else:
            return self.execute_query(
                '''SELECT * FROM announcements 
                ORDER BY sent_at DESC LIMIT ?''',
                (limit,),
                fetch='all'
            )
    
    # Birthday Methods
    def get_user_birthday(self, guild_id: str, user_id: str) -> Optional[dict]:
        debug_print(f"Entering get_user_birthday with guild_id: {guild_id}, user_id: {user_id}", level="all")
        result = self.execute_query(
            'SELECT * FROM user_birthdays WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id),
            fetch='one'
        )
        return dict(result) if result else None

    def add_user_birthday(self, guild_id: str, user_id: str, username: str, 
                          birthday_month: int, birthday_day: int, birthday_year: int = None, timezone: str = 'UTC'):
        debug_print(f"Entering add_user_birthday with guild_id: {guild_id}, user_id: {user_id}, birthday_month: {birthday_month}, birthday_day: {birthday_day}", level="all")
        # First ensure the user exists in the users table
        self.get_or_create_user(user_id, username)
        
        # Add or update the birthday
        self.execute_query(
            '''INSERT OR REPLACE INTO user_birthdays 
               (guild_id, user_id, username, birthday_month, birthday_day, birthday_year, timezone, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (guild_id, user_id, username, birthday_month, birthday_day, birthday_year, timezone)
        )

    def remove_user_birthday(self, guild_id: str, user_id: str):
        debug_print(f"Entering remove_user_birthday with guild_id: {guild_id}, user_id: {user_id}", level="all")
        self.execute_query(
            'DELETE FROM user_birthdays WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id)
        )

    def update_user_birthday(self, guild_id: str, user_id: str, username: str = None,
                             birthday_month: int = None, birthday_day: int = None, 
                             birthday_year: int = None, timezone: str = None):
        debug_print(f"Entering update_user_birthday with guild_id: {guild_id}, user_id: {user_id}", level="all")
        
        # Build dynamic update query
        updates = []
        params = []
        
        if username is not None:
            updates.append("username = ?")
            params.append(username)
        if birthday_month is not None:
            updates.append("birthday_month = ?")
            params.append(birthday_month)
        if birthday_day is not None:
            updates.append("birthday_day = ?")
            params.append(birthday_day)
        if birthday_year is not None:
            updates.append("birthday_year = ?")
            params.append(birthday_year)
        if timezone is not None:
            updates.append("timezone = ?")
            params.append(timezone)
        
        if updates:
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.extend([guild_id, user_id])
            
            self.execute_query(
                f'UPDATE user_birthdays SET {", ".join(updates)} WHERE guild_id = ? AND user_id = ?',
                tuple(params)
            )

    def get_guild_birthdays(self, guild_id: str) -> List[dict]:
        debug_print(f"Entering get_guild_birthdays with guild_id: {guild_id}", level="all")
        results = self.execute_query(
            '''SELECT * FROM user_birthdays 
               WHERE guild_id = ? 
               ORDER BY birthday_month, birthday_day''',
            (guild_id,),
            fetch='all'
        )
        return [dict(result) for result in results] if results else []

    def get_upcoming_birthdays(self, guild_id: str, days_ahead: int = 7) -> List[dict]:
        debug_print(f"Entering get_upcoming_birthdays with guild_id: {guild_id}, days_ahead: {days_ahead}", level="all")
        from datetime import datetime, timedelta
        
        today = datetime.now()
        end_date = today + timedelta(days=days_ahead)
        
        # This is a simplified version - in a more sophisticated implementation,
        # I might want to handle year boundaries and timezone conversions
        results = self.execute_query(
            '''SELECT * FROM user_birthdays 
               WHERE guild_id = ?
               ORDER BY birthday_month, birthday_day''',
            (guild_id,),
            fetch='all'
        )
        
        upcoming = []
        if results:
            for result in results:
                birthday_dict = dict(result)
                try:
                    # Create birthday date for this year
                    birthday_this_year = datetime(today.year, birthday_dict['birthday_month'], birthday_dict['birthday_day'])
                    
                    # If birthday already passed this year, check next year
                    if birthday_this_year < today:
                        birthday_this_year = datetime(today.year + 1, birthday_dict['birthday_month'], birthday_dict['birthday_day'])
                    
                    # Check if it's within our window
                    if birthday_this_year <= end_date:
                        upcoming.append(birthday_dict)
                        
                except ValueError:
                    # Invalid date (like Feb 29 on non-leap year)
                    continue
        
        return upcoming

    def get_birthdays_by_month(self, guild_id: str, month: int) -> List[dict]:
        debug_print(f"Entering get_birthdays_by_month with guild_id: {guild_id}, month: {month}", level="all")
        results = self.execute_query(
            '''SELECT * FROM user_birthdays 
               WHERE guild_id = ? AND birthday_month = ?
               ORDER BY birthday_day''',
            (guild_id, month),
            fetch='all'
        )
        return [dict(result) for result in results] if results else []

    def get_birthday_config(self, guild_id: str) -> dict:
        debug_print(f"Entering get_birthday_config with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT * FROM birthday_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        
        if not result:
            # Return default configuration
            return {
                'guild_id': guild_id,
                'birthday_channel_id': None,
                'birthday_message': '🎉 Happy Birthday {user}! 🎂 Hope you have a wonderful day!',
                'birthday_role_id': None,
                'birthday_role_to_give_id': None,
                'announce_birthdays': True,
                'show_age': True,
                'birthday_embed_enabled': True,
                'birthday_embed_title': '🎂 Birthday Alert!',
                'birthday_embed_color': 16766720,  # Orange color
                'public_calendar': False,
            }
        
        return dict(result)

    # Crafty Controller Methods
    def create_crafty_instance(self, guild_id: str, name: str, api_url: str, api_token: str, description: str = None) -> int:
        """Create a new Crafty Controller instance"""
        debug_print(f"Entering create_crafty_instance with guild_id: {guild_id}, name: {name}", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''INSERT INTO crafty_instances (guild_id, name, api_url, api_token, description, updated_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (guild_id, name, api_url, api_token, description)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_crafty_instances(self, guild_id: str) -> List[dict]:
        """Get all Crafty instances for a guild"""
        debug_print(f"Entering get_crafty_instances with guild_id: {guild_id}", level="all")
        results = self.execute_query(
            'SELECT * FROM crafty_instances WHERE guild_id = ? ORDER BY name',
            (guild_id,),
            fetch='all'
        )
        return results or []

    def get_crafty_instance(self, instance_id: int) -> Optional[dict]:
        """Get a specific Crafty instance"""
        debug_print(f"Entering get_crafty_instance with instance_id: {instance_id}", level="all")
        return self.execute_query(
            'SELECT * FROM crafty_instances WHERE id = ?',
            (instance_id,),
            fetch='one'
        )

    def update_crafty_instance(self, instance_id: int, name: str = None, api_url: str = None, 
                               api_token: str = None, description: str = None, enabled: bool = None):
        """Update a Crafty instance"""
        debug_print(f"Entering update_crafty_instance with instance_id: {instance_id}", level="all")
        updates = []
        params = []
        
        if name is not None:
            updates.append('name = ?')
            params.append(name)
        if api_url is not None:
            updates.append('api_url = ?')
            params.append(api_url)
        if api_token is not None:
            updates.append('api_token = ?')
            params.append(api_token)
        if description is not None:
            updates.append('description = ?')
            params.append(description)
        if enabled is not None:
            updates.append('enabled = ?')
            params.append(enabled)
        
        if updates:
            updates.append('updated_at = CURRENT_TIMESTAMP')
            params.append(instance_id)
            
            self.execute_query(
                f'UPDATE crafty_instances SET {", ".join(updates)} WHERE id = ?',
                tuple(params)
            )

    def delete_crafty_instance(self, instance_id: int):
        """Delete a Crafty instance and all related data"""
        debug_print(f"Entering delete_crafty_instance with instance_id: {instance_id}", level="all")
        self.execute_query(
            'DELETE FROM crafty_instances WHERE id = ?',
            (instance_id,)
        )

    def create_crafty_server(self, crafty_instance_id: int, server_id: str, server_name: str, 
                             description: str = None, port: int = None) -> int:
        """Create a new Crafty server"""
        debug_print(f"Entering create_crafty_server with instance_id: {crafty_instance_id}, server_name: {server_name}", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''INSERT INTO crafty_servers (crafty_instance_id, server_id, server_name, description, port, updated_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (crafty_instance_id, server_id, server_name, description, port)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_crafty_servers(self, crafty_instance_id: int) -> List[dict]:
        """Get all servers for a Crafty instance"""
        debug_print(f"Entering get_crafty_servers with instance_id: {crafty_instance_id}", level="all")
        results = self.execute_query(
            'SELECT * FROM crafty_servers WHERE crafty_instance_id = ? ORDER BY server_name',
            (crafty_instance_id,),
            fetch='all'
        )
        return results or []

    def get_guild_crafty_servers(self, guild_id: str) -> List[dict]:
        """Get all Crafty servers for a guild with instance info"""
        debug_print(f"Entering get_guild_crafty_servers with guild_id: {guild_id}", level="all")
        results = self.execute_query(
            '''SELECT cs.*, ci.name as instance_name, ci.api_url, ci.api_token, ci.enabled as instance_enabled
               FROM crafty_servers cs
               JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
               WHERE ci.guild_id = ? AND ci.enabled = 1
               ORDER BY ci.name, cs.server_name''',
            (guild_id,),
            fetch='all'
        )
        return results or []

    def get_crafty_server(self, server_id: int) -> Optional[dict]:
        """Get a specific Crafty server with instance info"""
        debug_print(f"Entering get_crafty_server with server_id: {server_id}", level="all")
        return self.execute_query(
            '''SELECT cs.*, ci.name as instance_name, ci.api_url, ci.api_token, ci.guild_id
               FROM crafty_servers cs
               JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
               WHERE cs.id = ?''',
            (server_id,),
            fetch='one'
        )

    def update_crafty_server(self, server_id: int, server_name: str = None, description: str = None, port: int = None):
        """Update a Crafty server"""
        debug_print(f"Entering update_crafty_server with server_id: {server_id}", level="all")
        updates = []
        params = []
        
        if server_name is not None:
            updates.append('server_name = ?')
            params.append(server_name)
        if description is not None:
            updates.append('description = ?')
            params.append(description)
        if port is not None:
            updates.append('port = ?')
            params.append(port)
        
        if updates:
            updates.append('updated_at = CURRENT_TIMESTAMP')
            params.append(server_id)
            
            self.execute_query(
                f'UPDATE crafty_servers SET {", ".join(updates)} WHERE id = ?',
                tuple(params)
            )

    def delete_crafty_server(self, server_id: int):
        """Delete a Crafty server and all related data"""
        debug_print(f"Entering delete_crafty_server with server_id: {server_id}", level="all")
        self.execute_query(
            'DELETE FROM crafty_servers WHERE id = ?',
            (server_id,)
        )

    def create_crafty_permission(self, guild_id: str, crafty_server_id: int, user_id: str = None, 
                                 role_id: str = None, can_start: bool = False, can_stop: bool = False,
                                 can_restart: bool = False, can_manage: bool = False) -> int:
        """Create a new Crafty permission"""
        debug_print(f"Entering create_crafty_permission for server: {crafty_server_id}", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''INSERT INTO crafty_permissions (guild_id, crafty_server_id, user_id, role_id, 
                                               can_start, can_stop, can_restart, can_manage, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (guild_id, crafty_server_id, user_id, role_id, can_start, can_stop, can_restart, can_manage)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_crafty_permissions(self, crafty_server_id: int) -> List[dict]:
        """Get all permissions for a Crafty server"""
        debug_print(f"Entering get_crafty_permissions for server: {crafty_server_id}", level="all")
        results = self.execute_query(
            'SELECT * FROM crafty_permissions WHERE crafty_server_id = ?',
            (crafty_server_id,),
            fetch='all'
        )
        return results or []

    def get_user_crafty_permissions(self, guild_id: str, user_id: str, user_roles: List[str]) -> List[dict]:
        """Get all Crafty permissions for a user (direct and through roles)"""
        debug_print(f"Entering get_user_crafty_permissions for user: {user_id}", level="all")
        
        # Get direct user permissions
        user_perms = self.execute_query(
            '''SELECT cp.*, cs.server_name, ci.name as instance_name
               FROM crafty_permissions cp
               JOIN crafty_servers cs ON cp.crafty_server_id = cs.id
               JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
               WHERE cp.guild_id = ? AND cp.user_id = ? AND ci.enabled = 1''',
            (guild_id, user_id),
            fetch='all'
        ) or []
        
        # Get role permissions
        role_perms = []
        if user_roles:
            placeholders = ','.join(['?' for _ in user_roles])
            role_perms = self.execute_query(
                f'''SELECT cp.*, cs.server_name, ci.name as instance_name
                    FROM crafty_permissions cp
                    JOIN crafty_servers cs ON cp.crafty_server_id = cs.id
                    JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
                    WHERE cp.guild_id = ? AND cp.role_id IN ({placeholders}) AND ci.enabled = 1''',
                [guild_id] + user_roles,
                fetch='all'
            ) or []
        
        return user_perms + role_perms

    def delete_crafty_permission(self, permission_id: int):
        """Delete a Crafty permission"""
        debug_print(f"Entering delete_crafty_permission with id: {permission_id}", level="all")
        return self.execute_query(
            'DELETE FROM crafty_permissions WHERE id = ?',
            (permission_id,)
        )

    def add_crafty_permission(self, server_id: int, guild_id: str, user_id: int = None, role_id: int = None, 
                             can_start: bool = False, can_stop: bool = False, 
                             can_restart: bool = False, can_manage: bool = False) -> int:
        """Add a new Crafty permission"""
        debug_print(f"Adding Crafty permission for server {server_id}", level="all")
        return self.execute_query(
            '''INSERT INTO crafty_permissions 
               (crafty_server_id, guild_id, user_id, role_id, can_start, can_stop, can_restart, can_manage, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (server_id, guild_id, user_id, role_id, can_start, can_stop, can_restart, can_manage),
            fetch='lastrowid'
        )

    def get_crafty_permission_by_target(self, server_id: int, user_id: int = None, role_id: int = None):
        """Get permission for specific user or role on server"""
        debug_print(f"Getting Crafty permission for server {server_id}, user {user_id}, role {role_id}", level="all")
        if user_id:
            return self.execute_query(
                'SELECT * FROM crafty_permissions WHERE crafty_server_id = ? AND user_id = ?',
                (server_id, user_id),
                fetch='one'
            )
        elif role_id:
            return self.execute_query(
                'SELECT * FROM crafty_permissions WHERE crafty_server_id = ? AND role_id = ?',
                (server_id, role_id),
                fetch='one'
            )
        return None

    def get_crafty_permission(self, permission_id: int):
        """Get a Crafty permission by ID"""
        debug_print(f"Getting Crafty permission {permission_id}", level="all")
        return self.execute_query(
            'SELECT * FROM crafty_permissions WHERE id = ?',
            (permission_id,),
            fetch='one'
        )

    def get_crafty_permissions_for_server(self, server_id: int):
        """Get all permissions for a specific server"""
        debug_print(f"Getting all permissions for server {server_id}", level="all")
        return self.execute_query(
            'SELECT * FROM crafty_permissions WHERE crafty_server_id = ?',
            (server_id,),
            fetch='all'
        ) or []

    # Cloudflare Methods
    def set_cloudflare_config(self, guild_id: str, api_token: str, zone_id: str, domain: str, enabled: bool = True):
        """Set Cloudflare configuration for a guild"""
        debug_print(f"Entering set_cloudflare_config with guild_id: {guild_id}", level="all")
        self.execute_query(
            '''INSERT OR REPLACE INTO cloudflare_config 
               (guild_id, api_token, zone_id, domain, enabled, updated_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (guild_id, api_token, zone_id, domain, enabled)
        )

    def get_cloudflare_config(self, guild_id: str) -> Optional[dict]:
        """Get Cloudflare configuration for a guild"""
        debug_print(f"Entering get_cloudflare_config with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM cloudflare_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def delete_cloudflare_config(self, guild_id: str):
        """Delete Cloudflare configuration for a guild"""
        debug_print(f"Entering delete_cloudflare_config with guild_id: {guild_id}", level="all")
        self.execute_query(
            'DELETE FROM cloudflare_config WHERE guild_id = ?',
            (guild_id,)
        )

    def create_minecraft_dns_record(self, guild_id: str, crafty_server_id: int, hostname: str, 
                                    port: int, record_id: str = None, priority: int = 0, 
                                    weight: int = 5) -> int:
        """Create a new Minecraft DNS record"""
        debug_print(f"Entering create_minecraft_dns_record for server: {crafty_server_id}", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''INSERT INTO minecraft_dns_records (guild_id, crafty_server_id, hostname, port, priority, weight, record_id, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (guild_id, crafty_server_id, hostname, port, priority, weight, record_id)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_minecraft_dns_records(self, guild_id: str) -> List[dict]:
        """Get all Minecraft DNS records for a guild"""
        debug_print(f"Entering get_minecraft_dns_records with guild_id: {guild_id}", level="all")
        results = self.execute_query(
            '''SELECT mdr.*, cs.server_name, ci.name as instance_name
               FROM minecraft_dns_records mdr
               LEFT JOIN crafty_servers cs ON mdr.crafty_server_id = cs.id
               LEFT JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
               WHERE mdr.guild_id = ?
               ORDER BY mdr.hostname''',
            (guild_id,),
            fetch='all'
        )
        return results or []

    def get_minecraft_dns_record(self, record_id: int) -> Optional[dict]:
        """Get a specific Minecraft DNS record"""
        debug_print(f"Entering get_minecraft_dns_record with record_id: {record_id}", level="all")
        return self.execute_query(
            '''SELECT mdr.*, cs.server_name, ci.name as instance_name
               FROM minecraft_dns_records mdr
               LEFT JOIN crafty_servers cs ON mdr.crafty_server_id = cs.id
               LEFT JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
               WHERE mdr.id = ?''',
            (record_id,),
            fetch='one'
        )

    def update_minecraft_dns_record(self, record_id: int, hostname: str = None, port: int = None, 
                                    priority: int = None, weight: int = None,
                                    cloudflare_record_id: str = None):
        """Update a Minecraft DNS record"""
        debug_print(f"Entering update_minecraft_dns_record with record_id: {record_id}", level="all")
        updates = []
        params = []
        
        if hostname is not None:
            updates.append('hostname = ?')
            params.append(hostname)
        if port is not None:
            updates.append('port = ?')
            params.append(port)
        if priority is not None:
            updates.append('priority = ?')
            params.append(priority)
        if weight is not None:
            updates.append('weight = ?')
            params.append(weight)
        if cloudflare_record_id is not None:
            updates.append('record_id = ?')
            params.append(cloudflare_record_id)
        
        if updates:
            updates.append('updated_at = CURRENT_TIMESTAMP')
            params.append(record_id)
            
            self.execute_query(
                f'UPDATE minecraft_dns_records SET {", ".join(updates)} WHERE id = ?',
                tuple(params)
            )

    def delete_minecraft_dns_record(self, record_id: int):
        """Delete a Minecraft DNS record"""
        debug_print(f"Entering delete_minecraft_dns_record with record_id: {record_id}", level="all")
        self.execute_query(
            'DELETE FROM minecraft_dns_records WHERE id = ?',
            (record_id,)
        )

    def update_birthday_config(self, guild_id: str, **kwargs):
        debug_print(f"Entering update_birthday_config with guild_id: {guild_id}, kwargs: {kwargs}", level="all")
        
        # Get existing config or create default
        existing_config = self.get_birthday_config(guild_id)
        
        # Build update query dynamically
        updates = []
        params = []
        
        valid_fields = [
            'birthday_channel_id', 'birthday_message', 'birthday_role_id', 'birthday_role_to_give_id',
            'announce_birthdays', 'show_age', 'birthday_embed_enabled',
            'birthday_embed_title', 'birthday_embed_color', 'public_calendar'
        ]
        
        for field in valid_fields:
            if field in kwargs:
                updates.append(f"{field} = ?")
                params.append(kwargs[field])
        
        if updates:
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(guild_id)
            
            # Insert or update
            self.execute_query(
                f'''INSERT OR REPLACE INTO birthday_config 
                   (guild_id, birthday_channel_id, birthday_message, birthday_role_id, birthday_role_to_give_id,
                    announce_birthdays, show_age, birthday_embed_enabled, 
                    birthday_embed_title, birthday_embed_color, public_calendar, updated_at)
                   VALUES (
                       ?, 
                       COALESCE(?, (SELECT birthday_channel_id FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT birthday_message FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT birthday_role_id FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT birthday_role_to_give_id FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT announce_birthdays FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT show_age FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT birthday_embed_enabled FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT birthday_embed_title FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT birthday_embed_color FROM birthday_config WHERE guild_id = ?)),
                       COALESCE(?, (SELECT public_calendar FROM birthday_config WHERE guild_id = ?)),
                       CURRENT_TIMESTAMP
                   )''',
                (guild_id, 
                 kwargs.get('birthday_channel_id', existing_config.get('birthday_channel_id')), guild_id,
                 kwargs.get('birthday_message', existing_config.get('birthday_message')), guild_id,
                 kwargs.get('birthday_role_id', existing_config.get('birthday_role_id')), guild_id,
                 kwargs.get('birthday_role_to_give_id', existing_config.get('birthday_role_to_give_id')), guild_id,
                 kwargs.get('announce_birthdays', existing_config.get('announce_birthdays')), guild_id,
                 kwargs.get('show_age', existing_config.get('show_age')), guild_id,
                 kwargs.get('birthday_embed_enabled', existing_config.get('birthday_embed_enabled')), guild_id,
                 kwargs.get('birthday_embed_title', existing_config.get('birthday_embed_title')), guild_id,
                 kwargs.get('birthday_embed_color', existing_config.get('birthday_embed_color')), guild_id,
                 kwargs.get('public_calendar', existing_config.get('public_calendar')), guild_id)
            )

    # Minecraft Server Scheduling Methods
    def create_minecraft_schedule(self, guild_id: str, crafty_server_id: int, action: str, 
                                  start_date: str, start_time: str, frequency_value: int, 
                                  frequency_unit: str, timezone: str = 'UTC', enabled: bool = True,
                                  check_player_count: bool = False, min_idle_minutes: int = 5) -> int:
        """Create a new Minecraft server schedule"""
        debug_print(f"Creating minecraft schedule for guild {guild_id}, server {crafty_server_id}, action {action}", level="all")
        debug_print(f"Schedule parameters: enabled={enabled}, check_player_count={check_player_count}, min_idle_minutes={min_idle_minutes}", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''INSERT INTO minecraft_server_schedules 
               (guild_id, crafty_server_id, action, start_date, start_time, frequency_value, 
                frequency_unit, timezone, enabled, check_player_count, min_idle_minutes, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (guild_id, crafty_server_id, action, start_date, start_time, frequency_value, 
             frequency_unit, timezone, int(enabled), int(check_player_count), min_idle_minutes)
        )
        self.conn.commit()
        schedule_id = cursor.lastrowid
        debug_print(f"Created minecraft schedule with ID {schedule_id}", level="all")
        return schedule_id

    def get_minecraft_schedules(self, guild_id: str, crafty_server_id: int = None) -> List[dict]:
        """Get all minecraft schedules for a guild or specific server"""
        debug_print(f"Getting minecraft schedules for guild {guild_id}, server {crafty_server_id}", level="all")
        if crafty_server_id:
            query = '''SELECT ms.*, cs.server_name, ci.name as instance_name
                       FROM minecraft_server_schedules ms
                       JOIN crafty_servers cs ON ms.crafty_server_id = cs.id
                       JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
                       WHERE ms.guild_id = ? AND ms.crafty_server_id = ?
                       ORDER BY ms.start_date, ms.start_time'''
            params = (guild_id, crafty_server_id)
        else:
            query = '''SELECT ms.*, cs.server_name, ci.name as instance_name
                       FROM minecraft_server_schedules ms
                       JOIN crafty_servers cs ON ms.crafty_server_id = cs.id
                       JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
                       WHERE ms.guild_id = ?
                       ORDER BY cs.server_name, ms.start_date, ms.start_time'''
            params = (guild_id,)
        
        results = self.execute_query(query, params, fetch='all')
        return results or []

    def get_minecraft_schedule(self, schedule_id: int) -> Optional[dict]:
        """Get a specific minecraft schedule"""
        debug_print(f"Getting minecraft schedule {schedule_id}", level="all")
        return self.execute_query(
            '''SELECT ms.*, cs.server_name, ci.name as instance_name
               FROM minecraft_server_schedules ms
               JOIN crafty_servers cs ON ms.crafty_server_id = cs.id
               JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
               WHERE ms.id = ?''',
            (schedule_id,),
            fetch='one'
        )

    def update_minecraft_schedule(self, schedule_id: int, **kwargs):
        """Update a minecraft schedule"""
        debug_print(f"Updating minecraft schedule {schedule_id} with {kwargs}", level="all")
        updates = []
        params = []
        
        allowed_fields = ['action', 'start_date', 'start_time', 'frequency_value', 
                         'frequency_unit', 'timezone', 'enabled', 'check_player_count', 'min_idle_minutes']
        
        for field in allowed_fields:
            if field in kwargs:
                updates.append(f'{field} = ?')
                value = kwargs[field]
                # Convert boolean fields to integers for SQLite
                if field in ['enabled', 'check_player_count'] and isinstance(value, bool):
                    value = int(value)
                params.append(value)
        
        if updates:
            updates.append('updated_at = CURRENT_TIMESTAMP')
            params.append(schedule_id)
            
            self.execute_query(
                f'UPDATE minecraft_server_schedules SET {", ".join(updates)} WHERE id = ?',
                tuple(params)
            )

    def delete_minecraft_schedule(self, schedule_id: int):
        """Delete a minecraft schedule"""
        debug_print(f"Deleting minecraft schedule {schedule_id}", level="all")
        self.execute_query(
            'DELETE FROM minecraft_server_schedules WHERE id = ?',
            (schedule_id,)
        )

    def get_enabled_minecraft_schedules(self) -> List[dict]:
        """Get all enabled minecraft schedules across all guilds"""
        debug_print("Getting all enabled minecraft schedules", level="all")
        results = self.execute_query(
            '''SELECT ms.*, cs.server_name, cs.server_id, ci.name as instance_name, 
                      ci.api_url, ci.api_token, ci.guild_id
               FROM minecraft_server_schedules ms
               JOIN crafty_servers cs ON ms.crafty_server_id = cs.id
               JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id
               WHERE ms.enabled = 1 AND ci.enabled = 1
               ORDER BY ms.start_date, ms.start_time''',
            fetch='all'
        )
        return results or []

    def log_minecraft_schedule_execution(self, schedule_id: int, success: bool, 
                                       player_count: int = None, error_message: str = None):
        """Log a minecraft schedule execution"""
        debug_print(f"Logging minecraft schedule execution: {schedule_id}, success: {success}", level="all")
        self.execute_query(
            '''INSERT INTO minecraft_schedule_logs 
               (schedule_id, success, player_count, error_message)
               VALUES (?, ?, ?, ?)''',
            (schedule_id, success, player_count, error_message)
        )

    def get_minecraft_schedule_logs(self, schedule_id: int, limit: int = 50) -> List[dict]:
        """Get execution logs for a minecraft schedule"""
        debug_print(f"Getting minecraft schedule logs for {schedule_id}", level="all")
        results = self.execute_query(
            '''SELECT * FROM minecraft_schedule_logs 
               WHERE schedule_id = ? 
               ORDER BY executed_at DESC 
               LIMIT ?''',
            (schedule_id, limit),
            fetch='all'
        )
        return results or []

    # Minecraft Server Idle Tracking Methods
    def set_server_idle_since(self, crafty_server_id: int, idle_since_timestamp: int = None):
        """
        Set when a server became idle (0 players)
        If idle_since_timestamp is None, it marks the server as NOT idle
        """
        debug_print(f"Setting server {crafty_server_id} idle_since to {idle_since_timestamp}", level="all")
        import time
        current_time = int(time.time())
        
        if idle_since_timestamp is None:
            # Server is no longer idle (has players), remove the record
            debug_print(f"Deleting idle tracking for server {crafty_server_id}", level="all")
            self.execute_query(
                'DELETE FROM minecraft_server_idle_tracking WHERE crafty_server_id = ?',
                (crafty_server_id,),
                fetch='none'
            )
            debug_print(f"Successfully deleted idle tracking for server {crafty_server_id}", level="all")
        else:
            # Server is idle, set or update the idle_since timestamp
            debug_print(f"Inserting/updating idle tracking for server {crafty_server_id}: idle_since={idle_since_timestamp}, last_checked={current_time}", level="all")
            self.execute_query(
                '''INSERT OR REPLACE INTO minecraft_server_idle_tracking 
                   (crafty_server_id, idle_since_timestamp, last_checked_timestamp)
                   VALUES (?, ?, ?)''',
                (crafty_server_id, idle_since_timestamp, current_time),
                fetch='none'
            )
            debug_print(f"Successfully inserted/updated idle tracking for server {crafty_server_id}", level="all")

    def get_server_idle_since(self, crafty_server_id: int) -> Optional[int]:
        """
        Get the timestamp when a server became idle
        Returns None if server is not currently idle
        """
        debug_print(f"Getting idle_since for server {crafty_server_id}", level="all")
        result = self.execute_query(
            'SELECT idle_since_timestamp FROM minecraft_server_idle_tracking WHERE crafty_server_id = ?',
            (crafty_server_id,),
            fetch='one'
        )
        return result['idle_since_timestamp'] if result else None

    def update_server_idle_check(self, crafty_server_id: int):
        """Update the last_checked_timestamp for a server"""
        import time
        current_time = int(time.time())
        self.execute_query(
            'UPDATE minecraft_server_idle_tracking SET last_checked_timestamp = ? WHERE crafty_server_id = ?',
            (current_time, crafty_server_id)
        )
        
    # IP Ban Methods
    def add_ip_ban(self, ip_address: str, reason: str, banned_by: str, expires_at: str = None) -> int:
        """Add an IP address to the ban list"""
        debug_print(f"Adding IP ban for {ip_address} by {banned_by}", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''INSERT INTO banned_ips (ip_address, reason, banned_by, expires_at, is_active)
               VALUES (?, ?, ?, ?, 1)
               ON CONFLICT(ip_address) DO UPDATE SET
                   reason = excluded.reason,
                   banned_by = excluded.banned_by,
                   banned_at = CURRENT_TIMESTAMP,
                   expires_at = excluded.expires_at,
                   is_active = 1''',
            (ip_address, reason, banned_by, expires_at)
        )
        self.conn.commit()
        return cursor.lastrowid

    def remove_ip_ban(self, ip_address: str = None, ban_id: int = None):
        """Remove an IP ban by address or ID"""
        debug_print(f"Removing IP ban for {ip_address or ban_id}", level="all")
        if ban_id:
            self.execute_query(
                'DELETE FROM banned_ips WHERE id = ?',
                (ban_id,)
            )
        elif ip_address:
            self.execute_query(
                'DELETE FROM banned_ips WHERE ip_address = ?',
                (ip_address,)
            )

    def is_ip_banned(self, ip_address: str) -> bool:
        """Check if an IP address is currently banned"""
        debug_print(f"Checking if {ip_address} is banned", level="all")
        result = self.execute_query(
            '''SELECT id FROM banned_ips 
               WHERE ip_address = ? 
               AND is_active = 1 
               AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)''',
            (ip_address,),
            fetch='one'
        )
        return bool(result)

    def get_ip_ban_info(self, ip_address: str) -> Optional[dict]:
        """Get detailed information about an IP ban"""
        debug_print(f"Getting ban info for {ip_address}", level="all")
        return self.execute_query(
            '''SELECT * FROM banned_ips 
               WHERE ip_address = ? 
               AND is_active = 1 
               AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)''',
            (ip_address,),
            fetch='one'
        )

    def get_all_ip_bans(self, include_expired: bool = False) -> List[dict]:
        """Get all IP bans"""
        debug_print(f"Getting all IP bans, include_expired={include_expired}", level="all")
        if include_expired:
            query = 'SELECT * FROM banned_ips ORDER BY banned_at DESC'
            params = ()
        else:
            query = '''SELECT * FROM banned_ips 
                      WHERE is_active = 1 
                      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                      ORDER BY banned_at DESC'''
            params = ()
        
        results = self.execute_query(query, params, fetch='all')
        return results or []

    def deactivate_expired_ip_bans(self) -> int:
        """Deactivate expired IP bans and return count of deactivated bans"""
        debug_print("Deactivating expired IP bans", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''UPDATE banned_ips 
               SET is_active = 0 
               WHERE is_active = 1 
               AND expires_at IS NOT NULL 
               AND expires_at <= CURRENT_TIMESTAMP'''
        )
        self.conn.commit()
        return cursor.rowcount

    # User Ban Methods
    def add_user_ban(self, user_id: str, reason: str, banned_by: str, username: str = None, expires_at: str = None) -> int:
        """Add a user to the ban list"""
        debug_print(f"Adding user ban for {user_id} by {banned_by}", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''INSERT INTO banned_users (user_id, username, reason, banned_by, expires_at, is_active)
               VALUES (?, ?, ?, ?, ?, 1)
               ON CONFLICT(user_id) DO UPDATE SET
                   username = excluded.username,
                   reason = excluded.reason,
                   banned_by = excluded.banned_by,
                   banned_at = CURRENT_TIMESTAMP,
                   expires_at = excluded.expires_at,
                   is_active = 1''',
            (user_id, username, reason, banned_by, expires_at)
        )
        self.conn.commit()
        return cursor.lastrowid

    def remove_user_ban(self, user_id: str = None, ban_id: int = None):
        """Remove a user ban by user_id or ID"""
        debug_print(f"Removing user ban for {user_id or ban_id}", level="all")
        if ban_id:
            self.execute_query(
                'DELETE FROM banned_users WHERE id = ?',
                (ban_id,)
            )
        elif user_id:
            self.execute_query(
                'DELETE FROM banned_users WHERE user_id = ?',
                (user_id,)
            )

    def is_user_banned(self, user_id: str) -> bool:
        """Check if a user is currently banned"""
        debug_print(f"Checking if user {user_id} is banned", level="all")
        result = self.execute_query(
            '''SELECT id FROM banned_users 
               WHERE user_id = ? 
               AND is_active = 1 
               AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)''',
            (user_id,),
            fetch='one'
        )
        return bool(result)

    def get_user_ban_info(self, user_id: str) -> Optional[dict]:
        """Get detailed information about a user ban"""
        debug_print(f"Getting ban info for user {user_id}", level="all")
        return self.execute_query(
            '''SELECT * FROM banned_users 
               WHERE user_id = ? 
               AND is_active = 1 
               AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)''',
            (user_id,),
            fetch='one'
        )

    def get_all_user_bans(self, include_expired: bool = False) -> List[dict]:
        """Get all user bans"""
        debug_print(f"Getting all user bans, include_expired={include_expired}", level="all")
        if include_expired:
            query = 'SELECT * FROM banned_users ORDER BY banned_at DESC'
            params = ()
        else:
            query = '''SELECT * FROM banned_users 
                      WHERE is_active = 1 
                      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                      ORDER BY banned_at DESC'''
            params = ()
        
        results = self.execute_query(query, params, fetch='all')
        return results or []

    def deactivate_expired_user_bans(self) -> int:
        """Deactivate expired user bans and return count of deactivated bans"""
        debug_print("Deactivating expired user bans", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''UPDATE banned_users 
               SET is_active = 0 
               WHERE is_active = 1 
               AND expires_at IS NOT NULL 
               AND expires_at <= CURRENT_TIMESTAMP'''
        )
        self.conn.commit()
        return cursor.rowcount

    # Guild Ban Methods
    def add_guild_ban(self, guild_id: str, reason: str, banned_by: str, guild_name: str = None, expires_at: str = None) -> int:
        """Add a guild to the ban list"""
        debug_print(f"Adding guild ban for {guild_id} by {banned_by}", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''INSERT INTO banned_guilds (guild_id, guild_name, reason, banned_by, expires_at, is_active)
               VALUES (?, ?, ?, ?, ?, 1)
               ON CONFLICT(guild_id) DO UPDATE SET
                   guild_name = excluded.guild_name,
                   reason = excluded.reason,
                   banned_by = excluded.banned_by,
                   banned_at = CURRENT_TIMESTAMP,
                   expires_at = excluded.expires_at,
                   is_active = 1''',
            (guild_id, guild_name, reason, banned_by, expires_at)
        )
        self.conn.commit()
        return cursor.lastrowid

    def remove_guild_ban(self, guild_id: str = None, ban_id: int = None):
        """Remove a guild ban by guild_id or ID"""
        debug_print(f"Removing guild ban for {guild_id or ban_id}", level="all")
        if ban_id:
            self.execute_query(
                'DELETE FROM banned_guilds WHERE id = ?',
                (ban_id,)
            )
        elif guild_id:
            self.execute_query(
                'DELETE FROM banned_guilds WHERE guild_id = ?',
                (guild_id,)
            )

    def is_guild_banned(self, guild_id: str) -> bool:
        """Check if a guild is currently banned"""
        debug_print(f"Checking if guild {guild_id} is banned", level="all")
        result = self.execute_query(
            '''SELECT id FROM banned_guilds 
               WHERE guild_id = ? 
               AND is_active = 1 
               AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)''',
            (guild_id,),
            fetch='one'
        )
        return bool(result)

    def get_guild_ban_info(self, guild_id: str) -> Optional[dict]:
        """Get detailed information about a guild ban"""
        debug_print(f"Getting ban info for guild {guild_id}", level="all")
        return self.execute_query(
            '''SELECT * FROM banned_guilds 
               WHERE guild_id = ? 
               AND is_active = 1 
               AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)''',
            (guild_id,),
            fetch='one'
        )

    def get_all_guild_bans(self, include_expired: bool = False) -> List[dict]:
        """Get all guild bans"""
        debug_print(f"Getting all guild bans, include_expired={include_expired}", level="all")
        if include_expired:
            query = 'SELECT * FROM banned_guilds ORDER BY banned_at DESC'
            params = ()
        else:
            query = '''SELECT * FROM banned_guilds 
                      WHERE is_active = 1 
                      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                      ORDER BY banned_at DESC'''
            params = ()
        
        results = self.execute_query(query, params, fetch='all')
        return results or []

    def deactivate_expired_guild_bans(self) -> int:
        """Deactivate expired guild bans and return count of deactivated bans"""
        debug_print("Deactivating expired guild bans", level="all")
        cursor = self.conn.cursor()
        cursor.execute(
            '''UPDATE banned_guilds 
               SET is_active = 0 
               WHERE is_active = 1 
               AND expires_at IS NOT NULL 
               AND expires_at <= CURRENT_TIMESTAMP'''
        )
        self.conn.commit()
        return cursor.rowcount
    
    # Restore Settings Methods
    def get_restore_settings(self, guild_id: str) -> dict:
        row = self.execute_query('SELECT * FROM restore_settings WHERE guild_id = ?', (guild_id,), fetch='one')
        if not row:
            # Defaults: all enabled, no excluded roles
            return {
                'guild_id': guild_id,
                'restore_roles': True,
                'restore_xp': True,
                'restore_nickname': True,
                'excluded_roles': [],
            }
        settings = dict(row)
        settings['restore_roles'] = bool(settings.get('restore_roles', 1))
        settings['restore_xp'] = bool(settings.get('restore_xp', 1))
        settings['restore_nickname'] = bool(settings.get('restore_nickname', 1))
        try:
            settings['excluded_roles'] = json.loads(settings.get('excluded_roles', '[]'))
        except Exception:
            settings['excluded_roles'] = []
        return settings

    def update_restore_settings(self, guild_id: str, restore_roles: bool = None, restore_xp: bool = None, restore_nickname: bool = None, excluded_roles: list = None):
        current = self.get_restore_settings(guild_id)
        restore_roles = int(restore_roles) if restore_roles is not None else int(current['restore_roles'])
        restore_xp = int(restore_xp) if restore_xp is not None else int(current['restore_xp'])
        restore_nickname = int(restore_nickname) if restore_nickname is not None else int(current['restore_nickname'])
        excluded_roles = excluded_roles if excluded_roles is not None else current['excluded_roles']
        self.execute_query(
            '''INSERT OR REPLACE INTO restore_settings (guild_id, restore_roles, restore_xp, restore_nickname, excluded_roles, updated_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (guild_id, restore_roles, restore_xp, restore_nickname, json.dumps(excluded_roles))
        )

    # User Restore Snapshots Methods
    def save_user_restore_snapshot(self, guild_id: str, user_id: str, roles: list, xp: float, level: int, nickname: str):
        self.execute_query(
            '''INSERT OR REPLACE INTO user_restore_snapshots (guild_id, user_id, roles, xp, level, nickname, left_at)
               VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (guild_id, user_id, json.dumps(roles), xp, level, nickname)
        )

    def get_user_restore_snapshot(self, guild_id: str, user_id: str) -> dict:
        row = self.execute_query('SELECT * FROM user_restore_snapshots WHERE guild_id = ? AND user_id = ?', (guild_id, user_id), fetch='one')
        if not row:
            return None
        snap = dict(row)
        try:
            snap['roles'] = json.loads(snap.get('roles', '[]'))
        except Exception:
            snap['roles'] = []
        return snap

    def delete_user_restore_snapshot(self, guild_id: str, user_id: str):
        self.execute_query('DELETE FROM user_restore_snapshots WHERE guild_id = ? AND user_id = ?', (guild_id, user_id))

    # Database Validation
    def validate_schema(self):
        debug_print(f"Entering validate_schema", level="all")
        required_tables = {
            'warnings': ['guild_id', 'user_id', 'warning_id', 'reason']
        }
        
        for table, columns in required_tables.items():
            result = self.execute_query(f'PRAGMA table_info({table})', fetch='all')
            existing = [row['name'] for row in result]
            missing = set(columns) - set(existing)
            
            if missing:
                raise RuntimeError(f"Missing columns in {table}: {', '.join(missing)}")