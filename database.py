import sqlite3
import json
import logging
import threading
import uuid
import time
from typing import Optional, List, Dict, Any
from config import Config
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
            debug_print(f"❌ Database connection failed: {str(e)}")
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
                    FOREIGN KEY(username) REFERENCES bot_admins(username) ON DELETE CASCADE
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
            (username, can_manage_servers, can_edit_config, can_remove_bot)
            VALUES (?, ?, ?, ?)''',
            (username, 
             privileges.get('manage_servers', False),
             privileges.get('edit_config', False),
             privileges.get('remove_bot', False))
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
            debug_print(f"❌ Database error adding guild: {str(e)}")
            raise

    def remove_guild(self, guild_id: str):
        debug_print(f"Entering remove_guild with guild_id: {guild_id}", level="all")
        try:
            with self.conn:
                self.conn.execute('DELETE FROM guilds WHERE guild_id = ?', (guild_id,))
        except sqlite3.Error as e:
            debug_print(f"Database error removing guild: {str(e)}")
            raise
        
    def get_all_guilds(self) -> list:
        debug_print(f"Entering get_all_guilds", level="all")
        return self.execute_query(
            'SELECT guild_id as id, name, icon FROM guilds',
            fetch='all'
        )
        
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
        
        if config:
            config = dict(config)
            try:
                # Handle excluded_channels
                excluded_channels = config.get('excluded_channels', '[]')
                if isinstance(excluded_channels, str):
                    config['excluded_channels'] = json.loads(excluded_channels)
                if not isinstance(config['excluded_channels'], list):
                    config['excluded_channels'] = []

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
                    
                config['xp_boost_roles'] = valid_boosts

                # Handle give_xp_to_bots and give_xp_to_self
                config['give_xp_to_bots'] = bool(config.get('give_xp_to_bots', 1))
                config['give_xp_to_self'] = bool(config.get('give_xp_to_self', 1))

            except Exception as e:
                logger.error(f"Error parsing level config: {str(e)}")
                config['xp_boost_roles'] = {}
                config['excluded_channels'] = []
                config['give_xp_to_bots'] = True
                config['give_xp_to_self'] = True
                
        return config or {}
            
    def update_level_config(self, guild_id: str, **kwargs):
        debug_print(f"Entering update_level_config with guild_id: {guild_id}, kwargs: {kwargs}", level="all")
        update_data = {}
        for key, value in kwargs.items():
            if key in ['xp_boost_roles', 'excluded_channels']:
                update_data[key] = json.dumps(value) if value else '{}' if key == 'xp_boost_roles' else '[]'
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