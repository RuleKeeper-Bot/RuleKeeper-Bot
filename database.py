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
        """
        No-op fallback for an optional debug printing function.
        
        This placeholder matches the signature of the optional `bot.debug_print` used elsewhere so callers can invoke it with arbitrary positional and keyword arguments; it intentionally does nothing.
        """
        pass

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_path: str = str(Config.DATABASE_PATH)):
        """
        Initialize the Database instance and verify connectivity.
        
        Creates thread-local storage, stores the provided SQLite file path, establishes an initial connection to validate the database (raises on failure), and configures the connection to return rows as sqlite3.Row.
        
        Parameters:
            db_path (str): Path to the SQLite database file (defaults to Config.DATABASE_PATH).
        """
        debug_print(f"Entering Database.__init__ with db_path: {db_path}", level="all")
        self.db_path = db_path
        self.local = threading.local()
        self._verify_connection()
        self.conn.row_factory = sqlite3.Row
        
    def _verify_connection(self):
        """
        Verify that the configured SQLite database is reachable and correctly initialized.
        
        Opens a temporary connection to self.db_path with a 30s timeout (thread-safe), enables foreign key support and WAL journaling, executes a simple test query (SELECT 1), and closes the connection. Raises any exception encountered if the connection or verification fails.
        """
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
        """
        Return the thread-local SQLite connection, creating it if missing.
        
        This property provides a per-thread sqlite3.Connection stored on thread-local
        storage. If no connection exists for the current thread (or it is None),
        _connect() is invoked to create and configure one before returning it.
        
        Returns:
            sqlite3.Connection: The SQLite connection instance for the current thread.
        """
        debug_print(f"Accessing conn property")
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            self._connect()
        return self.local.conn

    def _connect(self):
        """
        Create and configure a per-thread SQLite connection and store it on self.local.conn.
        
        The new connection uses the instance's db_path, sets a 30s timeout, allows cross-thread usage (check_same_thread=False),
        returns rows as sqlite3.Row, and enables foreign key support and WAL journaling.
        
        Side effects:
        - Assigns the sqlite3.Connection to self.local.conn.
        - Should be called when a thread needs its own DB connection.
        """
        debug_print(f"Entering _connect", level="all")
        self.local.conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        self.local.conn.row_factory = sqlite3.Row
        self.local.conn.execute("PRAGMA foreign_keys = ON")
        self.local.conn.execute("PRAGMA journal_mode=WAL;")
        logger.debug(f"Created new connection in thread {threading.get_ident()}")

    def close(self):
        """
        Close and clear the current thread-local SQLite connection.
        
        If a per-thread connection exists (self.local.conn), it will be closed and removed from thread-local storage so subsequent access will create a new connection. No value is returned.
        """
        debug_print(f"Entering close", level="all")
        if hasattr(self.local, 'conn') and self.local.conn:
            self.local.conn.close()
            self.local.conn = None
            logger.debug(f"Closed connection in thread {threading.get_ident()}")

    def execute_query(self, query: str, params=(), fetch: str = 'all', many: bool = False, retries: int = 5, retry_delay: float = 0.2):
        """
        Execute an SQL query against the database with optional fetch modes and automatic retry on locked database.
        
        Detailed behavior:
        - Executes `query` with `params`. If `many` is True, `params` must be an iterable of parameter sequences and executemany() is used.
        - `fetch` controls result extraction:
          - 'all' (default): returns a list of rows as dicts.
          - 'one': returns a single row as a dict, or None if no row.
        - If the SQL statement is not a SELECT, the connection is committed before returning.
        - On sqlite3.OperationalError containing "database is locked", the call will retry up to `retries` times, sleeping `retry_delay` seconds between attempts. If all retries fail, the last caught exception is raised.
        
        Parameters:
            query (str): SQL statement to execute.
            params: Parameters for the SQL statement (tuple/sequence) or an iterable of parameter sequences when `many` is True.
            fetch (str): 'all' or 'one' (case-insensitive) to select fetch behavior.
            many (bool): If True, use executemany() with `params`.
            retries (int): Number of attempts when encountering a locked database.
            retry_delay (float): Seconds to wait between retry attempts.
        
        Returns:
            list[dict] | dict | None: Result rows as a list of dicts for 'all', a single dict or None for 'one'.
        
        Raises:
            sqlite3.Error: Any non-retryable sqlite3 errors are propagated.
            sqlite3.OperationalError: If retries are exhausted due to a persistent "database is locked" condition, the last OperationalError is raised.
        """
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
        """
        Initialize the SQLite database schema used by the application.
        
        Creates all required tables (admins, guilds, users, playlists, commands, logging/level/spam configs, warnings, announcements, game-role tracking, forms, role menus, pending role changes, etc.) if they do not already exist, and commits the schema changes. Ensures foreign keys and required defaults are present for each table.
        
        Raises:
            sqlite3.Error: If any SQL execution fails during initialization.
        """
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
        """
        Create a new bot admin record.
        
        Inserts a row into the `bot_admins` table. The password provided must already be hashed; this function does not perform hashing or validation.
        
        Parameters:
            username (str): Unique username for the bot admin.
            password_hash (str): Hash of the admin's password to store.
        """
        debug_print(f"Entering create_bot_admin with username: {username}", level="all")
        self.execute_query(
            '''INSERT INTO bot_admins (username, password_hash)
            VALUES (?, ?)''',
            (username, password_hash)
        )

    def get_bot_admin(self, username: str) -> Optional[dict]:
        """
        Retrieve a bot administrator record by username.
        
        Parameters:
            username (str): The bot admin's username to look up.
        
        Returns:
            dict | None: A mapping of the bot_admins row (column names to values) if found, otherwise None.
        """
        debug_print(f"Entering get_bot_admin with username: {username}", level="all")
        return self.execute_query(
            'SELECT * FROM bot_admins WHERE username = ?',
            (username,),
            fetch='one'
        )

    def delete_bot_admin(self, username: str):
        """
        Delete the bot administrator record with the given username.
        
        Parameters:
            username (str): Admin username to remove from the bot_admins table.
        """
        debug_print(f"Entering delete_bot_admin with username: {username}", level="all")
        self.execute_query(
            'DELETE FROM bot_admins WHERE username = ?',
            (username,)
        )
        
    def update_admin_privileges(self, username: str, privileges: dict):
        """
        Update or insert admin privilege flags for a bot administrator.
        
        Writes an upsert into the admin_privileges table for the given username. The
        privileges dict may contain boolean keys that control stored flags; absent keys
        are treated as False.
        
        Parameters:
            username (str): Admin username key for the privileges row.
            privileges (dict): Permission flags. Recognized keys:
                - "manage_servers": whether the admin can manage servers.
                - "edit_config": whether the admin can edit configuration.
                - "remove_bot": whether the admin can remove the bot.
        """
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
        """
        Return the admin privileges row for a given bot admin username.
        
        Parameters:
            username (str): The bot admin's username to look up.
        
        Returns:
            dict or None: A dictionary representing the matching row from the `admin_privileges` table,
            or None if no row exists.
        """
        debug_print(f"Entering get_admin_privileges with username: {username}", level="all")
        return self.execute_query(
            'SELECT * FROM admin_privileges WHERE username = ?',
            (username,),
            fetch='one'
        )

    # User Methods
    def get_or_create_user(self, user_id: str, username: str = None, avatar_url: str = None):
        """
        Get a user row by ID, creating the user if it doesn't exist and optionally updating username and avatar.
        
        If the user is missing this inserts a new row with the provided values. If `username` or `avatar_url` are supplied they will be merged into the existing row (using COALESCE) and `last_updated` will be set to the current timestamp.
        
        Parameters:
            user_id (str): Unique user identifier.
            username (str, optional): New username to set if provided.
            avatar_url (str, optional): New avatar URL to set if provided.
        
        Returns:
            dict or None: The user row as a mapping (sqlite row converted to dict) or None if the row could not be retrieved.
        """
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
        """
        Return the guild row for the given guild_id.
        
        Parameters:
            guild_id (str): Snowflake or identifier of the guild to look up.
        
        Returns:
            dict | None: A mapping of column names to values for the guild row (from the `guilds` table), or None if no guild with the provided id exists.
        """
        debug_print(f"Entering get_guild with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM guilds WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def add_guild(self, guild_id: str, name: str, owner_id: str, icon: str = None):
        """
        Insert a guild row into the database if it does not already exist.
        
        Parameters:
            guild_id (str): Guild identifier.
            name (str): Guild name.
            owner_id (str): ID of the guild owner.
            icon (str, optional): URL or identifier for the guild icon.
        
        Notes:
            Uses `INSERT OR IGNORE` so existing rows with the same `guild_id` are left unchanged.
            Database errors from the underlying query are propagated as exceptions.
        """
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
        """
        Remove a guild record from the database.
        
        Deletes the row in the `guilds` table matching the provided guild_id inside a transaction.
        
        Parameters:
            guild_id (str): The guild's unique identifier to remove.
        
        Raises:
            sqlite3.Error: If the database operation fails.
        """
        debug_print(f"Entering remove_guild with guild_id: {guild_id}", level="all")
        try:
            with self.conn:
                self.conn.execute('DELETE FROM guilds WHERE guild_id = ?', (guild_id,))
        except sqlite3.Error as e:
            debug_print(f"Database error removing guild: {str(e)}")
            raise
        
    def get_all_guilds(self) -> list:
        """
        Return a list of all guilds stored in the database.
        
        Each item is a dict with keys:
        - id: guild_id (str)
        - name: guild name (str)
        - icon: guild icon URL or None (str | None)
        
        Returns:
            list: A list of guild dictionaries; empty list if no guilds exist.
        """
        debug_print(f"Entering get_all_guilds", level="all")
        return self.execute_query(
            'SELECT guild_id as id, name, icon FROM guilds',
            fetch='all'
        )
        
    # Playlist Methods
    def create_playlist(self, user_id: str, name: str) -> str:
        """
        Create a new playlist record for a user and return its generated UUID.
        
        Inserts a row into the user_playlists table owned by the given user.
        
        Parameters:
            user_id (str): Owner's user ID.
            name (str): Playlist name.
        
        Returns:
            str: Newly created playlist_id (UUID4 string).
        """
        debug_print(f"Creating playlist for user {user_id} with name '{name}'", level="all")
        playlist_id = str(uuid.uuid4())
        self.execute_query(
            '''INSERT INTO user_playlists (playlist_id, user_id, name) VALUES (?, ?, ?)''',
            (playlist_id, user_id, name)
        )
        return playlist_id

    def edit_playlist(self, playlist_id: str, user_id: str, new_name: str):
        """
        Update the name of a user's playlist.
        
        Updates the playlist's name and sets its updated_at timestamp for the row matching the given playlist_id and user_id. Does nothing if no matching playlist exists.
        """
        debug_print(f"Editing playlist {playlist_id} for user {user_id} to new name '{new_name}'", level="all")
        self.execute_query(
            '''UPDATE user_playlists SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE playlist_id = ? AND user_id = ?''',
            (new_name, playlist_id, user_id)
        )

    def delete_playlist(self, playlist_id: str, user_id: str):
        """
        Delete a user's playlist.
        
        Deletes the playlist with the given playlist_id only if it belongs to the specified user_id.
        
        Parameters:
            playlist_id (str): UUID of the playlist to delete.
            user_id (str): ID of the user who owns the playlist.
        """
        debug_print(f"Deleting playlist {playlist_id} for user {user_id}", level="all")
        self.execute_query(
            '''DELETE FROM user_playlists WHERE playlist_id = ? AND user_id = ?''',
            (playlist_id, user_id)
        )

    def get_user_playlists(self, user_id: str) -> list:
        """
        Return all playlists belonging to a user, ordered by most recently updated then created.
        
        Parameters:
            user_id (str): ID of the user whose playlists to retrieve.
        
        Returns:
            list[dict]: A list of playlist records (each as a dict). Returns an empty list when the user has no playlists.
        """
        debug_print(f"Getting playlists for user {user_id}", level="all")
        result = self.execute_query(
            '''SELECT * FROM user_playlists WHERE user_id = ? ORDER BY updated_at DESC, created_at DESC''',
            (user_id,),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []

    def get_playlist(self, playlist_id: str, user_id: str) -> dict:
        """
        Retrieve a single playlist belonging to a user.
        
        Parameters:
            playlist_id (str): Playlist UUID.
            user_id (str): Owner's user ID.
        
        Returns:
            dict | None: Playlist row as a dict (columns from user_playlists) or None if not found.
        """
        debug_print(f"Getting playlist {playlist_id} for user {user_id}", level="all")
        return self.execute_query(
            '''SELECT * FROM user_playlists WHERE playlist_id = ? AND user_id = ?''',
            (playlist_id, user_id),
            fetch='one'
        )

    def add_track_to_playlist(self, playlist_id: str, user_id: str, title: str, url: str, duration: int = None, thumbnail: str = None):
        """
        Add a track to a user's playlist.
        
        Inserts a new row into playlist_tracks for the given playlist_id with title, url, optional duration (seconds) and thumbnail.
        If a matching track already exists (based on the table's uniqueness constraints), the insert is ignored (no error).
        """
        debug_print(f"Adding track to playlist {playlist_id} for user {user_id}: {title} ({url})", level="all")
        self.execute_query(
            '''INSERT OR IGNORE INTO playlist_tracks (playlist_id, title, url, duration, thumbnail) VALUES (?, ?, ?, ?, ?)''',
            (playlist_id, title, url, duration, thumbnail)
        )

    def remove_track_from_playlist(self, playlist_id: str, user_id: str, url: str):
        """
        Remove a track from a playlist.
        
        Deletes any playlist_tracks rows matching the given playlist_id and track URL. The provided user_id is accepted for caller context but is not used in the deletion query (authorization must be enforced by the caller if required).
        """
        debug_print(f"Removing track from playlist {playlist_id} for user {user_id}: {url}", level="all")
        self.execute_query(
            '''DELETE FROM playlist_tracks WHERE playlist_id = ? AND url = ?''',
            (playlist_id, url)
        )

    def get_playlist_tracks(self, playlist_id: str, user_id: str) -> list:
        """
        Return the tracks for a playlist as a list of row dictionaries ordered by insertion time.
        
        Parameters:
            playlist_id (str): UUID of the playlist to fetch tracks for.
            user_id (str): Provided for API compatibility but not used by this query.
        
        Returns:
            list[dict]: Rows from `playlist_tracks` (fields such as `title`, `url`, `duration`, `thumbnail`, `added_at`) ordered by `added_at` ascending. Empty list if no tracks found.
        """
        debug_print(f"Getting tracks for playlist {playlist_id} for user {user_id}", level="all")
        result = self.execute_query(
            '''SELECT * FROM playlist_tracks WHERE playlist_id = ? ORDER BY added_at ASC''',
            (playlist_id,),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []
           
    # Command Methods
    def get_all_commands(self):
        """
        Return all entries from the `commands` table.
        
        Returns:
            list[dict]: A list of rows from the `commands` table as dictionaries (column names -> values). Empty list if no commands exist.
        """
        debug_print(f"Entering get_all_commands", level="all")
        return self.execute_query(
            'SELECT * FROM commands',
            fetch='all'
        )

    def get_guild_commands(self, guild_id):
        """
        Return a mapping of custom commands for a guild keyed by command name.
        
        Each value is a dict containing the command row (all columns from the `commands` table).
        Returns an empty dict if the guild has no commands.
        """
        debug_print(f"Entering get_guild_commands with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT * FROM commands WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return {row['command_name']: dict(row) for row in result} if result else {}
        
    def get_guild_commands_list(self, guild_id: str) -> list:
        """
        Return all commands for a guild as a list of dicts.
        
        Each dict corresponds to a row from the `commands` table. Returns an empty list if no commands exist for the given `guild_id`.
        """
        debug_print(f"Entering get_guild_commands_list with guild_id: {guild_id}", level="all")
        """Get list of command dictionaries (safe for iteration)"""
        result = self.execute_query(
            'SELECT * FROM commands WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []

    def get_commands(self, guild_id: str) -> list:
        """
        Return a list of custom commands for the specified guild.
        
        Retrieves rows from the `commands` table for the provided `guild_id` where both `command_name` and `content` are non-NULL. Each result row is returned as a dict keyed by column name.
        """
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
        """
        Retrieve a custom command record for a guild by exact command name.
        
        Returns the matching row from the `commands` table as a dict (sqlite3.Row -> dict) or None if no command exists for the given guild and name. The dict contains the table columns (e.g. id, guild_id, command_name, content, description, ephemeral, created_at, updated_at).
        """
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
        """
               Create or update a custom command for a guild.
               
               Inserts a command row (guild_id, command_name, content, description, ephemeral) or updates the existing
               row's content, description, and ephemeral flag when a command with the same guild_id and command_name exists.
               
               Parameters:
                   guild_id (str): Guild identifier where the command belongs.
                   command_name (str): Name/key of the custom command.
                   content (str): Response content for the command.
                   description (str): Short description of the command (defaults to "Custom command").
                   ephemeral (bool): Whether the command's response should be ephemeral; stored as an integer flag.
               
               Returns:
                   None
               """
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
        """
        Remove a custom command for a guild.
        
        Deletes the command row with the given guild_id and command_name; if no matching row exists this is a no-op.
        """
        debug_print(f"Entering remove_command with guild_id: {guild_id}, command_name: {command_name}", level="all")
        self.execute_query(
            'DELETE FROM commands WHERE guild_id = ? AND command_name = ?',
            (guild_id, command_name)
        )

    def get_command_permissions(self, guild_id, command_name):
        """
        Return the stored permission set for a custom command in a guild.
        
        If no permissions row exists for the given guild_id and command_name, returns a default
        permission structure with empty role/user lists and is_custom=False.
        
        Returns:
            dict: {
                "allow_roles": list[str|int],  # role IDs; any stored 'everyone' placeholder is converted to guild_id
                "allow_users": list[str|int],  # user IDs
                "is_custom": bool              # True if the command is marked custom in the DB
            }
        """
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
        """
        Set or replace permission rules for a custom or built-in command in a guild.
        
        Stores an upserted record in the `command_permissions` table. Role IDs equal to the guild_id are normalized to the string "everyone" before storage. The lists `allow_roles` and `allow_users` are JSON-encoded; `is_custom` is stored as an integer flag.
        
        Parameters:
            guild_id (str|int): Guild identifier where the command permissions apply.
            command_name (str): Name of the command to set permissions for.
            allow_roles (Iterable[str|int]): Role IDs allowed to use the command; any entry equal to `guild_id` will be stored as `"everyone"`.
            allow_users (Iterable[str|int]): User IDs allowed to use the command.
            is_custom (bool, optional): True if the command is a custom command (stored as 1); defaults to False.
        
        Side effects:
            Inserts or replaces a row in the `command_permissions` database table.
        """
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
        """
        Return the log configuration row for a guild.
        
        Parameters:
            guild_id (str): Guild (server) ID to look up.
        
        Returns:
            dict or None: The log_config row as a mapping of column names to values, or None if no config exists for the guild.
        """
        debug_print(f"Entering get_log_config with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM log_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def update_log_config(self, guild_id: str, **kwargs):
        """
        Update the log configuration row for a guild by setting one or more columns.
        
        Each keyword argument name must match a column in the `log_config` table; its value will be written for the row with the given guild_id. This performs an in-place UPDATE on the database and does not return a value.
        """
        debug_print(f"Entering update_log_config with guild_id: {guild_id}, kwargs: {kwargs}", level="all")
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id]
        self.execute_query(
            f'UPDATE log_config SET {columns} WHERE guild_id = ?',
            tuple(values)
        )
        
    # Welcome Message Method
    def get_welcome_config(self, guild_id: str) -> dict:
        """
        Return the welcome configuration row for a guild.
        
        Looks up the welcome_config row for the given guild ID and returns it as a dict (sqlite row -> dict) or None if no configuration exists.
        """
        debug_print(f"Entering get_welcome_config with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM welcome_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        
    # Goodbye Message Method
    def get_goodbye_config(self, guild_id: str) -> dict:
        """
        Return the goodbye configuration for a guild.
        
        Queries the goodbye_config table for the given guild_id and returns the row as a dict (column names -> values) or None if no config exists.
        
        Parameters:
            guild_id (str): The guild's ID.
        
        Returns:
            dict | None: The goodbye configuration row or None when not found.
        """
        debug_print(f"Entering get_goodbye_config with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM goodbye_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    # Blocked Words Methods
    def get_blocked_words(self, guild_id: str) -> List[str]:
        """
        Return the list of blocked words configured for a guild.
        
        Parameters:
            guild_id (str): ID of the guild to retrieve blocked words for.
        
        Returns:
            List[str]: A list of blocked words for the given guild. Returns an empty list if none are configured.
        """
        debug_print(f"Entering get_blocked_words with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT word FROM blocked_words WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [row['word'] for row in result] if result else []

    def add_blocked_word(self, guild_id: str, word: str):
        """
        Insert a blocked word for a guild (idempotent).
        
        Inserts the given word into the guild's blocked_words table. Duplicate entries are ignored (operation is idempotent).
        
        Parameters:
            guild_id (str): The guild identifier.
            word (str): The word to block.
        """
        debug_print(f"Entering add_blocked_word with guild_id: {guild_id}, word: {word}", level="all")
        self.execute_query(
            'INSERT OR IGNORE INTO blocked_words (guild_id, word) VALUES (?, ?)',
            (guild_id, word)
        )

    def remove_blocked_word(self, guild_id: str, word: str):
        """
        Remove a blocked word for a guild.
        
        Deletes the row in the blocked_words table matching the given guild_id and word. Safe to call if the word does not exist (no error is raised).
        
        Parameters:
            guild_id (str): ID of the guild.
            word (str): The blocked word to remove.
        """
        debug_print(f"Entering remove_blocked_word with guild_id: {guild_id}, word: {word}", level="all")
        self.execute_query(
            'DELETE FROM blocked_words WHERE guild_id = ? AND word = ?',
            (guild_id, word)
        )

    # Blocked Embed Methods
    def get_blocked_embed(self, guild_id: str) -> dict:
        """
        Return the blocked embed configuration for a guild.
        
        Queries the blocked_word_embeds table for the row matching guild_id.
        
        Parameters:
            guild_id (str): Guild identifier to look up.
        
        Returns:
            dict | None: A mapping of the row columns to values for the guild, or None if no configuration exists.
        """
        debug_print(f"Entering get_blocked_embed with guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM blocked_word_embeds WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def update_blocked_embed(self, guild_id: str, **kwargs):
        """
        Update the blocked_word_embeds configuration row for a guild.
        
        Accepts column=value pairs as keyword arguments and updates those columns on the blocked_word_embeds row identified by guild_id.
        
        Parameters:
            guild_id (str): ID of the guild whose blocked embed config should be updated.
            **kwargs: Column names and their new values to set. Keys must match existing columns in the blocked_word_embeds table and at least one key must be provided.
        
        Notes:
            - No value is returned. An error will propagate if SQL execution fails (e.g., unknown column names or empty kwargs).
        """
        debug_print(f"Entering update_blocked_embed with guild_id: {guild_id}, kwargs: {kwargs}", level="all")
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id]
        self.execute_query(
            f'UPDATE blocked_word_embeds SET {columns} WHERE guild_id = ?',
            tuple(values)
        )

    # Level System Methods
    def get_level_config(self, guild_id: str) -> dict:
        """
        Return the level configuration for a guild, normalizing stored JSON/legacy values.
        
        Retrieves the row from level_config for the given guild_id and converts/validates several fields:
        - excluded_channels: parsed to a list (defaults to []).
        - xp_boost_roles: parsed to a dict mapping role id (str) to integer XP multiplier; invalid entries are dropped (defaults to {}).
        - give_xp_to_bots and give_xp_to_self: normalized to booleans (defaults to True).
        
        If the row does not exist, returns an empty dict. JSON decoding issues are logged and result in sensible defaults for the normalized fields.
        
        Parameters:
            guild_id (str): Guild identifier for which to fetch the level configuration.
        
        Returns:
            dict: Normalized level configuration for the guild, or {} if no config exists.
        """
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
        """
        Update level configuration for a guild.
        
        Accepts keyword arguments for any columns in the level_config table and applies them in a single UPDATE for the given guild_id. Special handling:
        - xp_boost_roles, excluded_channels: stored as JSON strings; if falsy, xp_boost_roles becomes '{}' and excluded_channels becomes '[]'.
        - give_xp_to_bots, give_xp_to_self: converted to integers 1 (true) or 0 (false).
        
        Parameters:
            guild_id (str): ID of the guild whose level_config will be updated.
            **kwargs: Column names and their new values to set; only provided keys are updated.
        
        Side effects:
            Persists changes to the database by executing an UPDATE against the level_config table.
        """
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
        """
        Return a mapping of level -> role_id for level rewards configured in a guild.
        
        Parameters:
            guild_id (str): ID of the guild to query.
        
        Returns:
            dict: Mapping where keys are levels (int) and values are role IDs (str). Returns an empty dict if no rewards exist.
        """
        debug_print(f"Entering get_level_rewards with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT level, role_id FROM level_rewards WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return {row['level']: row['role_id'] for row in result} if result else {}

    def add_level_reward(self, guild_id: str, level: int, role_id: str):
        """
        Insert or replace a level reward mapping for a guild.
        
        Upserts a row in the level_rewards table mapping the given level to the specified role_id for the supplied guild_id. This modifies the database and does not return a value.
        
        Parameters:
            guild_id (str): Guild identifier where the reward applies.
            level (int): Level number that triggers the reward.
            role_id (str): Role identifier to grant at the specified level.
        """
        debug_print(f"Entering add_level_reward with guild_id: {guild_id}, level: {level}, role_id: {role_id}", level="all")
        self.execute_query(
            '''INSERT OR REPLACE INTO level_rewards 
            (guild_id, level, role_id) VALUES (?, ?, ?)''',
            (guild_id, level, role_id)
        )

    def remove_level_reward(self, guild_id: str, level: int):
        """
        Remove the configured level reward for a guild at a specific level.
        
        Deletes any entry in the `level_rewards` table matching the given guild_id and level.
        
        Parameters:
            guild_id (str): Guild identifier.
            level (int): The level whose reward should be removed.
        """
        debug_print(f"Entering remove_level_reward with guild_id: {guild_id}, level: {level}", level="all")
        self.execute_query(
            'DELETE FROM level_rewards WHERE guild_id = ? AND level = ?',
            (guild_id, level)
        )

    def get_user_level(self, guild_id: str, user_id: str) -> dict:
        """
        Return the stored level record for a given user in a guild.
        
        Parameters:
            guild_id (str): Discord guild (server) ID to query.
            user_id (str): Discord user ID to query.
        
        Returns:
            dict or None: A mapping of the user's level row (columns from `user_levels`) if present, otherwise None.
        """
        debug_print(f"Entering get_user_level with guild_id: {guild_id}, user_id: {user_id}", level="all")
        return self.execute_query(
            'SELECT * FROM user_levels WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id),
            fetch='one'
        )

    def update_user_level(self, guild_id: str, user_id: str, **kwargs):
        """
        Update one or more columns on a user's level record for a guild.
        
        Parameters:
            guild_id (str): ID of the guild containing the user record.
            user_id (str): ID of the user whose record will be updated.
            **kwargs: Column=value pairs to set on the user_levels row. Keys must match actual column names in the user_levels table and at least one pair must be provided.
        
        Notes:
            - Performs an SQL UPDATE on user_levels WHERE guild_id = ? AND user_id = ?.
            - No value transformation is performed; values are stored as provided.
        """
        debug_print(f"Entering update_user_level with guild_id: {guild_id}, user_id: {user_id}, kwargs: {kwargs}", level="all")
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id, user_id]
        self.execute_query(
            f'UPDATE user_levels SET {columns} WHERE guild_id = ? AND user_id = ?',
            tuple(values)
        )
        
    # Auto Roles Methods
    def get_autoroles(self, guild_id: str) -> List[str]:
        """
        Return the list of autorole IDs configured for a guild.
        
        Parameters:
            guild_id (str): Discord guild (server) ID to query.
        
        Returns:
            List[str]: A list of role ID strings assigned as autoroles for the given guild; empty list if none are configured.
        """
        debug_print(f"Entering get_autoroles with guild_id: {guild_id}", level="all")
        result = self.execute_query(
            'SELECT role_id FROM autoroles WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [row['role_id'] for row in result] if result else []

    def update_autoroles(self, guild_id: str, role_ids: List[str]):
        """
        Replace the autoroles list for a guild by deleting existing entries and inserting the provided role IDs.
        
        This runs inside a transaction: all existing autoroles for the given guild_id are removed, and if `role_ids` is non-empty each role_id is inserted into the autoroles table. If `role_ids` is empty or falsy, the function will simply clear autoroles for the guild.
        
        Parameters:
            guild_id (str): Discord guild (server) identifier whose autoroles will be replaced.
            role_ids (List[str]): Iterable of role IDs to set as the guild's autoroles; order is preserved in insertion.
        """
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
        """
        Return the list of warnings for a user in a guild.
        
        Each item is a dict representing a warning row joined with the issuing user's username (columns from the `warnings` table plus `username`). Results are ordered by `timestamp` descending.
        """
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
        """
        Create a new warning record for a user in a guild and return the generated warning ID.
        
        Parameters:
            guild_id (str): ID of the guild where the warning is issued.
            user_id (str): ID of the user receiving the warning.
            reason (str): Reason text for the warning.
            moderator_id (str, optional): ID of the moderator who issued the warning; may be None.
        
        Returns:
            str: A newly generated UUID string (warning_id) for the inserted warning.
        """
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
        """
        Delete a specific warning for a user in a guild.
        
        Removes the row from the `warnings` table matching the provided guild_id, user_id, and warning_id.
        This operation is idempotent — if no matching warning exists nothing is changed.
        """
        debug_print(f"Entering remove_warning with guild_id: {guild_id}, user_id: {user_id}, warning_id: {warning_id}", level="all")
        self.execute_query(
            '''DELETE FROM warnings 
            WHERE guild_id = ? AND user_id = ? AND warning_id = ?''',
            (guild_id, user_id, warning_id)
        )
        
    def update_warning_reason(self, guild_id: str, user_id: str, warning_id: str, new_reason: str):
        """
        Update the reason text for a specific warning record.
        
        Updates the warnings table row matching the given guild_id, user_id, and warning_id with a new reason.
        This performs an immediate database UPDATE and does not return a value.
        
        Parameters:
            guild_id (str): Guild (server) identifier containing the warning.
            user_id (str): ID of the user who received the warning.
            warning_id (str): Warning identifier (UUID) that uniquely identifies the warning row.
            new_reason (str): New reason text to store for the warning.
        """
        debug_print(f"Entering update_warning_reason with guild_id: {guild_id}, user_id: {user_id}, warning_id: {warning_id}, new_reason: {new_reason}", level="all")
        self.execute_query(
            '''UPDATE warnings 
            SET reason = ? 
            WHERE guild_id = ? AND user_id = ? AND warning_id = ?''',
            (new_reason, guild_id, user_id, warning_id)
        )

    # Warning Actions Config
    def get_warning_actions(self, guild_id: str) -> list:
        """
        Return the warning action rules for a guild, ordered by `warning_count` ascending.
        
        Each item is a dict representing a row from `warning_actions`. Typical keys:
        - `warning_count` (int): number of warnings that triggers the action
        - `action` (str): action to take
        - `duration_seconds` (int|None): optional duration for the action
        
        Parameters:
            guild_id (str): ID of the guild to retrieve rules for.
        
        Returns:
            list[dict]: Ordered list of warning action dicts (empty list if none).
        """
        debug_print(f"Entering get_warning_actions with guild_id: {guild_id}", level="all")
        """Returns a list of dicts sorted by warning_count ascending."""
        actions = self.execute_query(
            '''SELECT * FROM warning_actions WHERE guild_id = ? ORDER BY warning_count ASC''',
            (guild_id,),
            fetch='all'
        )
        return [dict(a) for a in actions] if actions else []

    def set_warning_action(self, guild_id: str, warning_count: int, action: str, duration_seconds: int = None):
        """
        Upsert a warning-action rule for a guild.
        
        Inserts or replaces a row in the `warning_actions` table for the given guild and warning count,
        storing the action to perform and an optional duration in seconds (e.g., for temporary bans or mutes).
        
        Parameters:
            guild_id (str): Snowflake/ID of the guild.
            warning_count (int): Warning threshold that triggers this action.
            action (str): Action identifier (e.g., "mute", "kick", "ban", or a custom action).
            duration_seconds (int, optional): Optional duration in seconds for time-limited actions; stored as NULL if omitted.
        """
        debug_print(f"Entering set_warning_action with guild_id: {guild_id}, warning_count: {warning_count}, action: {action}, duration_seconds: {duration_seconds}", level="all")
        """Upsert a warning action rule."""
        self.execute_query(
            '''INSERT OR REPLACE INTO warning_actions (guild_id, warning_count, action, duration_seconds)
               VALUES (?, ?, ?, ?)''',
            (guild_id, warning_count, action, duration_seconds)
        )

    def remove_warning_action(self, guild_id: str, warning_count: int):
        """
        Remove a warning action rule for a guild.
        
        Deletes the row in `warning_actions` matching the given guild_id and warning_count.
        No value is returned.
        
        Parameters:
            guild_id (str): ID of the guild that owns the warning action.
            warning_count (int): The warning threshold whose action should be removed.
        """
        debug_print(f"Entering remove_warning_action with guild_id: {guild_id}, warning_count: {warning_count}", level="all")
        self.execute_query(
            '''DELETE FROM warning_actions WHERE guild_id = ? AND warning_count = ?''',
            (guild_id, warning_count)
        )
        
    # Spam config methods
    def get_spam_config(self, guild_id: str) -> dict:
        """
        Return the spam-detection configuration for a guild, merging stored values with defaults.
        
        If no configuration row exists for the guild, returns a dictionary of sensible defaults. Stored JSON-encoded fields "excluded_channels" and "excluded_roles" are decoded into Python lists. The returned mapping always includes an integer "no_xp_duration" and boolean "enabled". Keys provided by the database override the defaults; unspecified keys use default values.
        
        Parameters:
            guild_id (str): Guild identifier to look up configuration for.
        
        Returns:
            dict: Spam configuration with the following keys (examples shown from defaults):
                - spam_threshold (int)
                - spam_time_window (int)
                - mention_threshold (int)
                - mention_time_window (int)
                - excluded_channels (list[str])
                - excluded_roles (list[str])
                - enabled (bool)
                - spam_strikes_before_warning (int)
                - no_xp_duration (int)
        """
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
        """
        Upsert spam detection configuration for a guild.
        
        Writes a row into spam_detection_config for the given guild_id (INSERT ... ON CONFLICT DO UPDATE).
        Accepted keyword options (and defaults used when not provided):
          - spam_threshold (int) — 5
          - spam_time_window (int, seconds) — 10
          - mention_threshold (int) — 3
          - mention_time_window (int, seconds) — 30
          - excluded_channels (list[str]) — [] (stored as JSON)
          - excluded_roles (list[str]) — [] (stored as JSON)
          - enabled (bool) — True (stored as 0/1)
          - spam_strikes_before_warning (int) — 1
          - no_xp_duration (int, seconds) — 60
        
        Behavioral notes:
          - Lists provided for excluded_channels and excluded_roles are JSON-encoded before storage.
          - The enabled flag is converted to an integer (0 or 1) for SQLite.
          - no_xp_duration is coerced to int.
          - The operation creates the row if missing or updates all columns if the guild_id already exists.
        """
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
        """
        Ensure game roles and user game time tables exist.
        
        Creates two tables if they do not already exist:
        - game_roles: maps (guild_id, game_name) to a role_id and required_time (minutes).
        - user_game_time: tracks per-user per-guild per-game total_time and last_start timestamps.
        
        This is a schema-setup helper with no return value; it modifies the database schema as a side effect.
        """
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
        """
        Return all game role records for a guild.
        
        Parameters:
            guild_id (str): Guild identifier; will be converted to string for the query.
        
        Returns:
            list[dict]: A list of rows from the `game_roles` table as dictionaries (empty list if none).
        """
        debug_print(f"Entering get_game_roles with guild_id: {guild_id}")
        """Query with string guild_id"""
        return self.execute_query(
            'SELECT * FROM game_roles WHERE guild_id = ?',
            (str(guild_id),),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []

    def update_game_role(self, guild_id, game_name, role_id, required_time):
        """
        Upsert a game-role requirement for a guild.
        
        Creates or replaces a row in the game_roles table linking a guild, normalized game name, and role with a required play time.
        
        Parameters:
            guild_id: Guild identifier (stored as string).
            game_name: Name of the game; will be normalized to lowercase before storing.
            role_id: Role identifier (stored as string).
            required_time: Required play time in minutes (stored in the `required_minutes` column).
        
        Side effects:
            Writes to the database (INSERT OR REPLACE into game_roles). No return value.
        """
        debug_print(f"Entering update_game_role with guild_id: {guild_id}, game_name: {game_name}, role_id: {role_id}, required_time: {required_time}", level="all")
        self.execute_query(
            '''INSERT OR REPLACE INTO game_roles 
            (guild_id, game_name, role_id, required_minutes)
            VALUES (?, ?, ?, ?)''',
            (str(guild_id), game_name.lower(), str(role_id), required_time),
            fetch='all'
        )

    def delete_game_role(self, guild_id, game_name):
        """
        Delete the configured role mapping for a game in a guild.
        
        Removes the row from the game_roles table matching the given guild_id and game_name. The operation is idempotent (no error if no matching row exists).
        
        Parameters:
            guild_id: Identifier of the guild where the game role is defined.
            game_name: Name of the game whose role mapping should be removed.
        """
        debug_print(f"Entering delete_game_role with guild_id: {guild_id}, game_name: {game_name}", level="all")
        self.execute_query(
            'DELETE FROM game_roles WHERE guild_id = ? AND game_name = ?',
            (guild_id, game_name)
        )

    def update_game_time(self, user_id, guild_id, game_name, start_time):
        """
        Record or update a user's current game start time for a guild.
        
        Inserts or replaces a row in the user_game_time table setting the last_start timestamp for the given user, guild, and game. This upserts the record so calling it again will overwrite the previous last_start for the same (user_id, guild_id, game_name) tuple.
        
        Parameters:
            user_id (str): ID of the user.
            guild_id (str): ID of the guild (server).
            game_name (str): Name of the game.
            start_time (int | float): Timestamp (typically seconds since epoch) representing when the session started.
        
        Returns:
            None
        """
        debug_print(f"Entering update_game_time with user_id: {user_id}, guild_id: {guild_id}, game_name: {game_name}, start_time: {start_time}", level="all")
        self.execute_query('''
            INSERT OR REPLACE INTO user_game_time 
            (user_id, guild_id, game_name, last_start)
            VALUES (?, ?, ?, ?)
        ''', (user_id, guild_id, game_name, start_time))

    def add_game_session(self, user_id, guild_id, game_name, session_duration):
        """
        Add the given session duration to a user's accumulated play time for a specific game in a guild.
        
        Parameters:
            user_id (str): ID of the user.
            guild_id (str): ID of the guild.
            game_name (str): Name of the game.
            session_duration (int | float): Amount to add to the stored `total_time` (same unit as stored value).
        """
        debug_print(f"Entering add_game_session with user_id: {user_id}, guild_id: {guild_id}, game_name: {game_name}, session_duration: {session_duration}", level="all")
        self.execute_query('''
            UPDATE user_game_time 
            SET total_time = total_time + ?
            WHERE user_id = ? AND guild_id = ? AND game_name = ?
        ''', (session_duration, user_id, guild_id, game_name))

    # Twitch Status
    def get_twitch_live_status(self, ann_id: int) -> bool:
        """
        Return whether a Twitch announcement is currently marked live.
        
        Queries the twitch_announcements row by id and returns the boolean value of its
        last_live_status column. If the row is not found or last_live_status is NULL,
        returns False.
        
        Parameters:
            ann_id (int): ID of the twitch_announcements row to check.
        
        Returns:
            bool: True if last_live_status is truthy, otherwise False.
        """
        debug_print(f"Entering get_twitch_live_status with ann_id: {ann_id}", level="all")
        row = self.execute_query(
            'SELECT last_live_status FROM twitch_announcements WHERE id = ?',
            (ann_id,),
            fetch='one'
        )
        return bool(row['last_live_status']) if row and row['last_live_status'] is not None else False

    def set_twitch_live_status(self, ann_id: int, is_live: bool):
        """
        Set the stored "live" status for a Twitch announcement record.
        
        Updates the `last_live_status` column for the twitch_announcements row identified by `ann_id`.
        This stores the boolean `is_live` as an integer (1 for True, 0 for False).
        
        Parameters:
            ann_id (int): Primary key of the twitch_announcements row to update.
            is_live (bool): True if the stream is live, False otherwise.
        """
        debug_print(f"Entering set_twitch_live_status with ann_id: {ann_id}, is_live: {is_live}", level="all")
        self.execute_query(
            'UPDATE twitch_announcements SET last_live_status = ? WHERE id = ?',
            (int(is_live), ann_id)
        )

    # Pending Role Changes
    def get_pending_role_changes(self, user_id: str, guild_id: str) -> dict:
        """
        Return the pending role-change record for a specific user in a guild.
        
        Returns a single row from the pending_role_changes table as a dict (column names -> values), or None if no pending change exists.
        """
        debug_print(f"Entering get_pending_role_changes with user_id: {user_id}, guild_id: {guild_id}", level="all")
        return self.execute_query(
            'SELECT * FROM pending_role_changes WHERE user_id = ? AND guild_id = ?',
            (user_id, guild_id),
            fetch='one'
        )

    def clear_pending_role_changes(self, user_id: str, guild_id: str):
        """
        Remove any pending role-change requests for a user in a guild.
        
        Deletes rows from the pending_role_changes table matching the given user_id and guild_id. This operation is idempotent and does not return a value.
        """
        debug_print(f"Entering clear_pending_role_changes with user_id: {user_id}, guild_id: {guild_id}", level="all")
        self.execute_query(
            'DELETE FROM pending_role_changes WHERE user_id = ? AND guild_id = ?',
            (user_id, guild_id)
        )

    # Database Validation
    def validate_schema(self):
        """
        Validate that required database tables contain expected columns.
        
        Checks a hard-coded mapping of table names to required column names by querying
        SQLite's PRAGMA table_info for each table. If any required column is missing,
        raises a RuntimeError listing the missing columns.
        
        Raises:
            RuntimeError: If one or more required columns are absent from a table.
        """
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