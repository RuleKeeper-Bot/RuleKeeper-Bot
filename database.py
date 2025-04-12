import sqlite3
import json
import logging
import threading
from typing import Optional, List, Dict, Any
from config import Config
import uuid

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_path: str = str(Config.DATABASE_PATH)):
        self.db_path = db_path
        self.local = threading.local()
        self._verify_connection()
        
    def _verify_connection(self):
        """Verify database connection during initialization"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("SELECT 1")
            conn.close()
            print(f"✅ Database connection verified at {self.db_path}")
        except Exception as e:
            print(f"❌ Database connection failed: {str(e)}")
            raise

    @property
    def conn(self):
        """Thread-local connection property"""
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            self._connect()
        return self.local.conn

    def _connect(self):
        """Create a new thread-local connection"""
        self.local.conn = sqlite3.connect(self.db_path)
        self.local.conn.row_factory = sqlite3.Row
        self.local.conn.execute("PRAGMA foreign_keys = ON")
        logger.debug(f"Created new connection in thread {threading.get_ident()}")

    def close(self):
        """Close the thread-local connection"""
        if hasattr(self.local, 'conn') and self.local.conn:
            self.local.conn.close()
            self.local.conn = None
            logger.debug(f"Closed connection in thread {threading.get_ident()}")

    def execute_query(self, query: str, params=(), fetch: str = 'all', many: bool = False):
        """Safe query execution with connection handling"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
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
        except sqlite3.Error as e:
            logger.error(f"Database error: {str(e)}")
            raise
        finally:
            if conn:
                conn.close()

    def initialize_db(self):
        """Initialize database structure"""
        try:
            self._connect()
            cursor = self.conn.cursor()

            # Guilds Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS guilds (
                    guild_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    icon TEXT,
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Users Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT,
                    avatar_url TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Log Config Table
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
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            # Blocked Words Tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_words (
                    guild_id TEXT,
                    word TEXT,
                    PRIMARY KEY(guild_id, word),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_word_embeds (
                    guild_id TEXT PRIMARY KEY,
                    title TEXT DEFAULT 'Blocked Word Detected!',
                    description TEXT DEFAULT 'You have used a word that is not allowed.',
                    color INTEGER DEFAULT 16711680,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            # Commands Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    guild_id TEXT,
                    command_name TEXT,
                    content TEXT,
                    description TEXT,
                    ephemeral BOOLEAN DEFAULT 1,
                    PRIMARY KEY(guild_id, command_name),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            # Level System Tables
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
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS level_rewards (
                    guild_id TEXT,
                    level INTEGER,
                    role_id TEXT,
                    PRIMARY KEY(guild_id, level),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

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
                )
            ''')

            # Warnings Table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS warnings (
                    guild_id TEXT,
                    user_id TEXT,
                    warning_id TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reason TEXT,
                    action_type TEXT DEFAULT 'warn',
                    moderator_id TEXT,
                    PRIMARY KEY(guild_id, user_id, warning_id),
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            # Appeal System Tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS appeal_forms (
                    guild_id TEXT PRIMARY KEY,
                    base_url TEXT,
                    ban_enabled BOOLEAN DEFAULT 0,
                    ban_channel_id TEXT,
                    ban_form_url TEXT,
                    ban_form_fields TEXT DEFAULT '[]',
                    kick_enabled BOOLEAN DEFAULT 0,
                    kick_channel_id TEXT,
                    kick_form_url TEXT,
                    kick_form_fields TEXT DEFAULT '[]',
                    timeout_enabled BOOLEAN DEFAULT 0,
                    timeout_channel_id TEXT,
                    timeout_form_url TEXT,
                    timeout_form_fields TEXT DEFAULT '[]',
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS appeals (
                    guild_id TEXT,
                    appeal_id TEXT,
                    user_id TEXT,
                    type TEXT,
                    data TEXT,
                    status TEXT DEFAULT 'pending',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    channel_id TEXT,
                    PRIMARY KEY(guild_id, appeal_id),
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
                    PRIMARY KEY (user_id, guild_id)
                )
            ''')

            self.conn.commit()
            logger.info("Database initialized successfully")
        finally:
            self.close()

    # Username Methods
    def get_or_create_user(self, user_id: str, username: str = None, avatar_url: str = None):
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

    # Guild Management
    def get_guild(self, guild_id: str) -> Optional[dict]:
        return self.execute_query(
            'SELECT * FROM guilds WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def add_guild(self, guild_id: str, name: str, owner_id: str, icon: str = None):
        try:
            self.execute_query(
                '''INSERT OR IGNORE INTO guilds 
                (guild_id, name, owner_id, icon) 
                VALUES (?, ?, ?, ?)''',
                (guild_id, name, owner_id, icon)
            )
            print(f"✅ Saved guild {guild_id} to database")
        except Exception as e:
            print(f"❌ Database error adding guild: {str(e)}")
            raise

    def remove_guild(self, guild_id: str):
        """Remove a guild and all its data"""
        try:
            with self.conn:
                # Delete guild and let foreign keys clean up related data
                self.conn.execute('DELETE FROM guilds WHERE guild_id = ?', (guild_id,))
            print(f"🗑️ Removed guild {guild_id} and all related data")
        except sqlite3.Error as e:
            print(f"Database error removing guild: {str(e)}")
            raise
        
    def get_all_guilds(self) -> list:
        return self.execute_query(
            'SELECT guild_id as id, name, icon FROM guilds',
            fetch='all'
        )
           
    # All Commands Methods
    def get_all_commands(self):
        """Get all commands from all guilds"""
        return self.execute_query(
            'SELECT * FROM commands',
            fetch='all'
        )

    def get_guild_commands(self, guild_id):
        """Get all commands for a specific guild"""
        result = self.execute_query(
            'SELECT * FROM commands WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return {row['command_name']: dict(row) for row in result} if result else {}

    def get_commands(self, guild_id: str) -> dict:
        """Get all commands for a specific guild as {command_name: command_data}"""
        result = self.execute_query(
            '''SELECT * FROM commands 
            WHERE guild_id = ? 
            AND command_name IS NOT NULL 
            AND content IS NOT NULL''',
            (guild_id,),
            fetch='all'
        )
        return {row['command_name']: dict(row) for row in result} if result else {}

    # Log Config Methods
    def get_log_config(self, guild_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM log_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def update_log_config(self, guild_id: str, **kwargs):
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id]
        self.execute_query(
            f'UPDATE log_config SET {columns} WHERE guild_id = ?',
            tuple(values)
        )

    # Blocked Words Methods
    def get_blocked_words(self, guild_id: str) -> List[str]:
        result = self.execute_query(
            'SELECT word FROM blocked_words WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [row['word'] for row in result] if result else []

    def add_blocked_word(self, guild_id: str, word: str):
        self.execute_query(
            'INSERT OR IGNORE INTO blocked_words (guild_id, word) VALUES (?, ?)',
            (guild_id, word)
        )

    def remove_blocked_word(self, guild_id: str, word: str):
        self.execute_query(
            'DELETE FROM blocked_words WHERE guild_id = ? AND word = ?',
            (guild_id, word)
        )

    # Blocked Word Embed Methods
    def get_blocked_embed(self, guild_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM blocked_word_embeds WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def update_blocked_embed(self, guild_id: str, **kwargs):
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id]
        self.execute_query(
            f'UPDATE blocked_word_embeds SET {columns} WHERE guild_id = ?',
            tuple(values)
        )

    # Commands Methods
    def get_commands(self, guild_id: str) -> list:
        commands = self.execute_query(
            '''SELECT * FROM commands 
            WHERE guild_id = ? 
            AND command_name IS NOT NULL 
            AND content IS NOT NULL''',
            (guild_id,),
            fetch='all'
        )
        return [dict(c) for c in commands] if commands else []

    def add_command(self, guild_id: str, command_name: str, content: str, 
                   description: str = "Custom command", ephemeral: bool = True):
        self.execute_query(
            '''INSERT OR REPLACE INTO commands 
            (guild_id, command_name, content, description, ephemeral)
            VALUES (?, ?, ?, ?, ?)''',
            (guild_id, command_name, content, description, int(ephemeral))
        )

    def remove_command(self, guild_id: str, command_name: str):
        self.execute_query(
            'DELETE FROM commands WHERE guild_id = ? AND command_name = ?',
            (guild_id, command_name)
        )

    # Level System Methods
    def get_level_config(self, guild_id: str) -> dict:
        config = self.execute_query(
            'SELECT * FROM level_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        # Ensure proper deserialization
        if config and 'excluded_channels' in config and isinstance(config['excluded_channels'], str):
            config['excluded_channels'] = json.loads(config['excluded_channels'])
        if config and 'xp_boost_roles' in config and isinstance(config['xp_boost_roles'], str):
            config['xp_boost_roles'] = json.loads(config['xp_boost_roles'])
        return config or {}
            
        config = dict(config)  # Convert sqlite3.Row to dict
        
        # Ensure xp_boost_roles is properly decoded
        if 'xp_boost_roles' in config and isinstance(config['xp_boost_roles'], str):
            try:
                config['xp_boost_roles'] = json.loads(config['xp_boost_roles'])
            except json.JSONDecodeError:
                config['xp_boost_roles'] = {}
        
        # Ensure excluded_channels is properly decoded
        if 'excluded_channels' in config and isinstance(config['excluded_channels'], str):
            try:
                config['excluded_channels'] = json.loads(config['excluded_channels'])
            except json.JSONDecodeError:
                config['excluded_channels'] = []
        
        return config

    def update_level_config(self, guild_id: str, **kwargs):
        # Serialize JSON fields
        if 'excluded_channels' in kwargs and not isinstance(kwargs['excluded_channels'], str):
            kwargs['excluded_channels'] = json.dumps(kwargs['excluded_channels'])
        if 'xp_boost_roles' in kwargs and not isinstance(kwargs['xp_boost_roles'], str):
            kwargs['xp_boost_roles'] = json.dumps(kwargs['xp_boost_roles'])
        # Prepare the data for update
        update_data = {}
        
        for key, value in kwargs.items():
            if key in ['xp_boost_roles', 'excluded_channels']:
                # Ensure these fields are properly JSON encoded
                update_data[key] = json.dumps(value) if value else '{}' if key == 'xp_boost_roles' else '[]'
            else:
                update_data[key] = value
        
        columns = ', '.join(f"{k} = ?" for k in update_data)
        values = list(update_data.values()) + [guild_id]
        
        self.execute_query(
            f'UPDATE level_config SET {columns} WHERE guild_id = ?',
            tuple(values)
        )

    def get_level_rewards(self, guild_id: str) -> dict:
        result = self.execute_query(
            'SELECT level, role_id FROM level_rewards WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        # Always return a dict, even if empty
        return {row['level']: row['role_id'] for row in result} if result else {}

    def add_level_reward(self, guild_id: str, level: int, role_id: str):
        self.execute_query(
            '''INSERT OR REPLACE INTO level_rewards 
            (guild_id, level, role_id) VALUES (?, ?, ?)''',
            (guild_id, level, role_id)
        )

    def remove_level_reward(self, guild_id: str, level: int):
        self.execute_query(
            'DELETE FROM level_rewards WHERE guild_id = ? AND level = ?',
            (guild_id, level)
        )

    def get_user_level(self, guild_id: str, user_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM user_levels WHERE guild_id = ? AND user_id = ?',
            (guild_id, user_id),
            fetch='one'
        )

    def update_user_level(self, guild_id: str, user_id: str, **kwargs):
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id, user_id]
        self.execute_query(
            f'UPDATE user_levels SET {columns} WHERE guild_id = ? AND user_id = ?',
            tuple(values)
        )

    # Warnings Methods
    def get_warnings(self, guild_id: str, user_id: str) -> list:
        return self.execute_query(
            '''SELECT w.*, u.username 
            FROM warnings w
            LEFT JOIN users u ON w.user_id = u.user_id
            WHERE w.guild_id = ? AND w.user_id = ? 
            ORDER BY timestamp DESC''',
            (guild_id, user_id),
            fetch='all'
        )

    def add_warning(self, guild_id: str, user_id: str, reason: str) -> str:
        return self.add_warning_with_action(guild_id, user_id, reason, 'warn')

    def remove_warning(self, guild_id: str, user_id: str, warning_id: str):
        self.execute_query(
            '''DELETE FROM warnings 
            WHERE guild_id = ? AND user_id = ? AND warning_id = ?''',
            (guild_id, user_id, warning_id)
        )
        
    def update_warning_reason(self, guild_id: str, user_id: str, warning_id: str, new_reason: str):
        self.execute_query(
            '''UPDATE warnings 
            SET reason = ? 
            WHERE guild_id = ? AND user_id = ? AND warning_id = ?''',
            (new_reason, guild_id, user_id, warning_id)
        )
        
    def add_warning_with_action(self, guild_id: str, user_id: str, reason: str, action_type: str = 'warn', moderator_id: str = None) -> str:
        warning_id = str(uuid.uuid4())
        self.execute_query(
            '''INSERT INTO warnings 
            (guild_id, user_id, warning_id, reason, action_type, moderator_id) 
            VALUES (?, ?, ?, ?, ?, ?)''',
            (guild_id, user_id, warning_id, reason, action_type, moderator_id)
        )
        return warning_id

    def get_warnings_by_action(self, guild_id: str, action_type: str) -> list:
        return self.execute_query(
            '''SELECT w.*, u.username 
            FROM warnings w
            LEFT JOIN users u ON w.user_id = u.user_id
            WHERE w.guild_id = ? AND w.action_type = ?
            ORDER BY timestamp DESC''',
            (guild_id, action_type),
            fetch='all'
        )

    # Appeal System Methods
    def get_appeal_forms(self, guild_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM appeal_forms WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def update_appeal_forms(self, guild_id: str, **kwargs):
        columns = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [guild_id]
        self.execute_query(
            f'UPDATE appeal_forms SET {columns} WHERE guild_id = ?',
            tuple(values)
        )

    def create_appeal(self, guild_id, appeal_data) -> str:
        appeal_id = str(uuid.uuid4())
        self.execute_query(
            '''INSERT INTO appeals 
            (guild_id, appeal_id, user_id, type, data, status, channel_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (
                str(guild_id),
                appeal_id,
                str(appeal_data['user_id']),
                str(appeal_data['type']),
                str(appeal_data['data']),
                str(appeal_data.get('status', 'pending')),
                str(appeal_data['channel_id'])
            )
        )
        return appeal_id

    def get_appeal(self, guild_id: str, appeal_id: str) -> dict:
        result = self.execute_query(
            'SELECT * FROM appeals WHERE guild_id = ? AND appeal_id = ?',
            (guild_id, appeal_id),
            fetch='one'
        )
        if result:
            result['data'] = json.loads(result['data'])
        return result

    def update_appeal_status(self, guild_id: str, appeal_id: str, status: str):
        self.execute_query(
            'UPDATE appeals SET status = ? WHERE guild_id = ? AND appeal_id = ?',
            (status, guild_id, appeal_id)
        )

# Initialize database instance
db = Database()
db.initialize_db()