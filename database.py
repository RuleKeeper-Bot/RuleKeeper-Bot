import sqlite3
import json
import logging
import threading
import uuid
import time
from typing import Optional, List, Dict, Any
from config import Config

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_path: str = str(Config.DATABASE_PATH)):
        self.db_path = db_path
        self.local = threading.local()
        self._verify_connection()
        self.conn.row_factory = sqlite3.Row
        
    def _verify_connection(self):
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
        if not hasattr(self.local, 'conn') or self.local.conn is None:
            self._connect()
        return self.local.conn

    def _connect(self):
        self.local.conn = sqlite3.connect(self.db_path)
        self.local.conn.row_factory = sqlite3.Row
        self.local.conn.execute("PRAGMA foreign_keys = ON")
        self.local.conn.execute("PRAGMA journal_mode=WAL;")
        logger.debug(f"Created new connection in thread {threading.get_ident()}")

    def close(self):
        if hasattr(self.local, 'conn') and self.local.conn:
            self.local.conn.close()
            self.local.conn = None
            logger.debug(f"Closed connection in thread {threading.get_ident()}")

    def execute_query(self, query: str, params=(), fetch: str = 'all', many: bool = False):
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
        
        # Ensure params are SQLite compatible types
        validated_params = []
        for p in params:
            if isinstance(p, (int, float, str, bytes, bool, type(None))):
                validated_params.append(p)
            else:
                validated_params.append(str(p))
        
        params = tuple(validated_params)

    def initialize_db(self):
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
                    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT,
                    avatar_url TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    message_count INTEGER DEFAULT 0,
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
                CREATE TABLE IF NOT EXISTS appeal_forms (
                    guild_id TEXT PRIMARY KEY,
                    ban_enabled BOOLEAN DEFAULT 0,
                    ban_form_fields TEXT DEFAULT '[]',
                    ban_form_description TEXT,
                    ban_channel_id TEXT,
                    kick_enabled BOOLEAN DEFAULT 0,
                    kick_form_fields TEXT DEFAULT '[]',
                    kick_form_description TEXT,
                    kick_channel_id TEXT,
                    timeout_enabled BOOLEAN DEFAULT 0,
                    timeout_form_fields TEXT DEFAULT '[]',
                    timeout_form_description TEXT,
                    timeout_channel_id TEXT,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS appeals (
                    appeal_id TEXT PRIMARY KEY,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    appeal_data TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    appeal_token TEXT UNIQUE NOT NULL,
                    expires_at INTEGER NOT NULL,
                    moderator_id TEXT NOT NULL,
                    submitted_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
                    preview_text TEXT,
                    reviewed_by TEXT,
                    reviewed_at INTEGER,
                    moderator_notes TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )''')
                
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
                CREATE TABLE IF NOT EXISTS stream_announcements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    platform TEXT NOT NULL,
                    streamer_id TEXT NOT NULL,
                    message TEXT DEFAULT '@everyone {streamer} is live! {title} - {url}',
                    last_announced TIMESTAMP DEFAULT NULL,
                    role_id TEXT DEFAULT NULL,
                    FOREIGN KEY(guild_id) REFERENCES guilds(guild_id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS video_announcements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    announce_channel_id TEXT DEFAULT NULL,
                    enabled BOOLEAN DEFAULT 1,
                    platform TEXT NOT NULL,
                    message TEXT DEFAULT '@everyone {streamer} uploaded: {title} - {url}',
                    last_video_id TEXT DEFAULT NULL,
                    last_video_time TEXT DEFAULT NULL,
                    role_id TEXT DEFAULT NULL,
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
                CREATE INDEX IF NOT EXISTS idx_appeals_token 
                ON appeals(appeal_token)''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_appeals_user 
                ON appeals(user_id, guild_id)''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_appeals_status 
                ON appeals(status, expires_at)
            ''')
                
            # Add message_count column if missing
            cursor.execute('''
                PRAGMA table_info(user_levels)
            ''')
            columns = [column[1] for column in cursor.fetchall()]
            if 'message_count' not in columns:
                cursor.execute('''
                    ALTER TABLE user_levels 
                    ADD COLUMN message_count INTEGER DEFAULT 0
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
        self.execute_query(
            '''INSERT INTO bot_admins (username, password_hash)
            VALUES (?, ?)''',
            (username, password_hash)
        )

    def get_bot_admin(self, username: str) -> Optional[dict]:
        return self.execute_query(
            'SELECT * FROM bot_admins WHERE username = ?',
            (username,),
            fetch='one'
        )

    def delete_bot_admin(self, username: str):
        self.execute_query(
            'DELETE FROM bot_admins WHERE username = ?',
            (username,)
        )
        
    def update_admin_privileges(self, username: str, privileges: dict):
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
        return self.execute_query(
            'SELECT * FROM admin_privileges WHERE username = ?',
            (username,),
            fetch='one'
        )

    # User Methods
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

    # Guild Methods
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
        except Exception as e:
            print(f"❌ Database error adding guild: {str(e)}")
            raise

    def remove_guild(self, guild_id: str):
        try:
            with self.conn:
                self.conn.execute('DELETE FROM guilds WHERE guild_id = ?', (guild_id,))
        except sqlite3.Error as e:
            print(f"Database error removing guild: {str(e)}")
            raise
        
    def get_all_guilds(self) -> list:
        return self.execute_query(
            'SELECT guild_id as id, name, icon FROM guilds',
            fetch='all'
        )
           
    # Command Methods
    def get_all_commands(self):
        return self.execute_query(
            'SELECT * FROM commands',
            fetch='all'
        )

    def get_guild_commands(self, guild_id):
        result = self.execute_query(
            'SELECT * FROM commands WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return {row['command_name']: dict(row) for row in result} if result else {}
        
    def get_guild_commands_list(self, guild_id: str) -> list:
        """Get list of command dictionaries (safe for iteration)"""
        result = self.execute_query(
            'SELECT * FROM commands WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []

    def get_commands(self, guild_id: str) -> list:
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
        self.execute_query(
            'DELETE FROM commands WHERE guild_id = ? AND command_name = ?',
            (guild_id, command_name)
        )

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
        
    # Welcome Message Method
    def get_welcome_config(self, guild_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM welcome_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        
    # Goodbye Message Method
    def get_goodbye_config(self, guild_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM goodbye_config WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
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

    # Blocked Embed Methods
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

    # Level System Methods
    def get_level_config(self, guild_id: str) -> dict:
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

            except Exception as e:
                logger.error(f"Error parsing level config: {str(e)}")
                config['xp_boost_roles'] = {}
                config['excluded_channels'] = []
                
        return config or {}
            
    def update_level_config(self, guild_id: str, **kwargs):
        update_data = {}
        for key, value in kwargs.items():
            if key in ['xp_boost_roles', 'excluded_channels']:
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
        
    # Auto Roles Methods
    def get_autoroles(self, guild_id: str) -> List[str]:
        result = self.execute_query(
            'SELECT role_id FROM autoroles WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return [row['role_id'] for row in result] if result else []

    def update_autoroles(self, guild_id: str, role_ids: List[str]):
        with self.conn:
            self.conn.execute('DELETE FROM autoroles WHERE guild_id = ?', (guild_id,))
            if role_ids:
                self.conn.executemany(
                    'INSERT INTO autoroles (guild_id, role_id) VALUES (?, ?)',
                    [(guild_id, rid) for rid in role_ids]
                )

    # User Connections Methods
    def get_user_connections(self, user_id: str, guild_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM user_connections WHERE user_id = ? AND guild_id = ?',
            (user_id, guild_id),
            fetch='one'
        )

    def update_user_connection(self, user_id: str, guild_id: str, **kwargs):
        """UPSERT operation for user connections"""
        if not kwargs:
            return

        # Filter valid columns
        valid_columns = {'twitch_username', 'youtube_channel_id'}
        update_data = {k: v for k, v in kwargs.items() if k in valid_columns}
        
        if not update_data:
            return

        # Prepare query
        columns = ', '.join(update_data.keys())
        placeholders = ', '.join(['?'] * len(update_data))
        updates = ', '.join([f"{k} = ?" for k in update_data.keys()])
        
        query = f'''
            INSERT INTO user_connections (user_id, guild_id, {columns})
            VALUES (?, ?, {placeholders})
            ON CONFLICT(user_id, guild_id) DO UPDATE SET {updates}
        '''
        
        values = [user_id, guild_id] + list(update_data.values())
        values += list(update_data.values())  # For the UPDATE part
        
        self.execute_query(query, tuple(values))

    # Stream Alerts Methods
    def get_stream_alerts(self, guild_id: str) -> list:
        """Get all stream alerts for a guild"""
        return self.execute_query(
            'SELECT * FROM stream_alerts WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )

    def update_stream_alert(self, guild_id: str, platform: str, notification_type: str,
                           enabled: bool, role_id: str, channel_id: str, message_template: str):
        """Generic method for updating any stream alert"""
        self.execute_query(
            '''INSERT INTO stream_alerts 
            (guild_id, platform, notification_type, enabled, role_id, channel_id, message_template)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(guild_id, platform, notification_type) DO UPDATE SET
                enabled = excluded.enabled,
                role_id = excluded.role_id,
                channel_id = excluded.channel_id,
                message_template = excluded.message_template''',
            (guild_id, platform, notification_type, enabled, role_id, channel_id, message_template)
        )

    def get_video_alerts(self, guild_id: str) -> dict:
        """Get YouTube video alerts specifically"""
        alert = self.execute_query(
            '''SELECT * FROM stream_alerts 
            WHERE guild_id = ? 
            AND platform = 'youtube' 
            AND notification_type = 'video' ''',
            (guild_id,),
            fetch='one'
        )
        if alert:
            return {
                'enabled': bool(alert['enabled']),
                'role_id': alert['role_id'],
                'channel_id': alert['channel_id'],
                'message_template': alert['message_template']
            }
        return None

    def update_video_alert(self, guild_id: str, platform: str, notification_type: str,
                          enabled: bool, role_id: str, channel_id: str, message_template: str):
        """Wrapper for video-specific alerts"""
        self.update_stream_alert(
            guild_id=guild_id,
            platform=platform,
            notification_type=notification_type,
            enabled=enabled,
            role_id=role_id,
            channel_id=channel_id,
            message_template=message_template
        )

    # Stream Status Methods
    def get_stream_status(self, user_id: str, guild_id: str, platform: str) -> dict:
        return self.execute_query(
            'SELECT * FROM stream_status WHERE user_id = ? AND guild_id = ? AND platform = ?',
            (user_id, guild_id, platform),
            fetch='one'
        )

    def update_stream_status(self, user_id: str, guild_id: str, platform: str, is_live: bool, title: str, url: str):
        self.execute_query(
            '''INSERT INTO stream_status (user_id, guild_id, platform, is_live, stream_title, stream_url, last_live_time)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id, guild_id, platform) DO UPDATE SET
                    is_live = excluded.is_live,
                    stream_title = excluded.stream_title,
                    stream_url = excluded.stream_url,
                    last_live_time = excluded.last_live_time''',
            (user_id, guild_id, platform, is_live, title, url)
        )

    # Warning Methods
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

    def add_warning(self, guild_id: str, user_id: str, reason: str, moderator_id: str = None) -> str:
        warning_id = str(uuid.uuid4())
        self.execute_query(
            '''INSERT INTO warnings 
            (guild_id, user_id, warning_id, reason, moderator_id) 
            VALUES (?, ?, ?, ?, ?)''',
            (guild_id, user_id, warning_id, reason, moderator_id)
        )
        return warning_id

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
        
    # Spam config methods
    def get_spam_config(self, guild_id: str) -> dict:
        default = {
            "spam_threshold": 5,
            "spam_time_window": 10,
            "mention_threshold": 3,
            "mention_time_window": 30,
            "excluded_channels": [],
            "excluded_roles": []
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
        return {**default, **config}

    def update_spam_config(self, guild_id: str, **kwargs):
        # Ensure all possible columns are present with defaults
        full_data = {
            "spam_threshold": 5,
            "spam_time_window": 10,
            "mention_threshold": 3,
            "mention_time_window": 30,
            "excluded_channels": [],
            "excluded_roles": [],
            **kwargs
        }
        
        # Convert list fields to JSON strings
        full_data["excluded_channels"] = json.dumps(full_data["excluded_channels"])
        full_data["excluded_roles"] = json.dumps(full_data["excluded_roles"])
        
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

    # Appeal Methods
    def get_appeal_forms(self, guild_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM appeal_forms WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

    def update_appeal_forms(self, guild_id: str, **kwargs):
        existing = self.get_appeal_forms(guild_id) or {}
        merged = {**existing, **kwargs}
        
        # Convert boolean values to integers for SQLite
        for key in ['ban_enabled', 'kick_enabled', 'timeout_enabled']:
            merged[key] = int(bool(merged.get(key, 0)))

        columns = ', '.join(f"{k} = ?" for k in merged)
        values = list(merged.values()) + [guild_id]
        
        self.execute_query(f'''
            INSERT INTO appeal_forms 
            (guild_id, {', '.join(merged.keys())})
            VALUES (?{', ?' * len(merged)})
            ON CONFLICT(guild_id) DO UPDATE SET 
            {columns}
        ''', [guild_id] + list(merged.values()) + list(merged.values()))
    
    def create_appeal(self, guild_id: str, appeal_data: dict) -> str:
        appeal_id = str(uuid.uuid4())
        self.execute_query(
            '''INSERT INTO appeals 
            (appeal_id, guild_id, user_id, type, appeal_data,
             status, appeal_token, expires_at, moderator_id, preview_text)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                appeal_id,
                str(guild_id),
                str(appeal_data['user_id']),
                appeal_data['type'],
                json.dumps(appeal_data.get('data', {})),
                'pending',  # Initial status
                appeal_data['appeal_token'],
                int(appeal_data['expires_at']),
                str(appeal_data['moderator_id']),
                appeal_data.get('preview_text', '')
            )
        )
        return appeal_id

    def get_appeal(self, guild_id: str, appeal_id: str) -> Optional[dict]:
        result = self.execute_query(
            'SELECT * FROM appeals WHERE guild_id = ? AND appeal_id = ?',
            (str(guild_id), appeal_id),
            fetch='one'
        )
        if result:
            result = dict(result)
            result['appeal_data'] = json.loads(result['appeal_data'])
            return result
        return None

    def update_appeal_status(self, guild_id: str, appeal_id: str, status: str):
        valid_statuses = ['pending', 'under_review', 'approved', 'rejected']
        if status not in valid_statuses:
            raise ValueError(f"Invalid status: {status}")
        
        self.execute_query(
            '''UPDATE appeals 
            SET status = ? 
            WHERE guild_id = ? AND appeal_id = ?''',
            (status, str(guild_id), appeal_id)
        )
        
    def get_appeal_by_token(self, appeal_token: str) -> Optional[dict]:
        result = self.execute_query(
            'SELECT * FROM appeals WHERE appeal_token = ?',
            (appeal_token,),
            fetch='one'
        )
        if result:
            result = dict(result)
            try:
                result['appeal_data'] = json.loads(result['appeal_data'])
            except (json.JSONDecodeError, TypeError):
                result['appeal_data'] = {}
            return result
        return None

    def update_appeal(self, appeal_id: str, **kwargs):
        if 'appeal_data' in kwargs:
            kwargs['appeal_data'] = json.dumps(kwargs['appeal_data'])
        
        # Convert reviewed_by to string if present
        if 'reviewed_by' in kwargs and kwargs['reviewed_by'] is not None:
            kwargs['reviewed_by'] = str(kwargs['reviewed_by'])
            
        set_clause = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [appeal_id]
        
        self.execute_query(
            f'''UPDATE appeals 
            SET {set_clause} 
            WHERE appeal_id = ?''',
            tuple(values)
        )
        
    # Auto Roles on Game Play Time
    def setup_game_roles_table(self):
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
        """Query with string guild_id"""
        return self.execute_query(
            'SELECT * FROM game_roles WHERE guild_id = ?',
            (str(guild_id),),
            fetch='all'
        )
        return [dict(row) for row in result] if result else []

    def update_game_role(self, guild_id, game_name, role_id, required_time):
        self.execute_query(
            '''INSERT OR REPLACE INTO game_roles 
            (guild_id, game_name, role_id, required_minutes)
            VALUES (?, ?, ?, ?)''',
            (str(guild_id), game_name.lower(), str(role_id), required_time),
            fetch='all'
        )

    def delete_game_role(self, guild_id, game_name):
        self.execute_query(
            'DELETE FROM game_roles WHERE guild_id = ? AND game_name = ?',
            (guild_id, game_name)
        )

    def update_game_time(self, user_id, guild_id, game_name, start_time):
        self.execute_query('''
            INSERT OR REPLACE INTO user_game_time 
            (user_id, guild_id, game_name, last_start)
            VALUES (?, ?, ?, ?)
        ''', (user_id, guild_id, game_name, start_time))

    def add_game_session(self, user_id, guild_id, game_name, session_duration):
        self.execute_query('''
            UPDATE user_game_time 
            SET total_time = total_time + ?
            WHERE user_id = ? AND guild_id = ? AND game_name = ?
        ''', (session_duration, user_id, guild_id, game_name))

    # Pending Role Changes
    def get_pending_role_changes(self, user_id: str, guild_id: str) -> dict:
        return self.execute_query(
            'SELECT * FROM pending_role_changes WHERE user_id = ? AND guild_id = ?',
            (user_id, guild_id),
            fetch='one'
        )

    def clear_pending_role_changes(self, user_id: str, guild_id: str):
        self.execute_query(
            'DELETE FROM pending_role_changes WHERE user_id = ? AND guild_id = ?',
            (user_id, guild_id)
        )

    # Database Validation
    def validate_schema(self):
        required_tables = {
            'appeals': ['appeal_id', 'guild_id', 'user_id', 'type',
                       'appeal_token', 'expires_at', 'status'],
            'warnings': ['guild_id', 'user_id', 'warning_id', 'reason']
        }
        
        for table, columns in required_tables.items():
            result = self.execute_query(f'PRAGMA table_info({table})', fetch='all')
            existing = [row['name'] for row in result]
            missing = set(columns) - set(existing)
            
            if missing:
                raise RuntimeError(f"Missing columns in {table}: {', '.join(missing)}")

    def get_video_announcement(self, guild_id: str, channel_id: str) -> Optional[dict]:
        """Get a video announcement configuration including last video info"""
        return self.execute_query(
            'SELECT * FROM video_announcements WHERE guild_id = ? AND channel_id = ?',
            (str(guild_id), str(channel_id)),
            fetch='one'
        )

    def update_video_announcement(self, guild_id: str, channel_id: str, **kwargs):
        """Update video announcement settings including last video info"""
        if 'last_video_time' in kwargs:
            kwargs['last_video_time'] = str(kwargs['last_video_time'])
            
        set_clause = ', '.join(f"{k} = ?" for k in kwargs)
        values = list(kwargs.values()) + [str(guild_id), str(channel_id)]
        
        self.execute_query(
            f'''UPDATE video_announcements 
            SET {set_clause} 
            WHERE guild_id = ? AND channel_id = ?''',
            tuple(values)
        )

    def update_last_video_info(self, guild_id: str, channel_id: str, video_id: str, video_time: str):
        """Update both last video ID and time for a channel"""
        self.execute_query(
            '''UPDATE video_announcements 
            SET last_video_id = ?, last_video_time = ? 
            WHERE guild_id = ? AND channel_id = ?''',
            (video_id, str(video_time), str(guild_id), str(channel_id))
        )