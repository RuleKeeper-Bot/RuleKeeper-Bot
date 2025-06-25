# -------------------- Standard Libraries -----------------
import asyncio
import json
import logging
import math
import os
import random
import sys
import threading
import time
import traceback
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from functools import partial

# -------------------- Third-Party Libraries -----------------
import discord
from discord import app_commands
from discord.errors import Forbidden, HTTPException
from discord.ext import commands, tasks
from discord.utils import sleep_until
import aiohttp
from aiohttp import web, hdrs
from cachetools import TTLCache
from dotenv import load_dotenv
from expiringdict import ExpiringDict
import sqlite3

# -------------------- Local Imports -----------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config
from database import db

# -------------------- Runtime Config -----------------
load_dotenv()

_bot_loop = None
_loop_lock = threading.Lock()
def get_event_loop():
    """Safely retrieve the current event loop"""
    with _loop_lock:
        return _bot_loop

def set_event_loop(loop):
    """Update the event loop reference"""
    global _bot_loop
    with _loop_lock:
        _bot_loop = loop

# -------------------- API and Frontend URLs -----------------
API_URL = os.getenv('API_URL', 'http://localhost:5003')  # Default for local dev
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')  # Default for local dev

# -------------------- Load Secrets --------------------
BOT_TOKEN = os.getenv('BOT_TOKEN')

# -------------------- Caching --------------------
level_config_cache = TTLCache(maxsize=100, ttl=300)  # 10 minutes
logger = logging.getLogger(__name__)


YOUTUBE_QUOTA_EXCEEDED = False
# -------------------- Log Config --------------------

def load_log_config(guild_id):
    default_config = {
        "log_channel_id": None,
        "log_config_update": True,
        "message_delete": True,
        "bulk_message_delete": True,
        "message_edit": True,
        "invite_create": True,
        "invite_delete": True,
        "member_role_add": True,
        "member_role_remove": True,
        "member_timeout": True,
        "member_warn": True,
        "member_unwarn": True,
        "member_ban": True,
        "member_unban": True,
        "role_create": True,
        "role_delete": True,
        "role_update": True,
        "channel_create": True,
        "channel_delete": True,
        "channel_update": True,
        "emoji_create": True,
        "emoji_name_change": True,
        "emoji_delete": True
    }

    # Get config from database
    config = db.get_log_config(str(guild_id))
    
    if not config:
        # Create new entry with defaults
        db.conn.execute('INSERT INTO log_config (guild_id) VALUES (?)', (str(guild_id),))
        db.conn.commit()
        config = db.get_log_config(str(guild_id))
    
    # Convert database values to proper types and merge with defaults
    converted_config = {}
    for key in default_config:
        value = config.get(key)
        
        if isinstance(default_config[key], bool):
            # Convert SQLite integer (0/1) to boolean
            converted_config[key] = bool(value) if value is not None else default_config[key]
        else:
            converted_config[key] = value if value is not None else default_config[key]
    
    return converted_config

def save_log_config(guild_id, config):
    # Convert boolean values to integers for SQLite storage
    db_config = {k: int(v) if isinstance(v, bool) else v for k, v in config.items()}
    db.update_log_config(str(guild_id), **db_config)

processed_messages = ExpiringDict(max_len=1000, max_age_seconds=300)

# -------------------- Batch Role Changes --------------------
class RoleChangeBatcher:
    def __init__(self, bot):
        self.bot = bot
        self.timers = {}  # Track active timers {user_id: timer_task}
        
    async def initialize(self):
        """Load existing pending changes from database on startup"""
        pending = db.conn.execute('SELECT * FROM pending_role_changes').fetchall()
        for entry in pending:
            user_id = entry['user_id']
            guild_id = entry['guild_id']
            expiration = datetime.fromisoformat(entry['expiration_time'])
            now = datetime.utcnow()
            delay = (expiration - now).total_seconds()
            
            if delay > 0:
                self.schedule_timer(user_id, guild_id, delay)
            else:
                await self.log_and_reset(user_id, guild_id)

    def schedule_timer(self, user_id, guild_id, delay):
        """Schedule or reschedule a timer"""
        if user_id in self.timers:
            self.timers[user_id].cancel()
            
        self.timers[user_id] = self.bot.loop.create_task(
            self.delayed_log(user_id, guild_id, delay)
        )

    async def delayed_log(self, user_id, guild_id, delay):
        """Handle the delayed logging"""
        await asyncio.sleep(delay)
        await self.log_and_reset(user_id, guild_id)

    async def log_and_reset(self, user_id, guild_id):
        """Process and clear the changes"""
        entry = db.conn.execute('''
            SELECT * FROM pending_role_changes 
            WHERE user_id = ? AND guild_id = ?
        ''', (user_id, guild_id)).fetchone()
        
        if not entry:
            return

        guild = self.bot.get_guild(int(guild_id))
        if not guild:
            return
            
        if guild:
            added = entry['added_roles'].split(',') if entry['added_roles'] else []
            removed = entry['removed_roles'].split(',') if entry['removed_roles'] else []
            
            description = f"**Member:** <@{user_id}>\n"
            if added:
                description += f"**Added Roles:** {', '.join(f'<@&{r}>' for r in added)}\n"
            if removed:
                description += f"**Removed Roles:** {', '.join(f'<@&{r}>' for r in removed)}"
            
            await log_event(
                guild,
                "member_role_change",
                "Role Updates",
                description,
                color=discord.Color.blue()
            )

        # Clean up
        db.conn.execute('''
            DELETE FROM pending_role_changes 
            WHERE user_id = ? AND guild_id = ?
        ''', (user_id, guild_id))
        db.conn.commit()
        
        if user_id in self.timers:
            del self.timers[user_id]

    async def add_change(self, member, added_roles, removed_roles):
        """Add new role changes to the database"""
        user_id = str(member.id)
        guild_id = str(member.guild.id)
        expiration = datetime.utcnow() + timedelta(seconds=15)
        
        # Merge with existing changes
        existing = db.conn.execute('''
            SELECT * FROM pending_role_changes 
            WHERE user_id = ? AND guild_id = ?
        ''', (user_id, guild_id)).fetchone()
        
        added = {str(r.id) for r in added_roles}
        removed = {str(r.id) for r in removed_roles}
        
        if existing:
            added = added.union(set(existing['added_roles'].split(','))) if existing['added_roles'] else added
            removed = removed.union(set(existing['removed_roles'].split(','))) if existing['removed_roles'] else removed
            added.difference_update(removed)
            removed.difference_update(added)

        # Update database
        db.conn.execute('''
            INSERT OR REPLACE INTO pending_role_changes 
            (user_id, guild_id, added_roles, removed_roles, expiration_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            user_id,
            guild_id,
            ','.join(added) if added else None,
            ','.join(removed) if removed else None,
            expiration.isoformat()
        ))
        db.conn.commit()
        
        # Calculate remaining time
        now = datetime.utcnow()
        delay = (expiration - now).total_seconds()
        self.schedule_timer(user_id, guild_id, delay)

# -------------------- Blocked Words --------------------
def get_blocked_words(guild_id: int) -> list:
    """Get blocked words list from database for a specific guild"""
    try:
        return db.get_blocked_words(str(guild_id))
    except Exception as e:
        print(f"Error getting blocked words: {str(e)}")
        return []

def get_blocked_embed(guild_id: int) -> dict:
    """Get blocked word embed config from database for a specific guild"""
    try:
        embed = db.get_blocked_embed(str(guild_id))
        if not embed:
            # Create default embed config if none exists
            embed = {
                "title": "Blocked Word Detected!",
                "description": "You have used a word that is not allowed.",
                "color": 0xff0000
            }
            db.conn.execute('''INSERT INTO blocked_word_embeds 
                            (guild_id, title, description, color)
                            VALUES (?, ?, ?, ?)''',
                         (str(guild_id), embed['title'], 
                          embed['description'], embed['color']))
            db.conn.commit()
        return embed
    except Exception as e:
        print(f"Error getting blocked embed: {str(e)}")
        return {
            "title": "Blocked Word Detected!",
            "description": "You have used a word that is not allowed.",
            "color": 0xff0000
        }


# -------------------- Spam and Warning Tracking --------------------
message_timestamps = defaultdict(list)  # Tracks timestamps of messages per user
user_mentions = defaultdict(list)        # Tracks timestamps of mentions

def get_warnings(guild_id: str, user_id: str) -> list:
    """Get warnings for a specific user in a guild"""
    return db.get_warnings(str(guild_id), str(user_id))

def add_warning(guild_id: str, user_id: str, reason: str) -> str:
    """Add a warning and return the warning ID"""
    return db.add_warning(str(guild_id), str(user_id), reason)

def remove_warning(guild_id: str, user_id: str, warning_id: str):
    """Remove a specific warning"""
    db.remove_warning(str(guild_id), str(user_id), warning_id)

def update_warning(guild_id: str, user_id: str, warning_id: str, new_reason: str):
    """Update a warning's reason"""
    db.update_warning_reason(str(guild_id), str(user_id), warning_id, new_reason)

WARNING_ACTIONS = {
    2: "timeout",
    3: "ban"
}

# -------------------- Stream and Video Stuff --------------------
class StreamAnnouncer:
    def __init__(self, bot):
        self.bot = bot
        self.twitch_token = None
        self.twitch_expiry = 0
        self.youtube_cache = {}
        self.check_loop.start()
        
    @tasks.loop(minutes=3)
    async def check_loop(self):
        await self.bot.wait_until_ready()
        
        # Process live streams
        await self.check_twitch_streams()
        await self.check_youtube_streams()
        
        # Process videos
        await self.check_youtube_videos()
    
    async def get_twitch_token(self):
        if time.time() < self.twitch_expiry - 60:
            return self.twitch_token
            
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'https://id.twitch.tv/oauth2/token',
                params={
                    'client_id': os.getenv('TWITCH_CLIENT_ID'),
                    'client_secret': os.getenv('TWITCH_CLIENT_SECRET'),
                    'grant_type': 'client_credentials'
                }
            ) as resp:
                data = await resp.json()
                self.twitch_token = data['access_token']
                self.twitch_expiry = time.time() + data['expires_in']
                return self.twitch_token
    
    async def check_twitch_streams(self):
        try:
            # Get all Twitch stream announcements
            announcements = self.bot.db.execute_query(
                'SELECT * FROM stream_announcements WHERE platform = "twitch" AND enabled = 1',
                fetch='all'
            )
            
            if not announcements:
                return
                
            token = await self.get_twitch_token()
            headers = {
                'Client-ID': os.getenv('TWITCH_CLIENT_ID'),
                'Authorization': f'Bearer {token}'
            }
            
            # Group by streamer to minimize API calls
            streamer_map = defaultdict(list)
            for ann in announcements:
                streamer_map[ann['streamer_id']].append(ann)
            
            # Check all unique streamers
            async with aiohttp.ClientSession() as session:
                for streamer_id, ann_list in streamer_map.items():
                    # Get user ID from username
                    async with session.get(
                        f'https://api.twitch.tv/helix/users?login={streamer_id}',
                        headers=headers
                    ) as resp:
                        user_data = await resp.json()
                        if not user_data.get('data'):
                            continue
                        user_id = user_data['data'][0]['id']
                    
                    # Check stream status
                    async with session.get(
                        f'https://api.twitch.tv/helix/streams?user_id={user_id}',
                        headers=headers
                    ) as resp:
                        stream_data = await resp.json()
                        is_live = bool(stream_data.get('data'))
                        stream = stream_data['data'][0] if is_live else None
                    
                    # Process announcements
                    for ann in ann_list:
                        if is_live:
                            # Check if we already announced this stream
                            last_announced = datetime.fromisoformat(ann['last_announced']) if ann['last_announced'] else None
                            if last_announced and (datetime.utcnow() - last_announced).total_seconds() < 3600:
                                continue
                                
                            # Send announcement
                            await self.send_stream_announcement(ann, stream)
                        else:
                            # Mark as offline in DB
                            self.bot.db.execute_query(
                                'UPDATE stream_announcements SET last_announced = NULL WHERE id = ?',
                                (ann['id'],)
                            )
                            
        except Exception as e:
            logger.error(f"Twitch check error: {str(e)}")
    
    async def check_youtube_streams(self):
        try:
            announcements = self.bot.db.execute_query(
                'SELECT * FROM stream_announcements WHERE platform = "youtube" AND enabled = 1',
                fetch='all'
            )
            
            if not announcements:
                return
                
            API_KEY = os.getenv('YOUTUBE_API_KEY')
            if not API_KEY:
                return
                
            # Group by channel ID
            channel_map = defaultdict(list)
            for ann in announcements:
                channel_map[ann['streamer_id']].append(ann)
            
            async with aiohttp.ClientSession() as session:
                for channel_id, ann_list in channel_map.items():
                    # Check for live streams
                    url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&channelId={channel_id}&eventType=live&type=video&key={API_KEY}"
                    async with session.get(url) as resp:
                        data = await resp.json()
                        is_live = bool(data.get('items'))
                        stream = data['items'][0] if is_live else None
                    
                    # Process announcements
                    for ann in ann_list:
                        if is_live:
                            # Check if we already announced
                            last_announced = datetime.fromisoformat(ann['last_announced']) if ann['last_announced'] else None
                            if last_announced and (datetime.utcnow() - last_announced).total_seconds() < 3600:
                                continue
                                
                            # Send announcement
                            await self.send_stream_announcement(ann, {
                                'title': stream['snippet']['title'],
                                'url': f"https://youtu.be/{stream['id']['videoId']}"
                            })
                        else:
                            # Mark as offline
                            self.bot.db.execute_query(
                                'UPDATE stream_announcements SET last_announced = NULL WHERE id = ?',
                                (ann['id'],)
                            )
                            
        except Exception as e:
            logger.error(f"YouTube live check error: {str(e)}")
    
    async def check_youtube_videos(self):
        """Check for new YouTube videos using the uploads playlist"""
        if not self.bot.youtube_api_key:
            return

        async with aiohttp.ClientSession() as session:
            # Get all video announcements
            announcements = self.bot.db.execute_query(
                'SELECT * FROM video_announcements WHERE platform = ? AND enabled = 1',
                ('youtube',),
                fetch='all'
            )

            for ann in announcements:
                try:
                    # Get channel uploads playlist ID
                    channel_id = ann['channel_id']
                    async with session.get(
                        f'https://www.googleapis.com/youtube/v3/channels?part=contentDetails&id={channel_id}&key={self.bot.youtube_api_key}'
                    ) as resp:
                        channel_data = await resp.json()
                        if not channel_data.get('items'):
                            continue
                        uploads_playlist = channel_data['items'][0]['contentDetails']['relatedPlaylists']['uploads']

                    # Get last processed video info
                    last_video_id = ann.get('last_video_id')
                    last_video_time = ann.get('last_video_time')

                    # Fetch up to 50 recent videos from the uploads playlist
                    async with session.get(
                        f'https://www.googleapis.com/youtube/v3/playlistItems?part=snippet&playlistId={uploads_playlist}&maxResults=50&key={self.bot.youtube_api_key}'
                    ) as resp:
                        playlist_data = await resp.json()
                        items = playlist_data.get('items', [])

                    # Process videos in upload order (oldest first)
                    videos_to_announce = []
                    for item in reversed(items):
                        snippet = item['snippet']
                        video_id = snippet['resourceId']['videoId']
                        published_at = snippet['publishedAt']

                        # Stop if we reach the last processed video
                        if last_video_id and video_id == last_video_id:
                            break

                        # Only process videos published after the last processed time
                        if last_video_time and published_at <= last_video_time:
                            continue

                        # Skip if live stream
                        async with session.get(
                            f'https://www.googleapis.com/youtube/v3/videos?part=liveStreamingDetails&id={video_id}&key={self.bot.youtube_api_key}'
                        ) as vresp:
                            video_data = await vresp.json()
                            if 'liveStreamingDetails' in video_data.get('items', [{}])[0]:
                                continue

                        videos_to_announce.append({
                            'video_id': video_id,
                            'title': snippet['title'],
                            'url': f'https://youtu.be/{video_id}',
                            'published_at': published_at
                        })

                    # Announce videos in order
                    for video in videos_to_announce:
                        await self.send_video_announcement(ann, {
                            'title': video['title'],
                            'url': video['url']
                        })
                        # Update last_video_id and last_video_time after each announcement
                        self.bot.db.update_last_video_info(
                            ann['guild_id'],
                            ann['channel_id'],
                            video['video_id'],
                            video['published_at']
                        )

                except Exception as e:
                    print(f"Error checking YouTube videos for channel {ann['channel_id']}: {e}")
                    continue
    
    async def send_stream_announcement(self, announcement, stream_data):
        try:
            channel = self.bot.get_channel(int(announcement['channel_id']))
            if not channel:
                return
                
            message = announcement['message'].format(
                streamer=announcement['streamer_id'],
                title=stream_data['title'],
                url=stream_data['url']
            )
            
            await channel.send(message)
            
            # Update last announced time
            self.bot.db.execute_query(
                'UPDATE stream_announcements SET last_announced = CURRENT_TIMESTAMP WHERE id = ?',
                (announcement['id'],)
            )
            
        except Exception as e:
            logger.error(f"Stream announcement error: {str(e)}")
    
    async def send_video_announcement(self, announcement, video_data):
        try:
            channel = self.bot.get_channel(int(announcement['channel_id']))
            if not channel:
                return
                
            message = announcement['message'].format(
                streamer=announcement['channel_id'],  # For videos, channel_id is the identifier
                title=video_data['title'],
                url=video_data['url']
            )
            
            await channel.send(message)
            
        except Exception as e:
            logger.error(f"Video announcement error: {str(e)}")

# -------------------- Bot Setup --------------------
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True
intents.moderation = True
intents.presences = True

Config.verify_paths()
class CustomBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = db
        self.role_batcher = RoleChangeBatcher(self)
        self._command_registry = {}
        self.synced_guilds = set()
        self._command_initialized = False

    def _create_command_callback(self, cmd_data: dict):
        """Factory method to create properly typed callbacks"""
        async def callback(interaction: discord.Interaction):
            await self.custom_command_handler(interaction, cmd_data)
        return callback

    async def setup_hook(self):
        """Initialize command tree with proper error handling"""
        await super().setup_hook()
        await self.load_extension("cogs.moderation")
        await self.load_extension("cogs.leveling")
        await self.load_extension("cogs.utilities")
        await self.load_extension("cogs.debug")
        await self.load_extension("cogs.music")
        
        if self._command_initialized:
            return
        
        try:
            # Clear existing guild commands
            for guild in self.guilds:
                self.tree.clear_commands(guild=guild)

            # Load and process custom commands
            raw_commands = self.db.execute_query(
                'SELECT guild_id, command_name, content, description, ephemeral FROM commands',
                fetch='all'
            ) or []
            
            # Convert to dictionaries and validate
            valid_commands = []
            required_keys = {'guild_id', 'command_name', 'content'}
            for cmd in raw_commands:
                cmd_data = dict(cmd) if isinstance(cmd, sqlite3.Row) else cmd
                if all(key in cmd_data for key in required_keys):
                    valid_commands.append(cmd_data)
                else:
                    print(f"⚠️ Invalid command format: {cmd_data}")

            # Group commands by guild
            guild_groups = defaultdict(list)
            for cmd in valid_commands:
                guild_id = str(cmd['guild_id']).strip()
                guild_groups[guild_id].append(cmd)

            # Process global commands
            global_commands = guild_groups.get('0', [])
            for cmd_data in global_commands:
                try:
                    callback = self._create_command_callback(cmd_data)
                    cmd = app_commands.Command(
                        name=cmd_data['command_name'],
                        description=cmd_data.get('description', 'Custom command'),
                        callback=callback
                    )
                    self.tree.add_command(cmd)
                except Exception as e:
                    print(f"  🚨 Global command error: {str(e)}")

            # Process guild-specific commands
            for guild_id_str, cmds in guild_groups.items():
                if guild_id_str == '0':
                    continue

                try:
                    guild = await self.fetch_guild(int(guild_id_str))
                except (discord.NotFound, discord.Forbidden):
                    print(f"  🚫 Guild {guild_id_str} not accessible")
                    continue
                    
                self.tree.clear_commands(guild=guild)

                for cmd_data in cmds:
                    try:
                        callback = self._create_command_callback(cmd_data)
                        cmd = app_commands.Command(
                            name=cmd_data['command_name'],
                            description=cmd_data.get('description', 'Custom command'),
                            callback=callback
                        )
                        self.tree.add_command(cmd, guild=guild)
                    except Exception as e:
                        print(f"    🚨 Command error: {str(e)}")

                # Sync guild commands with retry
                await self.safe_sync(guild=guild)

            # Final global sync
            await self.safe_sync()
            
            # Initialize components
            await self.role_batcher.initialize()
            self._command_initialized = True

        except Exception as e:
            print(f"❌ Critical initialization error: {str(e)}")
            traceback.print_exc()
            sys.exit(1)
            
    async def safe_sync(self, guild=None):
        """Sync commands with rate limit handling"""
        target = "global" if guild is None else f"guild {guild.id}"
        
        for attempt in range(3):
            try:
                synced = await self.tree.sync(guild=guild)
                count = len(synced)
                return True
            except discord.HTTPException as e:
                if e.status == 429:
                    delay = e.retry_after or 5 * (attempt + 1)
                    print(f"  ⏳ Rate limited. Retrying in {delay:.1f}s")
                    await asyncio.sleep(delay)
                else:
                    print(f"  ❌ Sync failed: {e.status} {e.text}")
                    return False
            except Exception as e:
                print(f"  ❌ Unexpected sync error: {str(e)}")
                traceback.print_exc()
                return False
        return False

    async def custom_command_handler(self, interaction: discord.Interaction, cmd_data: dict):
        """Handler for database-stored commands"""
        try:
            content = cmd_data.get('content', 'No content configured')
            ephemeral = bool(cmd_data.get('ephemeral', True))
            response_args = {'ephemeral': ephemeral}

            # Handle image URLs
            if any(content.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif']):
                embed = discord.Embed().set_image(url=content)
                await interaction.response.send_message(embed=embed, **response_args)
            elif content.startswith('http'):
                await interaction.response.send_message(content, **response_args)
            else:
                # Handle multi-line responses
                if '\n' in content:
                    parts = [content[i:i+2000] for i in range(0, len(content), 2000)]
                    await interaction.response.send_message(parts[0], **response_args)
                    for part in parts[1:]:
                        await interaction.followup.send(part, ephemeral=ephemeral)
                else:
                    await interaction.response.send_message(content, **response_args)

        except Exception as e:
            error_msg = "❌ Command execution failed"
            print(f"Command error: {str(e)}\n{traceback.format_exc()}")
            try:
                await interaction.response.send_message(error_msg, ephemeral=True)
            except discord.InteractionResponded:
                await interaction.followup.send(error_msg, ephemeral=True)

bot_instance = CustomBot(
    command_prefix='!',
    intents=discord.Intents.all(),
    help_command=None,
    activity=discord.Activity(
        type=discord.ActivityType.watching,
        name="for rule breakers"
    )
)        
        
# -------------------- Logging Helper --------------------
async def log_event(guild, event_key, title=None, description=None, color=discord.Color.blue(), extra_fields=None, embed=None):
    # Get guild-specific log configuration from database
    log_config = db.get_log_config(str(guild.id))

    # Create default config if not exists
    if not log_config:
        db.conn.execute(
            'INSERT INTO log_config (guild_id) VALUES (?)',
            (str(guild.id),)
        )
        db.conn.commit()
        log_config = db.get_log_config(str(guild.id))

    # Check if logging for this event is enabled
    if not log_config.get(event_key, True):
        return

    # Get channel ID from config
    channel_id = log_config.get('log_channel_id')
    if not channel_id:
        return  # No log channel configured

    channel = guild.get_channel(int(channel_id))
    if channel is None:
        print(f"Log channel not found in guild: {guild.name} (ID: {channel_id})")
        return

    # Create embed only if not passed
    if embed is None:
        embed = discord.Embed(
            title=title,
            description=description,
            color=color,
            timestamp=discord.utils.utcnow()
        )
        # Add extra fields if provided
        if extra_fields:
            for name, value in extra_fields.items():
                embed.add_field(name=name, value=value, inline=False)

    # Send to log channel
    try:
        await channel.send(embed=embed)
    except Exception as e:
        print(f"Failed to send log message in {guild.name}: {str(e)}")

# -------------------- Custom Commands Storage --------------------
def load_commands(guild_id):
    """Load commands from database for a specific guild"""
    return db.get_commands(str(guild_id))

def save_commands(guild_id, commands_dict):
    """Save commands to database for a specific guild"""
    # Clear existing commands
    db.conn.execute('DELETE FROM commands WHERE guild_id = ?', (str(guild_id),))
    
    # Insert new commands
    for command_name, data in commands_dict.items():
        db.conn.execute('''
            INSERT INTO commands 
            (guild_id, command_name, content, description, ephemeral)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            str(guild_id),
            command_name,
            data["content"],
            data.get("description", "Custom command"),
            int(data.get("ephemeral", True))
        ))
    db.conn.commit()

def get_all_commands():
    """Get commands for all guilds with connection check"""
    if not db.conn:
        db._connect()
        
    commands = {}
    with db.conn:
        cursor = db.conn.execute('SELECT * FROM commands')
        for row in cursor.fetchall():
            guild_id = row['guild_id']
            if guild_id not in commands:
                commands[guild_id] = {}
            commands[guild_id][row['command_name']] = dict(row)
    return commands

# Initialize commands from database
custom_commands = get_all_commands()

# -------------------- Web Server for Syncing --------------------
async def webserver():
    # Define CORS middleware
    async def cors_middleware(app, handler):
        async def middleware(request):
            # Handle OPTIONS requests (preflight)
            if request.method == hdrs.METH_OPTIONS:
                response = web.Response(status=204)  # 204 No Content
                response.headers.update({
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "POST, GET, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    "Access-Control-Max-Age": "86400",  # Cache preflight for 24 hours
                })
                return response

            # Handle actual requests
            response = await handler(request)
            response.headers.update({
                "Access-Control-Allow-Origin": "*",
            })
            return response
        return middleware

    # Create app with CORS middleware
    app = web.Application(middlewares=[cors_middleware])
    
    # Routes
    app.router.add_post('/send_appeal_to_discord', handle_send_to_discord)
    app.router.add_get('/health', lambda _: web.Response(text="OK"))
    app.router.add_post('/sync', handle_sync)
    app.router.add_post('/sync_warnings', handle_sync_warnings)
    app.router.add_post('/appeal', handle_appeal_submission)
    app.router.add_get('/get_bans', handle_get_bans)
    app.router.add_post('/unban/{userid}', handle_unban)
    app.router.add_route(hdrs.METH_OPTIONS, '/unban/{userid}', handle_options)
    
    # Setup and start the server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 5003)
    await site.start()
    print("Endpoints running on port 5003")

async def validate_appeal_token(request):
    data = await request.json()
    token = data.get('token')
    
    appeal = db.conn.execute('''
        SELECT * FROM appeals 
        WHERE appeal_token = ?
        AND expires_at > ?
        AND status = 'pending'
    ''', (token, int(time.time()))).fetchone()
    
    if not appeal:
        return web.json_response({"error": "Invalid or expired token"}, status=400)
    
    request['appeal_data'] = dict(appeal)
    return None

async def handle_options(request):
    return web.Response(
        status=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
    )

async def handle_sync(request):
    return web.Response(text="Commands synced successfully!")
    
async def handle_sync_warnings(request):
    reload_warnings()
    return web.Response(text="Warnings synced successfully!")
    
async def handle_get_bans(request):
    try:
        print("Fetching bans...")
        data = await request.json()
        guild_id = data.get('guild_id')
        
        if not guild_id or not guild_id.isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)
        
        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Guild not found"}, status=404)
            
        bans = []
        async for entry in guild.bans():
            bans.append({
                "user_id": str(entry.user.id),
                "username": str(entry.user),
                "reason": entry.reason or "No reason provided",
                "date": datetime.now().isoformat()
            })
        
        print(f"Total bans fetched: {len(bans)}")
        return web.json_response(bans)
        
    except Exception as e:
        print(f"Error fetching bans: {str(e)}")
        return web.json_response({"error": str(e)}, status=500)

async def handle_appeal_submission(request):
    try:
        data = await request.json()
        appeal_type = data.get('type')
        user_id = data.get('user_id')
        form_data = data.get('data', [])
        channel_id = data.get('channel_id')

        if not all([appeal_type, user_id, channel_id]):
            return web.Response(status=400, text="Missing required fields")

        channel = bot_instance.get_channel(int(channel_id))
        if not channel:
            return web.Response(status=404, text=f"Channel {channel_id} not found")

        guild_id = channel.guild.id
        appeal_id = str(uuid.uuid4())

        appeal_data = {
            'appeal_id': appeal_id,
            'user_id': user_id,
            'type': appeal_type,
            'data': json.dumps(form_data),
            'status': 'pending',
            'channel_id': channel_id
        }

        db.create_appeal(str(guild_id), appeal_data)

        embed = discord.Embed(
            title=f"{appeal_type.capitalize()} Appeal - {appeal_id}",
            color=discord.Color.orange(),
            description=(
                f"**User ID:** {user_id}\n"
                f"**Submitted:** <t:{int(time.time())}:R>\n"
                f"**Appeal ID:** `{appeal_id}`"
            )
        )

        for index, item in enumerate(form_data, 1):
            embed.add_field(
                name=f"{index}. {item.get('question', f'Question #{index}')}",
                value=item.get('answer', 'No response provided') or "N/A",
                inline=False
            )

        view = discord.ui.View()
        view.add_item(discord.ui.Button(
            style=discord.ButtonStyle.green,
            label="Approve",
            custom_id=f"approve_{appeal_type}_{appeal_id}"
        ))
        view.add_item(discord.ui.Button(
            style=discord.ButtonStyle.red,
            label="Reject",
            custom_id=f"reject_{appeal_type}_{appeal_id}"
        ))

        await channel.send(embed=embed, view=view)
        return web.Response(text="Appeal processed successfully")

    except Exception as e:
        print(f"Unexpected error processing appeal: {str(e)}")
        return web.Response(status=500, text="Internal server error")

def validate_uuid(uuid_str):
    """Validate UUIDv4 format"""
    try:
        uuid.UUID(uuid_str, version=4)
        return True
    except ValueError:
        return False

def get_guild_id_from_channel(channel_id):
    """Resolve guild ID from channel ID with fallbacks"""
    try:
        channel = bot_instance.get_channel(int(channel_id))
        return str(channel.guild.id) if channel else None
    except Exception as e:
        print(f"⚠️ Channel resolution error: {str(e)}")
        return None

async def handle_unban(request):
    user_id = request.match_info['userid']
    data = await request.json()
    
    try:
        guild_id = data.get('guild_id')
        if not guild_id or not guild_id.isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)
        
        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Guild not found"}, status=404)

        user = await bot_instance.fetch_user(int(user_id))
        
        try:
            await guild.unban(user, reason="Ban appeal approved")
            db.conn.execute('''
                UPDATE appeals 
                SET status = 'approved' 
                WHERE guild_id = ? AND user_id = ? AND status = 'pending'
            ''', (guild_id, user_id))
            db.conn.commit()
            return web.json_response({"status": "success"})
        except discord.NotFound:
            return web.json_response({"error": "User not banned"}, status=404)
            
    except Exception as e:
        print(f"Unban error: {str(e)}")
        return web.json_response({"error": str(e)}, status=500)

@tasks.loop(minutes=5)
async def cleanup():
    # Clean expired data
    processed_messages.clear()

@bot_instance.event
async def on_ready():
    set_event_loop(bot_instance.loop)
    print("""
    +==============================================================+
    |  _____         _        _   __                               |
    | | ___ \       | |      | | / /                               |
    | | |_/ / _   _ | |  ___ | |/ /   ___   ___  _ __    ___  _ __ |
    | |    / | | | || | / _ \|    \  / _ \ / _ \| '_ \  / _ \| '__||
    | | |\ \ | |_| || ||  __/| |\  \|  __/|  __/| |_) ||  __/| |   |
    | \_| \_| \__,_||_| \___|\_| \_/ \___| \___|| .__/  \___||_|   |
    |                                           | |                |
    |                                           |_|                |
    +==============================================================+
    """)
    
    print(f'Logged in as {bot_instance.user}')
    if not bot_instance.guilds:
        print("⚠️ Bot not in any guilds, skipping command sync")
        return  
    
    # Temporary guild verification
    for guild in bot_instance.guilds:
        cmds = bot_instance.db.conn.execute(
            'SELECT command_name FROM commands WHERE guild_id = ?',
            (str(guild.id),)
        ).fetchall()
        
    cleanup.start()
    # Get current guild IDs as strings
    current_guild_ids = {str(g.id) for g in bot_instance.guilds}
    
    # Get database guild IDs
    db_guilds = db.get_all_guilds()
    db_guild_ids = {g['id'] for g in db_guilds}
    
    # Add missing guilds
    added = 0
    for guild in bot_instance.guilds:
        if str(guild.id) not in db_guild_ids:
            db.add_guild(str(guild.id), guild.name, str(guild.owner_id))
            added += 1
    
    # Remove orphaned guilds
    removed = 0
    for db_guild_id in db_guild_ids - current_guild_ids:
        db.remove_guild(db_guild_id)
        removed += 1
    
    # Final verification
    new_count = len(db.get_all_guilds())
    
    try:
        test_uuid = uuid.uuid4()
    except NameError:
        print("❌ UUID MODULE NOT LOADED - CHECK IMPORTS")
        raise
    bot_instance.loop.create_task(webserver())
    await bot_instance.role_batcher.initialize()

def load_appeal_forms(guild_id: str) -> dict:
    forms = db.get_appeal_forms(guild_id)
    if not forms:
        # Create default entry if none exists
        db.update_appeal_forms(guild_id, 
                             ban_enabled=True,
                             ban_form_url="",
                             kick_enabled=False,
                             kick_form_url="",
                             timeout_enabled=False,
                             timeout_form_url="")
        return {
            "ban": {"enabled": True, "form_url": ""},
            "kick": {"enabled": False, "form_url": ""},
            "timeout": {"enabled": False, "form_url": ""}
        }
    return forms

def load_appeals(guild_id: str) -> list:
    appeals = db.conn.execute('SELECT * FROM appeals WHERE guild_id = ?', (guild_id,)).fetchall()
    return [dict(a) for a in appeals]

def reload_warnings(guild_id: str):
    global warnings
    warnings = db.conn.execute('''
        SELECT * FROM warnings 
        WHERE guild_id = ?
        ORDER BY timestamp DESC
    ''', (guild_id,)).fetchall()
    warnings = [dict(w) for w in warnings]

# -------------------- Appeal Embed ------------------
async def handle_send_to_discord(request):
    """Handle appeal sending with full data validation"""
    try:
        data = await request.json()
        appeal_id = data.get('appeal_id')
        guild_id = data.get('guild_id')

        if not appeal_id or not guild_id:
            return web.Response(status=400, text="Missing appeal_id or guild_id")

        # Get full appeal data from database
        appeal = db.get_appeal(guild_id, appeal_id)
        if not appeal:
            return web.Response(status=404, text="Appeal not found")

        # Get channel ID from appeal form config
        form_config = db.get_appeal_forms(guild_id) or {}
        channel_id = form_config.get(f"{appeal['type']}_channel_id")
        if not channel_id:
            return web.Response(status=400, text="No channel configured for this appeal type")

        # Send to Discord
        success = await send_appeal_to_discord(
            channel_id=int(channel_id),
            appeal_data={
                'id': appeal['appeal_id'],
                'user_id': appeal['user_id'],
                'guild_id': guild_id,
                'type': appeal['type'],
                'data': appeal.get('appeal_data', {})
            }
        )

        if success:
            return web.Response(text="Appeal sent to Discord")
        return web.Response(status=500, text="Failed to send appeal")

    except Exception as e:
        logger.error(f"Send error: {traceback.format_exc()}")
        return web.Response(status=500, text="Internal server error")

async def send_appeal_to_discord(channel_id: int, appeal_data: dict) -> bool:
    """Final version with complete data handling"""
    try:
        # Validate required data
        required_keys = ['id', 'user_id', 'guild_id', 'type', 'data']
        if any(key not in appeal_data for key in required_keys):
            logger.error(f"Missing keys in appeal_data: {required_keys}")
            return False

        # Get form configuration
        form_config = db.get_appeal_forms(appeal_data['guild_id']) or {}
        form_fields = json.loads(form_config.get(f"{appeal_data['type']}_form_fields", "[]"))
        
        # Create embed with questions
        embed = discord.Embed(
            title=f"{appeal_data['type'].title()} Appeal - {appeal_data['id'][:8]}",
            description=(
                f"**User ID:** {appeal_data['user_id']}\n"
                f"**Submitted:** <t:{int(time.time())}:R>\n"
                f"**Appeal ID:** `{appeal_data['id'][:8]}`"
            ),
            color=0xFFA500
        )

        # Add form fields and answers
        for idx, question in enumerate(form_fields, 1):
            answer = appeal_data['data'].get(f'response_{idx}', 'No response')
            embed.add_field(
                name=f"{idx}. {question}",
                value=str(answer)[:1024],
                inline=False
            )
            
        embed.add_field(
            name="Visit in Dashboard",
            value=f"[Manage Appeal]({FRONTEND_URL}/dashboard/{appeal_data['guild_id']}/appeals/{appeal_data['id']})",
            inline=False
        )

        # Create action buttons
        view = discord.ui.View()
        view.add_item(discord.ui.Button(
            style=discord.ButtonStyle.green,
            custom_id=f"approve_{appeal_data['type']}_{appeal_data['id']}",
            label="Approve"
        ))
        view.add_item(discord.ui.Button(
            style=discord.ButtonStyle.red,
            custom_id=f"reject_{appeal_data['type']}_{appeal_data['id']}",
            label="Reject"
        ))

        # Send message
        channel = bot_instance.get_channel(channel_id)
        await channel.send(embed=embed, view=view)
        return True

    except Exception as e:
        logger.error(f"Send failed: {traceback.format_exc()}")
        return False

@bot_instance.event
async def on_interaction(interaction: discord.Interaction):
    if interaction.type == discord.InteractionType.component:
        custom_id = interaction.data.get('custom_id', '')
        
        # Handle approve/reject actions
        if custom_id.startswith(('approve_', 'reject_')):
            try:
                # Split into action_type_appealid format
                parts = custom_id.split('_', 2)  # Split into max 3 parts
                if len(parts) != 3:
                    raise ValueError("Invalid custom ID format")

                action, appeal_type, appeal_id = parts
                guild_id = str(interaction.guild.id)

                # Get full appeal data
                appeal = db.get_appeal(guild_id, appeal_id)
                if not appeal:
                    await interaction.response.send_message("Appeal not found", ephemeral=True)
                    return

                # Update appeal status
                new_status = 'approved' if action == 'approve' else 'rejected'
                db.update_appeal(
                    appeal_id=appeal_id,
                    status=new_status,
                    reviewed_by=str(interaction.user.id),
                    reviewed_at=int(time.time())
                )

                # Handle actions
                user = await bot_instance.fetch_user(int(appeal['user_id']))
                if action == 'approve':
                    if appeal_type == 'ban':
                        await interaction.guild.unban(user, reason=f"Appeal {appeal_id} approved")
                    elif appeal_type == 'timeout':
                        member = await interaction.guild.fetch_member(user.id)
                        await member.timeout(None, reason=f"Appeal {appeal_id} approved")
                    elif appeal_type == 'kick':
                        invite = await interaction.channel.create_invite(max_uses=1, reason="Appeal approved")
                        await user.send(f"Your kick appeal was approved: {invite.url}")

                # Update message components
                embed = interaction.message.embeds[0].copy()
                embed.color = discord.Color.green() if action == 'approve' else discord.Color.red()
                
                # Add status field if missing
                status_exists = any(field.name.lower() == "status" for field in embed.fields)
                if not status_exists:
                    embed.add_field(name="Status", value=new_status.capitalize(), inline=False)
                
                # Disable all buttons
                view = discord.ui.View()
                for component in interaction.message.components:
                    if component.type == discord.ComponentType.button:
                        btn = discord.ui.Button.from_component(component)
                        btn.disabled = True
                        view.add_item(btn)

                await interaction.message.edit(embed=embed, view=view)
                await interaction.response.send_message(f"Appeal {new_status}", ephemeral=True)

            except discord.Forbidden:
                await interaction.response.send_message("Missing permissions to perform this action", ephemeral=True)
            except discord.NotFound:
                await interaction.response.send_message("User not found", ephemeral=True)
            except Exception as e:
                logger.error(f"Appeal handling error: {traceback.format_exc()}")
                await interaction.response.send_message("Error processing appeal", ephemeral=True)
                return

# -------------------- Level System --------------------
def get_level_data(guild_id, user_id):
    try:
        data = db.get_user_level(str(guild_id), str(user_id))
        if not data:
            # Create new user with default values
            db.conn.execute('''
                INSERT INTO user_levels 
                (guild_id, user_id, xp, level, username, last_message, message_count)
                VALUES (?, ?, 0, 0, ?, 0, 0)
            ''', (str(guild_id), str(user_id), ""))
            db.conn.commit()
            return {
                "xp": 0,
                "level": 0,
                "username": "",
                "last_message": 0,
                "message_count": 0
            }
        return data
    except Exception as e:
        print(f"Error getting level data: {str(e)}")
        traceback.print_exc()
        return None

def save_level_data(guild_id, user_id, data):
    db.update_user_level(str(guild_id), str(user_id), **data)

def get_level_config(guild_id: str) -> dict:
    """Get validated level configuration with caching and type safety"""
    # Default configuration template (create new copy each call)
    default_config = {
        'cooldown': 60,
        'xp_min': 15,
        'xp_max': 25,
        'level_channel': None,
        'announce_level_up': True,
        'excluded_channels': [],
        'xp_boost_roles': {},
        'embed_title': '🎉 Level Up!',
        'embed_description': '{user} has reached level **{level}**!',
        'embed_color': 0xffd700
    }

    try:
        # Check cache first
        cached_config = level_config_cache.get(guild_id)
        if cached_config:
            return cached_config.copy()

        # Get raw config from database
        raw_config = db.get_level_config(guild_id)
        if not raw_config:
            # Store default in cache
            level_config_cache[guild_id] = default_config.copy()
            return default_config.copy()

        # Convert to dict if needed (SQLite Row object)
        config = dict(raw_config) if not isinstance(raw_config, dict) else raw_config.copy()
        validated = default_config.copy()

        # Validate integer fields
        int_fields = ['cooldown', 'xp_min', 'xp_max']
        for field in int_fields:
            try:
                value = int(config.get(field, default_config[field]))
                validated[field] = max(value, 1)  # Ensure minimum 1
            except (ValueError, TypeError):
                logger.warning(f"Invalid {field} value, using default")
                validated[field] = default_config[field]

        # Validate color (0-0xFFFFFF)
        try:
            color = int(config.get('embed_color', default_config['embed_color']))
            validated['embed_color'] = max(0, min(color, 0xFFFFFF))
        except (ValueError, TypeError):
            logger.warning("Invalid embed color, using default gold")
            validated['embed_color'] = 0xffd700

        # Validate boolean
        validated['announce_level_up'] = bool(config.get(
            'announce_level_up', 
            default_config['announce_level_up']
        ))

        # Validate JSON fields
        json_fields = {
            'excluded_channels': list,
            'xp_boost_roles': dict
        }
        for field, expected_type in json_fields.items():
            raw_value = config.get(field, default_config[field])
            
            if isinstance(raw_value, str):
                try:
                    parsed = json.loads(raw_value)
                    if isinstance(parsed, expected_type):
                        validated[field] = parsed
                    else:
                        raise ValueError("Invalid type")
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"Invalid {field} JSON: {str(e)}")
                    validated[field] = default_config[field].copy()
            elif isinstance(raw_value, expected_type):
                validated[field] = raw_value.copy() if isinstance(raw_value, (list, dict)) else raw_value
            else:
                logger.warning(f"Invalid {field} type, using default")
                validated[field] = default_config[field].copy()

        # Validate string fields
        str_fields = ['level_channel', 'embed_title', 'embed_description']
        for field in str_fields:
            value = str(config.get(field, default_config[field]))
            validated[field] = value[:255]  # Prevent overly long strings

        # Final sanity checks
        validated['xp_min'] = min(validated['xp_min'], validated['xp_max'])
        validated['xp_max'] = max(validated['xp_min'], validated['xp_max'])
        
        # Update cache
        level_config_cache[guild_id] = validated.copy()
        return validated.copy()

    except Exception as e:
        logger.error(f"Critical error loading level config: {str(e)}")
        # Return fresh default copy
        return default_config.copy()

def calculate_xp_for_level(level: int) -> int:
    """Calculate total XP required to reach a specific level"""
    return int(100 * (level ** 1.7))  # Exponential scaling

def calculate_level(xp: float) -> int:
    """Calculate level based on total XP using inverse function"""
    if xp <= 0:
        return 0
    return int((xp / 100) ** (1/1.7))

def calculate_progress(xp: float) -> tuple:
    current_level = calculate_level(xp)
    current_level_xp = calculate_xp_for_level(current_level)
    next_level_xp = calculate_xp_for_level(current_level + 1)
    progress = xp - current_level_xp
    return progress, next_level_xp - current_level_xp

def calculate_xp_with_boost(base_xp, user_roles, xp_boost_roles):
    boost = 0
    for role in user_roles:
        # Use role ID as integer key
        role_id = str(role.id)
        if role_id in xp_boost_roles:
            boost += xp_boost_roles[role_id]
    return base_xp * (1 + boost / 100)

async def handle_level_up(user, guild, channel):
    try:
        guild_id = guild.id
        user_id = user.id
        
        user_data = get_level_data(guild_id, user_id)
        total_xp = user_data['xp']
        new_level = calculate_level(total_xp)
        
        # Handle multiple level jumps
        old_level = user_data['level']
        if new_level > old_level:
            # Update to new level
            save_level_data(guild_id, user_id, {'level': new_level})
            
            # Get rewards for all levels between old and new
            rewards = db.get_level_rewards(str(guild_id))
            roles_to_add = []
            for level in range(old_level + 1, new_level + 1):
                role_id = rewards.get(level)
                if role_id:
                    role = guild.get_role(int(role_id))
                    if role:
                        roles_to_add.append(role)
            
            if roles_to_add:
                try:
                    await user.add_roles(*roles_to_add, reason=f"Level {new_level} rewards")
                except discord.Forbidden:
                    print(f"Missing permissions to assign roles in {guild.name}")
                except Exception as e:
                    print(f"Error assigning roles: {str(e)}")
            
            # Send notifications for each level up if configured
            config = get_level_config(guild_id)
            if config['announce_level_up']:
                await send_level_up_notification(user, guild, channel, new_level, config)
    
    except Exception as e:
        print(f"Error handling level up: {str(e)}")
        traceback.print_exc()

async def send_level_up_notification(user, guild, channel, new_level, config):
    try:
        target_channel = guild.get_channel(int(config['level_channel'])) if config['level_channel'] else channel
        if target_channel:
            embed = discord.Embed(
                title=config['embed_title'],
                description=config['embed_description'].format(
                    user=user.mention, 
                    level=new_level
                ),
                color=config['embed_color']
            )
            embed.set_thumbnail(url=user.display_avatar.url)
            await target_channel.send(embed=embed)
    except Exception as e:
        print(f"Error sending level up notification: {str(e)}")
            
# -------------------- Message Processing --------------------
@bot_instance.event
async def on_message(message):
    if message.author.bot or not message.guild:
        return await bot_instance.process_commands(message)

    try:
        guild_id = str(message.guild.id)
        user_id = str(message.author.id)
        current_time = time.time()

        # ===== LEVEL SYSTEM PROCESSING =====
        level_config = get_level_config(guild_id)
        spam_config = db.get_spam_config(guild_id)
        
        # Process XP if not in excluded level channels
        if str(message.channel.id) not in level_config['excluded_channels']:
            # XP processing logic
            cooldown_seconds = level_config['cooldown']
            user_data = get_level_data(guild_id, user_id)
            last_cooldown_time = user_data.get('last_message', 0)

            if (current_time - last_cooldown_time) >= cooldown_seconds:
                # Update message count and last message time
                db.conn.execute('''
                    INSERT INTO user_levels (guild_id, user_id, username, message_count, last_message, xp)
                    VALUES (?, ?, ?, 1, ?, 0)
                    ON CONFLICT(guild_id, user_id) 
                    DO UPDATE SET 
                        message_count = message_count + 1,
                        username = excluded.username,
                        last_message = excluded.last_message
                ''', (guild_id, user_id, message.author.name, current_time))

                # Calculate XP with boost
                base_xp = random.randint(level_config['xp_min'], level_config['xp_max'])
                xp_multiplier = 1.0 + sum(
                    level_config['xp_boost_roles'].get(str(role.id), 0) / 100 
                    for role in message.author.roles
                )
                earned_xp = int(base_xp * xp_multiplier)

                # Update XP
                db.conn.execute('''
                    UPDATE user_levels 
                    SET xp = xp + ?,
                        last_message = ?
                    WHERE guild_id = ? AND user_id = ?
                ''', (earned_xp, current_time, guild_id, user_id))
                db.conn.commit()

                # Check for level up
                new_total_xp = db.get_user_level(guild_id, user_id)['xp']
                new_level = calculate_level(new_total_xp)
                
                if new_level > user_data.get('level', 0):
                    db.conn.execute('''
                        UPDATE user_levels 
                        SET level = ?
                        WHERE guild_id = ? AND user_id = ?
                    ''', (new_level, guild_id, user_id))
                    db.conn.commit()
                    await handle_level_up(message.author, message.guild, message.channel)

        # ===== BLOCKED WORDS CHECK =====
        content_lower = message.content.lower()
        blocked_words = db.get_blocked_words(guild_id)
        
        for word in blocked_words:
            if word.lower() in content_lower:
                try:
                    await message.delete()
                    embed_config = db.get_blocked_embed(guild_id) or {
                        "title": "Blocked Word Detected!",
                        "description": "You have used a word that is not allowed.",
                        "color": 0xff0000
                    }
                    
                    try:
                        embed = discord.Embed(
                            title=embed_config['title'],
                            description=embed_config['description'],
                            color=discord.Color(embed_config['color'])
                        )
                        await message.author.send(embed=embed)
                    except discord.Forbidden:
                        pass
                    
                    await log_event(
                        message.guild,
                        "message_delete",
                        "Blocked Word Detected",
                        f"**User:** {message.author.mention}\n**Word:** ||{word}||",
                        color=discord.Color.red()
                    )
                    return
                except Exception as e:
                    print(f"Blocked word handling error: {str(e)}")
                return

        # ===== SPAM DETECTION =====
        # Check if user/channel is excluded
        user_roles = [str(role.id) for role in message.author.roles]
        is_excluded = (
            str(message.channel.id) in spam_config["excluded_channels"] or
            any(role in spam_config["excluded_roles"] for role in user_roles)
        )

        if not is_excluded:
            # Spam detection
            spam_key = f"{guild_id}:{user_id}"
            
            # Initialize timestamp list if needed
            if spam_key not in message_timestamps:
                message_timestamps[spam_key] = []
            
            # Add current message timestamp
            message_timestamps[spam_key].append(current_time)
            
            # Filter out expired timestamps (older than time window)
            window_start = current_time - spam_config["spam_time_window"]
            message_timestamps[spam_key] = [
                t for t in message_timestamps[spam_key] 
                if t >= window_start
            ]
            
            # Check if current count exceeds threshold
            if len(message_timestamps[spam_key]) >= spam_config["spam_threshold"]:
                try:
                    await message.channel.send(
                        embed=discord.Embed(
                            title="Spam Detected",
                            description=f"{message.author.mention} Please stop spamming!",
                            color=discord.Color.red()
                        ),
                        delete_after=10
                    )
                    await message.delete()
                    await log_event(
                        message.guild,
                        "message_delete",
                        "Spam Detected",
                        f"**User:** {message.author.mention}\n**Count:** {len(message_timestamps[spam_key])} messages\n**Threshold:** {spam_config['spam_threshold']}/{spam_config['spam_time_window']}s",
                        color=discord.Color.orange()
                    )
                    # Reset after handling spam
                    message_timestamps[spam_key] = []
                except Exception as e:
                    print(f"Spam handling error: {str(e)}")

            # Mention flood detection
            mention_count = len(message.mentions)
            if mention_count > 0:
                mention_key = f"{guild_id}:{user_id}"
                user_mentions[mention_key] = user_mentions.get(mention_key, []) + [current_time] * mention_count
                
                # Cleanup old mentions
                window_start = current_time - spam_config["mention_time_window"]
                user_mentions[mention_key] = [t for t in user_mentions[mention_key] if t >= window_start]
                
                if len(user_mentions[mention_key]) > spam_config["mention_threshold"]:
                    try:
                        await message.channel.send(
                            embed=discord.Embed(
                                title="Mention Flood",
                                description=f"{message.author.mention} Too many mentions!",
                                color=discord.Color.orange()
                            ),
                            delete_after=10
                        )
                        await message.delete()
                        await log_event(
                            message.guild,
                            "message_delete",
                            "Mention Flood",
                            f"**User:** {message.author.mention}\n**Count:** {len(user_mentions[mention_key])} mentions\n**Threshold:** {spam_config['mention_threshold']}/{spam_config['mention_time_window']}s",
                            color=discord.Color.orange()
                        )
                        user_mentions[mention_key] = []
                    except Exception as e:
                        print(f"Mention flood handling error: {str(e)}")

        # Track processed messages
        processed_messages[message.id] = True
        if len(processed_messages) > 1000:
            processed_messages.clear()

    except Exception as e:
        print(f"Error in on_message handler: {str(e)}")
        traceback.print_exc()

    await bot_instance.process_commands(message)

# -------------------- Logging Event Handlers --------------------

@bot_instance.event
async def on_message_delete(message):
    if message.guild is None or message.author.bot:
        return
    config = load_log_config(message.guild.id)
    if config.get("message_delete", True):
        description = (
            f"**Author:** {message.author.mention}\n"
            f"**Channel:** {message.channel.mention}\n"
            f"**Content:** {message.content if message.content else 'No text content.'}"
        )
        await log_event(message.guild, "message_delete", "Message Deleted", description, color=discord.Color.red())
        if message.attachments:
            for attachment in message.attachments:
                if attachment.content_type and attachment.content_type.startswith("image"):
                    img_description = (
                        f"**Author:** {message.author.mention}\n"
                        f"**Channel:** {message.channel.mention}\n"
                        f"**Image URL:** {attachment.url}"
                    )
                    await log_event(message.guild, "message_delete", "Image Deleted", img_description, color=discord.Color.dark_red())
                    
#--------------------- Events ------------------------
@bot_instance.event
async def on_member_join(member):
    try:
        # Assign auto-roles
        autoroles = db.get_autoroles(str(member.guild.id))
        if autoroles:
            roles_to_add = []
            for role_id in autoroles:
                role = member.guild.get_role(int(role_id))
                if role and role < member.guild.me.top_role:
                    roles_to_add.append(role)
            
            if roles_to_add:
                try:
                    await member.add_roles(*roles_to_add, reason="Automatic role assignment")
                except discord.Forbidden:
                    logger.error(f"Missing permissions to assign roles in {member.guild.name}")
                except Exception as e:
                    logger.error(f"Error assigning auto-roles: {str(e)}")        
        
        config = db.get_welcome_config(str(member.guild.id))
        if not config or not config.get('enabled'):
            return

        channel = member.guild.get_channel(int(config['channel_id']))
        if not channel:
            return

        replacements = {
            '{user}': member.mention,
            '{server}': member.guild.name,
            '{member_count}': str(member.guild.member_count)
        }

        if config.get('message_type', 'text') == 'embed':
            # Create both content and embed
            content = replace_placeholders(config.get('message_content', ''), replacements)
            embed = discord.Embed(
                title=replace_placeholders(config.get('embed_title', 'Welcome!'), replacements),
                description=replace_placeholders(config.get('embed_description', 'Welcome to {server}!'), replacements),
                color=config.get('embed_color', 0x00FF00)
            )
            
            if config.get('embed_thumbnail', True):
                embed.set_thumbnail(url=member.display_avatar.url)
            
            if config.get('show_server_icon', False) and member.guild.icon:
                embed.set_author(name=member.guild.name, icon_url=member.guild.icon.url)

            await channel.send(content=content, embed=embed)
        else:
            # Text-only message
            content = replace_placeholders(config.get('message_content', 'Welcome {user} to {server}!'), replacements)
            await channel.send(content)

    except Exception as e:
        print(f"Welcome message error: {str(e)}")

def replace_placeholders(text, replacements):
    for placeholder, value in replacements.items():
        text = text.replace(placeholder, value)
    return text
    
@bot_instance.event
async def on_member_remove(member):
    try:
        config = db.get_goodbye_config(str(member.guild.id))
        if not config or not config.get('enabled'):
            return

        channel = member.guild.get_channel(int(config['channel_id']))
        if not channel:
            return

        replacements = {
            '{user}': member.mention,
            '{server}': member.guild.name,
            '{member_count}': str(member.guild.member_count)
        }

        if config.get('message_type', 'text') == 'embed':
            content = replace_placeholders(config.get('message_content', ''), replacements)
            embed = discord.Embed(
                title=replace_placeholders(config.get('embed_title', 'Goodbye!'), replacements),
                description=replace_placeholders(config.get('embed_description', '{user} has left {server}'), replacements),
                color=config.get('embed_color', 0xFF0000)
            )
            
            if config.get('embed_thumbnail', True):
                embed.set_thumbnail(url=member.display_avatar.url)
            
            if config.get('show_server_icon', False) and member.guild.icon:
                embed.set_author(name=member.guild.name, icon_url=member.guild.icon.url)

            await channel.send(content=content, embed=embed)
        else:
            content = replace_placeholders(config.get('message_content', 'Goodbye {user}!'), replacements)
            await channel.send(content)

    except Exception as e:
        print(f"Goodbye message error: {str(e)}")

@bot_instance.event
async def on_member_update(before, after):
    if before.guild is None:
        return
    config = load_log_config(before.guild.id)
    log_channel_id = config.get("log_channel_id")
    if not (config.get("member_role_add", True) or config.get("member_role_remove", True)):
        return

    # Find added and removed roles
    before_roles = set(before.roles)
    after_roles = set(after.roles)
    added_roles = after_roles - before_roles
    removed_roles = before_roles - after_roles

    # Only log if there are changes
    if not added_roles and not removed_roles:
        return

    # Log added roles
    if added_roles and config.get("member_role_add", True):
        description = f"**User:** {after.mention} ({after.id})\n"
        description += f"**Added Roles:** {', '.join(role.mention for role in added_roles)}\n"
        await log_event(
            after.guild,
            "member_role_add",
            "Member Role Added",
            description.strip(),
            color=discord.Color.green()
        )

    # Log removed roles
    if removed_roles and config.get("member_role_remove", True):
        description = f"**User:** {after.mention} ({after.id})\n"
        description += f"**Removed Roles:** {', '.join(role.mention for role in removed_roles)}\n"
        await log_event(
            after.guild,
            "member_role_remove",
            "Member Role Removed",
            description.strip(),
            color=discord.Color.red()
        )

@bot_instance.event
async def on_guild_available(guild):
    if not db.get_guild(str(guild.id)):
        print(f"⚠️ Guild {guild.name} not in database, attempting recovery...")
        await on_guild_join(guild)  # Re-trigger join logic

@bot_instance.event
async def on_guild_join(guild):
    """Handle when the bot joins a new guild"""
    try:
        print(f"🤖 Joined new guild: {guild.name} ({guild.id})")
        
        # Add to database
        db.add_guild(
            guild_id=str(guild.id),
            name=guild.name,
            owner_id=str(guild.owner_id),
            icon=str(guild.icon.url) if guild.icon else None
        )
        
        # Create default configurations
        db.conn.execute('INSERT OR IGNORE INTO log_config (guild_id) VALUES (?)', (str(guild.id),))
        db.conn.execute('INSERT OR IGNORE INTO level_config (guild_id) VALUES (?)', (str(guild.id),))
        db.conn.commit()
        
        print(f"💾 Saved guild {guild.id} to database")
        
    except Exception as e:
        print(f"❌ Error handling guild join: {str(e)}")
        traceback.print_exc()
        
@bot_instance.event
async def on_guild_remove(guild):
    """Handle when the bot is removed from a guild"""
    try:
        print(f"🚪 Left guild: {guild.name} ({guild.id})")
        
        # Convert to string for database compatibility
        guild_id = str(guild.id)
        
        # Remove from database
        db.remove_guild(guild_id)
        
        # Clean up related data
        db.conn.execute('DELETE FROM log_config WHERE guild_id = ?', (guild_id,))
        db.conn.execute('DELETE FROM level_config WHERE guild_id = ?', (guild_id,))
        db.conn.execute('DELETE FROM blocked_words WHERE guild_id = ?', (guild_id,))
        db.conn.execute('DELETE FROM commands WHERE guild_id = ?', (guild_id,))
        db.conn.commit()
        
        print(f"🧹 Cleaned up data for guild {guild_id}")
        
    except Exception as e:
        print(f"❌ Error handling guild removal: {str(e)}")
        traceback.print_exc()

@bot_instance.event
async def on_bulk_message_delete(messages):
    if not messages:
        return
    guild = messages[0].guild
    if guild is None:
        return
    config = load_log_config(guild.id)
    if config.get("bulk_message_delete", True):
        description = f"Bulk deleted {len(messages)} messages in {messages[0].channel.mention}"
        await log_event(guild, "bulk_message_delete", "Bulk Message Delete", description, color=discord.Color.dark_red())

@bot_instance.event
async def on_message_edit(before, after):
    if before.guild is None:
        return
    if before.content == after.content:
        return
    config = load_log_config(before.guild.id)
    if config.get("message_edit", True):
        description = (
            f"**Author:** {before.author.mention}\n"
            f"**Channel:** {before.channel.mention}\n"
            f"**Before:** {before.content}\n"
            f"**After:** {after.content}"
        )
        await log_event(before.guild, "message_edit", "Message Edited", description, color=discord.Color.orange())

@bot_instance.event
async def on_invite_create(invite):
    guild = invite.guild
    config = load_log_config(guild.id)
    if config.get("invite_create", True):
        description = (
            f"**Invite Code:** {invite.code}\n"
            f"**Inviter:** {invite.inviter.mention if invite.inviter else 'Unknown'}\n"
            f"**Channel:** {invite.channel.mention}\n"
            f"**Max Uses:** {invite.max_uses}\n"
            f"**Expires In:** {invite.max_age} seconds"
        )
        await log_event(guild, "invite_create", "Invite Created", description, color=discord.Color.green())

@bot_instance.event
async def on_invite_delete(invite):
    guild = invite.guild
    config = load_log_config(guild.id)
    if config.get("invite_delete", True):
        description = (
            f"**Invite Code:** {invite.code}\n"
            f"**Inviter:** {invite.inviter.mention if invite.inviter else 'Unknown'}\n"
            f"**Channel:** {invite.channel.mention}"
        )
        await log_event(guild, "invite_delete", "Invite Deleted", description, color=discord.Color.dark_green())
        
@bot_instance.event
async def on_member_ban(guild, user):
    config = load_log_config(guild.id)
    if config.get("member_ban", True):
        description = f"**Member:** {user.mention} has been banned."
        await log_event(guild, "member_ban", "Member Banned", description, color=discord.Color.dark_red())

@bot_instance.event
async def on_guild_role_create(role):
    guild = role.guild
    config = load_log_config(guild.id)
    if config.get("role_create", True):
        description = f"**Role Created:** {role.name}\n**ID:** {role.id}"
        await log_event(guild, "role_create", "Role Created", description, color=discord.Color.green())

@bot_instance.event
async def on_guild_role_delete(role):
    guild = role.guild
    config = load_log_config(guild.id)
    if config.get("role_delete", True):
        description = f"**Role Deleted:** {role.name}\n**ID:** {role.id}"
        await log_event(guild, "role_delete", "Role Deleted", description, color=discord.Color.red())

@bot_instance.event
async def on_guild_role_update(before, after):
    guild = before.guild
    config = load_log_config(guild.id)
    if config.get("role_update", True):
        changes = []
        if before.name != after.name:
            changes.append(f"**Name:** {before.name} -> {after.name}")
        if changes:
            description = f"**Role Updated:** {after.name}\n" + "\n".join(changes)
            await log_event(guild, "role_update", "Role Updated", description, color=discord.Color.orange())

@bot_instance.event
async def on_guild_channel_create(channel):
    guild = channel.guild
    config = load_log_config(guild.id)
    if config.get("channel_create", True):
        description = f"**Channel Created:** {channel.mention}\n**Type:** {channel.type}"
        await log_event(guild, "channel_create", "Channel Created", description, color=discord.Color.green())

@bot_instance.event
async def on_guild_channel_delete(channel):
    guild = channel.guild
    config = load_log_config(guild.id)
    if config.get("channel_delete", True):
        description = f"**Channel Deleted:** {channel.name}\n**Type:** {channel.type}"
        await log_event(guild, "channel_delete", "Channel Deleted", description, color=discord.Color.red())

@bot_instance.event
async def on_guild_channel_update(before, after):
    guild = before.guild
    config = load_log_config(guild.id)
    if config.get("channel_update", True):
        changes = []
        if before.name != after.name:
            changes.append(f"**Name:** {before.name} -> {after.name}")
        if changes:
            description = f"**Channel Updated:** {after.mention if hasattr(after, 'mention') else after.name}\n" + "\n".join(changes)
            await log_event(guild, "channel_update", "Channel Updated", description, color=discord.Color.orange())

@bot_instance.event
async def on_guild_emojis_update(guild, before, after):
    config = load_log_config(guild.id)
    before_dict = {e.id: e for e in before}
    after_dict = {e.id: e for e in after}
    
    new_emojis = [e for e in after if e.id not in before_dict]
    for emoji in new_emojis:
        if config.get("emoji_create", True):
            embed = discord.Embed(
                title="Emoji Created",
                description=f"`:{emoji.name}:`",
                color=discord.Color.green(),
                timestamp=datetime.utcnow()
            )
            embed.set_thumbnail(url=emoji.url)
            embed.set_footer(text=f"ID: {emoji.id}")
            await log_event(guild, "emoji_create", embed=embed)

    deleted_emojis = [e for e in before if e.id not in after_dict]
    for emoji in deleted_emojis:
        if config.get("emoji_delete", True):
            embed = discord.Embed(
                title="Emoji Deleted",
                description=f"`:{emoji.name}:`",
                color=discord.Color.red(),
                timestamp=datetime.utcnow()
            )
            embed.set_thumbnail(url=emoji.url)
            embed.set_footer(text=f"ID: {emoji.id}")
            await log_event(guild, "emoji_delete", embed=embed)

    for emoji in after:
        if emoji.id in before_dict:
            old_emoji = before_dict[emoji.id]
            if old_emoji.name != emoji.name and config.get("emoji_name_change", True):
                embed = discord.Embed(
                    title="Emoji Updated",
                    description=f"`:{old_emoji.name}:` was changed to `:{emoji.name}:`",
                    color=discord.Color.orange(),
                    timestamp=datetime.utcnow()
                )
                embed.set_thumbnail(url=emoji.url)
                embed.set_footer(text=f"ID: {emoji.id}")
                await log_event(guild, "emoji_name_change", embed=embed)

@bot_instance.event
async def on_member_update(before, after):
    if before.guild is None:
        return
    config = load_log_config(before.guild.id)
    log_channel_id = config.get("log_channel_id")
    if not (config.get("member_role_add", True) or config.get("member_role_remove", True)):
        return

    # Find added and removed roles
    before_roles = set(before.roles)
    after_roles = set(after.roles)
    added_roles = after_roles - before_roles
    removed_roles = before_roles - after_roles

    # Only log if there are changes
    if not added_roles and not removed_roles:
        return

    description = f"**User:** {after.mention} ({after.id})\n"
    if added_roles and config.get("member_role_add", True):
        description += f"**Added Roles:** {', '.join(role.mention for role in added_roles)}\n"
    if removed_roles and config.get("member_role_remove", True):
        description += f"**Removed Roles:** {', '.join(role.mention for role in removed_roles)}\n"

    # Pick color
    color = discord.Color.green() if added_roles and not removed_roles else discord.Color.red() if removed_roles and not added_roles else discord.Color.orange()

    await log_event(
        after.guild,
        "member_role_change",
        "Member Role Updated",
        description.strip(),
        color=color
    )

@bot_instance.event
async def on_presence_update(before, after):
    try:
        # Skip processing for bots and non-guild members
        if after.bot or not after.guild:
            return

        guild = after.guild
        member = after.guild.get_member(after.id)
        current_time = int(time.time())
        user_id = str(member.id)
        guild_id = str(guild.id)

        # Get game role configurations for this guild
        game_roles = db.get_game_roles(guild_id)
        if not game_roles:
            return

        # Track game activity changes
        current_games = {
            a.name.lower(): a 
            for a in after.activities 
            if a.type == discord.ActivityType.playing
        }
        
        previous_games = {
            a.name.lower(): a 
            for a in before.activities 
            if a.type == discord.ActivityType.playing
        }

        tracked_games = {
            gr['game_name'].lower(): {
                'role_id': gr['role_id'],
                'required_seconds': gr['required_minutes'] * 60
            } for gr in game_roles
        }

        # Handle game starts
        for game_name in current_games:
            if game_name in tracked_games and game_name not in previous_games:
                db.execute_query(
                    '''INSERT INTO user_game_time 
                    (user_id, guild_id, game_name, last_start)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id, guild_id, game_name) 
                    DO UPDATE SET last_start = excluded.last_start''',
                    (user_id, guild_id, game_name, current_time)
                )

        # Handle game stops
        for game_name in previous_games:
            if game_name in tracked_games and game_name not in current_games:
                record = db.execute_query(
                    '''SELECT * FROM user_game_time 
                    WHERE user_id = ? AND guild_id = ? AND game_name = ?''',
                    (user_id, guild_id, game_name),
                    fetch='one'
                )
                
                if record and record.get('last_start'):
                    session_duration = current_time - record['last_start']
                    db.execute_query(
                        '''UPDATE user_game_time 
                        SET total_time = total_time + ?, 
                            last_start = NULL
                        WHERE user_id = ? AND guild_id = ? AND game_name = ?''',
                        (session_duration, user_id, guild_id, game_name)
                    )

        # Update roles based on playtime
        for game_name, config in tracked_games.items():
            record = db.execute_query(
                '''SELECT * FROM user_game_time 
                WHERE user_id = ? AND guild_id = ? AND game_name = ?''',
                (user_id, guild_id, game_name),
                fetch='one'
            )
            
            if record:
                total_time = record['total_time']
                
                # Add active session time if currently playing
                if record['last_start']:
                    total_time += current_time - record['last_start']
                
                required_seconds = config['required_seconds']
                role = guild.get_role(int(config['role_id']))
                
                if role and role < guild.me.top_role:
                    if total_time >= required_seconds and role not in member.roles:
                        await member.add_roles(role)
                    elif total_time < required_seconds and role in member.roles:
                        await member.remove_roles(role)

    except Exception as e:
        print(f"Presence update error: {str(e)}")

# Error handlers
@bot_instance.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: discord.app_commands.AppCommandError):
    """Global error handler for app commands"""
    if isinstance(error, app_commands.CheckFailure):
        if not interaction.response.is_done():
            await interaction.response.send_message(
                "❌ You must be an administrator to use this command.",
                ephemeral=True
            )
        else:
            await interaction.followup.send(
                "❌ You must be an administrator to use this command.",
                ephemeral=True
            )
    else:
        print(f"Unhandled command error: {error}")
        raise error

if __name__ == "__main__":
    bot_instance.run(BOT_TOKEN)