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
import re
import io
from collections import defaultdict
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path

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
import jwt
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR, EVENT_JOB_MISSED
from pytz import utc, timezone, all_timezones
import xml.etree.ElementTree as ETree

# -------------------- Local Imports -----------------
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config
from database import Database
from backups.backups import add_backup, get_backups, get_backup, init_db, get_conn


# -------------------- Runtime Config -----------------
load_dotenv()
init_db()
scheduler = AsyncIOScheduler(timezone=utc)


# -------------------- Debug Mode --------------------
DEBUG_MODE = os.getenv("DEBUG_MODE", "none").lower()  # 'none', 'some', 'all'
def debug_print(*args, level="some", **kwargs):
    """
    Print debug output based on DEBUG_MODE:
    - 'none': no debug output
    - 'some': prints all debug_prints except those with level='all'
    - 'all': prints all debug_prints
    """
    if DEBUG_MODE == "none":
        return
    if DEBUG_MODE == "some" and level == "all":
        return
    print("[DEBUG]", *args, **kwargs)

# ------------------- APScheduler Stuff -------------------
def job_listener(event):
    if event.exception:
        debug_print(f"[APSCHEDULER] Job {event.job_id} raised an exception: {event.exception}")
    elif event.code == EVENT_JOB_MISSED:
        debug_print(f"[APSCHEDULER] Job {event.job_id} MISSED!")
    else:
        debug_print(f"[APSCHEDULER] Job {event.job_id} executed successfully.")

scheduler.add_listener(job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED)

# -------------------- JWT Authentication for Bot API --------------------
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable is not set!")

async def require_jwt(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return web.json_response({"error": "Missing or invalid Authorization header"}, status=401)
    token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        request["jwt_payload"] = payload
    except jwt.ExpiredSignatureError:
        return web.json_response({"error": "Token expired"}, status=401)
    except jwt.InvalidTokenError:
        return web.json_response({"error": "Invalid token"}, status=403)
    return None

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

# -------------------- Backup Stuff --------------------
backup_progress_store = {}
backup_progress_lock = threading.Lock()

def set_backup_progress(guild_id, value, step_text=None):
    with backup_progress_lock:
        backup_progress_store[str(guild_id)] = {
            "progress": value,
            "step_text": step_text or ""
        }

def get_backup_progress(guild_id):
    with backup_progress_lock:
        return backup_progress_store.get(str(guild_id), {"progress": 0, "step_text": ""})

def schedule_backup_wrapper(guild_id):
    loop = get_event_loop()
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(scheduled_backup_job(guild_id), loop)
    else:
        debug_print("No running event loop for scheduled backup!")

async def scheduled_backup_job(guild_id):
    try:
        guild = bot_instance.get_guild(int(guild_id))
        if guild:
            def set_progress(val, step_text=None):
                set_backup_progress(guild_id, val, step_text)
            await save_guild_backup(guild, set_progress=set_progress)
    except Exception as e:
        debug_print(f"Exception in scheduled_backup_job: {e}")

def load_schedules():
    with get_conn() as conn:
        schedules = conn.execute('SELECT * FROM schedules WHERE enabled = 1').fetchall()
        for sched in schedules:
            start_time = sched['start_time']
            start_date = sched['start_date']
            tz_str = sched['timezone'] if 'timezone' in sched.keys() and sched['timezone'] else 'UTC'
            if start_time == "24:00":
                dt = datetime.strptime(start_date, "%Y-%m-%d") + timedelta(days=1)
                start_date = dt.strftime("%Y-%m-%d")
                start_time = "00:00"
            freq_unit = str(sched['frequency_unit']).lower()
            freq_val = int(sched['frequency_value']) if 'frequency_value' in sched.keys() else 1
            job_id = f"backup_{sched['guild_id']}_{sched['id']}"

            # Convert local time + timezone to UTC
            try:
                local_tz = timezone(tz_str)
            except Exception:
                debug_print(f"[WARNING] Invalid timezone '{tz_str}', defaulting to UTC")
                local_tz = utc
            local_dt = datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M")
            local_dt = local_tz.localize(local_dt)
            first_run = local_dt.astimezone(utc)
            now = utc.localize(datetime.utcnow())

            # Remove any existing job with the same ID (avoid duplicates on reload)
            try:
                scheduler.remove_job(job_id)
            except Exception:
                pass

            # Determine interval and advance first_run if needed
            interval_args = {}
            if freq_unit == "days":
                interval_args["days"] = freq_val
                interval = timedelta(days=freq_val)
            elif freq_unit == "weeks":
                interval_args["weeks"] = freq_val
                interval = timedelta(weeks=freq_val)
            elif freq_unit == "months":
                interval_args["weeks"] = freq_val * 4  # Approximate
                interval = timedelta(weeks=freq_val * 4)
            elif freq_unit == "years":
                interval_args["weeks"] = freq_val * 52  # Approximate
                interval = timedelta(weeks=freq_val * 52)
            else:
                debug_print(f"[WARNING] Unknown frequency unit: {freq_unit}, defaulting to days")
                interval_args["days"] = freq_val
                interval = timedelta(days=freq_val)

            # Advance first_run to the next valid future time if needed
            while first_run <= now:
                first_run += interval


            # Schedule only the interval job (no one-off job)
            scheduler.add_job(
                schedule_backup_wrapper,
                'interval',
                start_date=first_run,
                args=[sched['guild_id']],
                id=job_id,
                **interval_args
            )
            
            time.sleep(1)

# -------------------- Base Directory Stuff -----------------
if getattr(sys, 'frozen', False):
    # PyInstaller bundle: cogs are in sys._MEIPASS
    base_dir = Path(sys._MEIPASS)
else:
    base_dir = Path(__file__).parent

cogs_path = base_dir / "cogs"

# -------------------- Initialize database -----------------
Config.verify_paths()
db = Database(str(Config.DATABASE_PATH))
db.initialize_db()
try:
    db.validate_schema()
    debug_print("✅ Database schema validation passed")
except RuntimeError as e:
    debug_print(f"❌ Database schema validation failed: {str(e)}")
    raise

# -------------------- API and Frontend URLs -----------------
API_URL = os.getenv('API_URL', 'http://localhost:5003')  # Default for local dev
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')  # Default for local dev

# -------------------- Load Secrets --------------------
BOT_TOKEN = os.getenv('BOT_TOKEN')

# -------------------- Caching --------------------
level_config_cache = TTLCache(maxsize=100, ttl=300)  # 10 minutes
logger = logging.getLogger(__name__)
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
        "emoji_delete": True,
        "backup_created": True,
        "backup_failed": True,
        "backup_deleted": True,
        "backup_restored": True,
        "backup_restore_failed": True,
        "backup_schedule_created": True,
        "backup_schedule_deleted": True,
        "excluded_users": [],
        "excluded_roles": [],
        "excluded_channels": [],
        "log_bots": True,
        "log_self": False
    }

    # Check if guild exists before inserting log_config
    guild_exists = db.conn.execute(
        'SELECT 1 FROM guilds WHERE guild_id = ?', (str(guild_id),)
    ).fetchone()
    if not guild_exists:
        # Guild does not exist, return default config only
        return default_config

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
        if key in ["excluded_users", "excluded_roles", "excluded_channels"]:
            # Stored as JSON/text, convert to list
            if value is None or value == "":
                converted_config[key] = []
            elif isinstance(value, list):
                converted_config[key] = value
            else:
                try:
                    converted_config[key] = json.loads(value)
                except Exception:
                    converted_config[key] = []
        elif isinstance(default_config[key], bool):
            converted_config[key] = bool(int(value)) if value is not None else default_config[key]
        else:
            converted_config[key] = value if value is not None else default_config[key]
    return converted_config

def save_log_config(guild_id, config):
    # Convert boolean values to integers for SQLite storage, lists to JSON
    db_config = {}
    for k, v in config.items():
        if isinstance(v, bool):
            db_config[k] = int(v)
        elif k in ["excluded_users", "excluded_roles", "excluded_channels"]:
            db_config[k] = json.dumps(v) if isinstance(v, (list, dict)) else v
        else:
            db_config[k] = v
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
        debug_print(f"Error getting blocked words: {str(e)}")
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
        debug_print(f"Error getting blocked embed: {str(e)}")
        return {
            "title": "Blocked Word Detected!",
            "description": "You have used a word that is not allowed.",
            "color": 0xff0000
        }


# -------------------- Spam and Warning Tracking --------------------
spam_detection_strikes = defaultdict(lambda: defaultdict(int))  # Tracks strikes per user per guild
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

# -------------------- Stream and Video Stuff --------------------
YOUTUBE_API_KEY = os.getenv("YOUTUBE_API_KEY")

class PingAnnouncer:
    def __init__(self, bot):
        self.bot = bot
        self.last_youtube_video = {}    # {announcement_id: video_id}
        self.last_youtube_live = {}     # {announcement_id: bool}
        asyncio.create_task(self._initialize_twitch_status())
        asyncio.create_task(self._initialize_youtube_live_status())
        self.check_loop.start()         # Twitch and YouTube live stream polling
        if YOUTUBE_API_KEY:
            asyncio.create_task(self.unsubscribe_all_pubsub_channels()) # Unsubscribe from all channels
            self.check_youtube_uploads_api.start()  # Use API polling for uploads
        else:
            self.pubsub_renew_subscriptions.start() # Use PubSubHubbub for uploads

    @tasks.loop(minutes=2)
    async def check_loop(self):
        debug_print("[PingAnnouncer] Running check_loop")
        await self.bot.wait_until_ready()
        await self.check_twitch_streams()
        await self.check_youtube_live()

    async def fetch_recent_video_ids(self, channel_id):
        playlist_id = f"UU{channel_id[2:]}" if channel_id.startswith("UC") else None
        if not playlist_id:
            return []
        api_url = (
            f"https://www.googleapis.com/youtube/v3/playlistItems"
            f"?key={YOUTUBE_API_KEY}"
            f"&playlistId={playlist_id}"
            f"&part=snippet"
            f"&maxResults=10"
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, timeout=10) as resp:
                    if resp.status != 200:
                        debug_print(f"[YouTubeAPI] playlistItems.list failed for {channel_id}: {resp.status}")
                        return []
                    data = await resp.json()
            items = data.get("items", [])
            return [item["snippet"]["resourceId"]["videoId"] for item in items if "snippet" in item and "resourceId" in item["snippet"]]
        except Exception as e:
            debug_print(f"[YouTubeAPI] Error fetching recent video IDs for {channel_id}: {e}")
            return []

    async def pubsub_subscribe(self, channel_id):
        hub_url = "https://pubsubhubbub.appspot.com/subscribe"
        topic_url = f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"
        callback_url = f"{API_URL}/youtube/callback"
        async with aiohttp.ClientSession() as session:
            data = {
                "hub.mode": "subscribe",
                "hub.topic": topic_url,
                "hub.callback": callback_url,
                "hub.verify": "async"
            }
            async with session.post(hub_url, data=data) as resp:
                if resp.status == 202:
                    debug_print(f"[PubSub] Subscription request sent for channel {channel_id}")
                else:
                    debug_print(f"[PubSub] Failed to subscribe {channel_id}: {resp.status}")
                    debug_print(await resp.text())

    async def pubsub_unsubscribe(self, channel_id):
        hub_url = "https://pubsubhubbub.appspot.com/subscribe"
        topic_url = f"https://www.youtube.com/feeds/videos.xml?channel_id={channel_id}"
        callback_url = f"{API_URL}/youtube/callback"
        async with aiohttp.ClientSession() as session:
            data = {
                "hub.mode": "unsubscribe",
                "hub.topic": topic_url,
                "hub.callback": callback_url,
                "hub.verify": "async"
            }
            async with session.post(hub_url, data=data) as resp:
                if resp.status == 202:
                    debug_print(f"[PubSub] Unsubscribe request sent for channel {channel_id}")
                else:
                    debug_print(f"[PubSub] Failed to unsubscribe {channel_id}: {resp.status}")
                    debug_print(await resp.text())

    async def unsubscribe_all_pubsub_channels(self):
        # Unsubscribe from all channels
        video_anns = self.bot.db.execute_query(
            'SELECT DISTINCT channel_id FROM youtube_announcements WHERE live_stream = 0 AND enabled = 1',
            fetch='all'
        ) or []
        for ann in video_anns:
            channel_id = ann['channel_id']
            if channel_id:
                await self.pubsub_unsubscribe(channel_id)

    @tasks.loop(seconds=60 * 60 * 24 * 4)
    async def pubsub_renew_subscriptions(self):
        debug_print("[PubSub] Renewing subscriptions...")
        video_anns = self.bot.db.execute_query(
            'SELECT DISTINCT channel_id FROM youtube_announcements WHERE live_stream = 0 AND enabled = 1',
            fetch='all'
        ) or []
        for ann in video_anns:
            channel_id = ann['channel_id']
            if channel_id:
                await self.pubsub_subscribe(channel_id)

    async def handle_pubsub_verify(self, request):
        hub_challenge = request.query.get("hub.challenge")
        hub_mode = request.query.get("hub.mode")
        hub_lease_seconds = request.query.get("hub.lease_seconds")
        if hub_mode == "subscribe" and hub_challenge:
            debug_print(f"[PubSub] Verified subscription! Lease: {hub_lease_seconds}s")
            return web.Response(text=hub_challenge)
        return web.Response(text="Invalid verification", status=400)

    async def handle_pubsub_callback(self, request):
        body = await request.text()
        debug_print("[PubSub] Notification received!")
        try:
            root = ETree.fromstring(body)
            for entry in root.findall("{http://www.w3.org/2005/Atom}entry"):
                video_id = entry.find("{http://www.youtube.com/xml/schemas/2015}videoId").text
                title = entry.find("{http://www.w3.org/2005/Atom}title").text
                channel_id = entry.find("{http://www.youtube.com/xml/schemas/2015}channelId").text
                url = f"https://www.youtube.com/watch?v={video_id}"
                # Find all announcement configs for this channel
                video_anns = self.bot.db.execute_query(
                    'SELECT * FROM youtube_announcements WHERE live_stream = 0 AND enabled = 1 AND channel_id = ?',
                    (channel_id,),
                    fetch='all'
                ) or []
                for ann in video_anns:
                    # Bootstrap recent_video_ids if empty
                    recent_ids_raw = ann.get('recent_video_ids', '[]')
                    try:
                        recent_ids = json.loads(recent_ids_raw)
                        if not isinstance(recent_ids, list):
                            recent_ids = []
                    except Exception:
                        recent_ids = []
                    if not recent_ids:
                        # Bootstrap: fetch 5 most recent, store, do not announce
                        recent_ids = await self.fetch_recent_video_ids(channel_id)
                        self.bot.db.execute_query(
                            'UPDATE youtube_announcements SET recent_video_ids = ? WHERE id = ?',
                            (json.dumps(recent_ids), ann['id'])
                        )
                        debug_print(f"[YouTubeAPI] Bootstrapped recent_video_ids for {channel_id}: {recent_ids}")
                        continue  # Do not announce on bootstrap
                    if video_id in recent_ids:
                        continue  # Already announced

                    await self.send_youtube_announcement(ann, {
                        "title": title,
                        "url": url,
                        "id": video_id,
                        "channel": channel_id,
                        "streamer": ann.get('streamer_id', '')
                    })
                    # Update recent_video_ids in DB
                    recent_ids = [video_id] + [vid for vid in recent_ids if vid != video_id]
                    recent_ids = recent_ids[:10]
                    self.bot.db.execute_query(
                        'UPDATE youtube_announcements SET last_video_id = ?, recent_video_ids = ? WHERE id = ?',
                        (video_id, json.dumps(recent_ids), ann['id'])
                    )
                    self.last_youtube_video[ann['id']] = video_id
        except Exception as e:
            debug_print(f"[PubSub] Error parsing notification: {e}")
        return web.Response(text="OK")

    @tasks.loop(minutes=10)
    async def check_youtube_uploads_api(self):
        debug_print("[YouTubeAPI] Checking YouTube uploads via Data API v3")
        try:
            video_anns = self.bot.db.execute_query(
                'SELECT * FROM youtube_announcements WHERE live_stream = 0 AND enabled = 1',
                fetch='all'
            ) or []
            for ann in video_anns:
                yt_channel_id = ann['channel_id']
                playlist_id = f"UU{yt_channel_id[2:]}" if yt_channel_id.startswith("UC") else None
                if not playlist_id:
                    debug_print(f"[YouTubeAPI] Invalid channel_id: {yt_channel_id}")
                    continue
                api_url = (
                    f"https://www.googleapis.com/youtube/v3/playlistItems"
                    f"?key={YOUTUBE_API_KEY}"
                    f"&playlistId={playlist_id}"
                    f"&part=snippet"
                    f"&maxResults=1"
                )
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(api_url, timeout=10) as resp:
                            if resp.status != 200:
                                debug_print(f"[YouTubeAPI] playlistItems.list failed for {yt_channel_id}: {resp.status}")
                                continue
                            data = await resp.json()
                    items = data.get("items", [])
                    if not items:
                        continue
                    video = items[0]
                    video_id = video["snippet"]["resourceId"]["videoId"]
                    title = video["snippet"]["title"]
                    url = f"https://www.youtube.com/watch?v={video_id}"

                    # Check if this is a live stream or regular upload
                    video_api_url = (
                        f"https://www.googleapis.com/youtube/v3/videos"
                        f"?key={YOUTUBE_API_KEY}"
                        f"&id={video_id}"
                        f"&part=snippet"
                    )
                    async with aiohttp.ClientSession() as session:
                        async with session.get(video_api_url, timeout=10) as resp:
                            if resp.status != 200:
                                debug_print(f"[YouTubeAPI] videos.list failed for {video_id}: {resp.status}")
                                continue
                            video_data = await resp.json()
                    video_items = video_data.get("items", [])
                    if not video_items:
                        continue
                    live_broadcast_content = video_items[0]["snippet"].get("liveBroadcastContent", "none")
                    if live_broadcast_content != "none":
                        debug_print(f"[YouTubeAPI] Skipping live stream video {video_id} for upload-only announcement.")
                        continue

                    # Bootstrap recent_video_ids if empty
                    recent_ids_raw = ann.get('recent_video_ids', '[]')
                    try:
                        recent_ids = json.loads(recent_ids_raw)
                        if not isinstance(recent_ids, list):
                            recent_ids = []
                    except Exception:
                        recent_ids = []
                    if not recent_ids:
                        # Bootstrap: fetch 5 most recent, store, do not announce
                        recent_ids = await self.fetch_recent_video_ids(yt_channel_id)
                        self.bot.db.execute_query(
                            'UPDATE youtube_announcements SET recent_video_ids = ? WHERE id = ?',
                            (json.dumps(recent_ids), ann['id'])
                        )
                        debug_print(f"[YouTubeAPI] Bootstrapped recent_video_ids for {yt_channel_id}: {recent_ids}")
                        continue  # Do not announce on bootstrap
                    if video_id in recent_ids:
                        continue

                    debug_print(f"[YouTubeAPI] New upload detected for {yt_channel_id}: {title} ({video_id})")
                    await self.send_youtube_announcement(ann, {
                        "title": title,
                        "url": url,
                        "id": video_id,
                        "channel": yt_channel_id,
                        "streamer": ann.get('streamer_id', '')
                    })
                    # Update recent_video_ids in DB
                    recent_ids = [video_id] + [vid for vid in recent_ids if vid != video_id]
                    recent_ids = recent_ids[:10]
                    self.bot.db.execute_query(
                        'UPDATE youtube_announcements SET last_video_id = ?, recent_video_ids = ? WHERE id = ?',
                        (video_id, json.dumps(recent_ids), ann['id'])
                    )
                except Exception as e:
                    debug_print(f"[YouTubeAPI] Error checking uploads for {yt_channel_id}: {e}")
        except Exception as e:
            debug_print(f"[YouTubeAPI] YouTube upload check error: {e}")

    async def check_twitch_streams(self):
        debug_print("[PingAnnouncer] Checking Twitch streams")
        try:
            announcements = self.bot.db.execute_query(
                'SELECT * FROM twitch_announcements WHERE enabled = 1',
                fetch='all'
            )
            debug_print(f"[PingAnnouncer] Twitch announcements found: {len(announcements) if announcements else 0}")
            if not announcements:
                return

            for ann in announcements:
                debug_print(f"[PingAnnouncer] Processing Twitch announcement: {ann}")
                channel_username = ann['streamer_id']
                url = f"https://decapi.me/twitch/uptime/{channel_username}"
                ann_id = ann['id']
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, timeout=10) as resp:
                            text = await resp.text()
                            debug_print(f"[PingAnnouncer] decapi.me response for {channel_username}: {text}")
                            is_live = not ("offline" in text.lower() or "not live" in text.lower())
                except Exception as e:
                    debug_print(f"[PingAnnouncer] Twitch uptime check failed for {channel_username}: {e}")
                    continue

                was_live = self.bot.db.get_twitch_live_status(ann_id)
                debug_print(f"[PingAnnouncer] Twitch live status for {channel_username}: was_live={was_live}, is_live={is_live}")
                if is_live and not was_live:
                    debug_print(f"[PingAnnouncer] Sending Twitch live announcement for {channel_username}")
                    await self.send_stream_announcement(ann, {
                        "title": f"{channel_username} is live!",
                        "url": f"https://twitch.tv/{channel_username}"
                    })
                self.bot.db.set_twitch_live_status(ann_id, is_live)

        except Exception as e:
            debug_print(f"[PingAnnouncer] Twitch check error: {str(e)}")

    async def _initialize_twitch_status(self):
        """Set last_live_status for all enabled announcements on startup to avoid duplicate announcements."""
        await self.bot.wait_until_ready()
        announcements = self.bot.db.execute_query(
            'SELECT * FROM twitch_announcements WHERE enabled = 1',
            fetch='all'
        ) or []
        for ann in announcements:
            channel_username = ann['streamer_id']
            ann_id = ann['id']
            url = f"https://decapi.me/twitch/uptime/{channel_username}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=10) as resp:
                        text = await resp.text()
                        is_live = not ("offline" in text.lower() or "not live" in text.lower())
                        self.bot.db.set_twitch_live_status(ann_id, is_live)
                        debug_print(f"[PingAnnouncer] Startup: {channel_username} is_live={is_live}")
            except Exception as e:
                debug_print(f"[PingAnnouncer] Error initializing status for {channel_username}: {e}")
                self.bot.db.set_twitch_live_status(ann_id, False)

    async def _initialize_youtube_live_status(self):
        """Set last_youtube_live for all enabled live announcements on startup to avoid duplicate announcements."""
        await self.bot.wait_until_ready()
        announcements = self.bot.db.execute_query(
            'SELECT * FROM youtube_announcements WHERE live_stream = 1 AND enabled = 1',
            fetch='all'
        ) or []
        for ann in announcements:
            yt_channel_id = ann.get('channel_id') or ann.get('streamer_id')
            ann_id = ann.get('id')
            live_url = f"https://www.youtube.com/channel/{yt_channel_id}/live"
            is_live = False
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(live_url, allow_redirects=True, timeout=15) as resp:
                        final_url = str(resp.url)
                        html = await resp.text()
                        # 1. Check redirect
                        match = re.search(r"youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})", final_url)
                        if match:
                            is_live = True
                        else:
                            # 2. Check canonical link
                            canon = re.search(r'<link rel="canonical" href="https://www\.youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})"', html)
                            if canon:
                                is_live = True
                            else:
                                # 3. Check ytInitialPlayerResponse for videoId
                                player_response = re.search(r'ytInitialPlayerResponse\s*=\s*({.*?});', html, re.DOTALL)
                                if player_response:
                                    try:
                                        data = json.loads(player_response.group(1))
                                        video_id = data.get("videoDetails", {}).get("videoId")
                                        if video_id:
                                            is_live = True
                                    except Exception:
                                        pass
                self.last_youtube_live[ann_id] = is_live
                debug_print(f"[PingAnnouncer] Startup: YouTube {yt_channel_id} is_live={is_live}")
            except Exception as e:
                debug_print(f"[PingAnnouncer] Error initializing YouTube live status for {yt_channel_id}: {e}")
                self.last_youtube_live[ann_id] = False

    async def check_youtube_live(self):
        debug_print("[PingAnnouncer] Checking YouTube live streams via scraping")
        try:
            stream_anns = self.bot.db.execute_query(
                'SELECT * FROM youtube_announcements WHERE live_stream = 1 AND enabled = 1',
                fetch='all'
            ) or []

            for ann in stream_anns:
                yt_channel_id = ann.get('channel_id') or ann.get('streamer_id')
                live_url = f"https://www.youtube.com/channel/{yt_channel_id}/live"
                is_live = False
                live_video_url = None
                live_title = None

                debug_print(f"[PingAnnouncer] Scraping live status for channel: {yt_channel_id}")
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(live_url, allow_redirects=True, timeout=15) as resp:
                            final_url = str(resp.url)
                            html = await resp.text()
                            # 1. Check redirect
                            match = re.search(r"youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})", final_url)
                            if match:
                                is_live = True
                                live_video_id = match.group(1)
                            else:
                                # 2. Check canonical link
                                canon = re.search(r'<link rel="canonical" href="https://www\.youtube\.com/watch\?v=([a-zA-Z0-9_-]{11})"', html)
                                if canon:
                                    is_live = True
                                    live_video_id = canon.group(1)
                                else:
                                    # 3. Check ytInitialPlayerResponse for videoId
                                    player_response = re.search(r'ytInitialPlayerResponse\s*=\s*({.*?});', html, re.DOTALL)
                                    if player_response:
                                        try:
                                            import json
                                            data = json.loads(player_response.group(1))
                                            video_id = data.get("videoDetails", {}).get("videoId")
                                            if video_id:
                                                is_live = True
                                                live_video_id = video_id
                                        except Exception:
                                            pass
                            if is_live:
                                live_video_url = f"https://www.youtube.com/watch?v={live_video_id}"
                                # Try to get the title from the HTML
                                title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
                                if title_match:
                                    live_title = title_match.group(1).replace("- YouTube", "").strip()
                                else:
                                    live_title = "🔴 Live Now!"
                except Exception as e:
                    debug_print(f"[PingAnnouncer] Error scraping YouTube live status for {yt_channel_id}: {e}")

                ann_id = ann.get('id')
                was_live = self.last_youtube_live.get(ann_id, None)
                debug_print(f"[PingAnnouncer] YouTube live status for {yt_channel_id}: was_live={was_live}, is_live={is_live}")
                if is_live and (was_live is False or was_live is None):
                    debug_print(f"[PingAnnouncer] Sending YouTube live announcement for channel {yt_channel_id}")
                    await self.send_youtube_announcement(ann, {
                        "title": live_title or "🔴 Live Now!",
                        "url": live_video_url or live_url,
                        "streamer": live_title or yt_channel_id
                    })
                self.last_youtube_live[ann_id] = is_live

        except Exception as e:
            debug_print(f"[PingAnnouncer] YouTube live scrape announcement error: {str(e)}")

    async def send_stream_announcement(self, announcement, stream_data):
        debug_print(f"[PingAnnouncer] send_stream_announcement called with: {announcement}, {stream_data}")
        try:
            channel = self.bot.get_channel(int(announcement['channel_id']))
            debug_print(f"[PingAnnouncer] Discord channel resolved: {channel}")
            if not channel:
                return
            role_id = announcement.get('role_id')
            if role_id == "@everyone":
                role_mention = "@everyone"
            elif role_id:
                role_mention = f"<@&{role_id}>"
            else:
                role_mention = ""
            message = announcement['message'].format(
                streamer=announcement['streamer_id'],
                title=stream_data.get('title', ''),
                url=stream_data.get('url', ''),
                role=role_mention,
                game=stream_data.get('game', '')
            )
            debug_print(f"[PingAnnouncer] Sending message: {message}")
            await channel.send(message)
            self.bot.db.execute_query(
                'UPDATE twitch_announcements SET last_announced = CURRENT_TIMESTAMP WHERE id = ?',
                (announcement['id'],)
            )
            debug_print("[PingAnnouncer] Updated last_announced in DB")
        except Exception as e:
            debug_print(f"[PingAnnouncer] Stream announcement error: {str(e)}")

    async def send_youtube_announcement(self, announcement, video_data):
        debug_print(f"[PingAnnouncer] send_youtube_announcement called with: {announcement}, {video_data}")
        try:
            channel_id = announcement.get('announce_channel_id') or announcement.get('channel_id')
            channel = self.bot.get_channel(int(channel_id))
            debug_print(f"[PingAnnouncer] Discord channel resolved: {channel}")
            if not channel:
                return
            # Add role mention if role_id is set
            role_id = announcement.get('role_id')
            if role_id == "@everyone":
                role_mention = "@everyone"
            elif role_id:
                role_mention = f"<@&{role_id}>"
            else:
                role_mention = ""
            message = announcement['message'].format(
                streamer=video_data.get('streamer', ''),
                channel=video_data.get('channel', ''),
                title=video_data.get('title', ''),
                url=video_data.get('url', ''),
                role=role_mention,
                game=video_data.get('game', '')
            )
            debug_print(f"[PingAnnouncer] Sending message: {message}")
            await channel.send(message)
            if 'id' in announcement and 'id' in video_data:
                debug_print(f"[PingAnnouncer] Updating last_video_id in DB for announcement {announcement['id']}")
                self.bot.db.execute_query(
                    'UPDATE youtube_announcements SET last_video_id = ? WHERE id = ?',
                    (video_data['id'], announcement['id'])
                )
        except Exception as e:
            debug_print(f"[PingAnnouncer] YouTube announcement error: {str(e)}")

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
        self._last_resync = 0

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
        await self.load_extension("cogs.backup")
        
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
                    debug_print(f"⚠️ Invalid command format: {cmd_data}")

            # Group commands by guild
            guild_groups = defaultdict(list)
            for cmd in valid_commands:
                guild_id = str(cmd['guild_id']).strip()
                guild_groups[guild_id].append(cmd)

            # Process global commands
            global_commands = guild_groups.get('0', [])
            for cmd_data in global_commands:
                try:
                    # Ensure all fields are strings and valid
                    cmd_data['command_name'] = str(cmd_data.get('command_name', '')).strip().lower()
                    cmd_data['description'] = str(cmd_data.get('description', '') or 'Custom command').strip()
                    if not cmd_data['description']:
                        cmd_data['description'] = 'Custom command'
                    cmd_data['content'] = str(cmd_data.get('content', ''))
                    # Discord command name rules
                    if not (1 <= len(cmd_data['command_name']) <= 32) or not cmd_data['command_name'].replace('_', '').isalnum():
                        debug_print(f"Skipping invalid command name: {cmd_data['command_name']}")
                        continue
                    callback = self._create_command_callback(cmd_data)
                    cmd = app_commands.Command(
                        name=cmd_data['command_name'],
                        description=cmd_data['description'],
                        callback=callback
                    )
                    self.tree.add_command(cmd)
                except Exception as e:
                    debug_print(f"  🚨 Global command error: {str(e)}")

            # Process guild-specific commands
            for guild_id_str, cmds in guild_groups.items():
                if guild_id_str == '0':
                    continue

                try:
                    guild = await self.fetch_guild(int(guild_id_str))
                except (discord.NotFound, discord.Forbidden):
                    debug_print(f"  🚫 Guild {guild_id_str} not accessible")
                    continue

                self.tree.clear_commands(guild=guild)

                for cmd_data in cmds:
                    try:
                        # Ensure all fields are strings and valid
                        cmd_data['command_name'] = str(cmd_data.get('command_name', '')).strip().lower()
                        cmd_data['description'] = str(cmd_data.get('description', '') or 'Custom command').strip()
                        if not cmd_data['description']:
                            cmd_data['description'] = 'Custom command'
                        cmd_data['content'] = str(cmd_data.get('content', ''))
                        if not (1 <= len(cmd_data['command_name']) <= 32) or not cmd_data['command_name'].replace('_', '').isalnum():
                            debug_print(f"Skipping invalid command name: {cmd_data['command_name']}")
                            continue
                        callback = self._create_command_callback(cmd_data)
                        cmd = app_commands.Command(
                            name=cmd_data['command_name'],
                            description=cmd_data['description'],
                            callback=callback
                        )
                        self.tree.add_command(cmd, guild=guild)
                    except Exception as e:
                        debug_print(f"    🚨 Command error: {str(e)}")

                # Sync guild commands with retry
                await self.safe_sync(guild=guild)

            # Final global sync
            await self.safe_sync()
            
            # Initialize components
            await self.role_batcher.initialize()
            self._command_initialized = True

        except Exception as e:
            debug_print(f"❌ Critical initialization error: {str(e)}")
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
                    debug_print(f"  ⏳ Rate limited. Retrying in {delay:.1f}s")
                    await asyncio.sleep(delay)
                else:
                    debug_print(f"  ❌ Sync failed: {e.status} {e.text}")
                    return False
            except Exception as e:
                debug_print(f"  ❌ Unexpected sync error: {str(e)}")
                traceback.print_exc()
                return False
        return False

    async def custom_command_handler(self, interaction: discord.Interaction, cmd_data: dict):
        try:
            content = cmd_data.get('content', 'No content configured')
            ephemeral = bool(cmd_data.get('ephemeral', True))
            
            # Ensure we can respond to the interaction
            if interaction.response.is_done():
                send_method = interaction.followup.send
            else:
                send_method = interaction.response.send_message

            # Handle different content types
            if any(content.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif']):
                embed = discord.Embed().set_image(url=content)
                await send_method(embed=embed, ephemeral=ephemeral)
            elif content.startswith('http'):
                await send_method(content, ephemeral=ephemeral)
            else:
                if '\n' in content:
                    parts = [content[i:i+2000] for i in range(0, len(content), 2000)]
                    first = True
                    for part in parts:
                        if first:
                            await send_method(part, ephemeral=ephemeral)
                            first = False
                        else:
                            await interaction.followup.send(part, ephemeral=ephemeral)
                else:
                    await send_method(content, ephemeral=ephemeral)
                    
        except Exception as e:
            error_msg = f"❌ Command error: {str(e)}"
            debug_print(f"Command execution failed: {traceback.format_exc()}")
            try:
                if interaction.response.is_done():
                    await interaction.followup.send(error_msg, ephemeral=True)
                else:
                    await interaction.response.send_message(error_msg, ephemeral=True)
            except:
                pass

    async def reload_and_resync_commands(self):
        try:
            """Reload custom commands from DB and resync with Discord, with rate limiting."""
            RATE_LIMIT_SECONDS = 10
            now = time.time()
            if now - self._last_resync < RATE_LIMIT_SECONDS:
                raise RuntimeError(f"Rate limited: Try again in {int(RATE_LIMIT_SECONDS - (now - self._last_resync))} seconds.")
            self._last_resync = now

            # Clear all commands from the tree
            for guild in self.guilds:
                self.tree.clear_commands(guild=guild)
            self.tree.clear_commands(guild=None)  # Also clear global

            # Load commands from DB
            raw_commands = self.db.execute_query(
                'SELECT guild_id, command_name, content, description, ephemeral FROM commands',
                fetch='all'
            ) or []

            # Group by guild
            guild_groups = defaultdict(list)
            for cmd in raw_commands:
                guild_groups[str(cmd['guild_id'])].append(cmd)

            # Add global commands
            for cmd_data in guild_groups.get('0', []):
                try:
                    cmd_data['command_name'] = str(cmd_data.get('command_name', '') or '').strip().lower()
                    cmd_data['description'] = str(cmd_data.get('description', '') or 'Custom command').strip()
                    if not cmd_data['description']:
                        cmd_data['description'] = 'Custom command'
                    cmd_data['description'] = cmd_data['description'][:100]
                    cmd_data['content'] = str(cmd_data.get('content', '') or '')
                    # Discord command name rules
                    if not re.fullmatch(r'[a-z0-9_\-]{1,32}', cmd_data['command_name']):
                        debug_print(f"Skipping invalid command name: {cmd_data['command_name']}")
                        continue
                    debug_print(f"Adding command: {cmd_data}")
                    callback = self._create_command_callback(cmd_data)
                    cmd = app_commands.Command(
                        name=cmd_data['command_name'],
                        description=cmd_data['description'],
                        callback=callback
                    )
                    self.tree.add_command(cmd)
                except Exception as e:
                    debug_print(f"Global command error: {cmd_data} | {str(e)}")
                    traceback.print_exc()

            for guild in self.guilds:
                cmds = guild_groups.get(str(guild.id), [])
                for cmd_data in cmds:
                    try:
                        cmd_data['command_name'] = str(cmd_data.get('command_name', '') or '').strip().lower()
                        cmd_data['description'] = str(cmd_data.get('description', '') or 'Custom command').strip()
                        if not cmd_data['description']:
                            cmd_data['description'] = 'Custom command'
                        cmd_data['description'] = cmd_data['description'][:100]
                        cmd_data['content'] = str(cmd_data.get('content', '') or '')
                        if not re.fullmatch(r'[a-z0-9_\-]{1,32}', cmd_data['command_name']):
                            debug_print(f"Skipping invalid command name: {cmd_data['command_name']}")
                            continue
                        if not (1 <= len(cmd_data['command_name']) <= 32) or not cmd_data['command_name'].replace('_', '').isalnum():
                            debug_print(f"Skipping invalid command name: {cmd_data['command_name']}")
                            continue
                        callback = self._create_command_callback(cmd_data)
                        cmd = app_commands.Command(
                            name=cmd_data['command_name'],
                            description=cmd_data['description'],
                            callback=callback
                        )
                        self.tree.add_command(cmd, guild=guild)
                    except Exception as e:
                        debug_print(f"Guild command error: {cmd_data} | {str(e)}")
                        traceback.print_exc()

        except Exception as e:
            debug_print("Exception in reload_and_resync_commands")
            traceback.print_exc()
            raise

        # Sync all
        await self.tree.sync()
        for guild in self.guilds:
            await self.tree.sync(guild=guild)

bot_instance = CustomBot(
    command_prefix='!',
    intents=discord.Intents.all(),
    help_command=None,
    activity=discord.Activity(
        type=discord.ActivityType.watching,
        name="for rule breakers | /help"
    ),
    max_messages=5000
)

# -------------------- Logging Helper --------------------
async def log_event(guild, event_key, title=None, description=None, color=discord.Color.blue(), extra_fields=None, embed=None):
    debug_print("[LOG EVENT]: ENTER log_event for event_key=", event_key, "guild=", getattr(guild, 'id', None), level="all")
    debug_print("[LOG EVENT] guild=", guild.name if guild else 'None', "event_key=", event_key, "title=", title, "description=", description, "color=", color, "extra_fields=", extra_fields, "embed_provided=", embed is not None, level="all")
    # Get guild-specific log configuration from database
    log_config = db.get_log_config(str(guild.id))
    debug_print(f"[LOG EVENT]: loaded log_config: {log_config}", level="all")

    # Create default config if not exists
    if not log_config:
        db.conn.execute(
            'INSERT INTO log_config (guild_id) VALUES (?)',
            (str(guild.id),)
        )
        db.conn.commit()
        log_config = db.get_log_config(str(guild.id))
        debug_print(f"[LOG EVENT]: created default log_config: {log_config}", level="all")

    # Check if logging for this event is enabled
    if not log_config.get(event_key, True):
        debug_print(f"[LOG EVENT]: skipping log because event_key {event_key} is disabled in config", level="all")
        return

    # Get channel ID from config
    channel_id = log_config.get('log_channel_id')
    debug_print(f"[LOG EVENT]: channel_id from config: {channel_id}", level="all")
    if not channel_id:
        debug_print(f"[LOG EVENT]: skipping log because no log_channel_id configured", level="all")
        return  # No log channel configured

    try:
        channel = guild.get_channel(int(channel_id))
    except Exception as e:
        debug_print(f"[LOG EVENT]: Exception converting channel_id to int or getting channel: {e}", level="all")
        return
    debug_print(f"[LOG EVENT]: resolved channel: {channel}", level="all")
    if channel is None:
        debug_print(f"[LOG EVENT]: Log channel not found in guild: {guild.name} (ID: {channel_id})", level="all")
        return

    # --- Exclusion logic ---
    # If a message/user/role/channel is provided in extra_fields, check exclusions
    # This expects extra_fields to contain 'user_id', 'role_ids', 'channel_id', 'log_bot', 'log_self' if available
    user_id = None
    role_ids = []
    channel_id_event = None
    log_bot = False
    log_self = False
    if extra_fields:
        user_id = extra_fields.get('user_id')
        role_ids = extra_fields.get('role_ids', [])
        channel_id_event = extra_fields.get('channel_id')
        log_bot = extra_fields.get('log_bot', False)
        log_self = extra_fields.get('log_self', False)

    # Exclude if user is in excluded_users
    if user_id and str(user_id) in log_config.get('excluded_users', []):
        return

    # Exclude if any role is in excluded_roles
    if role_ids:
        excluded_roles = set(log_config.get('excluded_roles', []))
        if excluded_roles.intersection(set(str(r) for r in role_ids)):
            return

    # Exclude if channel is in excluded_channels
    if channel_id_event and str(channel_id_event) in log_config.get('excluded_channels', []):
        return

    # Exclude self if log_self is False
    debug_print(f"[LOG EVENT]: log_self={log_self}, log_bot={log_bot}, log_self={log_config.get('log_self', False)}, log_bots={log_config.get('log_bots', True)}, user_id={user_id}, role_ids={role_ids}, channel_id_event={channel_id_event}", level="all")
    debug_print(f"[LOG EVENT]: PASSED EXCLUSION LOGIC for event_key={event_key}, guild={getattr(guild, 'id', None)}", level="all")
    if log_self:
        if not log_config.get('log_self', False):
            debug_print("[LOG EVENT]: skipping log because log_self and log_self is False", level="all")
            return
        # If self, always log if log_self is True, regardless of log_bots (do not check log_bots)
    elif log_bot and not log_config.get('log_bots', True):
        debug_print("[LOG EVENT]: skipping log because log_bot and log_bots is False", level="all")
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
            for k, v in extra_fields.items():
                if k not in ('user_id', 'role_ids', 'channel_id', 'log_bot', 'log_self'):
                    embed.add_field(name=k, value=str(v), inline=False)

    # Send to log channel
    try:
        debug_print(f"[LOG EVENT]: sending embed to channel {channel} (id={getattr(channel, 'id', None)})", level="all")
        await channel.send(embed=embed)
        debug_print(f"[LOG EVENT]: embed sent successfully", level="all")
    except Exception as e:
        debug_print(f"[LOG EVENT]: Failed to send log message in {guild.name}: {str(e)}", level="all")

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

    async def json_error_middleware(app, handler):
        async def middleware(request):
            try:
                response = await handler(request)
                return response
            except web.HTTPException as ex:
                # If it's already a JSON response, return as is
                if ex.content_type == 'application/json':
                    raise
                return web.json_response({'error': ex.reason}, status=ex.status)
            except Exception as ex:
                debug_print("Unhandled exception in API:", traceback.format_exc())
                return web.json_response({'error': str(ex)}, status=500)
        return middleware

    # Create app with CORS middleware
    app = web.Application(middlewares=[cors_middleware, json_error_middleware])

    # Routes
    global ping_announcer
    app.router.add_get('/youtube/callback', ping_announcer.handle_pubsub_verify)
    app.router.add_post('/youtube/callback', ping_announcer.handle_pubsub_callback)
    app.router.add_post('/api/leave_guild', handle_leave_guild)
    app.router.add_post('/api/start_backup', handle_start_backup)
    app.router.add_post('/api/start_restore', handle_start_restore)
    app.router.add_get('/api/backup_progress', handle_backup_progress)
    app.router.add_post('/api/reload_schedules', handle_reload_schedules)
    app.router.add_get('/api/health', lambda _: web.Response(text="OK"))
    app.router.add_post('/api/sync', handle_command_sync)
    app.router.add_post('/api/sync_warnings', handle_sync_warnings)
    app.router.add_get('/api/get_bans', handle_get_bans)
    app.router.add_post('/api/unban/{userid}', handle_unban)
    app.router.add_post('/api/get_guild_users', handle_get_guild_users)
    app.router.add_post('/api/get_guild_commands', handle_get_guild_commands)
    app.router.add_post('/api/get_guild_invite', handle_get_guild_invite)
    app.router.add_post('/api/get_guild_audit_log', handle_get_guild_audit_log)
    app.router.add_post('/api/send_role_menu/{menu_id}', handle_send_role_menu)
    app.router.add_post('/api/forms/{form_id}/submit', handle_custom_form_submission)
    app.router.add_route(hdrs.METH_OPTIONS, '/api/unban/{userid}', handle_options)

    # Setup and start the server
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 5003)
    await site.start()
    debug_print("Endpoints running on port 5003")

async def handle_options(request):
    return web.Response(
        status=204,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
        }
    )

async def handle_leave_guild(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        guild_id = data.get('guild_id')
        if not guild_id or not str(guild_id).isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)
        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Bot is not in this server"}, status=404)
        await guild.leave()
        return web.json_response({"success": True, "message": f"Bot left guild {guild_id}"})
    except Exception as e:
        logger.error(f"Error leaving guild: {str(e)}")
        return web.json_response({"error": str(e)}, status=500)

async def handle_command_sync(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        await bot_instance.reload_and_resync_commands()
        return web.json_response({"success": True, "message": "Commands reloaded and resynced."})
    except RuntimeError as e:
        return web.json_response({"error": str(e)}, status=429)
    except Exception as e:
        traceback.print_exc()
        return web.json_response({"error": str(e)}, status=500)
    
async def handle_sync_warnings(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    reload_warnings()
    return web.Response(text="Warnings synced successfully!")
    
async def handle_get_bans(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        debug_print("Fetching bans...")
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
        
        debug_print(f"Total bans fetched: {len(bans)}")
        return web.json_response(bans)
        
    except Exception as e:
        debug_print(f"Error fetching bans: {str(e)}")
        return web.json_response({"error": str(e)}, status=500)

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
        debug_print(f"⚠️ Channel resolution error: {str(e)}")
        return None

async def handle_unban(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
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
            await guild.unban(user, reason=" User unbanned via the dashboard")
            return web.json_response({"status": "success"})
        except discord.NotFound:
            return web.json_response({"error": "User not banned"}, status=404)
            
    except Exception as e:
        debug_print(f"Unban error: {str(e)}")
        return web.json_response({"error": str(e)}, status=500)

async def handle_get_guild_users(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        guild_id = data.get('guild_id')
        if not guild_id or not str(guild_id).isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)
        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Guild not found"}, status=404)
        users = []
        for member in guild.members:
            users.append({
                "id": str(member.id),
                "username": member.name,
                "display_name": member.display_name,
                "avatar_url": str(member.display_avatar.url) if hasattr(member, "display_avatar") else None
            })
        return web.json_response(users)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

async def handle_get_guild_commands(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        guild_id = data.get('guild_id')
        if not guild_id or not str(guild_id).isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)
        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Guild not found"}, status=404)
        # Get custom command names for this guild
        custom_names = set(
            cmd['command_name']
            for cmd in bot_instance.db.get_guild_commands_list(guild_id)
        )
        # Get both global and guild commands
        commands = []
        seen = set()
        # Global commands
        for cmd in bot_instance.tree.get_commands():
            if cmd.name not in custom_names and cmd.name not in seen:
                commands.append({"name": cmd.name, "description": cmd.description})
                seen.add(cmd.name)
        # Guild-specific commands
        for cmd in bot_instance.tree.get_commands(guild=guild):
            if cmd.name not in custom_names and cmd.name not in seen:
                commands.append({"name": cmd.name, "description": cmd.description})
                seen.add(cmd.name)
        return web.json_response(commands)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

async def handle_get_guild_invite(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        guild_id = data.get('guild_id')
        if not guild_id or not guild_id.isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)

        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Bot is not in this server or cannot access it."}, status=404)

        # Try to find an existing invite
        for channel in guild.text_channels:
            try:
                invites = await channel.invites()
                if invites:
                    # Return the first valid invite
                    return web.json_response({"invite": f"https://discord.gg/{invites[0].code}"})
            except discord.Forbidden:
                continue  # Bot can't view invites in this channel

        # If no invite found, try to create one in the first channel bot can
        for channel in guild.text_channels:
            try:
                invite = await channel.create_invite(max_age=86400, max_uses=5, reason="Requested from admin panel")
                return web.json_response({"invite": f"https://discord.gg/{invite.code}"})
            except discord.Forbidden:
                continue  # Bot can't create invite in this channel

        return web.json_response({"error": "No accessible channel to create an invite."}, status=403)
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)

async def handle_get_guild_audit_log(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        guild_id = data.get('guild_id')
        if not guild_id or not guild_id.isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)

        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Bot is not in this server or cannot access it."}, status=404)

        entries = []
        async for entry in guild.audit_logs(limit=100):
            # Start with basic information
            action_name = str(entry.action).replace("AuditLogAction.", "")
            user_name = str(entry.user) if entry.user else "Unknown"
            target_name = str(entry.target) if entry.target else ""
            reason = entry.reason or ""
            created_at = entry.created_at.isoformat() if entry.created_at else ""
            
            # Initialize changes list
            changes = []
            
            # Handle different action types with their specific attributes
            if action_name == "role_update" and hasattr(entry, 'before') and hasattr(entry, 'after'):
                if hasattr(entry.before, 'name') and hasattr(entry.after, 'name'):
                    if entry.before.name != entry.after.name:
                        changes.append(f"Name: {entry.before.name} → {entry.after.name}")
                
                if hasattr(entry.before, 'permissions') and hasattr(entry.after, 'permissions'):
                    if entry.before.permissions.value != entry.after.permissions.value:
                        changes.append(f"Permissions: {entry.before.permissions.value} → {entry.after.permissions.value}")
                
                if hasattr(entry.before, 'color') and hasattr(entry.after, 'color'):
                    if entry.before.color.value != entry.after.color.value:
                        changes.append(f"Color: {entry.before.color.value} → {entry.after.color.value}")
            
            elif action_name == "channel_update" and hasattr(entry, 'before') and hasattr(entry, 'after'):
                if hasattr(entry.before, 'name') and hasattr(entry.after, 'name'):
                    if entry.before.name != entry.after.name:
                        changes.append(f"Name: {entry.before.name} → {entry.after.name}")
                
                if hasattr(entry.before, 'position') and hasattr(entry.after, 'position'):
                    if entry.before.position != entry.after.position:
                        changes.append(f"Position: {entry.before.position} → {entry.after.position}")
            
            elif action_name == "member_update" and hasattr(entry, 'before') and hasattr(entry, 'after'):
                if hasattr(entry.before, 'nick') and hasattr(entry.after, 'nick'):
                    if entry.before.nick != entry.after.nick:
                        changes.append(f"Nickname: {entry.before.nick} → {entry.after.nick}")
            
            elif action_name == "message_delete":
                if hasattr(entry.extra, 'count'):
                    changes.append(f"Messages deleted: {entry.extra.count}")
                if hasattr(entry.extra, 'channel'):
                    changes.append(f"Channel: {entry.extra.channel.name}")
            
            elif action_name in ["invite_create", "invite_delete"]:
                if hasattr(entry.extra, 'code'):
                    changes.append(f"Code: {entry.extra.code}")
                if hasattr(entry.extra, 'channel'):
                    changes.append(f"Channel: {entry.extra.channel.name}")
                if hasattr(entry.extra, 'uses'):
                    changes.append(f"Uses: {entry.extra.uses}")
            
            # Properly handle member role updates - PRIMARY FIX
            elif action_name == "member_role_update":
                # Try to get role changes from extra attribute
                if hasattr(entry, 'extra') and hasattr(entry.extra, 'roles'):
                    added = []
                    removed = []
                    
                    # Process each role in the extra roles
                    for role in entry.extra.roles:
                        # Some roles might be represented as tuples (name, added/removed)
                        if isinstance(role, tuple) and len(role) == 2:
                            role_name, action_type = role
                            if action_type == "added":
                                added.append(role_name)
                            elif action_type == "removed":
                                removed.append(role_name)
                        # Handle AuditLogRole objects
                        elif hasattr(role, 'name'):
                            if hasattr(role, 'added') and role.added:
                                added.append(role.name)
                            elif hasattr(role, 'removed') and role.removed:
                                removed.append(role.name)
                    
                    # Add to changes if we found any
                    if added:
                        changes.append(f"Added roles: {', '.join(added)}")
                    if removed:
                        changes.append(f"Removed roles: {', '.join(removed)}")
                
                # Fallback method if extra.roles doesn't work
                if not changes and hasattr(entry, 'changes'):
                    # Handle $add and $remove changes
                    for change_type in ['$add', '$remove']:
                        if hasattr(entry.changes, change_type):
                            change = getattr(entry.changes, change_type)
                            role_ids = change.after if hasattr(change, 'after') else []
                            role_names = [guild.get_role(rid).name for rid in role_ids if guild.get_role(rid)]
                            
                            if role_names:
                                action = "Added" if change_type == '$add' else "Removed"
                                changes.append(f"{action} roles: {', '.join(role_names)}")
            
            # Special handling for specific actions
            elif action_name == "message_pin":
                # Show which message was pinned
                if hasattr(entry.extra, 'channel') and hasattr(entry.extra, 'message_id'):
                    changes.append(f"Message pinned in #{entry.extra.channel.name}")
            
            elif action_name == "automod_flag_message":
                # Show rule that triggered the flag
                if hasattr(entry.extra, 'rule_name'):
                    changes.append(f"Rule: {entry.extra.rule_name}")
                if hasattr(entry.extra, 'rule_trigger_type'):
                    changes.append(f"Trigger: {entry.extra.rule_trigger_type}")
            
            # Handle overwrite actions
            elif action_name in ["overwrite_update", "overwrite_create", "overwrite_delete"]:
                if hasattr(entry.extra, 'channel'):
                    changes.append(f"Channel: {entry.extra.channel.name}")
                if hasattr(entry.extra, 'target'):
                    if hasattr(entry.extra.target, 'name'):
                        changes.append(f"Target: {entry.extra.target.name}")
                    else:
                        changes.append(f"Target: {str(entry.extra.target)}")
            
            # Handle channel creation
            elif action_name == "channel_create":
                if hasattr(entry.target, 'name'):
                    changes.append(f"Channel: {entry.target.name}")
                if hasattr(entry.target, 'type'):
                    changes.append(f"Type: {str(entry.target.type)}")
            
            # Handle guild updates
            elif action_name == "guild_update":
                if hasattr(entry, 'before') and hasattr(entry, 'after'):
                    if hasattr(entry.before, 'name') and hasattr(entry.after, 'name'):
                        if entry.before.name != entry.after.name:
                            changes.append(f"Name: {entry.before.name} → {entry.after.name}")
                    if hasattr(entry.before, 'verification_level') and hasattr(entry.after, 'verification_level'):
                        if entry.before.verification_level != entry.after.verification_level:
                            changes.append(f"Verification: {entry.before.verification_level} → {entry.after.verification_level}")
            
            # Format the changes for display
            changes_str = "<br>".join(changes) if changes else "No additional details"

            entries.append({
                "action": action_name,
                "user": user_name,
                "target": target_name,
                "reason": reason,
                "created_at": created_at,
                "changes": changes_str,
            })
            
        return web.json_response({"log": entries})
    except Exception as e:
        traceback.print_exc()
        return web.json_response({"error": str(e)}, status=500)

async def handle_send_role_menu(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        menu_id = data.get('menu_id')
        if not menu_id:
            return web.json_response({'error': 'Missing menu_id'}, status=400)
        # Fetch menu from DB
        menu = db.execute_query(
            'SELECT * FROM role_menus WHERE id = ?',
            (menu_id,),
            fetch='one'
        )
        if not menu:
            return web.json_response({'error': 'Menu not found'}, status=404)
        config = json.loads(menu['config'])
        channel = bot_instance.get_channel(int(menu['channel_id']))
        if not channel:
            return web.json_response({'error': 'Channel not found'}, status=404)
        message_id = menu.get('message_id')
        sent_message = None

        # Reaction Role: send embed, add reactions for each emoji
        if menu['type'] == 'reactionrole':
            # Always send a new message for reaction roles (to avoid reaction desync)
            sent_message = await channel.send(**build_menu_message(menu, config))
            # Add reactions for each option
            for opt in config.get('options', []):
                emoji_val = opt.get('emoji')
                if emoji_val:
                    try:
                        await sent_message.add_reaction(emoji_val)
                    except Exception as e:
                        debug_print(f"Failed to add reaction {emoji_val}: {e}")
            db.execute_query(
                'UPDATE role_menus SET message_id = ? WHERE id = ?',
                (str(sent_message.id), menu_id)
            )
            return web.json_response({'success': True, 'message_id': str(sent_message.id)})

        # If message_id exists, try to edit, else send new
        if message_id:
            try:
                old_msg = await channel.fetch_message(int(message_id))
                sent_message = await old_msg.edit(**build_menu_message(menu, config))
            except Exception:
                sent_message = await channel.send(**build_menu_message(menu, config))
        else:
            sent_message = await channel.send(**build_menu_message(menu, config))
            db.execute_query(
                'UPDATE role_menus SET message_id = ? WHERE id = ?',
                (str(sent_message.id), menu_id)
            )
        return web.json_response({'success': True, 'message_id': str(sent_message.id)})
    except Exception as e:
        return web.json_response({'error': str(e)}, status=500)

def color_name_to_button_style(color_name):
    color_map = {
        'blurple': discord.ButtonStyle.primary,
        'green': discord.ButtonStyle.success,
        'red': discord.ButtonStyle.danger,
        'yellow': discord.ButtonStyle.secondary
    }
    return color_map.get(color_name, discord.ButtonStyle.primary)

def build_menu_message(menu, config):
    menu_type = menu['type']
    menu_id = menu['id']
    label = config.get('label', '')
    description = config.get('description', '')
    embed_color = int(config.get('embed_color', '#5865F2').lstrip('#'), 16) if config.get('embed_color') else 0x5865F2
    embed = discord.Embed(title=label, description=description, color=embed_color)
    embed.set_footer(text=f"ID: {menu_id}")

    if menu_type == 'dropdown':
        options = []
        for opt in config.get('options', []):
            kwargs = {
                "label": opt.get('label', ''),
                "description": opt.get('description', ''),
                "value": opt.get('role', '')
            }
            emoji_val = opt.get('emoji')
            if emoji_val:
                kwargs["emoji"] = emoji_val
            options.append(discord.SelectOption(**kwargs))
        view = discord.ui.View()
        multi_select = config.get('multi_select', False)
        min_values = 0 if multi_select else 1
        max_values = len(options) if multi_select else 1
        view.add_item(
            discord.ui.Select(
                placeholder=config.get('placeholder', 'Choose...'),
                options=options,
                custom_id=f"dropdown_{menu_id}",
                min_values=min_values,
                max_values=max_values
            )
        )
        return {'embed': embed, 'view': view}

    elif menu_type == 'reactionrole':
        # Just return the embed; reactions will be added after sending
        return {'embed': embed}

    elif menu_type == 'button':
        view = discord.ui.View()
        for idx, opt in enumerate(config.get('options', [])):
            kwargs = {
                "label": opt.get('label', ''),
                "custom_id": f"button_{menu_id}_{idx}"
            }
            emoji_val = opt.get('emoji')
            if emoji_val:
                kwargs["emoji"] = emoji_val
            color_val = opt.get('color', 'blurple')
            kwargs["style"] = color_name_to_button_style(color_val)
            view.add_item(discord.ui.Button(**kwargs))
        return {'embed': embed, 'view': view}

    return {'embed': embed}

async def handle_start_backup(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        guild_id = data.get('guild_id')
        if not guild_id or not str(guild_id).isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)
        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Bot is not in this server"}, status=404)

        def set_progress(val, step_text=None):
            set_backup_progress(guild_id, val, step_text)

        async def do_backup():
            try:
                set_progress(0, "Preparing backup...")
                await save_guild_backup(guild, set_progress=set_progress)
                set_progress(100, "Backup complete!")
            except Exception as e:
                set_progress(0, f"Backup failed: {e}")

        # Start backup in background
        asyncio.create_task(do_backup())
        return web.json_response({"success": True})
    except Exception as e:
        logger.error(f"Error in handle_start_backup: {e}")
        return web.json_response({"error": str(e)}, status=500)

async def handle_start_restore(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        guild_id = data.get('guild_id')
        backup_path = data.get('backup_path')
        if not guild_id or not str(guild_id).isdigit():
            return web.json_response({"error": "Invalid guild ID"}, status=400)
        if not backup_path or not os.path.exists(backup_path):
            return web.json_response({"error": "Backup file not found"}, status=404)
        guild = bot_instance.get_guild(int(guild_id))
        if not guild:
            return web.json_response({"error": "Bot is not in this server"}, status=404)

        def set_progress(val, step_text=None):
            set_backup_progress(guild_id, val, step_text)

        async def do_restore():
            try:
                # --- DM the server owner with progress ---
                owner = guild.owner
                dm = await owner.create_dm()
                msg1 = await dm.send("Restoring backup... This may take a while.")
                msg2 = await dm.send("Starting...")

                last_progress = {"content": None, "time": 0}

                async def progress_callback(step_text):
                    now = time.monotonic()
                    if step_text != last_progress["content"] and now - last_progress["time"] > 1:
                        try:
                            await msg2.edit(content=f"🔄 {step_text}")
                            last_progress["content"] = step_text
                            last_progress["time"] = now
                            await asyncio.sleep(2.5)
                        except Exception:
                            pass

                set_progress(0, "Preparing restore...")
                result = await restore_guild_backup(guild, backup_path, progress_callback=progress_callback)
                set_progress(100, "Restore complete!")

                # Delete progress messages
                for m in (msg2, msg1):
                    if m:
                        try:
                            await m.delete()
                            await asyncio.sleep(1)
                        except Exception:
                            pass
                if result:
                    await dm.send("✅ Backup restored successfully!")
                else:
                    await dm.send("❌ Restore failed. Check logs for details.")
            except Exception as e:
                set_progress(0, f"Restore failed: {e}")
                for m in (msg2, msg1):
                    if m:
                        try:
                            await m.delete()
                            await asyncio.sleep(2)
                        except Exception:
                            pass
                try:
                    await dm.send(f"❌ Restore failed: {e}")
                except Exception:
                    pass

        # Start restore in background
        asyncio.create_task(do_restore())
        return web.json_response({"success": True})
    except Exception as e:
        logger.error(f"Error in handle_start_restore: {e}")
        return web.json_response({"error": str(e)}, status=500)

async def handle_backup_progress(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    guild_id = request.query.get('guild_id')
    if not guild_id:
        return web.json_response({"error": "Missing guild_id"}, status=400)
    return web.json_response(get_backup_progress(guild_id))

async def handle_reload_schedules(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    load_schedules()
    return web.json_response({"success": True})

async def handle_custom_form_submission(request):
    auth_error = await require_jwt(request)
    if auth_error:
        return auth_error
    try:
        data = await request.json()
        form_id = data.get('form_id')
        guild_id = data.get('guild_id')
        user_id = data.get('user_id')
        responses = data.get('responses', {})
        # Fetch form config
        form = db.execute_query('SELECT * FROM custom_forms WHERE id = ?', (form_id,), fetch='one')
        if not form:
            return web.json_response({'error': 'Form not found'}, status=404)
        config = json.loads(form['config'])
        embed_cfg = config.get('embed', {})
        # Build embed
        embed = discord.Embed(
            title=embed_cfg.get('title', form['name']),
            color=int(embed_cfg.get('color', '5865F2').lstrip('#'), 16) if isinstance(embed_cfg.get('color'), str) else embed_cfg.get('color', 0x5865F2),
            description=embed_cfg.get('description', form.get('description', ''))
        )

        for field in config.get('fields', []):
            val = responses.get(field['id'], 'N/A')
            embed.add_field(name=field.get('label', field['id']), value=str(val)[:1024], inline=False)

        # Add submitter at the very bottom in small italics
        if data.get("user_id"):
            submitter_line = f"\n\n-# Submitted by <@{data['user_id']}>"
            if embed.description:
                embed.description += submitter_line
            else:
                embed.description = submitter_line.lstrip()

        # Send to configured channel
        channel_id = embed_cfg.get('channel_id')
        if not channel_id:
            return web.json_response({'error': 'No channel configured for this form'}, status=400)
        channel = bot_instance.get_channel(int(channel_id))
        if not channel:
            return web.json_response({'error': 'Channel not found'}, status=404)
        await channel.send(embed=embed)
        return web.json_response({'success': True})
    except Exception as e:
        logger.error(f"Custom form submission error: {e}")
        return web.json_response({'error': str(e)}, status=500)

@tasks.loop(minutes=5)
async def cleanup():
    # Clean expired data
    processed_messages.clear()

@bot_instance.event
async def on_ready():
    set_event_loop(bot_instance.loop)
    load_schedules()
    scheduler._eventloop = bot_instance.loop
    scheduler.start()
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
        debug_print("⚠️ Bot not in any guilds, skipping command sync")
        return
        
    cleanup.start()
    # Get current guild IDs as strings
    current_guild_ids = {str(g.id) for g in bot_instance.guilds}
    
    # Instantiate PingAnnouncer here, when the loop is running
    global ping_announcer
    ping_announcer = PingAnnouncer(bot_instance)

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

    bot_instance.loop.create_task(webserver())
    await bot_instance.role_batcher.initialize()

def reload_warnings(guild_id: str):
    global warnings
    warnings = db.conn.execute('''
        SELECT * FROM warnings 
        WHERE guild_id = ?
        ORDER BY timestamp DESC
    ''', (guild_id,)).fetchall()
    warnings = [dict(w) for w in warnings]

@bot_instance.event
async def on_interaction(interaction: discord.Interaction):

    # Handle component interactions (buttons, selects, etc.)
    if interaction.type == discord.InteractionType.component:
        # Ensure interaction.user is a Member for role checks
        user = interaction.user
        if not isinstance(user, discord.Member) and interaction.guild is not None:
            try:
                user = await interaction.guild.fetch_member(user.id)
            except Exception:
                pass  # fallback to User if not found

        custom_id = interaction.data.get('custom_id', '')

        # Dropdown Role Menu
        if custom_id.startswith('dropdown_'):
            menu_id = custom_id.split('_', 1)[1]
            menu = db.execute_query('SELECT * FROM role_menus WHERE id = ?', (menu_id,), fetch='one')
            if not menu:
                await interaction.response.send_message("Menu not found.", ephemeral=True)
                return
            config = json.loads(menu['config'])
            selected_roles = interaction.data['values']
            method = config.get('grant_remove_method', 'grant')
            multi_select = config.get('multi_select', False)
            messages = []

            # --- Handle "no selection" for multi-select and grant_remove/remove ---
            if multi_select and not selected_roles and method in ('remove', 'grant_remove'):
                removed_any = False
                for opt in config.get('options', []):
                    role = interaction.guild.get_role(int(opt.get('role')))
                    if role and role in user.roles:
                        await user.remove_roles(role)
                        messages.append(opt.get('remove_message', f"Role {role.mention} removed!"))
                        removed_any = True
                if removed_any:
                    await interaction.response.send_message("\n".join(messages), ephemeral=True)
                else:
                    await interaction.response.send_message("No roles to remove.", ephemeral=True)
                return

            # --- Normal selection handling ---
            for opt in config.get('options', []):
                role = interaction.guild.get_role(int(opt.get('role')))
                if not role:
                    continue
                if opt.get('role') in selected_roles:
                    # Should have this role
                    if method == 'grant':
                        if role not in user.roles:
                            await user.add_roles(role)
                            messages.append(opt.get('grant_message', f"Role {role.mention} granted!"))
                    elif method == 'remove':
                        if role in user.roles:
                            await user.remove_roles(role)
                            messages.append(opt.get('remove_message', f"Role {role.mention} removed!"))
                    elif method == 'grant_remove':
                        if role not in user.roles:
                            await user.add_roles(role)
                            messages.append(opt.get('grant_message', f"Role {role.mention} granted!"))
                else:
                    # Should NOT have this role
                    if method in ('grant_remove', 'remove'):
                        if role in user.roles:
                            await user.remove_roles(role)
                            messages.append(opt.get('remove_message', f"Role {role.mention} removed!"))

            # --- Always send a non-empty message ---
            if messages:
                await interaction.response.send_message("\n".join(messages), ephemeral=True)
            else:
                await interaction.response.send_message("No changes made.", ephemeral=True)
            return

        # Reaction Role Button
        if custom_id.startswith('reactionrole_'):
            try:
                _, menu_id, emoji = custom_id.split('_', 2)
            except ValueError:
                await interaction.response.send_message("Invalid button ID.", ephemeral=True)
                return
            menu = db.execute_query('SELECT * FROM role_menus WHERE id = ?', (menu_id,), fetch='one')
            if not menu:
                await interaction.response.send_message("Menu not found.", ephemeral=True)
                return
            config = json.loads(menu['config'])
            for opt in config.get('options', []):
                if opt.get('emoji') == emoji:
                    role = interaction.guild.get_role(int(opt.get('role')))
                    if role:
                        await user.add_roles(role)
                        await interaction.response.send_message(f"Role {role.mention} granted!", ephemeral=True)
                    else:
                        await interaction.response.send_message("Role not found.", ephemeral=True)
                    return
            await interaction.response.send_message("Option not found.", ephemeral=True)
            return

        # Button Role Menu
        if custom_id.startswith('button_'):
            try:
                _, menu_id, idx = custom_id.split('_', 2)
                idx = int(idx)
            except ValueError:
                await interaction.response.send_message("Invalid button ID.", ephemeral=True)
                return
            menu = db.execute_query('SELECT * FROM role_menus WHERE id = ?', (menu_id,), fetch='one')
            if not menu:
                await interaction.response.send_message("Menu not found.", ephemeral=True)
                return
            config = json.loads(menu['config'])
            try:
                opt = config.get('options', [])[idx]
            except (IndexError, ValueError):
                await interaction.response.send_message("Option not found.", ephemeral=True)
                return
            role = interaction.guild.get_role(int(opt.get('role')))
            if role in user.roles:
                await user.remove_roles(role)
                msg = opt.get('remove_message', f"Role {role.mention} removed.")
            else:
                await user.add_roles(role)
                msg = opt.get('grant_message', f"Role {role.mention} granted.")
            await interaction.response.send_message(msg, ephemeral=True)
            return

    # Handle application commands
    if interaction.type == discord.InteractionType.application_command:
        cmd_data = None
        guild_id = str(interaction.guild.id) if interaction.guild else None
        if guild_id and hasattr(bot_instance, '_command_registry'):
            cmd_data = bot_instance._command_registry.get(f"{guild_id}_{interaction.command.name}")
        if cmd_data:
            await bot_instance.custom_command_handler(interaction, cmd_data)
            return

@bot_instance.event
async def on_raw_reaction_add(payload):
    if payload.user_id == bot_instance.user.id:
        return
    menu = db.execute_query(
        'SELECT * FROM role_menus WHERE message_id = ? AND type = "reactionrole"',
        (str(payload.message_id),),
        fetch='one'
    )
    if not menu:
        return
    config = json.loads(menu['config'])
    for opt in config.get('options', []):
        if str(opt.get('emoji')) == str(payload.emoji):
            guild = bot_instance.get_guild(payload.guild_id)
            member = guild.get_member(payload.user_id)
            role = guild.get_role(int(opt.get('role')))
            if role and member and role not in member.roles:
                await member.add_roles(role, reason="Reaction role given")
            break

@bot_instance.event
async def on_raw_reaction_remove(payload):
    menu = db.execute_query(
        'SELECT * FROM role_menus WHERE message_id = ? AND type = "reactionrole"',
        (str(payload.message_id),),
        fetch='one'
    )
    if not menu:
        return
    config = json.loads(menu['config'])
    for opt in config.get('options', []):
        if str(opt.get('emoji')) == str(payload.emoji):
            guild = bot_instance.get_guild(payload.guild_id)
            member = guild.get_member(payload.user_id)
            role = guild.get_role(int(opt.get('role')))
            if role and member and role in member.roles:
                await member.remove_roles(role, reason="Reaction role removed")
            break

# -------------------- Level System --------------------
def get_level_data(guild_id, user_id):
    try:
        data = db.get_user_level(str(guild_id), str(user_id))
        if not data:
            # Create new user with default values
            db.conn.execute('''
                INSERT INTO user_levels 
                (guild_id, user_id, xp, level, username, last_message)
                VALUES (?, ?, 0, 0, ?, 0)
            ''', (str(guild_id), str(user_id), ""))
            db.conn.commit()
            return {
                "xp": 0,
                "level": 0,
                "username": "",
                "last_message": 0
            }
        return data
    except Exception as e:
        debug_print(f"Error getting level data: {str(e)}")
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
        'embed_color': 0xffd700,
        'give_xp_to_bots': False,
        'give_xp_to_self': False
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
        validated['give_xp_to_bots'] = bool(config.get('give_xp_to_bots', default_config['give_xp_to_bots']))
        validated['give_xp_to_self'] = bool(config.get('give_xp_to_self', default_config['give_xp_to_self']))

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

async def handle_level_up(user, guild, channel, old_level=None, new_level=None):
    try:
        guild_id = str(guild.id)
        user_id = str(user.id)

        user_data = get_level_data(guild_id, user_id)
        total_xp = user_data['xp']

        # Use passed levels if provided, otherwise calculate
        if old_level is None:
            old_level = user_data['level']
        if new_level is None:
            new_level = calculate_level(total_xp)

        if new_level > old_level:
            save_level_data(guild_id, user_id, {'level': new_level})

            rewards = db.get_level_rewards(guild_id)
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
                    debug_print(f"Missing permissions to assign roles in {guild.name}")
                except Exception as e:
                    debug_print(f"Error assigning roles: {str(e)}")

            config = get_level_config(guild_id)
            announce_level_up = bool(config.get('announce_level_up', True))
            if announce_level_up:
                await send_level_up_notification(user, guild, channel, new_level, config)

    except Exception as e:
        debug_print(f"Error handling level up: {str(e)}")
        traceback.print_exc()

async def send_level_up_notification(user, guild, channel, new_level, config):
    try:
        # Use the configured channel if set, otherwise fallback to the current channel
        target_channel = None
        level_channel_id = config.get('level_channel')
        # Only try to convert if not None and not the string 'None'
        if level_channel_id not in (None, 'None', ''):
            try:
                target_channel = guild.get_channel(int(level_channel_id))
            except Exception as ex:
                debug_print(f"Error: Failed to resolve level_channel {level_channel_id}: {ex}")
                target_channel = None
        if not target_channel:
            target_channel = channel

        # Parse embed color safely
        embed_color = config.get('embed_color', 0xffd700)
        if isinstance(embed_color, str):
            try:
                if embed_color.startswith('#'):
                    embed_color = int(embed_color[1:], 16)
                else:
                    embed_color = int(embed_color)
            except Exception as ex:
                debug_print(f"Error: Failed to parse embed_color '{embed_color}': {ex}")
                embed_color = 0xffd700

        # Create the embed
        embed_title = config.get('embed_title', '🎉 Level Up!')
        embed_description = config.get('embed_description', '{user} has reached level **{level}**!')
        embed_description = embed_description.format(user=user.mention, level=new_level)
        embed = discord.Embed(
            title=embed_title,
            description=embed_description,
            color=embed_color
        )
        try:
            embed.set_thumbnail(url=user.display_avatar.url)
        except Exception as ex:
            debug_print(f"Failed to set embed thumbnail: {ex}")

        # Send the embed
        await target_channel.send(embed=embed)

    except Exception as e:
        debug_print(f"Error sending level up notification: {str(e)}")
        traceback.print_exc()

# -------------------- Backup System --------------------
async def collect_guild_backup(guild, set_progress=None):
    try:
        backup = {
            "roles": [],
            "channels": [],
            "bans": [],
            "timeouts": [],
            "emojis": [],
            "stickers": [],
            "settings": {},
            "audit_log": [],
            "features": list(guild.features),
            "tags": getattr(guild, "tags", []),
        }
        total_steps = 7
        step = 0

        # Roles
        if set_progress: set_progress(int(step / total_steps * 100), "Backing up roles...")
        for role in guild.roles:
            backup["roles"].append({
                "id": role.id,
                "name": role.name,
                "color": role.color.value,
                "position": role.position,
                "permissions": role.permissions.value,
                "mentionable": role.mentionable,
                "hoist": role.hoist,
                "managed": role.managed,
                "members": [m.id for m in role.members]
            })
        step += 1

        # Channels & Categories
        if set_progress: set_progress(int(step / total_steps * 100), "Backing up channels...")
        for channel in guild.channels:
            overwrites = {}
            for target, overwrite in channel.overwrites.items():
                overwrites[str(target.id)] = {
                    "allow": overwrite.pair()[0].value,
                    "deny": overwrite.pair()[1].value,
                    "type": "role" if hasattr(target, "members") else "member"
                }
            backup["channels"].append({
                "id": channel.id,
                "name": channel.name,
                "type": str(channel.type),
                "position": channel.position,
                "category": channel.category_id if hasattr(channel, "category_id") else None,
                "overwrites": overwrites,
                "topic": getattr(channel, "topic", None),
                "nsfw": getattr(channel, "nsfw", False),
                "slowmode_delay": getattr(channel, "slowmode_delay", 0),
                "bitrate": getattr(channel, "bitrate", None),
                "user_limit": getattr(channel, "user_limit", None),
            })
        step += 1

        # Bans
        if set_progress: set_progress(int(step / total_steps * 100), "Backing up bans...")
        try:
            async for entry in guild.bans():
                backup["bans"].append({
                    "user_id": entry.user.id,
                    "username": str(entry.user),
                    "reason": entry.reason
                })
        except Exception as e:
            debug_print(f"Error backing up bans: {e}")
        step += 1

        # Timed out users
        if set_progress: set_progress(int(step / total_steps * 100), "Backing up timed out users...")
        for member in guild.members:
            if member.timed_out_until:
                backup["timeouts"].append({
                    "user_id": member.id,
                    "until": member.timed_out_until.isoformat(),
                    "reason": getattr(member, "timeout_reason", None)
                })
        step += 1

        # Emojis
        if set_progress: set_progress(int(step / total_steps * 100), "Backing up emojis...")
        for emoji in guild.emojis:
            backup["emojis"].append({
                "id": emoji.id,
                "name": emoji.name,
                "url": str(emoji.url),
                "animated": emoji.animated
            })
        step += 1

        # Stickers
        if set_progress: set_progress(int(step / total_steps * 100), "Backing up stickers...")
        for sticker in getattr(guild, "stickers", []):
            backup["stickers"].append({
                "id": sticker.id,
                "name": sticker.name,
                "url": str(sticker.url) if hasattr(sticker, "url") else None
            })
        step += 1

        # Settings & Audit log
        if set_progress: set_progress(int(step / total_steps * 100), "Backing up server settings...")
        backup["settings"] = {
            "name": guild.name,
            "icon_url": str(guild.icon.url) if guild.icon else None,
            "banner_url": str(guild.banner.url) if guild.banner else None,
            "description": guild.description,
            "verification_level": guild.verification_level.value,
            "default_notifications": guild.default_notifications.value,
            "explicit_content_filter": guild.explicit_content_filter.value,
            "afk_channel_id": guild.afk_channel.id if guild.afk_channel else None,
            "afk_timeout": guild.afk_timeout,
            "system_channel_id": guild.system_channel.id if guild.system_channel else None,
            "rules_channel_id": guild.rules_channel.id if guild.rules_channel else None,
            "public_updates_channel_id": guild.public_updates_channel.id if guild.public_updates_channel else None,
            "preferred_locale": guild.preferred_locale,
            "mfa_level": getattr(guild, "mfa_level", None),
            "max_members": getattr(guild, "max_members", None),
            "max_presences": getattr(guild, "max_presences", None),
        }
        try:
            async for entry in guild.audit_logs(limit=50):
                backup["audit_log"].append({
                    "action": str(entry.action),
                    "user": str(entry.user) if entry.user else None,
                    "target": str(entry.target) if entry.target else None,
                    "reason": entry.reason,
                    "created_at": entry.created_at.isoformat() if entry.created_at else None,
                    "changes": str(getattr(entry, "changes", "")),
                })
        except Exception as e:
            debug_print(f"Error backing up audit log: {e}")
        step += 1

        if set_progress: set_progress(100, "Backup complete!")
        return backup
    except Exception as e:
        debug_print(f"Error during collect_guild_backup: {e}\n{traceback.format_exc()}")
        if set_progress:
            set_progress(0, "Backup failed.")
        raise

async def save_guild_backup(guild, set_progress=None):
    try:
        if set_progress:
            set_progress(0, "Preparing backup...")
        backup_data = await collect_guild_backup(guild, set_progress=set_progress)
        if set_progress:
            set_progress(99, "Saving backup file...")
        backup_dir = os.path.join(os.path.dirname(__file__), '..', 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        filename = f"{guild.id}_{int(time.time())}.json"
        file_path = os.path.join(backup_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2)
        add_backup(str(guild.id), file_path)
        if set_progress:
            set_progress(100, "Backup complete!")
        return file_path
    except Exception as e:
        debug_print(f"Error during save_guild_backup: {e}\n{traceback.format_exc()}")
        if set_progress:
            set_progress(0, f"Backup failed: {e}")
        raise

async def restore_guild_backup(guild, file_path, progress_callback=None):
    """
    Restore a guild from a backup file.
    WARNING: This is destructive and should only be used with full admin consent.
    """

    def progress(step):
        if progress_callback:
            coro = progress_callback(step)
            if asyncio.iscoroutine(coro):
                asyncio.create_task(coro)

    with open(file_path, 'r', encoding='utf-8') as f:
        backup = json.load(f)

    # --- Restore Roles ---
    try:
        progress("Deleting roles...")
        debug_print("Deleting existing roles...")
        rulekeeper_role = discord.utils.get(guild.roles, name="RuleKeeper")
        rulekeeper_id = rulekeeper_role.id if rulekeeper_role else None

        for role in reversed(guild.roles):
            if role.is_default() or (rulekeeper_id and role.id == rulekeeper_id):
                continue
            try:
                await role.delete(reason="Restoring from backup")
                await asyncio.sleep(2.5)
            except Exception as e:
                debug_print(f"Failed to delete role {role.name}: {e}")

        progress("Restoring roles...")
        debug_print("Restoring roles...")
        role_map = {}
        for role_data in sorted(backup["roles"], key=lambda r: r["position"]):
            if role_data["name"] in ("@everyone", "RuleKeeper"):
                continue
            try:
                new_role = await guild.create_role(
                    name=role_data["name"],
                    color=discord.Color(role_data["color"]),
                    permissions=discord.Permissions(role_data["permissions"]),
                    hoist=role_data.get("hoist", False),
                    mentionable=role_data.get("mentionable", False),
                    reason="Restoring from backup"
                )
                role_map[role_data["id"]] = new_role
                await asyncio.sleep(2.5)
            except Exception as e:
                debug_print(f"Error creating role {role_data['name']}: {e}")

        role_map[next(r.id for r in guild.roles if r.is_default())] = guild.default_role
        if rulekeeper_role:
            rk_backup = next((r for r in backup["roles"] if r["name"] == "RuleKeeper"), None)
            if rk_backup:
                role_map[rk_backup["id"]] = rulekeeper_role

        roles_in_order = []
        for role_data in sorted(backup["roles"], key=lambda r: r["position"]):
            if role_data["name"] == "@everyone":
                continue
            if role_data["name"] == "RuleKeeper" and rulekeeper_role:
                roles_in_order.append(rulekeeper_role)
            elif role_data["id"] in role_map:
                roles_in_order.append(role_map[role_data["id"]])
        try:
            await guild.edit_role_positions(positions={role: i+1 for i, role in enumerate(roles_in_order)})
        except Exception as e:
            debug_print(f"Error reordering roles: {e}")

    except Exception as e:
        debug_print(f"Error restoring roles: {e}")

    # --- Restore Role Assignments ---
    try:
        progress("Restoring role assignments...")
        debug_print("Restoring role assignments...")
        user_roles = {}
        for role_data in backup.get("roles", []):
            role_id = role_data["id"]
            if role_id not in role_map or role_map[role_id].is_default():
                continue
            member_ids = role_data.get("members", [])
            for user_id in member_ids:
                user_roles.setdefault(user_id, set()).add(role_id)
        # Get RuleKeeper role and its position
        rulekeeper_role = discord.utils.get(guild.roles, name="RuleKeeper")
        rulekeeper_pos = rulekeeper_role.position if rulekeeper_role else None

        for user_id, role_ids in user_roles.items():
            member = guild.get_member(int(user_id))
            if member:
                roles_to_assign = []
                for rid in role_ids:
                    role = role_map.get(rid)
                    if not role or role.name == "RuleKeeper":
                        continue
                    # If RuleKeeper exists and this role would be above RuleKeeper, skip or move below
                    if rulekeeper_role and rulekeeper_pos is not None:
                        if role.position >= rulekeeper_pos:
                            # Place below RuleKeeper by not assigning now
                            debug_print(f"Role {role.name} (pos {role.position}) would be above RuleKeeper (pos {rulekeeper_pos}), skipping for {member}.")
                            continue
                    roles_to_assign.append(role)
                # Assign roles in one go if any
                if roles_to_assign:
                    try:
                        await member.add_roles(*roles_to_assign, reason="Restoring roles from backup")
                        await asyncio.sleep(2.5)
                    except Exception as e:
                        debug_print(f"Failed to assign roles to {member}: {e}")
            else:
                debug_print(f"Member {user_id} not found in guild for role assignment")
    except Exception as e:
        debug_print(f"Error restoring role assignments: {e}")

    # --- Restore Channels and Categories ---
    try:
        progress("Deleting channels and categories...")
        debug_print("Deleting existing channels and categories...")
        required_channel_ids = set()
        required_channels = []
        for attr in ("rules_channel", "public_updates_channel", "safety_alerts_channel", "community_updates_channel"):
            ch = getattr(guild, attr, None)
            if ch:
                required_channel_ids.add(ch.id)
                required_channels.append(ch)

        for channel in guild.channels:
            if channel.id in required_channel_ids:
                continue
            try:
                await channel.delete(reason="Restoring from backup")
                await asyncio.sleep(2.5)
            except Exception as e:
                debug_print(f"Failed to delete channel {channel.name}: {e}")

        progress("Restoring channels and categories...")
        debug_print("Restoring channels and categories...")
        category_map = {}
        for ch in backup["channels"]:
            ch_type = ch["type"].lower().replace("channeltype.", "")
            if ch_type == "category":
                try:
                    new_cat = await guild.create_category(
                        name=ch["name"],
                        position=ch["position"],
                        reason="Restoring from backup"
                    )
                    category_map[ch["id"]] = new_cat
                    await asyncio.sleep(2.5)
                except Exception as e:
                    debug_print(f"Error creating category {ch['name']}: {e}")

        created_channel_map = {}
        for ch in backup["channels"]:
            ch_type = ch["type"].lower().replace("channeltype.", "")
            if ch_type == "category":
                continue
            if ch.get("id") in required_channel_ids:
                continue
            kwargs = {
                "name": ch["name"],
                "position": ch["position"],
                "reason": "Restoring from backup"
            }
            if ch.get("category"):
                parent = category_map.get(ch["category"])
                if parent:
                    kwargs["category"] = parent
            overwrites = {}
            for target_id, ow in ch.get("overwrites", {}).items():
                target_role = role_map.get(int(target_id))
                if not target_role:
                    continue
                allow = discord.Permissions(ow["allow"])
                deny = discord.Permissions(ow["deny"])
                overwrites[target_role] = discord.PermissionOverwrite.from_pair(allow, deny)
            if overwrites:
                kwargs["overwrites"] = overwrites
            try:
                if ch_type == "text":
                    kwargs["topic"] = ch.get("topic")
                    kwargs["nsfw"] = ch.get("nsfw", False)
                    kwargs["slowmode_delay"] = ch.get("slowmode_delay", 0)
                    new_ch = await guild.create_text_channel(**{k: v for k, v in kwargs.items() if v is not None})
                elif ch_type in ("news", "announcement"):
                    kwargs["topic"] = ch.get("topic")
                    kwargs["nsfw"] = ch.get("nsfw", False)
                    kwargs["slowmode_delay"] = ch.get("slowmode_delay", 0)
                    new_ch = await guild.create_text_channel(**{k: v for k, v in kwargs.items() if v is not None}, news=True)
                elif ch_type == "voice":
                    kwargs["bitrate"] = ch.get("bitrate")
                    kwargs["user_limit"] = ch.get("user_limit")
                    new_ch = await guild.create_voice_channel(**{k: v for k, v in kwargs.items() if v is not None})
                elif ch_type == "forum":
                    kwargs["topic"] = ch.get("topic")
                    kwargs["nsfw"] = ch.get("nsfw", False)
                    new_ch = await guild.create_forum_channel(**{k: v for k, v in kwargs.items() if v is not None})
                elif ch_type == "rules":
                    kwargs["topic"] = ch.get("topic")
                    new_ch = await guild.create_text_channel(**{k: v for k, v in kwargs.items() if v is not None})
                else:
                    debug_print(f"Skipping unknown channel type: {ch['type']}")
                    continue
                created_channel_map[ch["id"]] = new_ch
                await asyncio.sleep(2.5)
            except discord.HTTPException as e:
                debug_print(f"Error creating channel {ch['name']}: {e}")
            except Exception as e:
                debug_print(f"Error creating channel {ch['name']}: {e}")

        backup_required_channels = {ch["id"]: ch for ch in backup["channels"] if ch.get("id") in required_channel_ids}
        for req_ch in required_channels:
            backup_ch = backup_required_channels.get(req_ch.id)
            if not backup_ch:
                debug_print(f"No backup data for required channel {req_ch.name} ({req_ch.id}), skipping move.")
                continue
            parent = None
            if backup_ch.get("category"):
                parent = category_map.get(backup_ch["category"])
            try:
                await req_ch.edit(category=parent, position=backup_ch["position"], reason="Restoring from backup")
            except Exception as e:
                debug_print(f"Failed to move required channel {req_ch.name}: {e}")

    except Exception as e:
        debug_print(f"Error restoring channels: {e}")

    # --- Restore Bans ---
    try:
        progress("Unbanning users...")
        debug_print("Unbanning users...")
        bans = []
        try:
            async def fetch_bans():
                return [entry async for entry in guild.bans()]
            bans = await asyncio.wait_for(fetch_bans(), timeout=10)
        except asyncio.TimeoutError:
            debug_print("Timeout while fetching bans.")
            bans = []
        except Exception as e:
            debug_print(f"Error fetching bans: {e}")
            bans = []

        if not bans:
            debug_print("No users to unban.")
        else:
            for entry in bans:
                try:
                    await guild.unban(entry.user, reason="Restoring from backup")
                    await asyncio.sleep(2.5)
                except Exception as e:
                    debug_print(f"Failed to unban {entry.user}: {e}")

        progress("Restoring bans...")
        debug_print("Restoring bans...")
        for ban in backup.get("bans", []):
            try:
                user = discord.Object(id=ban["user_id"])
                await guild.ban(user, reason=ban.get("reason", "Restored from backup"))
                await asyncio.sleep(2.5)
            except Exception as e:
                debug_print(f"Failed to ban user {ban['user_id']}: {e}")
    except Exception as e:
        debug_print(f"Error restoring bans: {e}")

    # --- Restore Timed Out Users ---
    try:
        progress("Restoring timed out users...")
        debug_print("Restoring timed out users...")
        for timeout in backup.get("timeouts", []):
            user_id = timeout.get("user_id")
            until = timeout.get("until")
            reason = timeout.get("reason", "Restored timeout from backup")
            if not user_id or not until:
                continue
            member = guild.get_member(user_id)
            if member:
                try:
                    until_dt = datetime.fromisoformat(until)
                    if until_dt > datetime.utcnow():
                        await member.timeout(until_dt, reason=reason)
                        await asyncio.sleep(1)
                except Exception as e:
                    debug_print(f"Error restoring timeout for user {user_id}: {e}")
            else:
                debug_print(f"Member {user_id} not found for timeout")
    except Exception as e:
        debug_print(f"Error restoring timed out users: {e}")

    # --- Restore Emojis ---
    try:
        progress("Deleting emojis...")
        debug_print("Deleting existing emojis...")
        for emoji in guild.emojis:
            try:
                await emoji.delete(reason="Restoring from backup")
                await asyncio.sleep(1)
            except Exception as e:
                debug_print(f"Failed to delete emoji {emoji.name}: {e}")

        progress("Restoring emojis...")
        debug_print("Restoring emojis...")
        async with aiohttp.ClientSession() as session:
            for idx, emoji_data in enumerate(backup.get("emojis", []), 1):
                try:
                    async with session.get(emoji_data["url"]) as resp:
                        img = await resp.read()
                    while True:
                        try:
                            await guild.create_custom_emoji(
                                name=emoji_data["name"],
                                image=img,
                                reason="Restoring from backup"
                            )
                            debug_print(f"Restored emoji {emoji_data['name']} ({idx}/{len(backup.get('emojis', []))})")
                            await asyncio.sleep(7)  # Discord recommends 5-7s between emoji creates
                            break
                        except discord.HTTPException as e:
                            if e.status == 429:
                                # Try to get retry_after from the exception or default to 10s
                                retry_after = getattr(e, "retry_after", None)
                                if retry_after is None:
                                    # Try to parse from the error text
                                    try:
                                        data = e.response.json()
                                        retry_after = float(data.get("retry_after", 10))
                                    except Exception:
                                        retry_after = 10
                                # If retry_after is very high, skip this emoji
                                if retry_after > 60 * 5:
                                    debug_print(f"Rate limited for {retry_after}s on emoji {emoji_data['name']}, skipping.")
                                    break
                                debug_print(f"Rate limited while creating emoji {emoji_data['name']}, sleeping for {retry_after} seconds.")
                                await asyncio.sleep(retry_after)
                            else:
                                debug_print(f"Failed to create emoji {emoji_data['name']}: {e}")
                                break
                        except Exception as e:
                            debug_print(f"Failed to create emoji {emoji_data['name']}: {e}")
                            break
                except Exception as e:
                    debug_print(f"Error restoring emojis: {e}")
    except Exception as e:
        debug_print(f"Error restoring emojis: {e}")

    # --- Restore Stickers ---
    try:
        progress("Deleting stickers...")
        debug_print("Deleting existing stickers...")
        for sticker in getattr(guild, "stickers", []):
            try:
                await sticker.delete(reason="Restoring from backup")
                await asyncio.sleep(1)
            except Exception as e:
                debug_print(f"Failed to delete sticker {sticker.name}: {e}")
        
        progress("Restoring stickers...")
        debug_print("Restoring stickers...")
        async with aiohttp.ClientSession() as session:
            for sticker_data in backup.get("stickers", []):
                try:
                    if not sticker_data.get("url"):
                        continue
                    async with session.get(sticker_data["url"]) as resp:
                        img = await resp.read()
                    await guild.create_sticker(
                        name=sticker_data["name"][:30],
                        description=sticker_data.get("description", "")[:100] or "Restored sticker",
                        emoji="😀",
                        file=discord.File(fp=io.BytesIO(img), filename=f"{sticker_data['name']}.png"),
                        reason="Restoring from backup"
                    )
                    await asyncio.sleep(1)
                except Exception as e:
                    debug_print(f"Failed to create sticker {sticker_data.get('name')}: {e}")
    except Exception as e:
        debug_print(f"Error restoring stickers: {e}")

    # --- Restore Server Settings ---
    try:
        progress("Restoring server settings...")
        debug_print("Restoring server settings...")
        settings = backup.get("settings", {})
        icon_bytes = None
        banner_bytes = None

        icon_url = settings.get("icon_url")
        if icon_url:
            async with aiohttp.ClientSession() as session:
                async with session.get(icon_url) as resp:
                    if resp.status == 200:
                        icon_bytes = await resp.read()

        banner_url = settings.get("banner_url")
        if banner_url:
            async with aiohttp.ClientSession() as session:
                async with session.get(banner_url) as resp:
                    if resp.status == 200:
                        banner_bytes = await resp.read()

        edit_kwargs = {
            "name": settings.get("name", guild.name),
            "description": settings.get("description", guild.description),
            "reason": "Restoring from backup"
        }
        if icon_bytes:
            edit_kwargs["icon"] = icon_bytes
        if banner_bytes:
            edit_kwargs["banner"] = banner_bytes
        try:
            await guild.edit(**edit_kwargs)
        except discord.Forbidden:
            debug_print("Error restoring settings: Missing Permissions (Manage Server required)")
        except discord.HTTPException as e:
            debug_print(f"Error restoring settings: {e}")
        except Exception as e:
            debug_print(f"Unexpected error restoring settings: {e}")
    except Exception as e:
        debug_print(f"Error restoring settings: {e}")

    progress("Restore complete!")
    debug_print("Restore complete!")

    # --- Restore Audit Log, Features, Tags ---
    # These are not restorable via Discord API currently.

    return True

# -------------------- Message Processing --------------------
@bot_instance.event
async def on_message(message):
    debug_print(f"Entering on_message with message: {message}", level="all")
    if not message.guild:
        return await bot_instance.process_commands(message)
    config = load_log_config(message.guild.id)
    log_bots = config.get("log_bots", False)
    log_self = config.get("log_self", False)
    log_self = message.author.id == bot_instance.user.id
    log_bot = getattr(message.author, "bot", False)
    if (log_self and not log_self) or (log_bot and not log_self and not log_bots):
        return await bot_instance.process_commands(message)

    try:
        guild = message.guild
        guild_id = str(message.guild.id)
        user_id = str(message.author.id)
        current_time = time.time()
        spam_key = f"{guild_id}:{user_id}"
        mention_key = f"{guild_id}:{user_id}"

        # ===== LEVEL SYSTEM PROCESSING =====
        level_config = get_level_config(guild_id)

        # XP toggles: skip if not allowed
        if message.author.bot:
            # If this bot
            if message.author.id == bot_instance.user.id:
                if not level_config.get('give_xp_to_self', False):
                    return
            else:
                if not level_config.get('give_xp_to_bots', False):
                    return
        spam_config = db.get_spam_config(guild_id)

        # --- NO XP after spam detection ---
        if not hasattr(bot_instance, "no_xp_until"):
            bot_instance.no_xp_until = defaultdict(dict)
        no_xp_until = bot_instance.no_xp_until
        no_xp_user_until = no_xp_until.get(guild_id, {}).get(user_id, 0)
        if current_time < no_xp_user_until:
            pass  # User is blocked from XP gain
        else:
            # Process XP if not in excluded level channels
            if str(message.channel.id) not in level_config['excluded_channels']:
                cooldown_seconds = level_config['cooldown']
                user_data = get_level_data(guild_id, user_id)
                last_cooldown_time = user_data.get('last_message', 0)

                if (current_time - last_cooldown_time) >= cooldown_seconds:
                    db.conn.execute('''
                        INSERT INTO user_levels (guild_id, user_id, username, last_message, xp)
                        VALUES (?, ?, ?, ?, 0)
                        ON CONFLICT(guild_id, user_id) 
                        DO UPDATE SET
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
                        await handle_level_up(message.author, message.guild, message.channel, old_level=user_data.get('level', 0), new_level=new_level)

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
                    debug_print(f"Blocked word handling error: {str(e)}")
                return

        # ===== SPAM DETECTION =====
        user_roles = [str(role.id) for role in message.author.roles]
        is_excluded = (
            str(message.channel.id) in spam_config["excluded_channels"] or
            any(role in spam_config["excluded_roles"] for role in user_roles)
        )

        if not is_excluded:
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
                        )
                    )
                    await message.delete()
                    await log_event(
                        message.guild,
                        "message_delete",
                        "Spam Detected",
                        f"**User:** {message.author.mention}\n**Count:** {len(message_timestamps[spam_key])} messages\n**Threshold:** {spam_config['spam_threshold']}/{spam_config['spam_time_window']}s",
                        color=discord.Color.orange()
                    )
                    # Set no-xp state for this user
                    duration = spam_config.get("no_xp_duration", 60)
                    no_xp_until.setdefault(guild_id, {})[user_id] = time.time() + duration
                    # Reset after handling spam
                    message_timestamps[spam_key] = []

                    # Increment spam detection strikes
                    strikes_needed = spam_config.get("spam_strikes_before_warning", 1)
                    spam_detection_strikes[guild_id][user_id] += 1
                    if spam_detection_strikes[guild_id][user_id] >= strikes_needed:
                        # Issue a warning
                        warning_id = add_warning(guild_id, user_id, "Spam detected by automated system.")
                        spam_detection_strikes[guild_id][user_id] = 0  # Reset after warning
                        try:
                            await message.channel.send(
                                embed=discord.Embed(
                                    title="User Warned",
                                    description=f"{message.author.mention} has been warned for repeated spam.",
                                    color=discord.Color.orange()
                                )
                            )
                        except Exception:
                            pass

                        # Check for warning actions and apply them
                        db_warning_actions = db.get_warning_actions(guild_id)
                        user_warnings = db.get_warnings(guild_id, user_id)
                        warning_count = len(user_warnings)
                        action_row = next((a for a in db_warning_actions if int(a['warning_count']) == warning_count), None)
                        if action_row:
                            action_type = action_row['action']
                            duration_seconds = action_row.get('duration_seconds')
                            member = message.guild.get_member(int(user_id))
                            action_text = None
                            if member:
                                if action_type == "timeout":
                                    if hasattr(member, "timeout"):
                                        try:
                                            until = discord.utils.utcnow() + timedelta(seconds=duration_seconds or 3600)
                                            await member.timeout(until, reason=f"Reached {warning_count} warnings (spam)")
                                            action_text = f"User timed out for {duration_seconds//60 if duration_seconds else 60} minutes."
                                        except Exception as e:
                                            debug_print(f"Failed to timeout user: {e}")
                                elif action_type == "kick":
                                    try:
                                        await member.kick(reason=f"Reached {warning_count} warnings (spam)")
                                        action_text = "User kicked."
                                    except Exception as e:
                                        debug_print(f"Failed to kick user: {e}")
                                elif action_type == "ban":
                                    try:
                                        await member.ban(reason=f"Reached {warning_count} warnings (spam)")
                                        action_text = "User banned."
                                    except Exception as e:
                                        debug_print(f"Failed to ban user: {e}")

                            # Notify the channel about the action
                            if action_text:
                                try:
                                    await message.channel.send(
                                        embed=discord.Embed(
                                            title="Moderation Action",
                                            description=f"{message.author.mention} has also been {action_text.lower()}",
                                            color=discord.Color.red()
                                        )
                                    )
                                except Exception:
                                    pass
                except Exception as e:
                    debug_print(f"Spam handling error in guild {message.guild.id} ({message.guild.name}): {str(e)}")

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
            try:
                await message.channel.send(
                    embed=discord.Embed(
                        title="Mention Flood Detected",
                        description=f"{message.author.mention} Please stop mass mentioning!",
                        color=discord.Color.red()
                    )
                )
                await message.delete()
                await log_event(
                    message.guild,
                    "message_delete",
                    "Mention Flood Detected",
                    f"**User:** {message.author.mention}\n**Count:** {len(user_mentions[mention_key])} mentions\n**Threshold:** {spam_config['mention_threshold']}/{spam_config['mention_time_window']}s",
                    color=discord.Color.orange()
                )
                user_mentions[mention_key] = []
            except Exception as e:
                debug_print(f"Mention flood handling error in guild {message.guild.id} ({message.guild.name}): {str(e)}")
    except Exception as e:
        debug_print(f"Error: {str(e)}")

    # Track processed messages
    processed_messages[message.id] = True
    if len(processed_messages) > 1000:
        processed_messages.clear()

    await bot_instance.process_commands(message)

# -------------------- Logging Event Handlers --------------------

@bot_instance.event
async def on_message_delete(message):
    debug_print(f"Entering on_message_delete with message: {message}", level="all")
    if message.guild is None:
        return
    config = load_log_config(message.guild.id)
    log_bots_enabled = config.get("log_bots", False)
    log_self_enabled = config.get("log_self", False)
    is_self = message.author.id == bot_instance.user.id
    is_bot = getattr(message.author, "bot", False)
    # Skip if message is from self and log_self is False
    if is_self and not log_self_enabled:
        return
    # Skip if message is from another bot and log_bots is False
    if is_bot and not is_self and not log_bots_enabled:
        return
    if config.get("message_delete", True):
        description = (
            f"**Author:** {message.author.mention}\n"
            f"**Channel:** {message.channel.mention}\n"
            f"**Content:** {message.content if message.content else 'No text content.'}"
        )
        await log_event(
            message.guild, "message_delete", "Message Deleted", description, color=discord.Color.red(),
            extra_fields={
                "user_id": str(message.author.id),
                "role_ids": [str(r.id) for r in getattr(message.author, "roles", [])],
                "channel_id": str(message.channel.id),
                "log_bot": is_bot,
                "log_self": is_self
            }
        )
        if message.attachments:
            for attachment in message.attachments:
                if attachment.content_type and attachment.content_type.startswith("image"):
                    img_description = (
                        f"**Author:** {message.author.mention}\n"
                        f"**Channel:** {message.channel.mention}\n"
                        f"**Image URL:** {attachment.url}"
                    )
                    await log_event(
                        message.guild, "message_delete", "Image Deleted", img_description, color=discord.Color.dark_red(),
                        extra_fields={
                            "user_id": str(message.author.id),
                            "role_ids": [str(r.id) for r in getattr(message.author, "roles", [])],
                            "channel_id": str(message.channel.id),
                            "log_bot": is_bot,
                            "log_self": is_self
                        }
                    )
                    
#--------------------- Events ------------------------
@bot_instance.event
async def on_member_join(member):
    debug_print(f"Entering on_member_join with member: {member}", level="all")
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
        debug_print(f"Welcome message error: {str(e)}")

def replace_placeholders(text, replacements):
    debug_print(f"Entering replace_placeholders with text: {text}, replacements: {replacements}", level="all")
    for placeholder, value in replacements.items():
        text = text.replace(placeholder, value)
    return text

async def send_custom_form_dm(user, guild, event_type):
    # Find a form for this guild with dm_on[event_type] enabled
    debug_print(f"Entering send_custom_form_dm with user: {user}, guild: {guild}, event_type: {event_type}", level="all")
    forms = db.execute_query(
        'SELECT * FROM custom_forms WHERE guild_id = ?', (str(guild.id),), fetch='all'
    )
    for form in forms:
        config = json.loads(form['config'])
        dm_on = config.get('dm_on', {})
        if dm_on.get(event_type):
            # Build DM message
            msg = dm_on.get('message') or "Please fill out this form:"
            form_url = f"{FRONTEND_URL}/forms/{form['id']}/fill"
            try:
                await user.send(f"{msg}\n{form_url}")
            except Exception as e:
                debug_print(f"Failed to DM user {user}: {e}")
            break  # Only send one form per event

@bot_instance.event
async def on_member_remove(member):
    debug_print(f"Entering on_member_remove with member: {member}", level="all")
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
        debug_print(f"Goodbye message error: {str(e)}")

    try:
        audit_logs = await member.guild.audit_logs(limit=1, action=discord.AuditLogAction.kick).flatten()
        if audit_logs:
            entry = audit_logs[0]
            if entry.target.id == member.id and (datetime.utcnow() - entry.created_at).total_seconds() < 10:
                await send_custom_form_dm(member, member.guild, "kick")
    except Exception as e:
        debug_print(f"Error checking for kick: {e}")

@bot_instance.event
async def on_member_update(before, after):
    debug_print(f"Entering on_member_update with before: {before}, after: {after}", level="all")
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
    debug_print(f"Entering on_guild_available with guild: {guild}", level="all")
    if not db.get_guild(str(guild.id)):
        debug_print(f"⚠️ Guild {guild.name} not in database, attempting recovery...")
        await on_guild_join(guild)  # Re-trigger join logic

@bot_instance.event
async def on_guild_join(guild):
    """Handle when the bot joins a new guild"""
    debug_print(f"Entering on_guild_join with guild: {guild}", level="all")
    try:
        debug_print(f"🤖 Joined new guild: {guild.name} ({guild.id})")
        
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
        
        debug_print(f"💾 Saved guild {guild.id} to database")
        
    except Exception as e:
        debug_print(f"❌ Error handling guild join: {str(e)}")
        traceback.print_exc()
        
@bot_instance.event
async def on_guild_remove(guild):
    """Handle when the bot is removed from a guild"""
    debug_print(f"Entering on_guild_remove with guild: {guild}", level="all")
    try:
        debug_print(f"🚪 Left guild: {guild.name} ({guild.id})")
        guild_id = str(guild.id)

        # List of all tables with guild_id
        tables = [
            'guilds',
            'log_config',
            'blocked_words',
            'blocked_word_embeds',
            'commands',
            'level_config',
            'level_rewards',
            'user_levels',
            'warnings',
            'warning_actions',
            'welcome_config',
            'goodbye_config',
            'spam_detection_config',
            'autoroles',
            'game_roles',
            'user_game_time',
            'twitch_announcements',
            'youtube_announcements',
            'role_menus',
            'pending_role_changes'
        ]

        # Delete from all tables
        for table in tables:
            db.conn.execute(f'DELETE FROM {table} WHERE guild_id = ?', (guild_id,))
        db.conn.commit()

        debug_print(f"🧹 Cleaned up all data for guild {guild_id}")

    except Exception as e:
        debug_print(f"❌ Error handling guild removal: {str(e)}")
        traceback.print_exc()

@bot_instance.event
async def on_bulk_message_delete(messages):
    debug_print(f"Entering on_bulk_message_delete with messages: {messages}", level="all")
    if not messages:
        return
    guild = messages[0].guild
    if guild is None:
        return
    config = load_log_config(guild.id)
    if config.get("bulk_message_delete", True):
        for message in messages:
            description = (
                f"**Author:** {message.author.mention}\n"
                f"**Channel:** {message.channel.mention}\n"
                f"**Content:** {message.content if message.content else 'No text content.'}"
            )
            await log_event(
                guild, "bulk_message_delete", "Bulk Message Deleted", description, color=discord.Color.dark_red(),
                extra_fields={
                    "user_id": str(message.author.id),
                    "role_ids": [str(r.id) for r in getattr(message.author, "roles", [])],
                    "channel_id": str(message.channel.id),
                    "log_bot": getattr(message.author, "bot", False),
                    "log_self": message.author.id == bot_instance.user.id
                }
            )

@bot_instance.event
async def on_message_edit(before, after):
    debug_print(f"Entering on_message_edit with before: {before}, after: {after}", level="all")
    if before.guild is None:
        return
    config = load_log_config(before.guild.id)
    log_bots_enabled = config.get("log_bots", False)
    log_self_enabled = config.get("log_self", False)
    is_self = before.author.id == bot_instance.user.id
    is_bot = getattr(before.author, "bot", False)
    # Skip if message is from self and log_self is False
    if is_self and not log_self_enabled:
        return
    # Skip if message is from another bot and log_bots is False
    if is_bot and not is_self and not log_bots_enabled:
        return
    if before.content == after.content:
        return
    if config.get("message_edit", True):
        description = (
            f"**Author:** {before.author.mention}\n"
            f"**Channel:** {before.channel.mention}\n"
            f"**Before:** {before.content}\n"
            f"**After:** {after.content}"
        )
        await log_event(
            before.guild, "message_edit", "Message Edited", description, color=discord.Color.orange(),
            extra_fields={
                "user_id": str(before.author.id),
                "role_ids": [str(r.id) for r in getattr(before.author, "roles", [])],
                "channel_id": str(before.channel.id),
                "log_bot": is_bot,
                "log_self": is_self
            }
        )

@bot_instance.event
async def on_invite_create(invite):
    debug_print(f"Entering on_invite_create with invite: {invite}", level="all")
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
        await log_event(
            guild, "invite_create", "Invite Created", description, color=discord.Color.green(),
            extra_fields={
                "user_id": str(invite.inviter.id) if invite.inviter else None,
                "role_ids": [str(r.id) for r in getattr(invite.inviter, "roles", [])] if invite.inviter else [],
                "channel_id": str(invite.channel.id),
                "log_bot": getattr(invite.inviter, "bot", False) if invite.inviter else False,
                "log_self": invite.inviter.id == bot_instance.user.id if invite.inviter else False
            }
        )

@bot_instance.event
async def on_invite_delete(invite):
    debug_print(f"Entering on_invite_delete with invite: {invite}", level="all")
    guild = invite.guild
    config = load_log_config(guild.id)
    if config.get("invite_delete", True):
        description = (
            f"**Invite Code:** {invite.code}\n"
            f"**Inviter:** {invite.inviter.mention if invite.inviter else 'Unknown'}\n"
            f"**Channel:** {invite.channel.mention}"
        )
        await log_event(
            guild, "invite_delete", "Invite Deleted", description, color=discord.Color.red(),
            extra_fields={
                "channel_id": str(invite.channel.id)
            }
        )
        
@bot_instance.event
async def on_member_ban(guild, user):
    debug_print(f"Entering on_member_ban with guild: {guild}, user: {user}", level="all")
    config = load_log_config(guild.id)
    if config.get("member_ban", True):
        description = f"**Member:** {user.mention} has been banned."
        await log_event(
            guild, "member_ban", "Member Banned", description, color=discord.Color.dark_red(),
            extra_fields={
                "user_id": str(user.id),
                "log_bot": getattr(user, "bot", False),
                "log_self": user.id == bot_instance.user.id
            }
        )
    await send_custom_form_dm(user, guild, "ban")

@bot_instance.event
async def on_guild_role_create(role):
    debug_print(f"Entering on_guild_role_create with role: {role}", level="all")
    guild = role.guild
    config = load_log_config(guild.id)
    if config.get("role_create", True):
        description = f"**Role Created:** {role.name}\n**ID:** {role.id}"
        await log_event(
            guild, "role_create", "Role Created", description, color=discord.Color.green(),
            extra_fields={
                "role_ids": [str(role.id)]
            }
        )

@bot_instance.event
async def on_guild_role_delete(role):
    debug_print(f"Entering on_guild_role_delete with role: {role}", level="all")
    guild = role.guild
    config = load_log_config(guild.id)
    if config.get("role_delete", True):
        description = f"**Role Deleted:** {role.name}\n**ID:** {role.id}"
        await log_event(
            guild, "role_delete", "Role Deleted", description, color=discord.Color.red(),
            extra_fields={
                "role_ids": [str(role.id)]
            }
        )

@bot_instance.event
async def on_guild_role_update(before, after):
    debug_print(f"Entering on_guild_role_update with before: {before}, after: {after}", level="all")
    guild = before.guild
    config = load_log_config(guild.id)
    if config.get("role_update", True):
        changes = []
        if before.name != after.name:
            changes.append(f"**Name:** {before.name} -> {after.name}")
        if changes:
            description = f"**Role Updated:** {after.name}\n" + "\n".join(changes)
            await log_event(
                guild, "role_update", "Role Updated", description, color=discord.Color.orange(),
                extra_fields={
                    "role_ids": [str(before.id)]
                }
            )

@bot_instance.event
async def on_guild_channel_create(channel):
    debug_print(f"Entering on_guild_channel_create with channel: {channel}", level="all")
    guild = channel.guild
    config = load_log_config(guild.id)
    if config.get("channel_create", True):
        description = f"**Channel Created:** {channel.mention}\n**Type:** {channel.type}"
        await log_event(
            guild, "channel_create", "Channel Created", description, color=discord.Color.green(),
            extra_fields={
                "channel_id": str(channel.id)
            }
        )

@bot_instance.event
async def on_guild_channel_delete(channel):
    debug_print(f"Entering on_guild_channel_delete with channel: {channel}", level="all")
    guild = channel.guild
    config = load_log_config(guild.id)
    if config.get("channel_delete", True):
        description = f"**Channel Deleted:** {channel.name}\n**Type:** {channel.type}"
        await log_event(
            guild, "channel_delete", "Channel Deleted", description, color=discord.Color.red(),
            extra_fields={
                "channel_id": str(channel.id)
            }
        )

@bot_instance.event
async def on_guild_channel_update(before, after):
    debug_print(f"Entering on_guild_channel_update with before: {before}, after: {after}", level="all")
    guild = before.guild
    config = load_log_config(guild.id)
    if config.get("channel_update", True):
        changes = []
        if before.name != after.name:
            changes.append(f"**Name:** {before.name} -> {after.name}")
        if changes:
            description = f"**Channel Updated:** {after.mention if hasattr(after, 'mention') else after.name}\n" + "\n".join(changes)
            await log_event(
                guild, "channel_update", "Channel Updated", description, color=discord.Color.orange(),
                extra_fields={
                    "channel_id": str(before.id)
                }
            )

@bot_instance.event
async def on_guild_emojis_update(guild, before, after):
    debug_print(f"Entering on_guild_emojis_update with guild: {guild}, before: {before}, after: {after}", level="all")
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
    debug_print(f"Entering on_presence_update", level="all")
    try:
        if not after.guild:
            return
        config = load_log_config(after.guild.id)
        log_bots_enabled = config.get("log_bots", False)
        log_self_enabled = config.get("log_self", False)
        is_self = after.id == bot_instance.user.id
        is_bot = getattr(after, "bot", False)
        # Skip if member is self and log_self is False
        if is_self and not log_self_enabled:
            return
        # Skip if member is another bot and log_bots is False
        if is_bot and not is_self and not log_bots_enabled:
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
        debug_print(f"Presence update error: {str(e)}")

# Error handlers
@bot_instance.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: discord.app_commands.AppCommandError):
    """Global error handler for app commands"""
    debug_print(f"Entering on_app_command_error with interaction: {interaction}, error: {error}", level="all")
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
        debug_print(f"Unhandled command error: {error}")
        raise error

if __name__ == "__main__":
    bot_instance.run(BOT_TOKEN)