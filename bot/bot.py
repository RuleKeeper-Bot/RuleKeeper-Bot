import uuid
import discord
from discord.ext import commands, tasks
from discord import app_commands
from discord.errors import Forbidden, HTTPException
from collections import defaultdict
import json
from datetime import datetime, timedelta
import time
import sys
import os
import threading
import random
import math
from aiohttp import web, hdrs
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config
from shared_config import Config
from discord.utils import sleep_until
from dotenv import load_dotenv
load_dotenv()
from database import db
from expiringdict import ExpiringDict
import asyncio
import sqlite3
from functools import partial
import traceback


# -------------------- API and Frontend URLs -----------------
API_URL = os.getenv('API_URL', 'http://localhost:5003')  # Default for local dev
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')  # Default for local dev

# -------------------- Load Secrets --------------------
BOT_TOKEN = os.getenv('BOT_TOKEN')

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
message_count = defaultdict(int)
user_mentions = defaultdict(list)
last_message_time = defaultdict(float)

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

SPAM_THRESHOLD = 5
SPAM_TIME_WINDOW = 10
MENTION_THRESHOLD = 3
MENTION_TIME_WINDOW = 30
WARNING_ACTIONS = {
    2: "timeout",
    3: "ban"
}


# -------------------- Bot Setup --------------------
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True
intents.moderation = True

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
        
        if self._command_initialized:
            return
            
        print("🔄 Starting command initialization...")
        
        try:
            # Clear existing guild commands
            print("🧹 Clearing guild-specific commands...")
            for guild in self.guilds:
                self.tree.clear_commands(guild=guild)
                print(f"  ✅ Cleared commands for {guild.name}")

            # Load and process custom commands
            print("📦 Loading commands from database...")
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

            print(f"🔍 Found {len(valid_commands)} valid command entries")

            # Group commands by guild
            guild_groups = defaultdict(list)
            for cmd in valid_commands:
                guild_id = str(cmd['guild_id']).strip()
                guild_groups[guild_id].append(cmd)

            print("\n📊 Command Distribution:")
            for guild_id, cmds in guild_groups.items():
                print(f" - Guild {guild_id}: {len(cmds)} commands")

            # Process global commands
            global_commands = guild_groups.get('0', [])
            print(f"\n🌍 Registering {len(global_commands)} global commands")
            for cmd_data in global_commands:
                try:
                    callback = self._create_command_callback(cmd_data)
                    cmd = app_commands.Command(
                        name=cmd_data['command_name'],
                        description=cmd_data.get('description', 'Custom command'),
                        callback=callback
                    )
                    self.tree.add_command(cmd)
                    print(f"  ➕ Global: /{cmd_data['command_name']}")
                except Exception as e:
                    print(f"  🚨 Global command error: {str(e)}")

            # Process guild-specific commands
            print("\n🔨 Processing guild-specific commands:")
            for guild_id_str, cmds in guild_groups.items():
                if guild_id_str == '0':
                    continue

                try:
                    guild = await self.fetch_guild(int(guild_id_str))
                except (discord.NotFound, discord.Forbidden):
                    print(f"  🚫 Guild {guild_id_str} not accessible")
                    continue

                print(f"\n🔄 Processing {guild.name} ({guild.id})")
                print("  🧹 Clearing existing commands...")
                self.tree.clear_commands(guild=guild)

                print(f"  ➕ Adding {len(cmds)} commands")
                for cmd_data in cmds:
                    try:
                        callback = self._create_command_callback(cmd_data)
                        cmd = app_commands.Command(
                            name=cmd_data['command_name'],
                            description=cmd_data.get('description', 'Custom command'),
                            callback=callback
                        )
                        self.tree.add_command(cmd, guild=guild)
                        # print(f"    - /{cmd_data['command_name']}")
                    except Exception as e:
                        print(f"    🚨 Command error: {str(e)}")

                # Sync guild commands with retry
                await self.safe_sync(guild=guild)

            # Final global sync
            print("\n🌐 Performing final global sync")
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
        print(f"  🔄 Syncing {target} commands...")
        
        for attempt in range(3):
            try:
                synced = await self.tree.sync(guild=guild)
                count = len(synced)
                print(f"  ✅ Synced {count} commands (attempt {attempt+1})")
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
async def log_event(guild, event_key, title, description, color=discord.Color.blue(), extra_fields=None):
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

    # Create embed
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
    
    # Add your routes (remove any explicit OPTIONS handlers)
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
    print("Sync endpoint running on port 5003")

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

        channel = bot.get_channel(int(channel_id))
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

def migrate_appeals():
    try:
        with open('appeals.json', 'r') as f:
            old_appeals = json.load(f)
            
        for appeal in old_appeals:
            # Let database.py handle UUID generation
            guild_id = str(appeal.get('guild_id', 'legacy'))
            db.create_appeal(
                guild_id=guild_id,
                appeal_data={
                    'user_id': appeal['user_id'],
                    'type': appeal['type'],
                    'data': appeal['data'],
                    'status': appeal.get('status', 'pending'),
                    'channel_id': appeal['channel_id']
                }
            )
            
        print(f"Migrated {len(old_appeals)} appeals successfully")
    except FileNotFoundError:
        print("No legacy appeals found")

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
        channel = bot.get_channel(int(channel_id))
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

        user = await bot.fetch_user(int(user_id))
        
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
    print(f'Logged in as {bot_instance.user}')
    if not bot_instance.guilds:
        print("⚠️ Bot not in any guilds, skipping command sync")
        return  
    
    # Temporary guild verification
    for guild in bot_instance.guilds:
        print(f"🔍 Checking guild {guild.name} ({guild.id})")
        cmds = bot_instance.db.conn.execute(
            'SELECT command_name FROM commands WHERE guild_id = ?',
            (str(guild.id),)
        ).fetchall()
        print(f"   📝 Found {len(cmds)} commands in database")
        print(f"   🤖 Guild in cache: {guild in bot_instance.guilds}")
        
    cleanup.start()
    # Get current guild IDs as strings
    current_guild_ids = {str(g.id) for g in bot_instance.guilds}
    print(f"🤖 Bot's actual guild count: {len(current_guild_ids)}")
    
    # Get database guild IDs
    db_guilds = db.get_all_guilds()
    db_guild_ids = {g['id'] for g in db_guilds}
    print(f"🗃️ Database guild count before sync: {len(db_guilds)}")
    
    # Add missing guilds
    added = 0
    for guild in bot_instance.guilds:
        if str(guild.id) not in db_guild_ids:
            db.add_guild(str(guild.id), guild.name, str(guild.owner_id))
            added += 1
    print(f"➕ Added {added} missing guilds to DB")
    
    # Remove orphaned guilds
    removed = 0
    for db_guild_id in db_guild_ids - current_guild_ids:
        db.remove_guild(db_guild_id)
        removed += 1
    print(f"➖ Removed {removed} orphaned guilds from DB")
    
    # Final verification
    new_count = len(db.get_all_guilds())
    print(f"🔄 Sync complete. New DB guild count: {new_count}")
    
    try:
        test_uuid = uuid.uuid4()
        print(f"🔑 Runtime UUID verification: {test_uuid}")
    except NameError:
        print("❌ UUID MODULE NOT LOADED - CHECK IMPORTS")
        raise
    bot_instance.loop.create_task(webserver())
    migrate_appeals()
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
async def send_appeal_to_discord(channel_id, appeal_data):
    channel = bot.get_channel(int(channel_id))
    if not channel:
        return

    embed = discord.Embed(
        title=f"🚨 New {appeal_data['type'].title()} Appeal",
        color=discord.Color.orange(),
        description=f"**Appeal ID:** `{appeal_data['appeal_id']}`\n"
                    f"**Submitted:** <t:{int(datetime.now().timestamp())}:R>"
    )
    
    # Add fields with emoji icons
    for field in json.loads(appeal_data['data']):
        embed.add_field(
            name=f"📌 {field.get('question', 'Question')}",
            value=field.get('answer', '*Not provided*'),
            inline=False
        )
    
    embed.set_footer(text="Use the buttons below to manage this appeal")

    view = discord.ui.View()
    view.add_item(discord.ui.Button(
        style=discord.ButtonStyle.success,
        label="Approve",
        custom_id=f"approve_{appeal_data['appeal_id']}",
        emoji="✅"
    ))
    view.add_item(discord.ui.Button(
        style=discord.ButtonStyle.danger,
        label="Reject",
        custom_id=f"reject_{appeal_data['appeal_id']}",
        emoji="❌"
    ))
    view.add_item(discord.ui.Button(
        style=discord.ButtonStyle.link,
        label="View Online",
        url=f"{FRONTEND_URL}/appeals/{appeal_data['appeal_id']}",
        emoji="🌐"
    ))

    await channel.send(embed=embed, view=view)

@bot_instance.event
async def on_interaction(interaction):
    if interaction.type == discord.InteractionType.component:
        custom_id = interaction.data.get('custom_id', '')
        
        # Handle approve/reject actions
        if custom_id.startswith('approve_') or custom_id.startswith('reject_'):
            parts = custom_id.split('_')
            if len(parts) != 2:
                await interaction.response.send_message("Invalid custom ID format.", ephemeral=True)
                return

            action = parts[0]  # 'approve' or 'reject'
            appeal_id = parts[1]  # The unique appeal ID
            guild_id = str(interaction.guild.id)

            try:
                # Load appeal data from database
                appeal = db.get_appeal(guild_id, appeal_id)
                if not appeal:
                    await interaction.response.send_message("Appeal not found.", ephemeral=True)
                    return

                # Update appeal status in database
                db.update_appeal_status(guild_id, appeal_id, action)
                
                # Fetch the user
                user_id = appeal['user_id']
                user = await bot.fetch_user(int(user_id))
                guild = interaction.guild

                # Perform the action based on appeal type
                try:
                    if action == 'approve':
                        if appeal['type'] == 'ban':
                            await guild.unban(user, reason="Appeal approved")
                            await interaction.response.send_message(
                                f"{user.mention} has been unbanned.", 
                                ephemeral=True
                            )
                        elif appeal['type'] == 'timeout':
                            member = await guild.fetch_member(user.id)
                            await member.timeout(None, reason="Appeal approved")
                            await interaction.response.send_message(
                                f"Timeout removed for {member.mention}.", 
                                ephemeral=True
                            )
                        elif appeal['type'] == 'kick':
                            invite = await interaction.channel.create_invite(
                                max_uses=1, 
                                reason="Appeal approved"
                            )
                            await user.send(f"Your kick appeal was approved. You may rejoin here: {invite.url}")
                            await interaction.response.send_message("Invite sent to user.", ephemeral=True)
                            
                    elif action == 'reject':
                        await interaction.response.send_message("Appeal rejected.", ephemeral=True)

                    # Disable buttons and update embed
                    view = discord.ui.View()
                    for component in interaction.message.components:
                        if component.type == discord.ComponentType.button:
                            btn = discord.ui.Button.from_component(component)
                            btn.disabled = True
                            view.add_item(btn)

                    embed = interaction.message.embeds[0]
                    embed.color = discord.Color.green() if action == 'approve' else discord.Color.red()
                    
                    # Find and update the status field
                    for index, field in enumerate(embed.fields):
                        if field.name == "Status":
                            embed.set_field_at(
                                index,
                                name="Status",
                                value="✅ Approved" if action == 'approve' else "❌ Rejected",
                                inline=False
                            )
                            break

                    await interaction.message.edit(embed=embed, view=view)

                except discord.Forbidden:
                    await interaction.response.send_message(
                        "I don't have permission to perform this action.", 
                        ephemeral=True
                    )
                except discord.NotFound:
                    await interaction.response.send_message(
                        "User not found in this server.", 
                        ephemeral=True
                    )
                except Exception as e:
                    await interaction.response.send_message(
                        f"Error processing appeal: {str(e)}", 
                        ephemeral=True
                    )

            except Exception as e:
                await interaction.response.send_message(
                    f"Error loading appeal data: {str(e)}", 
                    ephemeral=True
                )

        # Handle other component interactions
        else:
            await bot.process_commands(interaction)

# -------------------- Level System --------------------
def get_level_data(guild_id, user_id):
    data = db.get_user_level(str(guild_id), str(user_id))
    if not data:
        # Initialize new user
        data = {
            "xp": 0,
            "level": 0,
            "username": "",
            "last_message": 0
        }
        db.update_user_level(str(guild_id), str(user_id), **data)
    return data

def save_level_data(guild_id, user_id, data):
    db.update_user_level(str(guild_id), str(user_id), **data)

def get_level_config(guild_id):
    config = db.get_level_config(str(guild_id))
    if not config:
        # Create default config
        default_config = {
            "cooldown": 60,
            "xp_min": 15,
            "xp_max": 25,
            "level_channel": None,
            "announce_level_up": True,
            "excluded_channels": "[]",
            "xp_boost_roles": "{}",
            "embed_title": "🎉 Level Up!",
            "embed_description": "{user} has reached level **{level}**!",
            "embed_color": 0xffd700
        }
        db.update_level_config(str(guild_id), **default_config)
        config = default_config
    return config

user_cooldowns = defaultdict(dict)

def calculate_xp_for_level(level: int) -> int:
    """Calculate total XP required to reach a specific level"""
    return int(100 * (level ** 1.7))  # Exponential scaling

def calculate_level(xp: float) -> int:
    """Calculate level based on total XP using inverse function"""
    if xp <= 0:
        return 0
    return int((xp / 100) ** (1/1.7))

def calculate_progress(xp: float) -> tuple:
    """Calculate progress to next level"""
    current_level = calculate_level(xp)
    current_level_xp = current_level * 100
    next_level_xp = (current_level + 1) * 100
    progress = xp - current_level_xp
    return progress, next_level_xp

def calculate_xp_with_boost(base_xp, user_roles, xp_boost_roles):
    boost = 0
    for role in user_roles:
        # Use role ID as integer key
        role_id = str(role.id)
        if role_id in xp_boost_roles:
            boost += xp_boost_roles[role_id]
    return base_xp * (1 + boost / 100)

async def handle_level_up(user, guild, channel):
    guild_id = guild.id
    user_id = user.id
    
    # Get user data from database
    user_data = get_level_data(guild_id, user_id)
    total_xp = user_data['xp']
    
    # Calculate current and new level based on total XP
    current_level = calculate_level(total_xp - 1)  # Previous level
    new_level = calculate_level(total_xp)          # Current level
    
    if new_level > current_level:
        # Update level in database
        save_level_data(guild_id, user_id, {'level': new_level})
    
    # Load rewards from database
    rewards = db.get_level_rewards(str(guild_id))
    
    # Check for rewards
    roles_to_add = []
    for level, role_id in rewards.items():
        if new_level >= int(level):
            role = guild.get_role(int(role_id))
            if role:
                roles_to_add.append(role)
    
    # Assign roles
    if roles_to_add:
        try:
            await user.add_roles(*roles_to_add, reason=f"Level {new_level} rewards")
        except Forbidden:
            print(f"Missing permissions to assign roles in {guild.name}")
        except Exception as e:
            print(f"Error assigning roles: {str(e)}")
    
    # Get level config
    config = get_level_config(guild_id)
    
    # Create embed
    embed = discord.Embed(
        title=config['embed_title'],
        description=config['embed_description'].format(user=user.mention, level=new_level),
        color=config['embed_color']
    )
    embed.set_thumbnail(url=user.display_avatar.url)
    
    # Get announcement channel
    target_channel = guild.get_channel(int(config['level_channel'])) if config['level_channel'] else channel
    
    # Send announcement if enabled
    if config['announce_level_up'] and target_channel:
        try:
            await target_channel.send(embed=embed)
        except Exception as e:
            print(f"Error sending level up message: {str(e)}")
            
# -------------------- Message Processing --------------------
@bot_instance.event
async def on_message(message):
    if message.author.bot or not message.guild:
        return

    guild_id = str(message.guild.id)
    user_id = str(message.author.id)
    current_time = time.time()

    # Get level config from database
    level_config = db.get_level_config(guild_id) or {
        "cooldown": 60,
        "xp_min": 15,
        "xp_max": 25,
        "excluded_channels": "[]",
        "xp_boost_roles": "{}",
        "announce_level_up": True
    }

    excluded_channels = level_config.get('excluded_channels', []) or []
    if isinstance(excluded_channels, str):
        excluded_channels = json.loads(excluded_channels)

    xp_boost_roles = level_config.get('xp_boost_roles', {}) or {}
    if isinstance(xp_boost_roles, str):
        xp_boost_roles = json.loads(xp_boost_roles)

    # Check if message is in excluded channel
    if str(message.channel.id) in excluded_channels:
        return

    # Check cooldown
    cooldown = level_config.get('cooldown', 60)
    user_data = db.get_user_level(guild_id, user_id) or {'xp': 0, 'level': 0, 'last_message': 0}
    
    if (current_time - user_data['last_message']) < cooldown:
        return

    # Update last message time
    db.conn.execute('''
        UPDATE user_levels 
        SET last_message = ?
        WHERE guild_id = ? AND user_id = ?
    ''', (current_time, guild_id, user_id))
    db.conn.commit()

    # Calculate base XP with randomness
    base_xp = random.randint(
        int(level_config.get('xp_min', 15)),
        int(level_config.get('xp_max', 25))
    )

    # Apply role-based XP boosts
    xp_multiplier = 1.0
    for role in message.author.roles:
        role_id = str(role.id)
        if role_id in xp_boost_roles:
            xp_multiplier += xp_boost_roles[role_id] / 100

    earned_xp = int(base_xp * xp_multiplier)

    # Get current total XP and level
    user_data = db.get_user_level(guild_id, user_id) or {'xp': 0, 'level': 0}
    total_xp = user_data['xp'] + earned_xp
    new_level = 0

    # Calculate new level based on TOTAL XP
    while total_xp >= calculate_xp_for_level(new_level):
        new_level += 1
    new_level -= 1  # Adjust to actual current level

    # Update database with TOTAL XP and new level
    db.conn.execute('''
        INSERT OR REPLACE INTO user_levels 
        (guild_id, user_id, xp, level, username)
        VALUES (?, ?, ?, ?, ?)
    ''', (guild_id, user_id, total_xp, new_level, message.author.name))
    db.conn.commit()

    # Check for level up
    if new_level > user_data['level']:
        await handle_level_up(message.author, message.guild, message.channel)

    # Check blocked words
    blocked_words = db.get_blocked_words(guild_id)
    embed_config = db.get_blocked_embed(guild_id) or {
        "title": "Blocked Word Detected!",
        "description": "You have used a word that is not allowed.",
        "color": 0xff0000
    }

    content_lower = message.content.lower()
    for word in blocked_words:
        if word.lower() in content_lower:
            try:
                await message.delete()
                try:
                    embed = discord.Embed(
                        title=embed_config.get('title'),
                        description=embed_config.get('description'),
                        color=discord.Color(embed_config.get('color', 0xff0000))
                    )
                    await message.author.send(embed=embed)
                except discord.Forbidden:
                    pass
                
                await log_event(message.guild, "message_delete", "Blocked Word Detected",
                              f"**User:** {message.author.mention}\n**Message:** {message.content}",
                              color=discord.Color.red())
                return
            except Exception as e:
                print(f"Error handling blocked word: {str(e)}")
            return

    # Spam detection (now guild-specific)
    spam_key = f"{guild_id}:{user_id}"
    current_time = discord.utils.utcnow().timestamp()
    
    if current_time - last_message_time.get(spam_key, 0) < SPAM_TIME_WINDOW:
        message_count[spam_key] = message_count.get(spam_key, 0) + 1
    else:
        message_count[spam_key] = 1
    last_message_time[spam_key] = current_time

    if message_count[spam_key] > SPAM_THRESHOLD:
        await message.channel.send(embed=discord.Embed(
            title="Spam Detected",
            description="Please stop spamming or you will get a warning.",
            color=discord.Color.red()
        ))
        message_count[spam_key] = 0

    # Mention detection
    mention_count_current = len(message.mentions)
    if mention_count_current > 0:
        mention_key = f"{guild_id}:{user_id}"
        current_time = discord.utils.utcnow().timestamp()
        
        user_mentions[mention_key] = user_mentions.get(mention_key, []) + [current_time] * mention_count_current
        
        # Filter mentions within time window
        window_start = current_time - MENTION_TIME_WINDOW
        user_mentions[mention_key] = [t for t in user_mentions[mention_key] if t >= window_start]
        
        if len(user_mentions[mention_key]) > MENTION_THRESHOLD:
            await message.channel.send(embed=discord.Embed(
                title="Too Many Mentions",
                description="Please do not mention too many users at once or you will get a warning.",
                color=discord.Color.red()
            ))
            user_mentions[mention_key] = []
    
    await bot_instance.process_commands(message)
    
    # Track processed messages
    processed_messages[message.id] = True
    if len(processed_messages) > 1000:
        processed_messages.clear()

# -------------------- Logging Event Handlers --------------------

# Add this helper function at the top with other config functions
def get_log_config(guild_id):
    config = db.get_log_config(str(guild_id))
    if not config:
        # Create default config if not found
        db.conn.execute('INSERT INTO log_config (guild_id) VALUES (?)', (str(guild_id),))
        db.conn.commit()
        config = db.get_log_config(str(guild_id))
    return dict(config)

@bot_instance.event
async def on_message_delete(message):
    if message.guild is None or message.author.bot:
        return
    config = get_log_config(message.guild.id)
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
    config = get_log_config(guild.id)
    if config.get("bulk_message_delete", True):
        description = f"Bulk deleted {len(messages)} messages in {messages[0].channel.mention}"
        await log_event(guild, "bulk_message_delete", "Bulk Message Delete", description, color=discord.Color.dark_red())

@bot_instance.event
async def on_message_edit(before, after):
    if before.guild is None:
        return
    if before.content == after.content:
        return
    config = get_log_config(before.guild.id)
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
    config = get_log_config(guild.id)
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
    config = get_log_config(guild.id)
    if config.get("invite_delete", True):
        description = (
            f"**Invite Code:** {invite.code}\n"
            f"**Inviter:** {invite.inviter.mention if invite.inviter else 'Unknown'}\n"
            f"**Channel:** {invite.channel.mention}"
        )
        await log_event(guild, "invite_delete", "Invite Deleted", description, color=discord.Color.dark_green())
        
@bot_instance.event
async def on_member_ban(guild, user):
    config = get_log_config(guild.id)
    if config.get("member_ban", True):
        description = f"**Member:** {user.mention} has been banned."
        await log_event(guild, "member_ban", "Member Banned", description, color=discord.Color.dark_red())

@bot_instance.event
async def on_member_unban(guild, user):
    config = get_log_config(guild.id)
    if config.get("member_unban", True):
        description = f"**Member:** {user.mention} has been unbanned."
        await log_event(guild, "member_unban", "Member Unbanned", description, color=discord.Color.green())

@bot_instance.event
async def on_guild_role_create(role):
    guild = role.guild
    config = get_log_config(guild.id)
    if config.get("role_create", True):
        description = f"**Role Created:** {role.name}\n**ID:** {role.id}"
        await log_event(guild, "role_create", "Role Created", description, color=discord.Color.green())

@bot_instance.event
async def on_guild_role_delete(role):
    guild = role.guild
    config = get_log_config(guild.id)
    if config.get("role_delete", True):
        description = f"**Role Deleted:** {role.name}\n**ID:** {role.id}"
        await log_event(guild, "role_delete", "Role Deleted", description, color=discord.Color.red())

@bot_instance.event
async def on_guild_role_update(before, after):
    guild = before.guild
    config = get_log_config(guild.id)
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
    config = get_log_config(guild.id)
    if config.get("channel_create", True):
        description = f"**Channel Created:** {channel.mention}\n**Type:** {channel.type}"
        await log_event(guild, "channel_create", "Channel Created", description, color=discord.Color.green())

@bot_instance.event
async def on_guild_channel_delete(channel):
    guild = channel.guild
    config = get_log_config(guild.id)
    if config.get("channel_delete", True):
        description = f"**Channel Deleted:** {channel.name}\n**Type:** {channel.type}"
        await log_event(guild, "channel_delete", "Channel Deleted", description, color=discord.Color.red())

@bot_instance.event
async def on_guild_channel_update(before, after):
    guild = before.guild
    config = get_log_config(guild.id)
    if config.get("channel_update", True):
        changes = []
        if before.name != after.name:
            changes.append(f"**Name:** {before.name} -> {after.name}")
        if changes:
            description = f"**Channel Updated:** {after.mention if hasattr(after, 'mention') else after.name}\n" + "\n".join(changes)
            await log_event(guild, "channel_update", "Channel Updated", description, color=discord.Color.orange())

@bot_instance.event
async def on_guild_emojis_update(guild, before, after):
    config = get_log_config(guild.id)
    before_dict = {e.id: e for e in before}
    after_dict = {e.id: e for e in after}
    
    new_emojis = [e for e in after if e.id not in before_dict]
    for emoji in new_emojis:
        if config.get("emoji_create", True):
            description = f"**Emoji Created:** {emoji.name} (ID: {emoji.id})"
            await log_event(guild, "emoji_create", "Emoji Created", description, color=discord.Color.green())
    
    deleted_emojis = [e for e in before if e.id not in after_dict]
    for emoji in deleted_emojis:
        if config.get("emoji_delete", True):
            description = f"**Emoji Deleted:** {emoji.name} (ID: {emoji.id})"
            await log_event(guild, "emoji_delete", "Emoji Deleted", description, color=discord.Color.red())
    
    for emoji in after:
        if emoji.id in before_dict:
            old_emoji = before_dict[emoji.id]
            if old_emoji.name != emoji.name and config.get("emoji_name_change", True):
                description = f"**Emoji Name Changed:** {old_emoji.name} -> {emoji.name} (ID: {emoji.id})"
                await log_event(guild, "emoji_name_change", "Emoji Name Change", description, color=discord.Color.orange())

if __name__ == "__main__":
    bot_instance.run(BOT_TOKEN)