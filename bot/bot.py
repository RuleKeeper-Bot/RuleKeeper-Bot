import discord
from discord.ext import commands
from discord import app_commands
from collections import defaultdict
import json
from datetime import datetime, timedelta
import time
import sys
import os
import threading
import random
import math
from aiohttp import web
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config
from discord.errors import Forbidden
from discord.utils import sleep_until

# -------------------- Load Secrets --------------------
with open('secrets.json', 'r') as f:
    secrets = json.load(f)
    BOT_TOKEN = secrets['BOT_TOKEN']

# -------------------- Appeals Config --------------------
APPEALS_PATH = os.path.join('appeals.json')

# -------------------- Log Config --------------------
# Path to your logging configuration file
LOG_CONFIG_PATH = os.path.join('config', 'log_config.json')

def load_log_config():
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
    try:
        with open(LOG_CONFIG_PATH, 'r') as f:
            config = json.load(f)
        # Merge with default to ensure new keys exist
        return {**default_config, **config}
    except FileNotFoundError:
        # Create default config if not found
        with open(LOG_CONFIG_PATH, 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config

def save_log_config(config):
    with open(LOG_CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

# Global log configuration
log_config = load_log_config()

processed_messages = set()

# -------------------- Batch Role Changes --------------------
class RoleChangeBatcher:
    def __init__(self):
        self.pending = {}  # {user_id: {"added": set(), "removed": set(), "guild": None, "timer": None}}
    
    async def log_and_reset(self, user_id):
        entry = self.pending.pop(user_id, None)
        if not entry:
            return

        guild = entry["guild"]
        added = entry["added"]
        removed = entry["removed"]

        if not added and not removed:
            return

        description = f"**Member:** <@{user_id}>\n"
        if added:
            description += f"**Added Roles:** {', '.join([f'<@&{r}>' for r in added])}\n"
        if removed:
            description += f"**Removed Roles:** {', '.join([f'<@&{r}>' for r in removed])}"

        await log_event(
            guild,
            "member_role_change",
            "Role Updates",
            description,
            color=discord.Color.blue()
        )

    async def add_change(self, member, added_roles, removed_roles):
        user_id = str(member.id)
        current_entry = self.pending.get(user_id, {
            "added": set(),
            "removed": set(),
            "guild": member.guild,
            "timer": None
        })

        current_entry["added"].update([str(r.id) for r in added_roles])
        current_entry["removed"].update([str(r.id) for r in removed_roles])
        current_entry["guild"] = member.guild

        if current_entry["timer"]:
            current_entry["timer"].cancel()

        current_entry["timer"] = bot.loop.create_task(self.schedule_log(user_id))
        self.pending[user_id] = current_entry

    async def schedule_log(self, user_id):
        await asyncio.sleep(60)
        await self.log_and_reset(user_id)

role_batcher = RoleChangeBatcher()

# -------------------- Load Blocked Words --------------------
# Load blocked words from the config file
def load_blocked_words():
    try:
        with open('blocked_words.json', 'r') as f:
            data = json.load(f)
            
            # Handle both formats:
            if isinstance(data, dict):
                return data.get("blocked_words", [])
            return data  # Assume it's a list if not a dictionary
            
    except (FileNotFoundError, KeyError, json.JSONDecodeError):
        return []  # Return empty list if any error occurs
        
# Load the embed configuration for the blocked word notification
def load_embed():
    try:
        with open('blocked_word_embed.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "title": "Blocked Word Detected!",
            "description": "You have used a word that is not allowed.",
            "color": 0xff0000
        }  # Default embed if not configured

# -------------------- Bot Setup --------------------

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

processed_messages = set()

class CustomBot(commands.Bot):
    async def process_commands(self, message):
        """Override to completely disable command processing"""
        pass

bot = CustomBot(command_prefix="!", intents=intents, help_command=None)

# -------------------- Logging Helper --------------------
async def log_event(guild, event_key, title, description, color=discord.Color.blue(), extra_fields=None):
    # Check if logging for this event is enabled
    if not log_config.get(event_key, True):
        return
    
    # Get channel ID from config
    channel_id = log_config.get('log_channel_id')
    if not channel_id:
        return  # No log channel configured
    
    channel = guild.get_channel(channel_id)
    if channel is None:
        print(f"Log channel not found in guild: {guild.name}")
        return
    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=discord.utils.utcnow()
    )
    if extra_fields:
        for name, value in extra_fields.items():
            embed.add_field(name=name, value=value, inline=False)
    await channel.send(embed=embed)

# -------------------- Custom Commands Storage --------------------
def load_commands():
    try:
        with open('commands.json', 'r') as f:
            raw_commands = json.load(f)
            converted = {}
            for cmd, data in raw_commands.items():
                if isinstance(data, str):
                    converted[cmd] = {"content": data, "ephemeral": True, "description": "Custom command"}
                else:
                    if "description" not in data:
                        data["description"] = "Custom command"
                    converted[cmd] = data
            return converted
    except FileNotFoundError:
        return {}

def save_commands(commands_dict):
    with open('commands.json', 'w') as f:
        json.dump(commands_dict, f, indent=4)

custom_commands = load_commands()

def watch_commands():
    last_modified = os.path.getmtime('commands.json')
    while True:
        current_modified = os.path.getmtime('commands.json')
        if current_modified > last_modified:
            print("Reloading commands...")
            global custom_commands, processed_messages
            custom_commands = load_commands()
            processed_messages = set()
            last_modified = current_modified
            bot.loop.call_soon_threadsafe(
                lambda: bot.loop.create_task(reload_commands())
            )
        time.sleep(5)

threading.Thread(target=watch_commands, daemon=True).start()

# -------------------- Spam and Warning Tracking --------------------
message_count = defaultdict(int)
user_mentions = defaultdict(list)
last_message_time = defaultdict(float)

def load_warnings():
    try:
        with open('warnings.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_warnings(warnings_data):
    with open('warnings.json', 'w') as f:
        json.dump(warnings_data, f, indent=4)

warnings = load_warnings()

SPAM_THRESHOLD = 5
SPAM_TIME_WINDOW = 10
MENTION_THRESHOLD = 3
MENTION_TIME_WINDOW = 30
WARNING_ACTIONS = {2: "timeout", 3: "ban"}

# -------------------- Web Server for Syncing --------------------
async def webserver():
    app = web.Application()
    app.router.add_post('/sync', handle_sync)
    app.router.add_post('/sync_warnings', handle_sync_warnings)
    app.router.add_post('/appeal', handle_appeal_submission)
    app.router.add_get('/get_bans', handle_get_bans)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 5003)
    await site.start()
    print("Sync endpoint running on port 5003")

async def handle_sync(request):
    await reload_commands()
    return web.Response(text="Commands synced successfully!")
    
async def handle_sync_warnings(request):
    reload_warnings()
    return web.Response(text="Warnings synced successfully!")
    
async def handle_get_bans(request):
    try:
        print("Fetching bans...")
        if not bot.guilds:
            return web.json_response({"error": "Bot is not in any guilds"}, status=404)
            
        guild = bot.guilds[0]  # Use first guild the bot is in
        bans = []
        
        async for entry in guild.bans():
            # Get ban date from audit logs
            async for log in guild.audit_logs(action=discord.AuditLogAction.ban):
                if log.target.id == entry.user.id:
                    ban_date = log.created_at.isoformat()
                    break
            else:
                ban_date = "Unknown"

            bans.append({
                "user_id": str(entry.user.id),
                "username": str(entry.user),
                "reason": entry.reason or "No reason provided",
                "date": ban_date
            })
        
        print(f"Total bans fetched: {len(bans)}")
        return web.json_response(bans)
        
    except Exception as e:
        print(f"Error fetching bans: {str(e)}")
        return web.json_response({"error": str(e)}, status=500)

def save_appeals(appeals):
    with open('appeals.json', 'w') as f:
        json.dump(appeals, f, indent=4)

async def handle_appeal_submission(request):
    try:
        data = await request.json()
        appeal_type = data.get('type')
        user_id = data.get('user_id')
        appeal_id = data.get('id')
        form_data = data.get('data', [])
        channel_id = data.get('channel_id')

        # Create appeal object
        appeal = {
            "id": appeal_id,
            "user_id": user_id,
            "type": appeal_type,
            "data": form_data,
            "status": "pending",
            "timestamp": datetime.now().isoformat(),
            "channel_id": channel_id
        }

        # Load existing appeals and save the new one
        appeals = load_appeals()
        appeals.append(appeal)
        save_appeals(appeals)  # Save to appeals.json

        # Send embed to Discord
        channel = bot.get_channel(int(channel_id))
        if not channel:
            return web.Response(status=404, text=f"Channel {channel_id} not found")

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

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    bot.loop.create_task(webserver())
    await reload_commands()

# -------------------- Reloading and Custom Commands --------------------
async def reload_commands():
    print("Reloading commands...")
    global log_config
    log_config = load_log_config()  # Reload the logging configuration from file
    print("Reloading commands and log configuration...")
    bot.tree.clear_commands(guild=None)
    
    # Register custom commands from the file
    for command_name, data in custom_commands.items():
        def create_handler(cmd_data):
            async def handler(interaction: discord.Interaction):
                if not interaction.response.is_done():
                    await interaction.response.send_message(
                        content=cmd_data["content"],
                        ephemeral=cmd_data["ephemeral"]
                    )
            return handler
        
        handler = create_handler(data.copy())
        handler.__name__ = f"cmd_{command_name}"
        bot.tree.command(name=command_name, description=data["description"])(handler)
    
    @bot.tree.command(name="level", description="Check your current level and XP")
    async def level(interaction: discord.Interaction, user: discord.User = None):
        user = user or interaction.user
        user_id = str(user.id)
        
        if user_id not in level_data:
            await interaction.response.send_message(
                f"{user.mention} hasn't earned any XP yet!",
                ephemeral=True
            )
            return
        
        data = level_data[user_id]
        xp = data['xp']
        level = data['level']
        needed_xp = calculate_xp_for_level(level)
        
        embed = discord.Embed(
            title=f"{user.display_name}'s Level",
            color=discord.Color.blurple()
        )
        embed.add_field(name="Level", value=level, inline=True)
        embed.add_field(name="XP", value=f"{xp}/{needed_xp}", inline=True)
        embed.set_thumbnail(url=user.display_avatar.url)
        
        progress = xp / needed_xp
        progress_bar = "▓" * int(progress * 20) + "░" * (20 - int(progress * 20))
        embed.add_field(name="Progress", value=f"{progress_bar} ({round(progress*100)}%)", inline=False)
        
        await interaction.response.send_message(embed=embed)

    @bot.tree.command(name="leaderboard", description="Show the server level leaderboard")
    async def leaderboard(interaction: discord.Interaction):
        sorted_users = sorted(level_data.items(), 
                             key=lambda x: (x[1]['level'], x[1]['xp']), 
                             reverse=True)[:10]
        
        embed = discord.Embed(
            title="🏆 Server Leaderboard",
            color=discord.Color.gold()
        )
        
        for idx, (user_id, data) in enumerate(sorted_users, 1):
            user = interaction.guild.get_member(int(user_id))
            if user:
                embed.add_field(
                    name=f"{idx}. {user.display_name}",
                    value=f"Level {data['level']} | XP {data['xp']}",
                    inline=False
                )
        
        await interaction.response.send_message(embed=embed)
        
    @bot.tree.command(name="setlevel", description="Set a user's level (Admin only)")
    @app_commands.describe(
        user="User to modify",
        level="New level to set"
    )
    @app_commands.checks.has_permissions(administrator=True)
    async def set_level(interaction: discord.Interaction, user: discord.User, level: int):
        if level < 0:
            await interaction.response.send_message("Level must be a positive number!", ephemeral=True)
            return
            
        user_id = str(user.id)
        
        # Initialize user data if needed
        if user_id not in level_data:
            level_data[user_id] = {
                "xp": 0,
                "level": 0,
                "username": user.name
            }
        
        # Calculate required XP for target level
        required_xp = calculate_xp_for_level(level)
        level_data[user_id]['level'] = level
        level_data[user_id]['xp'] = required_xp
        
        # Handle role rewards
        with open('level_rewards.json', 'r') as f:
            rewards = json.load(f)
        
        roles_to_add = []
        for reward_level, role_id in rewards.items():
            if level >= int(reward_level):
                role = interaction.guild.get_role(int(role_id))
                if role:
                    roles_to_add.append(role)
        
        try:
            if roles_to_add:
                await user.add_roles(*roles_to_add, reason=f"Level set to {level}")
        except Forbidden:
            pass
        
        save_level_data(level_data)
        
        embed = discord.Embed(
            title="Level Updated",
            description=f"{user.mention}'s level has been set to **{level}**",
            color=discord.Color.green()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # Log the action
        await log_event(
            interaction.guild,
            "member_level_change",
            "Level Modified",
            f"**Admin:** {interaction.user.mention}\n"
            f"**User:** {user.mention}\n"
            f"**New Level:** {level}",
            color=discord.Color.blue()
        )
    
    @bot.tree.command(name="setxp", description="Set a user's XP (Admin only)")
    @app_commands.describe(
        user="User to modify",
        xp="New XP value to set"
    )
    @app_commands.checks.has_permissions(administrator=True)
    async def set_xp(interaction: discord.Interaction, user: discord.User, xp: int):
        if xp < 0:
            await interaction.response.send_message("XP must be a positive number!", ephemeral=True)
            return
            
        user_id = str(user.id)
        
        # Initialize user data if needed
        if user_id not in level_data:
            level_data[user_id] = {
                "xp": 0,
                "level": 0,
                "username": user.name
            }
        
        # Set XP and calculate level
        level_data[user_id]['xp'] = xp
        new_level = 0
        while level_data[user_id]['xp'] >= calculate_xp_for_level(new_level):
            new_level += 1
        
        # Update level and handle overflow XP
        level_data[user_id]['level'] = new_level - 1
        required_xp = calculate_xp_for_level(new_level - 1)
        level_data[user_id]['xp'] = min(xp, required_xp)
        
        await handle_level_up(user, interaction.guild, interaction.channel)
        save_level_data(level_data)
        
        embed = discord.Embed(
            title="XP Updated",
            description=f"{user.mention}'s XP has been set to **{xp}**",
            color=discord.Color.green()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # Log the action
        await log_event(
            interaction.guild,
            "member_xp_change",
            "XP Modified",
            f"**Admin:** {interaction.user.mention}\n"
            f"**User:** {user.mention}\n"
            f"**New XP:** {xp}",
            color=discord.Color.blue()
        )

    @bot.tree.command(name="addxp", description="Add XP to a user (Admin only)")
    @app_commands.describe(
        user="User to modify",
        xp="XP to add"
    )
    @app_commands.checks.has_permissions(administrator=True)
    async def add_xp(interaction: discord.Interaction, user: discord.User, xp: int):
        if xp < 0:
            await interaction.response.send_message("XP must be a positive number!", ephemeral=True)
            return
            
        user_id = str(user.id)
        
        # Initialize user data if needed
        if user_id not in level_data:
            level_data[user_id] = {
                "xp": 0,
                "level": 0,
                "username": user.name
            }
        
        # Add XP and calculate level changes
        level_data[user_id]['xp'] += xp
        new_level = level_data[user_id]['level']
        
        # Check for level ups
        while level_data[user_id]['xp'] >= calculate_xp_for_level(new_level):
            level_data[user_id]['xp'] -= calculate_xp_for_level(new_level)
            new_level += 1
        
        # Update level if changed
        if new_level != level_data[user_id]['level']:
            level_data[user_id]['level'] = new_level
            await handle_level_up(user, interaction.guild, interaction.channel)
        
        save_level_data(level_data)
        
        embed = discord.Embed(
            title="XP Added",
            description=f"Added **{xp}** XP to {user.mention}\n"
                        f"New Total: **{level_data[user_id]['xp']}** XP",
            color=discord.Color.green()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        
        # Log the action
        await log_event(
            interaction.guild,
            "member_xp_change",
            "XP Added",
            f"**Admin:** {interaction.user.mention}\n"
            f"**User:** {user.mention}\n"
            f"**XP Added:** {xp}\n"
            f"**New Total:** {level_data[user_id]['xp']}",
            color=discord.Color.blue()
        )

    @set_xp.error
    @add_xp.error
    async def xp_commands_error(interaction: discord.Interaction, error):
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message(
                "❌ You need administrator permissions to use this command!",
                ephemeral=True
            )
    
    @bot.tree.command(name="sync", description="Sync commands manually")
    async def sync_commands(interaction: discord.Interaction):
        # Send initial response to avoid "application did not respond" error
        await interaction.response.send_message("Syncing...", ephemeral=True)
        
        # Perform the sync operations
        await reload_commands()
        
        # Edit the original response to indicate success
        original = await interaction.original_response()
        await original.edit(content="✅ Sync was successful")

    @bot.tree.command(name="custom_command", description="Create a custom command")
    @app_commands.describe(
        command_name="Name of the command",
        content="Response content",
        description="Description of the command",
        ephemeral="Whether the response should be ephemeral (default: True)"
    )
    async def create_custom_command(
        interaction: discord.Interaction,
        command_name: str,
        content: str,
        description: str = "Custom command",
        ephemeral: bool = True
    ):
        custom_commands[command_name] = {
            "content": content,
            "description": description,
            "ephemeral": ephemeral
        }
        save_commands(custom_commands)
        await reload_commands()
        await interaction.response.send_message(
            f"Custom command '/{command_name}' created!",
            ephemeral=True
        )

    @bot.tree.command(name="remove_custom_command", description="Remove a custom command")
    @app_commands.describe(command_name="Name of the command to remove")
    async def remove_custom_command(interaction: discord.Interaction, command_name: str):
        if command_name not in custom_commands:
            await interaction.response.send_message(
                f"Command '/{command_name}' does not exist.",
                ephemeral=True
            )
            return
        
        del custom_commands[command_name]
        save_commands(custom_commands)
        await reload_commands()
        await interaction.response.send_message(
            f"Custom command '/{command_name}' has been removed.",
            ephemeral=True
        )

    @bot.tree.command(name="warn", description="Warn a user")
    @app_commands.describe(member="User to warn", reason="Reason for warning")
    async def warn(interaction: discord.Interaction, member: discord.Member, reason: str):
        # Check bot permissions
        if not interaction.guild.me.guild_permissions.moderate_members:
            await interaction.response.send_message(
                "I don't have permission to timeout or ban users.",
                ephemeral=True
            )
            return
        
        # Check role hierarchy
        if interaction.guild.me.top_role <= member.top_role:
            await interaction.response.send_message(
                "I cannot moderate this user because their role is equal to or higher than mine.",
                ephemeral=True
            )
            return
        
        # Check if the user is in the server
        if member not in interaction.guild.members:
            await interaction.response.send_message(
                "This user is not in the server.",
                ephemeral=True
            )
            return
        
        # Load warnings from file to ensure we have the latest data
        reload_warnings()
        
        user_id = str(member.id)
        if user_id not in warnings:
            warnings[user_id] = {
                "username": member.name,
                "warnings": []
            }
        
        # Add the new warning
        warnings[user_id]["warnings"].append({
            "timestamp": datetime.now().isoformat(),
            "reason": reason
        })
        
        # Save the updated warnings to the file
        save_warnings(warnings)  # Pass the warnings dictionary as an argument
        
        # Check if the user has no warnings left (e.g., if warnings were deleted externally)
        if not warnings[user_id]["warnings"]:
            del warnings[user_id]
            save_warnings(warnings)  # Pass the warnings dictionary as an argument
            await interaction.response.send_message(
                f"{member.mention} has no warnings left. Their warning record has been cleared.",
                ephemeral=True
            )
            return
        
        warning_count = len(warnings[user_id]["warnings"])
        
        # Send DM to the user
        dm_embed = discord.Embed(
            title="You have been warned!",
            description=f"**Reason:** {reason}",
            color=discord.Color.orange()
        )
        dm_embed.add_field(name="Total Warnings", value=str(warning_count))
        
        # Check if an action should be taken based on the number of warnings
        if warning_count in WARNING_ACTIONS:
            action = WARNING_ACTIONS[warning_count]
            action_text = ""
            if action == "timeout":
                try:
                    await member.timeout(discord.utils.utcnow() + timedelta(hours=24), reason="You got 2 warnings")
                    action_text = "24-hour timeout applied"
                except discord.Forbidden:
                    await interaction.response.send_message(
                        "I don't have permission to timeout this user.",
                        ephemeral=True
                    )
                    return
            elif action == "ban":
                # Load appeal configuration
                appeal_forms = load_appeal_forms()
                ban_config = appeal_forms.get('ban', {})
                
                ban_embed = discord.Embed(
                    title="You have been banned!",
                    description=("**Reason:** You got 3 warnings\n\n"
                                 "You have reached the maximum number of warnings and have been banned from the server."),
                    color=discord.Color.red()
                )
                
                # Use same appeal URL logic as regular ban command
                if ban_config.get('enabled', False) and ban_config.get('form_url'):
                    appeal_url = f"{appeal_forms['base_url']}{ban_config['form_url']}?user_id={member.id}"
                    ban_embed.add_field(
                        name="Appeal Form",
                        value=f"[Click here to appeal]({appeal_url})",
                        inline=False
                    )
                else:
                    ban_embed.add_field(
                        name="Appeal Information",
                        value="Contact server staff to appeal your ban",
                        inline=False
                    )

                try:
                    await member.send(embed=ban_embed)
                except discord.Forbidden:
                    pass
                try:
                    await member.ban(reason="Too many warnings")
                    action_text = "Permanent ban applied"
                    if user_id in warnings:
                        del warnings[user_id]
                        save_warnings(warnings)
                except discord.Forbidden:
                    await interaction.response.send_message(
                        "I don't have permission to ban this user.",
                        ephemeral=True
                    )
                    return
            
            dm_embed.add_field(name="Action Taken", value=action_text, inline=False)
        
        dm_embed.set_footer(text=f"Server: {interaction.guild.name}")
        try:
            await member.send(embed=dm_embed)
        except discord.Forbidden:
            pass
        
        # Log the warning event
        await log_event(interaction.guild, "member_warn", "Member Warned", 
                        f"**Member:** {member.mention}\n**Reason:** {reason}\n**Total Warnings:** {warning_count}",
                        color=discord.Color.orange())
        
        # Respond to the moderator
        await interaction.response.send_message(
            f"{member.mention} warned. They now have {warning_count} warning(s).",
            ephemeral=True
        )

    @bot.tree.command(name="warnings", description="View all warnings for a user")
    @app_commands.describe(member="User to check")
    async def view_warnings(interaction: discord.Interaction, member: discord.Member):
        user_id = str(member.id)
        if user_id not in warnings or not warnings[user_id]["warnings"]:
            await interaction.response.send_message(
                f"{member.display_name} has no warnings.",
                ephemeral=True
            )
            return
        
        embed = discord.Embed(
            title=f"Warnings for {member.display_name}",
            color=discord.Color.orange()
        )
        for idx, warning in enumerate(warnings[user_id]["warnings"], 1):
            embed.add_field(
                name=f"Warning #{idx}",
                value=f"**Date:** {warning['timestamp'][:10]}\n**Reason:** {warning['reason']}",
                inline=False
            )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @bot.tree.command(name="unwarn", description="Remove a warning from a user")
    @app_commands.describe(
        member="User to unwarn",
        warning_number="Warning number to remove"
    )
    async def unwarn(interaction: discord.Interaction, member: discord.Member, warning_number: int):
        user_id = str(member.id)
        if user_id not in warnings or not warnings[user_id]["warnings"]:
            await interaction.response.send_message(
                f"{member.display_name} has no warnings to remove.",
                ephemeral=True
            )
            return
        
        user_warnings = warnings[user_id]["warnings"]
        if warning_number < 1 or warning_number > len(user_warnings):
            await interaction.response.send_message(
                f"Invalid warning number. Please use a number between 1 and {len(user_warnings)}.",
                ephemeral=True
            )
            return
        
        removed_warning = user_warnings.pop(warning_number - 1)
        warnings[user_id]["warnings"] = user_warnings
        save_warnings(warnings)  # Pass the warnings dictionary as an argument
        new_count = len(user_warnings)
        
        if new_count + 1 in WARNING_ACTIONS:
            action = WARNING_ACTIONS[new_count + 1]
            if action == "timeout":
                try:
                    await member.timeout(None, reason="Warning removed")
                except discord.Forbidden:
                    await interaction.response.send_message(
                        "I don't have permission to remove the timeout for this user.",
                        ephemeral=True
                    )
                    return
        
        await log_event(interaction.guild, "member_unwarn", "Member Unwarned", 
                        f"**Member:** {member.mention}\nRemoved warning #{warning_number}\n**New total warnings:** {new_count}",
                        color=discord.Color.blue())
        
        await interaction.response.send_message(
            f"Removed warning #{warning_number} from {member.display_name}\n"
            f"**Reason:** {removed_warning['reason']}\n"
            f"**New total warnings:** {new_count}",
            ephemeral=True
        )
            
    @bot.tree.command(name="purge", description="Delete a specified number of messages")
    @app_commands.describe(
        amount="Number of messages to delete",
        user="User whose messages should be deleted (optional)",
        contains="Only delete messages containing this text (optional)"
    )
    @app_commands.checks.has_permissions(manage_messages=True)
    async def purge(interaction: discord.Interaction, amount: int, user: discord.User = None, contains: str = None):
        if amount <= 0 or amount > 100:
            await interaction.response.send_message("Amount must be between 1 and 100.", ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)

        def check(m):
            if user and m.author.id != user.id:
                return False
            if contains and contains.lower() not in m.content.lower():
                return False
            return True

        deleted = await interaction.channel.purge(limit=amount, check=check)

        # Log the purge action
        description = f"**Moderator:** {interaction.user.mention}\n**Channel:** {interaction.channel.mention}\n**Messages Deleted:** {len(deleted)}"
        if user:
            description += f"\n**User:** {user.mention}"
        if contains:
            description += f"\n**Containing:** {contains}"
        
        await log_event(interaction.guild, "message_delete", "Messages Purged", description, color=discord.Color.red())

        await interaction.followup.send(f"Successfully deleted {len(deleted)} messages.", ephemeral=True)

    @purge.error
    async def purge_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message("You don't have permission to use this command.", ephemeral=True)
        else:
            await interaction.response.send_message("An error occurred while executing this command.", ephemeral=True)
            print(f"Purge command error: {error}")
            
    @bot.tree.command(name="purge_after", description="Delete messages after a specific message ID")
    @app_commands.describe(
        message_id="The message ID to start purging after",
        count="Number of messages to delete after the specified message ID (optional, max 100)"
    )
    @app_commands.checks.has_permissions(manage_messages=True)
    async def purge_after(interaction: discord.Interaction, message_id: str, count: int = 100):
        # Validate count
        if count <= 0 or count > 100:
            await interaction.response.send_message("Count must be between 1 and 100.", ephemeral=True)
            return
    
        # Validate message ID
        try:
            message_id = int(message_id)
        except ValueError:
            await interaction.response.send_message("Invalid message ID format.", ephemeral=True)
            return
    
        await interaction.response.defer(ephemeral=True)
    
        try:
            # Verify the starting message exists
            start_message = await interaction.channel.fetch_message(message_id)
        except discord.NotFound:
            await interaction.followup.send("❌ Message ID not found in this channel.", ephemeral=True)
            return
        except discord.Forbidden:
            await interaction.followup.send("🔒 Missing permissions to access that message.", ephemeral=True)
            return
        except Exception as e:
            await interaction.followup.send(f"⚠️ Error fetching message: {str(e)}", ephemeral=True)
            return
    
        # Collect messages after the specified ID
        messages_to_delete = []
        try:
            async for message in interaction.channel.history(
                after=start_message,
                limit=count,
                oldest_first=False
            ):
                if message.id > message_id:
                    messages_to_delete.append(message)
        except Exception as e:
            await interaction.followup.send(f"⚠️ Error fetching history: {str(e)}", ephemeral=True)
            return
    
        # Delete messages if any were found
        if messages_to_delete:
            try:
                await interaction.channel.delete_messages(messages_to_delete)
            except discord.HTTPException as e:
                await interaction.followup.send(f"⚠️ Failed to delete messages: {str(e)}", ephemeral=True)
                return
    
            # Log the action
            log_description = (
                f"**Moderator:** {interaction.user.mention}\n"
                f"**Channel:** {interaction.channel.mention}\n"
                f"**Messages Deleted:** {len(messages_to_delete)}\n"
                f"**After Message ID:** {message_id}"
            )
            await log_event(
                interaction.guild,
                "message_delete",
                "Messages Purged After",
                log_description,
                color=discord.Color.red()
            )
    
            await interaction.followup.send(
                f"✅ Successfully deleted {len(messages_to_delete)} messages after {message_id}",
                ephemeral=True
            )
        else:
            await interaction.followup.send("🔍 No messages found to delete after the specified message.", ephemeral=True)
    
    @purge_after.error
    async def purge_after_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message("❌ You need manage messages permissions to use this command.", ephemeral=True)
        else:
            await interaction.response.send_message("⚠️ An error occurred while processing this command.", ephemeral=True)
            print(f"Purge After Error: {str(error)}")
            
    @bot.tree.command(name="setlogchannel", description="Set the channel for logging events")
    @app_commands.describe(channel="The channel to use for logging")
    @app_commands.checks.has_permissions(administrator=True)
    async def set_log_channel(interaction: discord.Interaction, channel: discord.TextChannel):
        if not isinstance(channel, discord.TextChannel):
            await interaction.response.send_message("❌ Must be a text channel", ephemeral=True)
            return
        global log_config
        log_config = load_log_config()  # Reload first
        log_config['log_channel_id'] = channel.id
        save_log_config(log_config)
        
        # Send confirmation
        await interaction.response.send_message(
            f"Log channel set to {channel.mention}",
            ephemeral=True
        )
        
        # Log the configuration change
        await log_event(
            interaction.guild,
            "log_config_update",
            "Log Channel Configured",
            f"Log channel set to {channel.mention} by {interaction.user.mention}",
            color=discord.Color.green()
        )
        
    @bot.tree.command(name="ban", description="Ban a user from the server")
    @app_commands.describe(user="The user to ban", reason="The reason for the ban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def ban(interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
        try:
            # Check bot permissions
            if not interaction.guild.me.guild_permissions.ban_members:
                await interaction.response.send_message("I don't have permission to ban users.", ephemeral=True)
                return

            # Load appeal forms configuration
            appeal_forms = load_appeal_forms()
            ban_config = appeal_forms.get('ban', {})
            
            # Create ban embed
            ban_embed = discord.Embed(
                title="You have been banned!",
                description=f"**Reason:** {reason}\n\nYou have been banned from {interaction.guild.name}.",
                color=discord.Color.red()
            )
            
            # Add appeal form if configured
            # Find this section in the ban command:
            if ban_config.get('enabled', False) and ban_config.get('form_url'):
                appeal_url = f"{appeal_forms['base_url']}{ban_config['form_url']}?user_id={user.id}"  # ← ADD USER ID
                ban_embed.add_field(
                    name="Appeal Form",
                    value=f"[Click here to appeal]({appeal_url})",
                    inline=False
                )

            try:
                # Send DM with ban notification
                await user.send(embed=ban_embed)
            except discord.Forbidden:
                pass  # Couldn't send DM

            # Execute the ban
            await interaction.guild.ban(user, reason=reason, delete_message_days=0)
            await interaction.response.send_message(
                f"{user.mention} has been banned. Reason: {reason}",
                ephemeral=True
            )
            
            # Log the ban
            await log_event(
                interaction.guild,
                "member_ban",
                "Member Banned",
                f"**User:** {user.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.red()
            )

        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to ban this user.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"An error occurred: {str(e)}", ephemeral=True)
            print(f"Ban error: {str(e)}")

    @bot.tree.command(name="unban", description="Unban a user from the server")
    @app_commands.describe(user="The user to unban", reason="The reason for the unban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def unban(interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
        if not interaction.guild.me.guild_permissions.ban_members:
            await interaction.response.send_message("I don't have permission to unban users.", ephemeral=True)
            return

        try:
            await interaction.guild.unban(user, reason=reason)
            await interaction.response.send_message(f"{user.mention} has been unbanned. Reason: {reason}", ephemeral=True)
            await log_event(
                interaction.guild,
                "member_unban",
                "Member Unbanned",
                f"**User:** {user.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.green()
            )
        except discord.NotFound:
            await interaction.response.send_message("This user is not banned.", ephemeral=True)

    @bot.tree.command(name="kick", description="Kick a user from the server")
    @app_commands.describe(member="The member to kick", reason="The reason for the kick")
    @app_commands.checks.has_permissions(kick_members=True)
    async def kick(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
        try:
            # Check bot permissions
            if not interaction.guild.me.guild_permissions.kick_members:
                await interaction.response.send_message("I don't have permission to kick users.", ephemeral=True)
                return

            # Load appeal forms configuration
            appeal_forms = load_appeal_forms()
            kick_config = appeal_forms.get('kick', {})
            
            # Create kick embed
            kick_embed = discord.Embed(
                title="You have been kicked!",
                description=f"**Reason:** {reason}\n\nYou have been kicked from {interaction.guild.name}.",
                color=discord.Color.orange()
            )
            
            # Add appeal form if configured
            if kick_config.get('enabled', False) and kick_config.get('form_url'):
                appeal_url = f"{appeal_forms['base_url']}{kick_config['form_url']}?user_id={member.id}"
                kick_embed.add_field(
                    name="Appeal Form",
                    value=f"[Click here to appeal]({appeal_url})",
                    inline=False
                )

            try:
                # Send DM with kick notification
                await member.send(embed=kick_embed)
            except discord.Forbidden:
                pass  # Couldn't send DM

            # Execute the kick
            await member.kick(reason=reason)
            await interaction.response.send_message(
                f"{member.mention} has been kicked. Reason: {reason}",
                ephemeral=True
            )
            
            # Log the kick
            await log_event(
                interaction.guild,
                "member_kick",
                "Member Kicked",
                f"**User:** {member.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.orange()
            )

        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to kick this user.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"An error occurred: {str(e)}", ephemeral=True)
            print(f"Kick error: {str(e)}")

    @bot.tree.command(name="deafen", description="Deafen a user in voice channels")
    @app_commands.describe(member="The member to deafen", reason="The reason for deafening")
    @app_commands.checks.has_permissions(deafen_members=True)
    async def deafen(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
        if not member.voice or not member.voice.channel:
            await interaction.response.send_message("The user is not in a voice channel.", ephemeral=True)
            return

        if not interaction.guild.me.guild_permissions.deafen_members:
            await interaction.response.send_message("I don't have permission to deafen members.", ephemeral=True)
            return

        await member.edit(deafen=True, reason=reason)
        await interaction.response.send_message(f"{member.mention} has been deafened. Reason: {reason}", ephemeral=True)
        await log_event(
            interaction.guild,
            "member_deafen",
            "Member Deafened",
            f"**User:** {member.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
            color=discord.Color.blue()
        )

    @bot.tree.command(name="undeafen", description="Undeafen a user in voice channels")
    @app_commands.describe(member="The member to undeafen", reason="The reason for undeffening")
    @app_commands.checks.has_permissions(deafen_members=True)
    async def undeafen(interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
        if not member.voice or not member.voice.channel:
            await interaction.response.send_message("The user is not in a voice channel.", ephemeral=True)
            return

        if not interaction.guild.me.guild_permissions.deafen_members:
            await interaction.response.send_message("I don't have permission to undeafen members.", ephemeral=True)
            return

        await member.edit(deafen=False, reason=reason)
        await interaction.response.send_message(f"{member.mention} has been undeafened. Reason: {reason}", ephemeral=True)
        await log_event(
            interaction.guild,
            "member_undeafen",
            "Member Undeafened",
            f"**User:** {member.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
            color=discord.Color.blue()
        )

    @bot.tree.command(name="timeout", description="Timeout a user (restrict interactions)")
    @app_commands.describe(
        member="The member to timeout",
        duration="Duration (e.g., 5m, 1h, 1d) - defaults to 5m",
        reason="The reason for timing out"
    )
    @app_commands.checks.has_permissions(moderate_members=True)
    async def timeout(
        interaction: discord.Interaction,
        member: discord.Member,
        duration: str = "5m",
        reason: str = "No reason provided"
    ):
        try:
            # Check bot permissions
            if not interaction.guild.me.guild_permissions.moderate_members:
                await interaction.response.send_message("I don't have permission to timeout members.", ephemeral=True)
                return

            # Parse duration
            time_units = {"m": 60, "h": 3600, "d": 86400}
            try:
                duration_num = int(duration[:-1])
                unit = duration[-1].lower()
                if unit not in time_units:
                    raise ValueError
                seconds = duration_num * time_units[unit]
                if seconds > 2419200:  # 28 day maximum
                    raise ValueError
            except (ValueError, IndexError):
                await interaction.response.send_message(
                    "Invalid duration format! Use: [number][m/h/d] (e.g., 30m, 2h, 1d)",
                    ephemeral=True
                )
                return

            timeout_duration = discord.utils.utcnow() + timedelta(seconds=seconds)

            # Load appeal forms configuration
            appeal_forms = load_appeal_forms()
            timeout_config = appeal_forms.get('timeout', {})
            
            # Create timeout embed
            timeout_embed = discord.Embed(
                title="You have been timed out!",
                description=f"**Duration:** {duration}\n**Reason:** {reason}",
                color=discord.Color.orange()
            )
            
            # Add appeal form if configured
            if timeout_config.get('enabled', False) and timeout_config.get('form_url'):
                appeal_url = f"{appeal_forms['base_url']}{timeout_config['form_url']}?user_id={member.id}"
                timeout_embed.add_field(
                    name="Appeal Form",
                    value=f"[Click here to appeal]({appeal_url})",
                    inline=False
                )

            try:
                # Send DM with timeout notification
                await member.send(embed=timeout_embed)
            except discord.Forbidden:
                pass  # Couldn't send DM

            # Execute the timeout
            await member.timeout(timeout_duration, reason=reason)
            await interaction.response.send_message(
                f"{member.mention} has been timed out for {duration}. Reason: {reason}",
                ephemeral=True
            )
            
            # Log the timeout
            await log_event(
                interaction.guild,
                "member_timeout",
                "Member Timed Out",
                f"**User:** {member.mention}\n**Duration:** {duration}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.orange()
            )

        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to timeout this member.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"An error occurred: {str(e)}", ephemeral=True)
            print(f"Timeout error: {str(e)}")

    @bot.tree.command(name="untimeout", description="Remove timeout from a user")
    @app_commands.describe(
        member="The member to untimeout",
        reason="The reason for removing timeout"
    )
    @app_commands.checks.has_permissions(moderate_members=True)
    async def untimeout(
        interaction: discord.Interaction,
        member: discord.Member,
        reason: str = "No reason provided"
    ):
        if not interaction.guild.me.guild_permissions.moderate_members:
            await interaction.response.send_message("I don't have permission to remove timeouts.", ephemeral=True)
            return

        if not member.is_timed_out():
            await interaction.response.send_message("This user is not currently timed out.", ephemeral=True)
            return

        try:
            await member.timeout(None, reason=reason)
            await interaction.response.send_message(
                f"Timeout removed from {member.mention}.\nReason: {reason}",
                ephemeral=True
            )
            await log_event(
                interaction.guild,
                "member_untimeout",
                "Timeout Removed",
                f"**User:** {member.mention}\n"
                f"**Reason:** {reason}\n"
                f"**Moderator:** {interaction.user.mention}",
                color=discord.Color.green()
            )
        except discord.Forbidden:
            await interaction.response.send_message("Failed to remove timeout - check role hierarchy.", ephemeral=True)

    @bot.tree.command(name="softban", description="Ban and immediately unban a user to delete their messages")
    @app_commands.describe(user="The user to softban", reason="The reason for softban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def softban(interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
        if not interaction.guild.me.guild_permissions.ban_members:
            await interaction.response.send_message("I don't have permission to ban users.", ephemeral=True)
            return

        try:
            # Create an invite for rejoining
            try:
                invite = await interaction.channel.create_invite(
                    max_uses=1,
                    unique=True,
                    reason=f"Rejoin invite for softbanned user {user}"
                )
                invite_link = invite.url
            except discord.Forbidden:
                invite_link = "Contact server staff for a new invite"
            
            # DM the user
            embed = discord.Embed(
                title=f"You were softbanned from {interaction.guild.name}",
                description="Your messages have been cleared but you can rejoin immediately.",
                color=discord.Color.orange()
            )
            embed.add_field(name="Reason", value=reason, inline=False)
            embed.add_field(name="Rejoin Link", value=invite_link, inline=False)
            
            try:
                await user.send(embed=embed)
            except discord.Forbidden:
                pass  # Couldn't send DM

            # Ban to delete messages (7 days worth)
            await interaction.guild.ban(user, reason=reason, delete_message_days=7)
            # Unban immediately
            await interaction.guild.unban(user, reason="Softban removal")
            
            await interaction.response.send_message(
                f"{user.mention} has been softbanned. They received a rejoin link.\nReason: {reason}",
                ephemeral=True
            )
            
            await log_event(
                interaction.guild,
                "member_softban",
                "Member Softbanned",
                f"**User:** {user.mention}\n**Reason:** {reason}\n" +
                f"**Rejoin Sent:** {'Yes' if invite_link else 'No'}\n" +
                f"**Moderator:** {interaction.user.mention}",
                color=discord.Color.purple()
            )

        except discord.NotFound:
            await interaction.response.send_message("User not found.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to ban/unban this user.", ephemeral=True)
    
    # Sync commands
    await bot.tree.sync()
    print("All commands reloaded successfully")
    
@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.CommandInvokeError):
        await interaction.response.send_message(
            "An error occurred while executing this command.",
            ephemeral=True
        )
        print(f"Command error: {error.original}")
    elif isinstance(error, app_commands.CheckFailure):
        await interaction.response.send_message(
            "You don't have permission to use this command.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            "Something went wrong with this command!",
            ephemeral=True
        )
        print(f"Command error: {error}")

def load_appeal_forms():
    try:
        with open('appeal_forms.json') as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "ban": {"enabled": True, "form_url": ""},
            "kick": {"enabled": False, "form_url": ""},
            "timeout": {"enabled": False, "form_url": ""}
        }
        
def load_appeals():
    try:
        with open('appeals.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []
        
def reload_warnings():
    global warnings
    warnings = load_warnings()

# -------------------- Appeal Embed ------------------
async def send_appeal_to_discord(channel_id, appeal_data):
    channel = bot.get_channel(int(channel_id))
    if not channel:
        return

    embed = discord.Embed(
        title=f"🚨 New {appeal_data['type'].title()} Appeal",
        color=discord.Color.orange(),
        description=f"**Appeal ID:** `{appeal_data['id']}`\n"
                    f"**Submitted:** <t:{int(datetime.now().timestamp())}:R>"
    )
    
    # Add fields with emoji icons
    for field in appeal_data['data']:
        embed.add_field(
            name=f"📌 {field['text']}",
            value=field['value'] or "*Not provided*",
            inline=False
        )
    
    embed.set_footer(text="Use the buttons below to manage this appeal")

    view = discord.ui.View()
    view.add_item(discord.ui.Button(
        style=discord.ButtonStyle.success,
        label="Approve",
        custom_id=f"approve_{appeal_data['id']}",
        emoji="✅"
    ))
    view.add_item(discord.ui.Button(
        style=discord.ButtonStyle.danger,
        label="Reject",
        custom_id=f"reject_{appeal_data['id']}",
        emoji="❌"
    ))
    view.add_item(discord.ui.Button(
        style=discord.ButtonStyle.link,
        label="View Online",
        url=f"https://rkbot.30-seven.cc/appeals/{appeal_data['id']}",
        emoji="🌐"
    ))

    await channel.send(embed=embed, view=view)
    
@bot.event
async def on_interaction(interaction):
    if interaction.type == discord.InteractionType.component:
        custom_id = interaction.data.get('custom_id', '')
        
        # Handle approve/reject actions
        if custom_id.startswith('approve_') or custom_id.startswith('reject_'):
            parts = custom_id.split('_')
            if len(parts) != 3:
                await interaction.response.send_message("Invalid custom ID format.", ephemeral=True)
                return

            action = parts[0]  # 'approve' or 'reject'
            appeal_type = parts[1]  # 'ban', 'kick', or 'timeout'
            appeal_id = parts[2]  # The unique appeal ID

            try:
                # Load appeal data
                appeals = load_appeals()
                appeal = next((a for a in appeals if a['id'] == appeal_id), None)

                if not appeal:
                    await interaction.response.send_message("Appeal not found.", ephemeral=True)
                    return

                # Update appeal status
                appeal['status'] = action
                save_appeals(appeals)  # Save the updated appeals list

                # Fetch the user and guild
                user_id = appeal['user_id']
                guild = interaction.guild
                user = await bot.fetch_user(int(user_id))

                # Perform the action based on appeal type
                try:
                    if action == 'approve':
                        if appeal_type == 'ban':
                            await guild.unban(user, reason="Appeal approved.")
                            await interaction.response.send_message(f"{user.mention} has been unbanned.", ephemeral=True)
                        elif appeal_type == 'timeout':
                            member = await guild.fetch_member(user.id)
                            await member.timeout(None, reason="Appeal approved.")
                            await interaction.response.send_message(f"Timeout removed for {member.mention}.", ephemeral=True)
                        elif appeal_type == 'kick':
                            invite = await interaction.channel.create_invite(max_uses=1, reason="Appeal approved.")
                            await user.send(f"Your kick appeal was approved. You may rejoin here: {invite.url}")
                            await interaction.response.send_message("Invite sent to user.", ephemeral=True)
                    elif action == 'reject':
                        await interaction.response.send_message("Appeal rejected.", ephemeral=True)

                    # Disable buttons after action
                    view = discord.ui.View()
                    for component in interaction.message.components:
                        if component.type == discord.ComponentType.button:
                            btn = discord.ui.Button.from_component(component)
                            btn.disabled = True
                            view.add_item(btn)

                    # Update the message to reflect the action
                    embed = interaction.message.embeds[0]
                    embed.color = discord.Color.green() if action == 'approve' else discord.Color.red()
                    embed.set_field_at(
                        -1,  # Status is the last field
                        name="Status",
                        value=f"✅ Approved" if action == 'approve' else "❌ Rejected"
                    )

                    await interaction.message.edit(embed=embed, view=view)

                except discord.Forbidden:
                    await interaction.response.send_message("I don't have permission to perform this action.", ephemeral=True)
                except discord.NotFound:
                    await interaction.response.send_message("User or appeal not found.", ephemeral=True)
                except Exception as e:
                    await interaction.response.send_message(f"Error processing appeal: {str(e)}", ephemeral=True)

            except Exception as e:
                await interaction.response.send_message(f"Error loading appeal data: {str(e)}", ephemeral=True)

        # Handle other types of interactions (e.g., custom buttons)
        else:
            await bot.process_commands(interaction)

async def handle_appeal_action(interaction, appeal_id, action, color):
    # Update appeal status in storage
    appeals = load_appeals()
    appeal = next((a for a in appeals if a['id'] == appeal_id), None)
    
    if appeal:
        appeal['status'] = action
        save_appeals(appeals)
        
        # Update embed
        embed = interaction.message.embeds[0]
        embed.color = color
        embed.set_field_at(
            -1,  # Status is last field
            name="Status",
            value=f"🔴 {action.capitalize()}"
        )
        
        # Disable buttons
        view = discord.ui.View()
        for item in interaction.message.components:
            if item.type == discord.ComponentType.button:
                button = discord.ui.Button.from_component(item)
                button.disabled = True
                view.add_item(button)
        
        await interaction.message.edit(embed=embed, view=view)
        await interaction.response.send_message(f"Appeal {appeal_id} {action}!", ephemeral=True)

# -------------------- Leveling System --------------------
def load_level_data():
    try:
        with open('levels.json', 'r') as f:
            data = json.load(f)
            # Convert all keys to strings for consistency
            return {str(k): v for k, v in data.items()}
    except FileNotFoundError:
        return {}

level_data = load_level_data()

def save_level_data(data):
    with open('levels.json', 'w') as f:
        json.dump(data, f, indent=4)

def load_level_config():
    default_config = {
        "cooldown": 60,
        "xp_range": [15, 25],
        "level_channel": None,
        "announce_level_up": True,
        "excluded_channels": [],
        "xp_boost_roles": {},
        "embed": {
            "title": "🎉 Level Up!",
            "description": "{user} has reached level **{level}**!",
            "color": 0xffd700
        }
    }
    try:
        with open('level_config.json', 'r') as f:
            config = json.load(f)
            # Ensure all fields exist
            return {**default_config, **config}
    except FileNotFoundError:
        with open('level_config.json', 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config

level_config = load_level_config()

def save_level_config(config):
    with open('level_config.json', 'w') as f:
        json.dump(config, f, indent=4)

user_cooldowns = {}

def calculate_xp_for_level(level):
    return math.floor(5 * (level ** 2) + (50 * level) + 100)

def calculate_xp_with_boost(base_xp, user_roles, xp_boost_roles):
    boost = 0
    for role in user_roles:
        if str(role.id) in xp_boost_roles:
            boost += xp_boost_roles[str(role.id)]
    return base_xp * (1 + boost / 100)

async def handle_level_up(user, guild, channel):
    user_id = str(user.id)
    current_level = level_data[user_id]['level']
    new_level = current_level + 1
    
    # Update level in data
    level_data[user_id]['level'] = new_level
    
    # Load rewards
    with open('level_rewards.json', 'r') as f:
        rewards = json.load(f)
    
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
    
    # Create embed
    embed = discord.Embed(
        title="🎉 Level Up!",
        description=f"{user.mention} has reached level **{new_level}**!",
        color=discord.Color.gold()
    )
    embed.set_thumbnail(url=user.display_avatar.url)
    
    # Get announcement channel
    target_channel = None
    if level_config['level_channel']:
        target_channel = guild.get_channel(int(level_config['level_channel']))
    if not target_channel:
        target_channel = channel
    
    # Send announcement if enabled
    if level_config['announce_level_up'] and target_channel:
        try:
            await target_channel.send(embed=embed)
        except Exception as e:
            print(f"Error sending level up message: {str(e)}")
# -------------------- Message Processing --------------------
@bot.event
async def on_message(message):
    if message.author.bot or not message.guild:
        return
        
    # Check if message is in excluded channel
    if message.channel.id in level_config['excluded_channels']:
        return

    user_id = str(message.author.id)
    current_time = time.time()
    
    # Check cooldown
    last_message = user_cooldowns.get(user_id, 0)
    if current_time - last_message < level_config['cooldown']:
        return
    
    user_cooldowns[user_id] = current_time
    
    # Initialize user data if needed
    if user_id not in level_data:
        level_data[user_id] = {
            "xp": 0,
            "level": 0,
            "username": message.author.name
        }
    
    # Calculate base XP
    base_xp = random.randint(*level_config['xp_range'])

    # Calculate XP with boosts
    total_xp = calculate_xp_with_boost(
        base_xp,
        message.author.roles,
        level_config['xp_boost_roles']
    )

    # Add XP to user
    level_data[user_id]['xp'] += total_xp
    
    # Check for level up
    while level_data[user_id]['xp'] >= calculate_xp_for_level(level_data[user_id]['level']):
        level_data[user_id]['xp'] -= calculate_xp_for_level(level_data[user_id]['level'])
        level_data[user_id]['level'] += 1
        await handle_level_up(message.author, message.guild, message.channel)
    
    # Save data
    save_level_data(level_data)    
        
    current_time = discord.utils.utcnow().timestamp()

    # Load fresh data every time
    blocked_words = load_blocked_words()
    embed_config = load_embed()
    
    content_lower = message.content.lower()
    
    for word in blocked_words:
        if word.lower() in content_lower:
            try:
                await message.delete()
                
                try:
                    embed = discord.Embed(
                        title=embed_config['title'],
                        description=embed_config['description'],
                        color=discord.Color(embed_config['color'])
                    )
                    await message.author.send(embed=embed)
                except discord.Forbidden:
                    pass
                
                await log_event(message.guild, "message_delete", "Blocked Word Detected",
                              f"**User:** {message.author.mention}\n**Message:** {message.content}",
                              color=discord.Color.red())
                return
            except discord.NotFound:
                print("Message already deleted elsewhere")
            except discord.Forbidden:
                print("Bot lacks permissions to delete messages!")
            except Exception as e:
                print(f"Unexpected error: {str(e)}")
            return

    current_time = discord.utils.utcnow().timestamp()
    if current_time - last_message_time[message.author.id] < SPAM_TIME_WINDOW:
        message_count[message.author.id] += 1
    else:
        message_count[message.author.id] = 1
    last_message_time[message.author.id] = current_time

    if message_count[message.author.id] > SPAM_THRESHOLD:
        await message.channel.send(embed=discord.Embed(
            title="Spam Detected",
            description="Please stop spamming or you will get a warning.",
            color=discord.Color.red()
        ))
        message_count[message.author.id] = 0

    mention_count_current = len(message.mentions)
    if mention_count_current > 0:
        user_id = message.author.id
        current_time = discord.utils.utcnow().timestamp()
        
        # Record timestamps for mentions
        user_mentions[user_id].extend([current_time] * mention_count_current)
        
        # Filter mentions to only keep those within 5 minutes
        window_start = current_time - MENTION_TIME_WINDOW
        user_mentions[user_id] = [t for t in user_mentions[user_id] if t >= window_start]
        
        if len(user_mentions[user_id]) > MENTION_THRESHOLD:
            await message.channel.send(embed=discord.Embed(
                title="Too Many Mentions",
                description="Please do not mention too many users at once or you will get a warning.",
                color=discord.Color.red()
            ))
            # Reset after warning
            user_mentions[user_id].clear()
            
            
    await bot.process_commands(message)
    
   # Track processed messages
    if 'processed_messages' not in globals():
        global processed_messages
        processed_messages = set()
    
    processed_messages.add(message.id)
    if len(processed_messages) > 1000:
        processed_messages = set()
    
    return

# -------------------- Logging Event Handlers --------------------

@bot.event
async def on_message_delete(message):
    if message.guild is None or message.author.bot:
        return
    if log_config.get("message_delete", True):
        description = (
            f"**Author:** {message.author.mention}\n"
            f"**Channel:** {message.channel.mention}\n"
            f"**Content:** {message.content if message.content else 'No text content.'}"
        )
        await log_event(message.guild, "message_delete", "Message Deleted", description, color=discord.Color.red())
        # Additionally log image deletion if applicable
        if message.attachments:
            for attachment in message.attachments:
                if attachment.content_type and attachment.content_type.startswith("image"):
                    img_description = (
                        f"**Author:** {message.author.mention}\n"
                        f"**Channel:** {message.channel.mention}\n"
                        f"**Image URL:** {attachment.url}"
                    )
                    await log_event(message.guild, "message_delete", "Image Deleted", img_description, color=discord.Color.dark_red())

@bot.event
async def on_bulk_message_delete(messages):
    if not messages:
        return
    guild = messages[0].guild
    if guild is None:
        return
    if log_config.get("bulk_message_delete", True):
        description = f"Bulk deleted {len(messages)} messages in {messages[0].channel.mention}"
        await log_event(guild, "bulk_message_delete", "Bulk Message Delete", description, color=discord.Color.dark_red())

@bot.event
async def on_message_edit(before, after):
    if before.guild is None:
        return
    if before.content == after.content:
        return
    if log_config.get("message_edit", True):
        description = (
            f"**Author:** {before.author.mention}\n"
            f"**Channel:** {before.channel.mention}\n"
            f"**Before:** {before.content}\n"
            f"**After:** {after.content}"
        )
        await log_event(before.guild, "message_edit", "Message Edited", description, color=discord.Color.orange())

@bot.event
async def on_invite_create(invite):
    guild = invite.guild
    if log_config.get("invite_create", True):
        description = (
            f"**Invite Code:** {invite.code}\n"
            f"**Inviter:** {invite.inviter.mention if invite.inviter else 'Unknown'}\n"
            f"**Channel:** {invite.channel.mention}\n"
            f"**Max Uses:** {invite.max_uses}\n"
            f"**Expires In:** {invite.max_age} seconds"
        )
        await log_event(guild, "invite_create", "Invite Created", description, color=discord.Color.green())

@bot.event
async def on_invite_delete(invite):
    guild = invite.guild
    if log_config.get("invite_delete", True):
        description = (
            f"**Invite Code:** {invite.code}\n"
            f"**Inviter:** {invite.inviter.mention if invite.inviter else 'Unknown'}\n"
            f"**Channel:** {invite.channel.mention}"
        )
        await log_event(guild, "invite_delete", "Invite Deleted", description, color=discord.Color.dark_green())

@bot.event
async def on_member_update(before, after):
    guild = before.guild
    # Check for role changes
    # Handle role changes with batcher
    added_roles = set(after.roles) - set(before.roles)
    removed_roles = set(before.roles) - set(after.roles)
    
    if added_roles or removed_roles:
        await role_batcher.add_change(after, added_roles, removed_roles)
        
    for role in added_roles:
        if log_config.get("member_role_add", True):
            description = f"**Member:** {after.mention}\n**Role Added:** {role.name}"
            await log_event(guild, "member_role_add", "Role Added", description, color=discord.Color.green())
    for role in removed_roles:
        if log_config.get("member_role_remove", True):
            description = f"**Member:** {after.mention}\n**Role Removed:** {role.name}"
            await log_event(guild, "member_role_remove", "Role Removed", description, color=discord.Color.red())
    
    # Check for timeout changes
    if before.timed_out_until != after.timed_out_until:
        if after.timed_out_until:
            if log_config.get("member_timeout", True):
                description = f"**Member:** {after.mention}\n**Timeout Until:** {after.timed_out_until}"
                await log_event(guild, "member_timeout", "Member Timed Out", description, color=discord.Color.dark_orange())
        else:
            if log_config.get("member_timeout", True):
                description = f"**Member:** {after.mention}\nTimeout removed"
                await log_event(guild, "member_timeout", "Timeout Removed", description, color=discord.Color.green())

@bot.event
async def on_member_ban(guild, user):
    if log_config.get("member_ban", True):
        description = f"**Member:** {user.mention} has been banned."
        await log_event(guild, "member_ban", "Member Banned", description, color=discord.Color.dark_red())

@bot.event
async def on_member_unban(guild, user):
    if log_config.get("member_unban", True):
        description = f"**Member:** {user.mention} has been unbanned."
        await log_event(guild, "member_unban", "Member Unbanned", description, color=discord.Color.green())

@bot.event
async def on_guild_role_create(role):
    guild = role.guild
    if log_config.get("role_create", True):
        description = f"**Role Created:** {role.name}\n**ID:** {role.id}"
        await log_event(guild, "role_create", "Role Created", description, color=discord.Color.green())

@bot.event
async def on_guild_role_delete(role):
    guild = role.guild
    if log_config.get("role_delete", True):
        description = f"**Role Deleted:** {role.name}\n**ID:** {role.id}"
        await log_event(guild, "role_delete", "Role Deleted", description, color=discord.Color.red())

@bot.event
async def on_guild_role_update(before, after):
    guild = before.guild
    if log_config.get("role_update", True):
        changes = []
        if before.name != after.name:
            changes.append(f"**Name:** {before.name} -> {after.name}")
        if changes:
            description = f"**Role Updated:** {after.name}\n" + "\n".join(changes)
            await log_event(guild, "role_update", "Role Updated", description, color=discord.Color.orange())

@bot.event
async def on_guild_channel_create(channel):
    guild = channel.guild
    if log_config.get("channel_create", True):
        description = f"**Channel Created:** {channel.mention}\n**Type:** {channel.type}"
        await log_event(guild, "channel_create", "Channel Created", description, color=discord.Color.green())

@bot.event
async def on_guild_channel_delete(channel):
    guild = channel.guild
    if log_config.get("channel_delete", True):
        description = f"**Channel Deleted:** {channel.name}\n**Type:** {channel.type}"
        await log_event(guild, "channel_delete", "Channel Deleted", description, color=discord.Color.red())

@bot.event
async def on_guild_channel_update(before, after):
    guild = before.guild
    if log_config.get("channel_update", True):
        changes = []
        if before.name != after.name:
            changes.append(f"**Name:** {before.name} -> {after.name}")
        if changes:
            description = f"**Channel Updated:** {after.mention if hasattr(after, 'mention') else after.name}\n" + "\n".join(changes)
            await log_event(guild, "channel_update", "Channel Updated", description, color=discord.Color.orange())

@bot.event
async def on_guild_emojis_update(guild, before, after):
    before_dict = {e.id: e for e in before}
    after_dict = {e.id: e for e in after}
    
    # New emojis
    new_emojis = [e for e in after if e.id not in before_dict]
    for emoji in new_emojis:
        if log_config.get("emoji_create", True):
            description = f"**Emoji Created:** {emoji.name} (ID: {emoji.id})"
            await log_event(guild, "emoji_create", "Emoji Created", description, color=discord.Color.green())
    
    # Deleted emojis
    deleted_emojis = [e for e in before if e.id not in after_dict]
    for emoji in deleted_emojis:
        if log_config.get("emoji_delete", True):
            description = f"**Emoji Deleted:** {emoji.name} (ID: {emoji.id})"
            await log_event(guild, "emoji_delete", "Emoji Deleted", description, color=discord.Color.red())
    
    # Emoji name changes
    for emoji in after:
        if emoji.id in before_dict:
            old_emoji = before_dict[emoji.id]
            if old_emoji.name != emoji.name and log_config.get("emoji_name_change", True):
                description = f"**Emoji Name Changed:** {old_emoji.name} -> {emoji.name} (ID: {emoji.id})"
                await log_event(guild, "emoji_name_change", "Emoji Name Change", description, color=discord.Color.orange())

bot.run(BOT_TOKEN)
