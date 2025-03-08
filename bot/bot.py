import discord
from discord.ext import commands
from discord import app_commands
from collections import defaultdict
import json
from datetime import datetime, timedelta
import time
import os
import threading
from aiohttp import web

# -------------------- Load Secrets --------------------
with open('secrets.json', 'r') as f:
    secrets = json.load(f)
    BOT_TOKEN = secrets['BOT_TOKEN']

# -------------------- Log Config --------------------
# Path to your logging configuration file
LOG_CONFIG_PATH = os.path.join('config', 'log_config.json')

def load_log_config():
    default_config = {
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
    except FileNotFoundError:
        # Create default config if not found
        with open(LOG_CONFIG_PATH, 'w') as f:
            json.dump(default_config, f, indent=4)
        config = default_config
    return config

def save_log_config(config):
    with open(LOG_CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

# Global log configuration
log_config = load_log_config()

# -------------------- Bot Setup --------------------
LOG_CHANNEL_ID = 123456789012345678  # Replace with your actual log channel ID

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
    channel = guild.get_channel(LOG_CHANNEL_ID)
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
mention_count = defaultdict(int)
last_message_time = defaultdict(float)

def load_warnings():
    try:
        with open('warnings.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_warnings():
    with open('warnings.json', 'w') as f:
        json.dump(warnings, f, indent=4)

warnings = load_warnings()

SPAM_THRESHOLD = 5
SPAM_TIME_WINDOW = 10
MENTION_THRESHOLD = 3
MENTION_TIME_WINDOW = 10
WARNING_ACTIONS = {2: "timeout", 3: "ban"}

# -------------------- Web Server for Syncing --------------------
async def webserver():
    app = web.Application()
    app.router.add_post('/sync', handle_sync)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 5003)
    await site.start()
    print("Sync endpoint running on port 5003")

async def handle_sync(request):
    await reload_commands()
    return web.Response(text="Commands synced successfully!")

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
    
    @bot.tree.command(name="sync", description="Sync commands manually")
    async def sync_commands(interaction: discord.Interaction):
        await reload_commands()
        await interaction.response.send_message("Commands synced!", ephemeral=True)

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
        if not interaction.guild.me.guild_permissions.moderate_members:
            await interaction.response.send_message(
                "I don't have permission to timeout or ban users.",
                ephemeral=True
            )
            return
        
        if interaction.guild.me.top_role <= member.top_role:
            await interaction.response.send_message(
                "I cannot moderate this user because their role is equal to or higher than mine.",
                ephemeral=True
            )
            return
        
        if member not in interaction.guild.members:
            await interaction.response.send_message(
                "This user is not in the server.",
                ephemeral=True
            )
            return
        
        user_id = str(member.id)
        if user_id not in warnings:
            warnings[user_id] = {
                "username": member.name,
                "warnings": []
            }
        
        warnings[user_id]["warnings"].append({
            "timestamp": datetime.now().isoformat(),
            "reason": reason
        })
        save_warnings()
        warning_count = len(warnings[user_id]["warnings"])
        
        dm_embed = discord.Embed(
            title="You have been warned!",
            description=f"**Reason:** {reason}",
            color=discord.Color.orange()
        )
        dm_embed.add_field(name="Total Warnings", value=str(warning_count))
        
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
                ban_embed = discord.Embed(
                    title="You have been banned!",
                    description=("**Reason:** You got 3 warnings\n\n"
                                 "You have reached the maximum number of warnings and have been banned from the server."),
                    color=discord.Color.red()
                )
                ban_embed.add_field(
                    name="Appeal Form",
                    value="If you believe this was a mistake, you can appeal your ban here: [Appeal Form](https://dyno.gg/form/f78d0f9a)",
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
                        save_warnings()
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
        
        await log_event(interaction.guild, "member_warn", "Member Warned", 
                        f"**Member:** {member.mention}\n**Reason:** {reason}\n**Total Warnings:** {warning_count}",
                        color=discord.Color.orange())
        
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
        save_warnings()
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
        
    await bot.tree.sync()
    print("All commands reloaded successfully")

@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if not interaction.response.is_done():
        await interaction.response.send_message(
            "Something went wrong with this command!",
            ephemeral=True
        )
    print(f"Command error: {error}")

# -------------------- Message Processing --------------------
@bot.event
async def on_message(message):
    global processed_messages
    if message.author.bot or message.id in processed_messages:
        return
        
    processed_messages.add(message.id)
    if len(processed_messages) > 1000:
        processed_messages = set()

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
        if current_time - last_message_time[message.author.id] > MENTION_TIME_WINDOW:
            mention_count[message.author.id] = 0
        mention_count[message.author.id] += mention_count_current
        if mention_count[message.author.id] > MENTION_THRESHOLD:
            await message.channel.send(embed=discord.Embed(
                title="Too Many Mentions",
                description="Please do not mention too many users at once or you will get a warning.",
                color=discord.Color.red()
            ))
            mention_count[message.author.id] = 0
            last_message_time[message.author.id] = current_time

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
    added_roles = set(after.roles) - set(before.roles)
    removed_roles = set(before.roles) - set(after.roles)
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