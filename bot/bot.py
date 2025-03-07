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

# Load the bot token from secrets.json
with open('secrets.json', 'r') as f:
    secrets = json.load(f)
    BOT_TOKEN = secrets['BOT_TOKEN']

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

processed_messages = set()

class CustomBot(commands.Bot):
    async def process_commands(self, message):
        """Override to completely disable command processing"""
        pass

bot = CustomBot(command_prefix="!", intents=intents, help_command=None)

# Custom commands storage
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

def save_commands(commands):
    with open('commands.json', 'w') as f:
        json.dump(commands, f, indent=4)

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

# Spam and mention tracking
message_count = defaultdict(int)
mention_count = defaultdict(int)
last_message_time = defaultdict(float)

# Warnings storage
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

# Thresholds
SPAM_THRESHOLD = 5
SPAM_TIME_WINDOW = 10
MENTION_THRESHOLD = 3
MENTION_TIME_WINDOW = 10
WARNING_ACTIONS = {2: "timeout", 3: "ban"}

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
    bot.loop.create_task(webserver())  # Start the sync server
    await reload_commands()

async def reload_commands():
    print("Reloading commands...")
    bot.tree.clear_commands(guild=None)
    
    # Register custom commands
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
        # Check if the bot has permission to moderate the user
        if not interaction.guild.me.guild_permissions.moderate_members:
            await interaction.response.send_message(
                "I don't have permission to timeout or ban users.",
                ephemeral=True
            )
            return
        
        # Check if the bot's role is higher than the user's role
        if interaction.guild.me.top_role <= member.top_role:
            await interaction.response.send_message(
                "I cannot moderate this user because their role is equal to or higher than mine.",
                ephemeral=True
            )
            return
        
        # Ensure the user is in the server
        if member not in interaction.guild.members:
            await interaction.response.send_message(
                "This user is not in the server.",
                ephemeral=True
            )
            return
        
        user_id = str(member.id)
        
        # Initialize user warnings if not already present
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
        
        # Save warnings to file
        save_warnings()
        
        warning_count = len(warnings[user_id]["warnings"])
        
        # DM embed to warned user
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
                # Send DM before banning
                ban_embed = discord.Embed(
                    title="You have been banned!",
                    description=f"**Reason:** You got 3 warnings\n\n"
                              f"You have reached the maximum number of warnings and have been banned from the server.",
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
                    pass  # User has DMs disabled
                
                # Ban the user
                try:
                    await member.ban(reason="Too many warnings")
                    action_text = "Permanent ban applied"
                    
                    # Remove the user's warnings after banning
                    if user_id in warnings:
                        del warnings[user_id]
                        save_warnings()  # Save the updated warnings to the file
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
            pass  # User has DMs disabled
        
        # Ephemeral response to moderator
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
    async def unwarn(interaction: discord.Interaction, 
                    member: discord.Member, 
                    warning_number: int):
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
        
        # Remove the specified warning
        removed_warning = user_warnings.pop(warning_number - 1)
        warnings[user_id]["warnings"] = user_warnings
        
        # Save warnings to file
        save_warnings()
        
        # Update warning count
        new_count = len(user_warnings)
        
        # Check if we need to reverse any actions
        if new_count + 1 in WARNING_ACTIONS:
            action = WARNING_ACTIONS[new_count + 1]
            if action == "timeout":
                # Remove timeout (if applicable)
                try:
                    await member.timeout(None, reason="Warning removed")
                except discord.Forbidden:
                    await interaction.response.send_message(
                        "I don't have permission to remove the timeout for this user.",
                        ephemeral=True
                    )
                    return
            elif action == "ban":
                pass  # Can't automatically unban
        
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

@bot.event
async def on_message(message):
    global processed_messages
    if message.author.bot or message.id in processed_messages:
        return
        
    processed_messages.add(message.id)
    if len(processed_messages) > 1000:
        processed_messages = set()

    # Spam detection
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

    # Mention detection
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

bot.run(BOT_TOKEN)