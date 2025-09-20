import os
import functools
import discord
from discord.ext import commands
from dotenv import load_dotenv
from bot.bot import bot_instance
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

load_dotenv()

def command_permission_check(command_name, is_custom=False):
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, interaction, *args, **kwargs):
            debug_print(f"Entered {func.__name__} in command_permission_check", level="all")
            db = getattr(self, "db", None) or getattr(self.bot, "db", None)
            if db is None:
                await interaction.response.send_message("Internal error: DB not found.", ephemeral=True)
                return
            guild_id = str(interaction.guild.id)
            user_id = str(interaction.user.id)
            user_roles = [str(r.id) for r in getattr(interaction.user, "roles", [])]
            # Always allow server owner
            if str(interaction.guild.owner_id) == user_id:
                return await func(self, interaction, *args, **kwargs)
            # Always allow users with Administrator permission
            if hasattr(interaction.user, 'guild_permissions') and getattr(interaction.user.guild_permissions, 'administrator', False):
                return await func(self, interaction, *args, **kwargs)
            perms = db.get_command_permissions(guild_id, command_name)
            # Only allow if user or their role is in allow list
            if perms['allow_roles'] or perms['allow_users']:
                if any(r in perms['allow_roles'] for r in user_roles) or user_id in perms['allow_users']:
                    return await func(self, interaction, *args, **kwargs)
                await interaction.response.send_message("**You do not have permission to use this command.**\n\n*If you are a normal user and believe this is an error, please contact an admin.*\n***If you are an admin, you can change the command permissions in the dashboard.***", ephemeral=True)
                return
            # If no allow list is set, deny by default
            await interaction.response.send_message("**You do not have permission to use this command.**\n\n*If you are a normal user and believe this is an error, please contact an admin.*\n***If you are an admin, you can change the command permissions in the dashboard.***", ephemeral=True)
            return
        return wrapper
    return decorator

class Shared:
    def __init__(self):
        debug_print("Entered Shared.__init__", level="all")
        self.token = os.getenv('BOT_TOKEN')
        
        if not self.token:
            raise ValueError("No BOT_TOKEN found in .env file!")
            
        self.bot = bot_instance

shared = Shared()