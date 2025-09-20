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
        """
        No-op fallback for debug printing.
        
        This function accepts any positional and keyword arguments like the built-in `print` but intentionally does nothing.
        It is provided as a safe placeholder when a real `debug_print` implementation is not available so callers can invoke it without conditional checks.
        """
        pass

load_dotenv()

def command_permission_check(command_name, is_custom=False):
    """
    Create a decorator that enforces per-guild, per-command permission checks for an async command callback.
    
    The returned decorator wraps an async command handler and, when invoked, resolves a `db` object from `self.db` or `self.bot.db`. If the DB is unavailable it sends an ephemeral internal error and aborts. It grants immediate access to the guild owner and to users with the Administrator guild permission. Otherwise it fetches permissions with `db.get_command_permissions(guild_id, command_name)` and allows the command only if the invoking user's ID or any of their role IDs appear in the returned `allow_users` or `allow_roles` lists. If no allow lists are configured the wrapper denies access by default and sends a standard ephemeral permission-denied message.
    
    Parameters:
        command_name (str): Name used to look up the command's permission entry in the DB.
        is_custom (bool): Optional flag for callers to indicate the command is custom (present for future or external use; does not alter current behavior).
    
    Returns:
        Callable: A decorator that wraps an async command function (signature: async def func(self, interaction, ...)) and enforces the described permission checks.
    """
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
        """
        Initialize the Shared helper.
        
        Reads the BOT_TOKEN environment variable and stores it as self.token; raises ValueError if the token is missing. Also sets self.bot to the module-level bot_instance.
        """
        debug_print("Entered Shared.__init__", level="all")
        self.token = os.getenv('BOT_TOKEN')
        
        if not self.token:
            raise ValueError("No BOT_TOKEN found in .env file!")
            
        self.bot = bot_instance

shared = Shared()