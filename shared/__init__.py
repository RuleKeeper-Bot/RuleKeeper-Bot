import os
import functools
import discord
from discord.ext import commands
from dotenv import load_dotenv

# Avoid circular import - import bot_instance only when needed
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
                
                # Create denial embed
                embed = discord.Embed(
                    title="🚫 Permission Denied",
                    description="You do not have permission to use this command.",
                    color=discord.Color.red()
                )
                embed.add_field(
                    name="ℹ️ For Users",
                    value="If you believe this is an error, please contact a server administrator.",
                    inline=False
                )
                embed.add_field(
                    name="⚙️ For Administrators",
                    value="You can manage command permissions through the dashboard.",
                    inline=False
                )
                embed.set_footer(text=f"Command: /{command_name}")
                await interaction.response.send_message(embed=embed, ephemeral=True)
                return
            
            # If no allow list is set, deny by default
            embed = discord.Embed(
                title="🚫 Permission Denied",
                description="You do not have permission to use this command.",
                color=discord.Color.red()
            )
            embed.add_field(
                name="ℹ️ For Users",
                value="If you believe this is an error, please contact a server administrator.",
                inline=False
            )
            embed.add_field(
                name="⚙️ For Administrators",
                value="You can manage command permissions through the dashboard.",
                inline=False
            )
            embed.set_footer(text=f"Command: /{command_name}")
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return
        return wrapper
    return decorator

class Shared:
    def __init__(self):
        debug_print("Entered Shared.__init__", level="all")
        self.token = os.getenv('BOT_TOKEN')
        
        if not self.token:
            raise ValueError("No BOT_TOKEN found in .env file!")
        
        self._bot = None
    
    @property
    def bot(self):
        """Lazily import bot_instance to avoid circular imports"""
        if self._bot is None:
            from bot.bot import bot_instance
            self._bot = bot_instance
        return self._bot

shared = Shared()