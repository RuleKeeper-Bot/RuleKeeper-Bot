import discord
from discord import app_commands
from discord.ext import commands
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        """
        No-op replacement for an optional debug_print function.
        
        Acts as a drop-in fallback that accepts any positional and keyword arguments and does nothing (returns None). Used when a real debug_print implementation cannot be imported so callers can safely call it without guarding.
        """
        pass

class GlobalCommands(commands.Cog):
    def __init__(self, bot):
        """
        Initialize the GlobalCommands cog and store references to the bot and its database.
        
        Sets self.bot to the provided bot instance and self.db to bot.db.
        """
        debug_print("Entered GlobalCommands.__init__", level="all")
        self.bot = bot
        self.db = bot.db

# -------------------- Error Handling --------------------    
    @commands.Cog.listener()
    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        """
        Handle application command errors by sending an appropriate ephemeral response to the interaction and logging the error.
        
        Checks the type of the AppCommandError:
        - CommandInvokeError: sends "An error occurred while executing this command." and logs the original underlying exception.
        - CheckFailure: sends "You don't have permission to use this command."
        - Other AppCommandError: sends "Something went wrong with this command!" and logs the error.
        
        Parameters:
            interaction (discord.Interaction): The interaction associated with the failed command; an ephemeral response is sent on this interaction.
            error (app_commands.AppCommandError): The exception raised during command invocation.
        """
        debug_print("Entered on_app_command_error", level="all")
        if isinstance(error, app_commands.CommandInvokeError):
            await interaction.response.send_message(
                "An error occurred while executing this command.",
                ephemeral=True
            )
            debug_print(f"Command error: {error.original}")
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
            debug_print(f"Command error: {error}")

async def setup(bot):
    """
    Add the GlobalCommands cog to the given bot.
    
    This async setup function is the entry point used by the bot to load this cog; it instantiates GlobalCommands with the provided bot and registers it via bot.add_cog.
    """
    await bot.add_cog(GlobalCommands(bot))