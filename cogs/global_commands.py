import discord
from discord import app_commands
from discord.ext import commands
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

class GlobalCommands(commands.Cog):
    def __init__(self, bot):
        debug_print("Entered GlobalCommands.__init__", level="all")
        self.bot = bot
        self.db = bot.db

# -------------------- Error Handling --------------------    
    @commands.Cog.listener()
    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
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
    await bot.add_cog(GlobalCommands(bot))