import discord
from discord import app_commands
from discord.ext import commands

class GlobalCommands(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.db = bot.db

# -------------------- Error Handling --------------------    
    @commands.Cog.listener()
    async def on_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
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

async def setup(bot):
    await bot.add_cog(GlobalCommands(bot))