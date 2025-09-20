import discord
from discord import app_commands
from discord.ext import commands
import asyncio
import logging
import sqlite3
from datetime import datetime
from collections import defaultdict
from shared import command_permission_check
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        """
        No-op fallback for debug printing.
        
        This function intentionally does nothing; it accepts any positional and keyword arguments to match the signature of the real `debug_print` used elsewhere so callers can invoke it safely when a real debug logger is not available.
        
        Parameters:
            *args: Ignored positional arguments.
            **kwargs: Ignored keyword arguments.
        
        Returns:
            None
        """
        pass

class DebugCog(commands.Cog):
    def __init__(self, bot):
        """
        Initialize the DebugCog.
        
        Stores the provided bot instance on self.bot and caches its database connection on self.db.
        """
        debug_print(f"Entering DebugCog.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.db = bot.db

    # @app_commands.command(name="safe_sync_command")
    # @command_permission_check("safe_sync_command")
    # @app_commands.checks.has_permissions(administrator=True)
    # async def safe_sync_command(self, interaction: discord.Interaction):
        # """Safe command sync with rate limit handling"""
        # await interaction.response.defer()
        
        # success = await self.bot.safe_sync()
        # if success:
            # await interaction.followup.send("✅ Sync completed")
        # else:
            # await interaction.followup.send("❌ Sync failed due to rate limits")
    
    # @app_commands.command(name="checkcmds")
    # @command_permission_check("checkcmds")
    # async def check_commands(self, interaction: discord.Interaction):
        # """Verify command registrations"""
        # global_cmds = await self.bot.tree.fetch_commands()
        # guild_cmds = await self.bot.tree.fetch_commands(guild=interaction.guild)
        
        # embed = discord.Embed(title="Command Status")
        # embed.add_field(name="Global", value="\n".join([c.name for c in global_cmds]))
        # embed.add_field(name="Guild", value="\n".join([c.name for c in guild_cmds]))
        
        # await interaction.response.send_message(embed=embed)
    
    # @app_commands.command(name="command_debug", description="Show command registration status")
    # @command_permission_check("command_debug")
    # async def command_debug(self, interaction: discord.Interaction):
        # """Verify command registration"""
        # await interaction.response.defer(ephemeral=True)
        
        # # Get registered global commands
        # global_commands = await self.bot.tree.fetch_commands()
        # global_names = [c.name for c in global_commands]
        
        # # Get guild commands
        # guild_commands = await self.bot.tree.fetch_commands(guild=interaction.guild)
        # guild_names = [c.name for c in guild_commands]
        
        # # Get database commands
        # db_commands = self.db.get_guild_commands(str(interaction.guild.id))
        # db_names = [c['command_name'] for c in db_commands]
        
        # embed = discord.Embed(title="Command Debug", color=0x00ff00)
        # embed.add_field(name="Global Commands", value="\n".join(global_names) or "None")
        # embed.add_field(name="Guild Commands", value="\n".join(guild_names) or "None")
        # embed.add_field(name="Database Commands", value="\n".join(db_names) or "None")
        
        # await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="list_commands", description="Show all custom commands")
    @command_permission_check("list_commands")
    @app_commands.checks.has_permissions(administrator=True)
    async def list_commands(self, interaction: discord.Interaction):
        """
        Show the guild's configured custom commands in an ephemeral embed to the invoking user.
        
        Builds a Discord embed titled for the current guild and lists each custom command (name, short description, truncated response). Long lists are split into multiple embed fields to avoid Discord field-length limits. Sends the embed as an ephemeral response to the provided interaction.
        
        Parameters:
            interaction (discord.Interaction): The interaction that invoked the command — used to determine the guild, author and to send the ephemeral reply.
        
        Notes:
            - Command descriptions are truncated to 25 characters and responses to 30 characters in the embed.
            - Fields are split when a field's accumulated text would exceed ~1000 characters.
            - This command requires the caller to pass the permission check applied by decorators (administrator privileges and the "list_commands" permission check).
        """
        debug_print(f"Entering /list_commands with interaction: {interaction}", level="all")
        guild_id = str(interaction.guild.id)
        commands = self.db.get_guild_commands_list(guild_id)
        
        embed = discord.Embed(
            title=f"Custom Commands for {interaction.guild.name}",
            color=discord.Color.blue()
        )
        
        if not commands:
            embed.description = "No custom commands configured"
        else:
            current_field = []
            current_length = 0
            field_number = 1
            
            for cmd in commands:
                entry = (
                    f"**/{cmd['command_name']}**\n"
                    f"Desc: {cmd.get('description', 'No description')[:25]}\n"
                    f"Response: {cmd.get('content', 'No content')[:30]}...\n\n"
                )
                
                # Check if adding this entry would exceed the limit
                if current_length + len(entry) > 1000:  # Leave buffer for markdown
                    embed.add_field(
                        name=f"Commands ({field_number})",
                        value="".join(current_field),
                        inline=False
                    )
                    current_field = []
                    current_length = 0
                    field_number += 1
                    
                current_field.append(entry)
                current_length += len(entry)
            
            # Add remaining commands
            if current_field:
                embed.add_field(
                    name=f"Commands ({field_number})",
                    value="".join(current_field),
                    inline=False
                )
                
            embed.set_footer(text=f"Total commands: {len(commands)}")
        
        await interaction.response.send_message(embed=embed, ephemeral=True)

async def setup(bot):
    """
    Register the DebugCog with the given bot.
    
    Adds an instance of DebugCog to the bot so its application command(s) become available.
    """
    await bot.add_cog(DebugCog(bot))