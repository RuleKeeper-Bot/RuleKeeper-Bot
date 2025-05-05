import discord
from discord import app_commands
from discord.ext import commands
from functools import partial
from bot.bot import log_event
from typing import Optional
import re

class UtilitiesCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.db = bot.db
        
    @staticmethod
    def validate_command_name(name: str) -> bool:
        """Validate command name format"""
        return re.fullmatch(r'^[\w-]{1,32}$', name) is not None
    
    @app_commands.command(name="create_command", description="Create a custom command")
    @app_commands.describe(
        command_name="Command name (no spaces)",
        content="Response content",
        description="Command description",
        ephemeral="Hide response from others"
    )
    @app_commands.checks.has_permissions(administrator=True)
    async def create_custom_command(
        self,
        interaction: discord.Interaction,
        command_name: str,
        content: str,
        description: str = "Custom command",
        ephemeral: bool = True
    ):
        guild_id = str(interaction.guild.id)

        # Validate command name
        if not self.validate_command_name(command_name):
            await interaction.response.send_message(
                "Invalid command name! Use 1-32 letters, numbers, hyphens or underscores",
                ephemeral=True
            )
            return

        # Create command data dictionary
        cmd_data = {
            'guild_id': guild_id,
            'command_name': command_name,
            'content': content,
            'description': description,
            'ephemeral': ephemeral
        }

        # Check for existing command
        existing = self.db.get_command(guild_id, command_name)
        if existing:
            await interaction.response.send_message(
                f"Command '/{command_name}' already exists in this server!",
                ephemeral=True
            )
            return

        # Create proper callback with closure
        async def command_callback(interaction: discord.Interaction):
            await self.handle_custom_command(interaction, cmd_data)

        try:
            # Insert into database
            self.db.add_command(
                guild_id=guild_id,
                command_name=command_name,
                description=description,
                content=content,
                ephemeral=ephemeral
            )

            # Create and register command
            cmd = app_commands.Command(
                name=command_name,
                description=description,
                callback=command_callback
            )
            
            # Store in bot registry
            self.bot._command_registry[f"{guild_id}_{command_name}"] = cmd_data
            
            # Add to command tree
            self.bot.tree.add_command(cmd, guild=interaction.guild)
            await self.bot.tree.sync(guild=interaction.guild)

            await interaction.response.send_message(
                f"Command '/{command_name}' created successfully!",
                ephemeral=True
            )

        except Exception as e:
            await interaction.response.send_message(
                f"Failed to create command: {str(e)}",
                ephemeral=True
            )
            traceback.print_exc()

    async def handle_custom_command(self, interaction: discord.Interaction, cmd_data: dict):
        """Handler for custom commands"""
        try:
            response = cmd_data['content']
            ephemeral = cmd_data.get('ephemeral', True)
            
            # Handle different response types
            if response.startswith(('http://', 'https://')):
                if any(response.lower().endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif']):
                    embed = discord.Embed().set_image(url=response)
                    await interaction.response.send_message(embed=embed, ephemeral=ephemeral)
                else:
                    await interaction.response.send_message(response, ephemeral=ephemeral)
            else:
                await interaction.response.send_message(response, ephemeral=ephemeral)
                
        except Exception as e:
            await interaction.response.send_message(
                "❌ Error executing command",
                ephemeral=True
            )
            print(f"Custom command error: {str(e)}")

    @app_commands.command(name="delete_command", description="Remove a custom command")
    @app_commands.describe(command_name="Name of command to remove")
    @app_commands.checks.has_permissions(administrator=True)
    async def delete_command(self, interaction: discord.Interaction, command_name: str):
        guild_id = str(interaction.guild.id)
        
        # Find command in database
        cmd = self.db.conn.execute('''
            SELECT * FROM commands 
            WHERE command_name = ? AND (guild_id = ? OR guild_id = '0')
        ''', (command_name, guild_id)).fetchone()
        
        if not cmd:
            await interaction.response.send_message(
                f"Command '/{command_name}' not found!",
                ephemeral=True
            )
            return
            
        # Delete from database
        self.db.conn.execute('''
            DELETE FROM commands 
            WHERE command_name = ? AND guild_id = ?
        ''', (command_name, cmd['guild_id']))
        self.db.conn.commit()
        
        # Remove from command tree
        try:
            if cmd['guild_id'] == '0':
                self.tree.remove_command(command_name)
                await self.bot.tree.sync()
            else:
                self.tree.remove_command(command_name, guild=interaction.guild)
                await self.bot.tree.sync(guild=interaction.guild)
        except Exception as e:
            await interaction.response.send_message(
                f"Command deleted but sync failed: {str(e)}",
                ephemeral=True
            )
            return

        await interaction.response.send_message(
            f"Command '/{command_name}' deleted successfully!",
            ephemeral=True
        )
                
    @app_commands.command(name="purge", description="Delete a specified number of messages")
    @app_commands.describe(
        amount="Number of messages to delete",
        user="User whose messages should be deleted (optional)",
        contains="Only delete messages containing this text (optional)"
    )
    @app_commands.checks.has_permissions(manage_messages=True)
    async def purge(self, interaction: discord.Interaction, amount: int, user: discord.User = None, contains: str = None):
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
            
        # Get guild-specific log config from database
        await log_event(
            interaction.guild,
            "message_delete",
            "Messages Purged",
            description,
            color=discord.Color.red()
        )

        await interaction.followup.send(f"Successfully deleted {len(deleted)} messages.", ephemeral=True)

    @purge.error
    async def purge_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message("You don't have permission to use this command.", ephemeral=True)
        else:
            await interaction.response.send_message("An error occurred while executing this command.", ephemeral=True)
            print(f"Purge command error: {error}")
                
    @app_commands.command(name="purge_after", description="Delete messages after a specific message ID")
    @app_commands.describe(
        message_id="The message ID to start purging after",
        count="Number of messages to delete after the specified message ID (optional, max 100)"
    )
    @app_commands.checks.has_permissions(manage_messages=True)
    async def purge_after(self, interaction: discord.Interaction, message_id: str, count: int = 100):
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

            # Log the action using database configuration
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
    async def purge_after_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError):
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message("❌ You need manage messages permissions to use this command.", ephemeral=True)
        else:
            await interaction.response.send_message("⚠️ An error occurred while processing this command.", ephemeral=True)
            print(f"Purge After Error: {str(error)}")
            
    @app_commands.command(name="messages", description="Check a user's message count")
    @app_commands.describe(user="The user to check (optional)")
    async def message_count(self, interaction: discord.Interaction, user: Optional[discord.User] = None):
        # Set user to interaction.user if not provided
        if user is None:
            user = interaction.user
        
        guild_id = str(interaction.guild.id)
        user_id = str(user.id)
        
        # Get message count from database
        user_data = self.db.execute_query(
            '''SELECT message_count FROM user_levels 
            WHERE guild_id = ? AND user_id = ?''',
            (guild_id, user_id),
            fetch='one'
        )
        
        count = user_data['message_count'] if user_data else 0
        
        await interaction.response.send_message(
            embed=discord.Embed(
                title="Message Count",
                description=f"{user.mention} has sent **{count}** messages in this server",
                color=discord.Color.blue()
            )
        )
                
    @app_commands.command(name="setlogchannel", description="Set the channel for logging events")
    @app_commands.describe(channel="The channel to use for logging")
    @app_commands.checks.has_permissions(administrator=True)
    async def set_log_channel(self, interaction: discord.Interaction, channel: discord.TextChannel):
        if not isinstance(channel, discord.TextChannel):
            await interaction.response.send_message("❌ Must be a text channel", ephemeral=True)
            return
            
        guild_id = str(interaction.guild.id)
        self.db.update_log_config(guild_id, log_channel_id=str(channel.id))
            
        await interaction.response.send_message(
            f"Log channel set to {channel.mention}",
            ephemeral=True
        )
            
        await log_event(
            interaction.guild,
            "log_config_update",
            "Log Channel Configured",
            f"Log channel set to {channel.mention} by {interaction.user.mention}",
            color=discord.Color.green()
        )
    
    async def custom_command_handler(self, interaction: discord.Interaction, cmd_data: dict):
        """Handler for database-stored commands"""
        try:
            await interaction.response.send_message(
                content=cmd_data['content'],
                ephemeral=bool(cmd_data.get('ephemeral', True))
            )
        except Exception as e:
            await interaction.response.send_message("Command error!", ephemeral=True)
            print(f"Custom command error: {str(e)}")
        
async def setup(bot):
    await bot.add_cog(UtilitiesCog(bot))