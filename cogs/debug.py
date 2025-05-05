import discord
from discord import app_commands
from discord.ext import commands
import asyncio
import logging
import sqlite3
from datetime import datetime
from collections import defaultdict

class DebugCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.db = bot.db

    # @app_commands.command(name="safe_sync_command")
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
    # async def check_commands(self, interaction: discord.Interaction):
        # """Verify command registrations"""
        # global_cmds = await self.bot.tree.fetch_commands()
        # guild_cmds = await self.bot.tree.fetch_commands(guild=interaction.guild)
        
        # embed = discord.Embed(title="Command Status")
        # embed.add_field(name="Global", value="\n".join([c.name for c in global_cmds]))
        # embed.add_field(name="Guild", value="\n".join([c.name for c in guild_cmds]))
        
        # await interaction.response.send_message(embed=embed)
    
    # @app_commands.command(name="command_debug", description="Show command registration status")
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
    @app_commands.checks.has_permissions(administrator=True)
    async def list_commands(self, interaction: discord.Interaction):
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
    
    async def _update_message_counts(self, message_counts, guild_id: str):
        """Atomic update with retry logic"""
        retries = 0
        while retries < 3:
            try:
                with self.db.conn:
                    for user_id, count in message_counts.items():
                        self.db.conn.execute('''
                            INSERT INTO user_levels (guild_id, user_id, message_count)
                            VALUES (?, ?, ?)
                            ON CONFLICT(guild_id, user_id) 
                            DO UPDATE SET 
                                message_count = message_count + excluded.message_count
                        ''', (guild_id, user_id, count))
                return
            except sqlite3.OperationalError as e:
                if "locked" in str(e):
                    retries += 1
                    await asyncio.sleep(2 ** retries)
                else:
                    raise
        raise Exception("Failed to update after 3 retries")
    
    # @app_commands.command(name="backfillmessages", description="Backfill historical message counts (Admin)")
    # @app_commands.checks.has_permissions(administrator=True)
    # async def backfill_messages(self, interaction: discord.Interaction):
        # """Backfill message counts from channel history with concurrency control"""
        # await interaction.response.defer(ephemeral=True)
        
        # guild = interaction.guild
        # guild_id = str(guild.id)
        # start_time = datetime.now()
        # message_counts = defaultdict(int)
        # processed_channels = 0
        # total_messages = 0
        # lock_retries = 0
        # max_retries = 3
        
        # # Ensure message_count column exists
        # try:
            # self.db.conn.execute('''
                # ALTER TABLE user_levels 
                # ADD COLUMN IF NOT EXISTS message_count INTEGER DEFAULT 0
            # ''')
            # self.db.conn.commit()
        # except sqlite3.OperationalError:
            # pass  # Column already exists
        
        # # Get text channels sorted by position
        # channels = sorted(guild.text_channels, key=lambda c: c.position)
        
        # for channel in channels:
            # try:
                # # Check permissions and channel type
                # if not isinstance(channel, discord.TextChannel):
                    # continue
                    
                # if not channel.permissions_for(guild.me).read_message_history:
                    # continue

                # # Process channel history in batches
                # batch_count = 0
                # async for message in channel.history(limit=None, oldest_first=True):
                    # if message.author.bot:
                        # continue
                        
                    # user_id = str(message.author.id)
                    # message_counts[user_id] += 1
                    # total_messages += 1
                    # batch_count += 1
                    
                    # # Commit every 500 messages to reduce locking
                    # if batch_count % 500 == 0:
                        # await self._update_message_counts(message_counts, guild_id)
                        # message_counts.clear()
                        # await asyncio.sleep(1)  # Release lock

                # # Final batch commit for channel
                # if message_counts:
                    # await self._update_message_counts(message_counts, guild_id)
                    # message_counts.clear()
                    
                # processed_channels += 1
                
                # # Progress update
                # elapsed = (datetime.now() - start_time).total_seconds()
                # await interaction.followup.send(
                    # f"✅ Processed {channel.mention} ({processed_channels}/{len(channels)})\n"
                    # f"• Messages: {total_messages:,}\n"
                    # f"• Elapsed: {elapsed:.1f}s",
                    # ephemeral=True
                # )
                
                # # Rate limit buffer
                # await asyncio.sleep(5)

            # except Exception as e:
                # logging.error(f"Channel {channel.name} error: {str(e)}", exc_info=True)
                # await interaction.followup.send(
                    # f"⚠️ Stopped at {channel.mention} due to error: {str(e)}",
                    # ephemeral=True
                # )
                # return

        # # Final report
        # elapsed = (datetime.now() - start_time).total_seconds()
        # await interaction.followup.send(
            # f"🏁 Backfill complete!\n"
            # f"• Channels processed: {processed_channels}/{len(channels)}\n"
            # f"• Total messages: {total_messages:,}\n"
            # f"• Time taken: {elapsed:.1f} seconds\n"
            # f"• Avg speed: {total_messages/elapsed:.1f} msg/s",
            # ephemeral=True
        # )
    
    # @app_commands.command(name="sync", description="Force command synchronization")
    # @app_commands.checks.has_permissions(administrator=True)
    # async def sync_commands(self, interaction: discord.Interaction):
        # """Force a full command synchronization"""
        # await interaction.response.defer(ephemeral=True)
        
        # report = ["**Synchronization Report**"]
        
        # try:
            # # Global sync
            # global_count = len(await self.bot.tree.sync())
            # report.append(f"🌐 Global commands: {global_count} synced")
            
            # # Guild sync with detailed status
            # guild_sync_count = 0
            # for guild in self.bot.guilds:
                # try:
                    # if guild.unavailable:
                        # report.append(f"⏸️ {guild.name} unavailable")
                        # continue
                    
                    # guild_count = len(await self.bot.tree.sync(guild=guild))
                    # report.append(f"✅ {guild.name}: {guild_count} commands synced")
                    # guild_sync_count += 1
                    # await asyncio.sleep(2)  # Rate limit buffer
                    
                # except Exception as e:
                    # report.append(f"⚠️ {guild.name} failed: {str(e)}")
            
            # report.append(f"\n**Total guilds synced:** {guild_sync_count}")
            
        # except Exception as e:
            # report.append(f"❌ Critical error: {str(e)}")
        
        # await interaction.followup.send("\n".join(report), ephemeral=True)
        
    # @app_commands.command(name="command_count")
    # async def command_count(self, interaction: discord.Interaction):
        # """Show registered command counts"""
        # global_commands = await self.bot.tree.fetch_commands()
        # guild_commands = await self.bot.tree.fetch_commands(guild=interaction.guild)
        
        # embed = discord.Embed(title="Command Status")
        # embed.add_field(name="Global Commands", value=str(len(global_commands)))
        # embed.add_field(name="Guild Commands", value=str(len(guild_commands)))
        
        # await interaction.response.send_message(embed=embed, ephemeral=True)
        
    # @app_commands.command(name="dbcheck")
    # @app_commands.checks.has_permissions(administrator=True)
    # async def db_check(self, interaction: discord.Interaction):
        # """Check database command entries"""
        # guild_id = str(interaction.guild.id)
        # commands = self.bot.db.conn.execute(
            # 'SELECT command_name FROM commands WHERE guild_id = ?',
            # (guild_id,)
        # ).fetchall()
        
        # embed = discord.Embed(title="Database Command Check")
        # embed.add_field(
            # name="Entries",
            # value="\n".join([c['command_name'] for c in commands]) or "None"
        # )
        # await interaction.response.send_message(embed=embed, ephemeral=True)
        
async def setup(bot):
    await bot.add_cog(DebugCog(bot))