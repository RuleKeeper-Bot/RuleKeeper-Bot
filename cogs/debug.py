import discord
from discord import app_commands
from discord.ext import commands
import asyncio

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
        commands = self.db.get_guild_commands(guild_id)
        
        embed = discord.Embed(
            title=f"Custom Commands for {interaction.guild.name}",
            color=discord.Color.blue()
        )
        
        if not commands:
            embed.description = "No custom commands configured"
        else:
            command_list = []
            for cmd in commands:
                command_list.append(
                    f"**/{cmd['command_name']}**\n"
                    f"Description: {cmd['description']}\n"
                    f"Response: {cmd['content'][:50]}..."
                )
            embed.add_field(
                name=f"Total Commands: {len(commands)}",
                value="\n\n".join(command_list),
                inline=False
            )
        
        await interaction.response.send_message(embed=embed, ephemeral=True)
    
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