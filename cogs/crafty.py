"""
Crafty Controller Bot Commands
Discord commands for managing Minecraft servers through Crafty Controller
"""

import discord
from discord.ext import commands
from discord import app_commands
from typing import Optional
from shared import command_permission_check
from shared.colors import red
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

class CraftyCog(commands.Cog):
    def __init__(self, bot):
        debug_print(f"Entering CraftyCog.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.db = bot.db
        
        # Import managers here to avoid circular imports
        from shared.crafty_api import CraftyManager
        self.crafty_manager = CraftyManager(self.db)

    async def get_server_choices(self, interaction: discord.Interaction, current: str):
        """Autocomplete function for server names"""
        try:
            guild_id = str(interaction.guild.id)
            servers = self.db.get_guild_crafty_servers(guild_id)
            
            # Filter servers based on current input
            filtered_servers = [
                server for server in servers 
                if current.lower() in server['server_name'].lower()
            ][:25]  # Discord limits to 25 choices
            
            return [
                app_commands.Choice(name=server['server_name'], value=server['server_name'])
                for server in filtered_servers
            ]
        except Exception as e:
            debug_print(red(f"Error in server autocomplete: {str(e)}", level="all"))
            return []

    @app_commands.command(name="crafty_start", description="Start a Minecraft server through Crafty Controller")
    @command_permission_check("crafty_start")
    @app_commands.describe(server_name="Name of the server to start")
    @app_commands.autocomplete(server_name=get_server_choices)
    async def start_crafty_server(self, interaction: discord.Interaction, server_name: str):
        """Start a Minecraft server"""
        debug_print(f"Start crafty server command called by {interaction.user.id} for server {server_name}", level="all")
        
        await interaction.response.defer(ephemeral=True)
        
        try:
            guild_id = str(interaction.guild.id)
            user_id = str(interaction.user.id)
            user_roles = [str(role.id) for role in interaction.user.roles]
            
            # Check if server is already running
            server = await self.crafty_manager.get_server_for_command(guild_id, server_name)
            if server:
                client = await self.crafty_manager.get_client(server['crafty_instance_id'])
                if client:
                    async with client:
                        status = await client.get_server_status(server['server_id'])
                        if status and status.get('running', False):
                            embed = discord.Embed(
                                title="ℹ️ Server Already Running",
                                description=f"Server '{server_name}' is already running.",
                                color=discord.Color.blue()
                            )
                            embed.add_field(name="Server", value=server_name, inline=True)
                            embed.add_field(name="Status", value="Already Online", inline=True)
                            embed.add_field(name="Requested by", value=interaction.user.mention, inline=True)
                            
                            await interaction.followup.send(embed=embed, ephemeral=True)
                            return
            
            success, message = await self.crafty_manager.perform_server_action(
                guild_id, server_name, 'start', user_id, user_roles
            )
            
            embed = discord.Embed(
                title="🎮 Server Start Command",
                description=message,
                color=discord.Color.green() if success else discord.Color.red()
            )
            embed.add_field(name="Server", value=server_name, inline=True)
            embed.add_field(name="Action", value="Start", inline=True)
            embed.add_field(name="Requested by", value=interaction.user.mention, inline=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in start_crafty_server: {e}", level="all"))
            embed = discord.Embed(
                title="❌ Error",
                description="An error occurred while starting the server.",
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="crafty_stop", description="Stop a Minecraft server through Crafty Controller")
    @command_permission_check("crafty_stop")
    @app_commands.describe(server_name="Name of the server to stop")
    @app_commands.autocomplete(server_name=get_server_choices)
    async def stop_crafty_server(self, interaction: discord.Interaction, server_name: str):
        """Stop a Minecraft server"""
        debug_print(f"Stop crafty server command called by {interaction.user.id} for server {server_name}", level="all")
        
        await interaction.response.defer(ephemeral=True)
        
        try:
            guild_id = str(interaction.guild.id)
            user_id = str(interaction.user.id)
            user_roles = [str(role.id) for role in interaction.user.roles]
            
            # Check if server is already stopped
            server = await self.crafty_manager.get_server_for_command(guild_id, server_name)
            if server:
                client = await self.crafty_manager.get_client(server['crafty_instance_id'])
                if client:
                    async with client:
                        status = await client.get_server_status(server['server_id'])
                        if status and not status.get('running', True):  # Default to True if status unknown
                            embed = discord.Embed(
                                title="ℹ️ Server Already Stopped",
                                description=f"Server '{server_name}' is already stopped.",
                                color=discord.Color.blue()
                            )
                            embed.add_field(name="Server", value=server_name, inline=True)
                            embed.add_field(name="Status", value="Already Offline", inline=True)
                            embed.add_field(name="Requested by", value=interaction.user.mention, inline=True)
                            
                            await interaction.followup.send(embed=embed, ephemeral=True)
                            return
            
            success, message = await self.crafty_manager.perform_server_action(
                guild_id, server_name, 'stop', user_id, user_roles
            )
            
            embed = discord.Embed(
                title="🛑 Server Stop Command",
                description=message,
                color=discord.Color.orange() if success else discord.Color.red()
            )
            embed.add_field(name="Server", value=server_name, inline=True)
            embed.add_field(name="Action", value="Stop", inline=True)
            embed.add_field(name="Requested by", value=interaction.user.mention, inline=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in stop_crafty_server: {e}", level="all"))
            embed = discord.Embed(
                title="❌ Error",
                description="An error occurred while stopping the server.",
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="crafty_restart", description="Restart a Minecraft server through Crafty Controller")
    @command_permission_check("crafty_restart")
    @app_commands.describe(server_name="Name of the server to restart")
    @app_commands.autocomplete(server_name=get_server_choices)
    async def restart_crafty_server(self, interaction: discord.Interaction, server_name: str):
        """Restart a Minecraft server"""
        debug_print(f"Restart crafty server command called by {interaction.user.id} for server {server_name}", level="all")
        
        await interaction.response.defer(ephemeral=True)
        
        try:
            guild_id = str(interaction.guild.id)
            user_id = str(interaction.user.id)
            user_roles = [str(role.id) for role in interaction.user.roles]
            
            success, message = await self.crafty_manager.perform_server_action(
                guild_id, server_name, 'restart', user_id, user_roles
            )
            
            embed = discord.Embed(
                title="🔄 Server Restart Command",
                description=message,
                color=discord.Color.blue() if success else discord.Color.red()
            )
            embed.add_field(name="Server", value=server_name, inline=True)
            embed.add_field(name="Action", value="Restart", inline=True)
            embed.add_field(name="Requested by", value=interaction.user.mention, inline=True)
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in restart_crafty_server: {e}", level="all"))
            embed = discord.Embed(
                title="❌ Error",
                description="An error occurred while restarting the server.",
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed, ephemeral=True)

    @app_commands.command(name="crafty_servers", description="List all available Minecraft servers")
    @command_permission_check("crafty_servers")
    async def list_crafty_servers(self, interaction: discord.Interaction):
        """List all available Minecraft servers"""
        debug_print(f"List crafty servers command called by {interaction.user.id}", level="all")
        
        await interaction.response.defer(ephemeral=True)
        
        try:
            guild_id = str(interaction.guild.id)
            servers = self.db.get_guild_crafty_servers(guild_id)
            
            if not servers:
                embed = discord.Embed(
                    title="📋 Minecraft Servers",
                    description="No Minecraft servers are configured for this server.",
                    color=discord.Color.orange()
                )
                embed.add_field(
                    name="Configure Servers",
                    value="Ask a server administrator to configure Crafty Controller instances through the web dashboard.",
                    inline=False
                )
                await interaction.followup.send(embed=embed, ephemeral=True)
                return
            
            embed = discord.Embed(
                title="📋 Available Minecraft Servers",
                description=f"Found {len(servers)} server(s) available for management:",
                color=discord.Color.blue()
            )
            
            # Group servers by instance
            instances = {}
            for server in servers:
                instance_name = server['instance_name']
                if instance_name not in instances:
                    instances[instance_name] = []
                instances[instance_name].append(server)
            
            for instance_name, instance_servers in instances.items():
                server_list = []
                for server in instance_servers:
                    port_text = f" (Port: {server['port']})" if server['port'] else ""
                    server_list.append(f"• **{server['server_name']}**{port_text}")
                
                embed.add_field(
                    name=f"🖥️ {instance_name}",
                    value="\n".join(server_list) or "No servers",
                    inline=False
                )
            
            embed.set_footer(text="Use /start_crafty_server, /stop_crafty_server, or /restart_crafty_server to manage these servers.")
            
            await interaction.followup.send(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in list_crafty_servers: {e}", level="all"))
            embed = discord.Embed(
                title="❌ Error",
                description="An error occurred while listing servers.",
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed, ephemeral=True)
    
    @app_commands.command(name="crafty_status", description="Get detailed server status data from Crafty Controller")
    @command_permission_check("crafty_status")
    @app_commands.describe(server_name="Name of the server to check status")
    @app_commands.autocomplete(server_name=get_server_choices)
    async def crafty_status(self, interaction: discord.Interaction, server_name: str):
        """Get detailed server status data from Crafty Controller"""
        debug_print(f"Crafty status command called by {interaction.user.id} for server {server_name}", level="all")
        
        await interaction.response.defer(ephemeral=True)
        
        try:
            guild_id = str(interaction.guild.id)
            
            # Get server info
            server = await self.crafty_manager.get_server_for_command(guild_id, server_name)
            if not server:
                embed = discord.Embed(
                    title="❌ Server Not Found",
                    description=f"Server '{server_name}' was not found.",
                    color=discord.Color.red()
                )
                await interaction.followup.send(embed=embed, ephemeral=True)
                return
            
            # Get Crafty client and fetch raw data
            client = await self.crafty_manager.get_client(server['crafty_instance_id'])
            if not client:
                embed = discord.Embed(
                    title="❌ Connection Failed",
                    description="Failed to connect to Crafty Controller instance.",
                    color=discord.Color.red()
                )
                await interaction.followup.send(embed=embed, ephemeral=True)
                return
            
            async with client:
                embed = discord.Embed(
                    title=f"🔍 Status Data: {server_name}",
                    color=discord.Color.blue()
                )
                
                # Try the stats endpoint first (real-time status)
                try:
                    stats_response = await client._make_request('GET', f'/servers/{server["server_id"]}/stats')
                    stats_data = stats_response.get('data', {})
                    
                    if stats_data:
                        # Show key status fields first
                        key_fields = ['running', 'online', 'cpu', 'mem', 'started', 'players', 'max', 'server_port', 'version']
                        shown_fields = []
                        other_fields = []
                        
                        for k, v in stats_data.items():
                            if k in key_fields:
                                shown_fields.append(f"• **{k}**: `{v}`")
                            else:
                                other_fields.append(f"• **{k}**: `{v}`")
                        
                        stats_text = "\n".join(shown_fields[:11])
                        if other_fields:
                            stats_text += f"\n... and {len(other_fields)} more fields"
                    else:
                        stats_text = "No data returned"
                        
                    embed.add_field(
                        name="⚡ /stats Endpoint (Real-time)",
                        value=stats_text or "Empty response",
                        inline=False
                    )
                except Exception as e:
                    embed.add_field(
                        name="⚡ /stats Endpoint (Real-time)",
                        value=f"Error: {str(e)}",
                        inline=False
                    )
                
                embed.add_field(
                    name="📋 Server Info",
                    value=f"**Server ID**: `{server['server_id']}`",
                    inline=False
                )
                
                await interaction.followup.send(embed=embed, ephemeral=True)
                
        except Exception as e:
            debug_print(red(f"Error in crafty_status: {e}", level="all"))
            embed = discord.Embed(
                title="❌ Error",
                description="An error occurred while getting server status data.",
                color=discord.Color.red()
            )
            await interaction.followup.send(embed=embed, ephemeral=True)

async def setup(bot):
    debug_print(f"Setting up CraftyCog", level="all")
    await bot.add_cog(CraftyCog(bot))