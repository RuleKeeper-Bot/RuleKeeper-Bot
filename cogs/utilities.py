import discord
from discord import app_commands
from discord.ext import commands
from functools import partial
from bot.bot import log_event
from typing import Optional, Union
import re
import random
import string
import os
import traceback
import asyncio
import time
from pytz import timezone as pytz_timezone, all_timezones
from datetime import datetime, timedelta
from bot.bot import save_guild_backup, load_schedules, restore_guild_backup as restore
from backups.backups import get_backup, get_conn
from shared import command_permission_check
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

def random_id(length=6):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')

class ConfirmRestoreView(discord.ui.View):
    def __init__(self, timeout=30):
        super().__init__(timeout=timeout)
        self.value = None

    @discord.ui.button(label="Restore from Backup", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.value = True
        self.stop()
        await interaction.response.defer()  # Prevents "This interaction failed" message

class ContinueCancelView(discord.ui.View):
    def __init__(self, timeout=60):
        super().__init__(timeout=timeout)
        self.value = None

    @discord.ui.button(label="Continue", style=discord.ButtonStyle.danger)
    async def continue_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.value = True
        self.stop()
        await interaction.response.defer()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.value = False
        self.stop()
        await interaction.response.defer()

@app_commands.autocomplete(permissions=True)
async def permissions_autocomplete(
    interaction: discord.Interaction,
    current: str
) -> list[app_commands.Choice[str]]:
    """Autocomplete for Discord permissions."""
    all_perms = [
        'add_reactions', 'administrator', 'attach_files', 'ban_members', 'change_nickname', 'connect',
        'create_instant_invite', 'deafen_members', 'embed_links', 'kick_members', 'manage_channels',
        'manage_emojis_and_stickers', 'manage_events', 'manage_guild', 'manage_messages', 'manage_nicknames',
        'manage_roles', 'manage_threads', 'manage_webhooks', 'mention_everyone', 'moderate_members',
        'move_members', 'mute_members', 'priority_speaker', 'read_message_history', 'read_messages',
        'request_to_speak', 'send_messages', 'send_messages_in_threads', 'send_tts_messages', 'speak',
        'stream', 'use_application_commands', 'use_embedded_activities', 'use_external_emojis',
        'use_external_stickers', 'use_voice_activation', 'view_audit_log', 'view_channel', 'view_guild_insights'
    ]
    matches = [p for p in all_perms if current.lower() in p.lower()]
    return [app_commands.Choice(name=p.replace('_', ' ').title(), value=p) for p in matches[:25]]

class UtilitiesCog(commands.Cog):
    def __init__(self, bot):
        debug_print(f"Entering UtilitiesCog.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.db = bot.db
        
    @staticmethod
    def validate_command_name(name: str) -> bool:
        """Validate command name format"""
        return re.fullmatch(r'^[\w-]{1,32}$', name) is not None

    # Commands
    @app_commands.command(name="create_command", description="Create a custom command")
    @command_permission_check("create_command")
    @app_commands.describe(
        command_name="Command name (no spaces)",
        content="Response content",
        description="Command description",
        ephemeral="Hide response from others"
    )
    async def create_custom_command(
        self,
        interaction: discord.Interaction,
        command_name: str,
        content: str,
        description: str = "Custom command",
        ephemeral: bool = True
    ):
        debug_print(f"Entering /create_custom_command with interaction: {interaction}, command_name: {command_name}, content: {content}, description: {description}, ephemeral: {ephemeral}", level="all")
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
        @command_permission_check(command_name, is_custom=True)
        async def command_callback(self, interaction: discord.Interaction):
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
                callback=partial(command_callback, self)
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
        debug_print(f"Entering /handle_custom_command with interaction: {interaction}, cmd_data: {cmd_data}", level="all")
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
            debug_print(f"[Custom Command Error]: {str(e)}")

    @app_commands.command(name="delete_command", description="Remove a custom command")
    @command_permission_check("delete_command")
    @app_commands.describe(command_name="Name of command to remove")
    async def delete_command(self, interaction: discord.Interaction, command_name: str):
        debug_print(f"Entering /delete_command with interaction: {interaction}, command_name: {command_name}", level="all")
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
                self.bot.tree.remove_command(command_name)
                await self.bot.tree.sync()
            else:
                self.bot.tree.remove_command(command_name, guild=interaction.guild)
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
        
    @app_commands.command(name="role", description="Give or take a role from a user")
    @command_permission_check("role")
    @app_commands.describe(
        action="Give or take the role",
        role="Role to give or take",
        user="User to modify"
    )
    @app_commands.choices(action=[
        app_commands.Choice(name="Give", value="give"),
        app_commands.Choice(name="Take", value="take")
    ])
    async def role(
        self,
        interaction: discord.Interaction,
        action: app_commands.Choice[str],
        role: discord.Role,
        user: discord.Member
    ):
        debug_print(f"Entering /role with interaction: {interaction}, action: {action}, role: {role}, user: {user}", level="all")
        author = interaction.user

        # Check bot permissions
        if not interaction.guild.me.guild_permissions.manage_roles:
            await interaction.response.send_message(
                "I need the 'Manage Roles' permission to do this.", ephemeral=True
            )
            return

        # Check role hierarchy
        if role >= interaction.guild.me.top_role:
            await interaction.response.send_message(
                "I can't manage that role because it's higher than my top role.", ephemeral=True
            )
            return

        if action.value == "give":
            if role in user.roles:
                await interaction.response.send_message(
                    f"{user.mention} already has the {role.mention} role.", ephemeral=True
                )
                return
            try:
                await user.add_roles(role, reason=f"Role given by {author}")
                await interaction.response.send_message(
                    f"Gave {role.mention} to {user.mention}.", ephemeral=True
                )
            except discord.Forbidden:
                await interaction.response.send_message(
                    "I don't have permission to give that role.", ephemeral=True
                )
        elif action.value == "take":
            if role not in user.roles:
                await interaction.response.send_message(
                    f"{user.mention} does not have the {role.mention} role.", ephemeral=True
                )
                return
            try:
                await user.remove_roles(role, reason=f"Role removed by {author}")
                await interaction.response.send_message(
                    f"Removed {role.mention} from {user.mention}.", ephemeral=True
                )
            except discord.Forbidden:
                await interaction.response.send_message(
                    "I don't have permission to remove that role.", ephemeral=True
                )
        else:
            await interaction.response.send_message(
                "Invalid action. Use 'give' or 'take'.", ephemeral=True
            )
            
    @app_commands.command(name="create_role", description="Create a new role with optional permissions")
    @command_permission_check("create_role")
    @app_commands.describe(
        name="Name of the new role",
        color="Hex color (e.g. #7289da) or leave blank",
        permissions="Comma-separated permissions",
        mentionable="Allow everyone to mention this role",
        hoist="Display role separately from online members",
        perms_integer="Permissions integer (overrides permissions if provided)"
    )
    @app_commands.autocomplete(permissions=permissions_autocomplete)
    async def create_role(
        self,
        interaction: discord.Interaction,
        name: str,
        color: Optional[str] = None,
        permissions: Optional[str] = None,
        mentionable: bool = False,
        hoist: bool = False,
        perms_integer: Optional[int] = None
    ):
        debug_print(f"Entering /create_role with interaction: {interaction}, name: {name}, color: {color}, permissions: {permissions}, mentionable: {mentionable}, hoist: {hoist}", level="all")
        guild = interaction.guild
        if not guild:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return
        # Parse color
        role_color = None
        if color:
            try:
                if color.startswith('#'):
                    color = color[1:]
                role_color = discord.Color(int(color, 16))
            except Exception:
                await interaction.response.send_message("Invalid color format. Use hex like #7289da.", ephemeral=True)
                return
        # Parse permissions
        if perms_integer is not None:
            perms = discord.Permissions(perms_integer)
        else:
            perms = discord.Permissions.none()
            if permissions:
                perms_list = [p.strip() for p in permissions.split(',') if p.strip()]
                invalid = []
                for p in perms_list:
                    if hasattr(perms, p):
                        setattr(perms, p, True)
                    else:
                        invalid.append(p)
                if invalid:
                    await interaction.response.send_message(f"Invalid permission(s): {', '.join(invalid)}", ephemeral=True)
                    return
        try:
            new_role = await guild.create_role(
                name=name,
                colour=role_color or discord.Color.default(),
                permissions=perms,
                mentionable=mentionable,
                hoist=hoist,
                reason=f"Created by {interaction.user} via /create_role"
            )
            await interaction.response.send_message(f"✅ Created role {new_role.mention}", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to create roles.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Failed to create role: {e}", ephemeral=True)

    @app_commands.command(name="delete_role", description="Delete a role by name or mention")
    @command_permission_check("delete_role")
    @app_commands.describe(role="Role to delete")
    async def delete_role(
        self,
        interaction: discord.Interaction,
        role: discord.Role
    ):
        debug_print(f"Entering /delete_role with interaction: {interaction}, role: {role}", level="all")
        guild = interaction.guild
        if not guild:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return
        # Check bot permissions and hierarchy
        if not guild.me.guild_permissions.manage_roles:
            await interaction.response.send_message("I need the 'Manage Roles' permission to delete roles.", ephemeral=True)
            return
        if role >= guild.me.top_role:
            await interaction.response.send_message("I can't delete that role because it's higher than my top role.", ephemeral=True)
            return
        try:
            await role.delete(reason=f"Deleted by {interaction.user} via /delete_role")
            await interaction.response.send_message(f"✅ Deleted role `{role.name}`.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to delete that role.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Failed to delete role: {e}", ephemeral=True)
                
    @app_commands.command(name="edit_role", description="Edit a role's name, color, allowed/denied permissions, mentionable, or hoist")
    @command_permission_check("edit_role")
    @app_commands.describe(
        role="Role to edit",
        name="New name (leave blank to keep current)",
        color="New hex color (e.g. #7289da) or leave blank",
        allow_perms="Comma-separated permissions to allow (leave blank to keep current)",
        deny_perms="Comma-separated permissions to deny (leave blank to keep current)",
        mentionable="Allow everyone to mention this role",
        hoist="Display role separately from online members",
        perms_integer="Permissions integer (overrides allow/deny perms if provided)"
    )
    @app_commands.autocomplete(allow_perms=permissions_autocomplete, deny_perms=permissions_autocomplete)
    async def edit_role(
        self,
        interaction: discord.Interaction,
        role: discord.Role,
        name: Optional[str] = None,
        color: Optional[str] = None,
        allow_perms: Optional[str] = None,
        deny_perms: Optional[str] = None,
        mentionable: Optional[bool] = None,
        hoist: Optional[bool] = None,
        perms_integer: Optional[int] = None
    ):
        debug_print(f"Entering /edit_role with interaction: {interaction}, role: {role}, name: {name}, color: {color}, allow_perms: {allow_perms}, deny_perms: {deny_perms}, mentionable: {mentionable}, hoist: {hoist}", level="all")
        guild = interaction.guild
        if not guild:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return
        # Check bot permissions and hierarchy
        if not guild.me.guild_permissions.manage_roles:
            await interaction.response.send_message("I need the 'Manage Roles' permission to edit roles.", ephemeral=True)
            return
        if role >= guild.me.top_role:
            await interaction.response.send_message("I can't edit that role because it's higher than my top role.", ephemeral=True)
            return
        kwargs = {}
        if name:
            kwargs['name'] = name
        if color:
            try:
                kwargs['colour'] = discord.Color(int(color.lstrip('#'), 16))
            except Exception:
                await interaction.response.send_message("Invalid color format. Use hex like #7289da.", ephemeral=True)
                return
        # Permissions logic
        if perms_integer is not None:
            kwargs['permissions'] = discord.Permissions(perms_integer)
        elif allow_perms or deny_perms:
            perms = role.permissions.value
            allow = discord.Permissions(perms)
            deny = discord.Permissions.none()
            invalid_allow = []
            invalid_deny = []
            if allow_perms:
                for p in [perm.strip() for perm in allow_perms.split(',') if perm.strip()]:
                    if p in discord.Permissions.VALID_FLAGS:
                        setattr(allow, p, True)
                    else:
                        invalid_allow.append(p)
            if deny_perms:
                for p in [perm.strip() for perm in deny_perms.split(',') if perm.strip()]:
                    if p in discord.Permissions.VALID_FLAGS:
                        setattr(allow, p, False)
                        setattr(deny, p, True)
                    else:
                        invalid_deny.append(p)
            if invalid_allow or invalid_deny:
                msg = ""
                if invalid_allow:
                    msg += f"Invalid allow permissions: {', '.join(invalid_allow)}\n"
                if invalid_deny:
                    msg += f"Invalid deny permissions: {', '.join(invalid_deny)}"
                await interaction.response.send_message(msg, ephemeral=True)
                return
            kwargs['permissions'] = allow
        if mentionable is not None:
            kwargs['mentionable'] = mentionable
        if hoist is not None:
            kwargs['hoist'] = hoist
        try:
            await role.edit(reason=f"Edited by {interaction.user} via /edit_role", **kwargs)
            await interaction.response.send_message(f"✅ Edited role `{role.name}`.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to edit that role.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Failed to edit role: {e}", ephemeral=True)

    @app_commands.command(name="create_channel", description="Create a new text or voice channel")
    @command_permission_check("create_channel")
    @app_commands.describe(
        name="Name of the new channel",
        type="Type of channel (text or voice)",
        category="Category to create the channel in (optional)",
        perms_integer="Permissions integer for @everyone (optional, overrides default permissions)"
    )
    @app_commands.choices(type=[
        app_commands.Choice(name="Text", value="text"),
        app_commands.Choice(name="Voice", value="voice")
    ])
    async def create_channel(
        self,
        interaction: discord.Interaction,
        name: str,
        type: app_commands.Choice[str],
        category: Optional[discord.CategoryChannel] = None,
        perms_integer: Optional[int] = None
    ):
        debug_print(f"Entering /create_channel with interaction: {interaction}, name: {name}, type: {type}, category: {category}", level="all")
        guild = interaction.guild
        if not guild:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return
        if not guild.me.guild_permissions.manage_channels:
            await interaction.response.send_message("I need the 'Manage Channels' permission to create channels.", ephemeral=True)
            return
        try:
            overwrites = None
            if perms_integer is not None:
                everyone = guild.default_role
                overwrites = {everyone: discord.PermissionOverwrite.from_pair(discord.Permissions(perms_integer), discord.Permissions.none())}
            if type.value == "text":
                channel = await guild.create_text_channel(name=name, category=category, overwrites=overwrites, reason=f"Created by {interaction.user} via /create_channel")
            elif type.value == "voice":
                channel = await guild.create_voice_channel(name=name, category=category, overwrites=overwrites, reason=f"Created by {interaction.user} via /create_channel")
            else:
                await interaction.response.send_message("Invalid channel type.", ephemeral=True)
                return
            await interaction.response.send_message(f"✅ Created channel {channel.mention}", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to create channels.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Failed to create channel: {e}", ephemeral=True)

    @app_commands.command(name="delete_channel", description="Delete a channel by name or mention")
    @command_permission_check("delete_channel")
    @app_commands.describe(channel="Channel to delete")
    async def delete_channel(
        self,
        interaction: discord.Interaction,
        channel: discord.abc.GuildChannel
    ):
        debug_print(f"Entering /delete_channel with interaction: {interaction}, channel: {channel}", level="all")
        guild = interaction.guild
        if not guild:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return
        if not guild.me.guild_permissions.manage_channels:
            await interaction.response.send_message("I need the 'Manage Channels' permission to delete channels.", ephemeral=True)
            return
        try:
            await channel.delete(reason=f"Deleted by {interaction.user} via /delete_channel")
            await interaction.response.send_message(f"✅ Deleted channel `{channel.name}`.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to delete that channel.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Failed to delete channel: {e}", ephemeral=True)

    @app_commands.command(name="edit_channel", description="Edit a channel's name, topic, or position")
    @command_permission_check("edit_channel")
    @app_commands.describe(
        channel="Channel to edit",
        name="New name (leave blank to keep current)",
        topic="New topic (text channels only, leave blank to keep current)",
        position="New position in the channel list (leave blank to keep current)",
        target="Role or user to set permissions for (optional)",
        allow_perms="Comma-separated permissions to allow (optional)",
        deny_perms="Comma-separated permissions to deny (optional)",
        perms_integer="Permissions integer for target (optional, overrides allow/deny perms)"
    )
    @app_commands.autocomplete(allow_perms=permissions_autocomplete, deny_perms=permissions_autocomplete)
    async def edit_channel(
        self,
        interaction: discord.Interaction,
        channel: discord.abc.GuildChannel,
        name: Optional[str] = None,
        topic: Optional[str] = None,
        position: Optional[int] = None,
        target: Optional[Union[discord.Member, discord.Role]] = None,
        allow_perms: Optional[str] = None,
        deny_perms: Optional[str] = None,
        perms_integer: Optional[int] = None
    ):
        debug_print(f"Entering /edit_channel with interaction: {interaction}, channel: {channel}, name: {name}, topic: {topic}, position: {position}, target: {target}, allow_perms: {allow_perms}, deny_perms: {deny_perms}", level="all")
        guild = interaction.guild
        if not guild:
            await interaction.response.send_message("This command can only be used in a server.", ephemeral=True)
            return
        if not guild.me.guild_permissions.manage_channels:
            await interaction.response.send_message("I need the 'Manage Channels' permission to edit channels.", ephemeral=True)
            return
        kwargs = {}
        if name:
            kwargs['name'] = name
        if topic and isinstance(channel, discord.TextChannel):
            kwargs['topic'] = topic
        if position is not None:
            kwargs['position'] = position
        # Permission overwrites
        if target and (perms_integer is not None or allow_perms or deny_perms):
            # Get the target object (role or member)
            overwrite_target = None
            if isinstance(target, discord.Role):
                overwrite_target = target
            elif isinstance(target, discord.Member):
                overwrite_target = target
            else:
                overwrite_target = guild.get_role(getattr(target, 'id', None)) or guild.get_member(getattr(target, 'id', None))
            if not overwrite_target:
                await interaction.response.send_message("Target role or user not found.", ephemeral=True)
                return
            # Build permissions
            if perms_integer is not None:
                perms_obj = discord.Permissions(perms_integer)
                perms_dict = {perm: getattr(perms_obj, perm) for perm in discord.Permissions.VALID_FLAGS}
            else:
                allow = discord.Permissions.none()
                deny = discord.Permissions.none()
                invalid_allow = []
                invalid_deny = []
                if allow_perms:
                    for p in [perm.strip() for perm in allow_perms.split(',') if perm.strip()]:
                        if hasattr(allow, p):
                            setattr(allow, p, True)
                        else:
                            invalid_allow.append(p)
                if deny_perms:
                    for p in [perm.strip() for perm in deny_perms.split(',') if perm.strip()]:
                        if hasattr(deny, p):
                            setattr(deny, p, True)
                        else:
                            invalid_deny.append(p)
                if invalid_allow or invalid_deny:
                    await interaction.response.send_message(f"Invalid permissions: Allow: {', '.join(invalid_allow)} Deny: {', '.join(invalid_deny)}", ephemeral=True)
                    return
                perms_dict = {}
                for perm in discord.Permissions.VALID_FLAGS:
                    if getattr(allow, perm, False):
                        perms_dict[perm] = True
                    elif getattr(deny, perm, False):
                        perms_dict[perm] = False
            # Get current overwrites
            overwrites = dict(channel.overwrites)
            overwrites[overwrite_target] = discord.PermissionOverwrite(**perms_dict)
            kwargs['overwrites'] = overwrites
        try:
            await channel.edit(reason=f"Edited by {interaction.user} via /edit_channel", **kwargs)
            await interaction.response.send_message(f"✅ Edited channel `#{channel.name}`.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to edit that channel.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"Failed to edit channel: {e}", ephemeral=True)
    
    @app_commands.command(name="purge", description="Delete a specified number of messages")
    @command_permission_check("purge")
    @app_commands.describe(
        amount="Number of messages to delete",
        user="User whose messages should be deleted (optional)",
        contains="Only delete messages containing this text (optional)"
    )
    @app_commands.checks.has_permissions(manage_messages=True)
    async def purge(self, interaction: discord.Interaction, amount: int, user: discord.User = None, contains: str = None):
        debug_print(f"Entering /purge with interaction: {interaction}, amount: {amount}, user: {user}, contains: {contains}", level="all")
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
        debug_print(f"Entering purge_error with interaction: {interaction}, error: {error}", level="all")
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message("You don't have permission to use this command.", ephemeral=True)
        else:
            await interaction.response.send_message("An error occurred while executing this command.", ephemeral=True)
            debug_print(f"[Purge Error]: {error}")

    @app_commands.command(name="purge_after", description="Delete messages after a specific message ID")
    @command_permission_check("purge_after")
    @app_commands.describe(
        message_id="The message ID to start purging after",
        count="Number of messages to delete after the specified message ID (optional, max 100)"
    )
    @app_commands.checks.has_permissions(manage_messages=True)
    async def purge_after(self, interaction: discord.Interaction, message_id: str, count: int = 100):
        debug_print(f"Entering /purge_after with interaction: {interaction}, message_id: {message_id}, count: {count}")
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
        debug_print(f"Entering purge_after_error with interaction: {interaction}, error: {error}", level="all")
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message("❌ You need manage messages permissions to use this command.", ephemeral=True)
        else:
            await interaction.response.send_message("⚠️ An error occurred while processing this command.", ephemeral=True)
            debug_print(f"[Purge After Error]: {str(error)}")

    async def _create_role_menu(self, interaction, menu_type):
        debug_print(f"Entering _create_role_menu with interaction: {interaction}, menu_type: {menu_type}", level="all")
        guild_id = str(interaction.guild.id)
        channel_id = str(interaction.channel.id)
        creator_id = str(interaction.user.id)
        menu_id = random_id()
        setup_url = f"{FRONTEND_URL}/dashboard/{guild_id}/{menu_type}/{menu_id}"

        # Store placeholder config in DB
        self.db.execute_query(
            '''INSERT INTO role_menus (id, guild_id, type, channel_id, config, created_by)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (menu_id, guild_id, menu_type, channel_id, '{}', creator_id)
        )

        await interaction.response.send_message(
            f"Setup your {menu_type} here: {setup_url}\n\nID: `{menu_id}`",
            ephemeral=True
        )

    @app_commands.command(name="create_dropdown", description="Create a dropdown role menu")
    @command_permission_check("create_dropdown")
    async def create_dropdown(self, interaction: discord.Interaction):
        debug_print(f"Entering /create_dropdown with interaction: {interaction}", level="all")
        await self._create_role_menu(interaction, "dropdown")

    @app_commands.command(name="create_reactionrole", description="Create a reaction role menu")
    @command_permission_check("create_reactionrole")
    async def create_reactionrole(self, interaction: discord.Interaction):
        debug_print(f"Entering /create_reactionrole with interaction: {interaction}", level="all")
        await self._create_role_menu(interaction, "reactionrole")

    @app_commands.command(name="create_button", description="Create a button role menu")
    @command_permission_check("create_button")
    async def create_button(self, interaction: discord.Interaction):
        debug_print(f"Entering /create_button with interaction: {interaction}", level="all")
        await self._create_role_menu(interaction, "button")

    @app_commands.command(name="setlogchannel", description="Set the channel for logging events")
    @command_permission_check("setlogchannel")
    @app_commands.describe(channel="The channel to use for logging")
    async def set_log_channel(self, interaction: discord.Interaction, channel: discord.TextChannel):
        debug_print(f"Entering /set_log_channel with interaction: {interaction}, channel: {channel}", level="all")
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
    
    @app_commands.command(name="help", description="Show information about available commands")
    @command_permission_check("help")
    async def help(self, interaction: discord.Interaction):
        debug_print(f"Entering /help with interaction: {interaction}", level="all")
        """Display a help message with available commands."""
        embed = discord.Embed(
            title="**SentinelBot Help**",
            description=(
                "**Here are some commands you can use to start:**\n"
                "**Or check the [documentation](https://docs.rulekeeper.cc/) for more details and commands.**"
            ),
            color=discord.Color.blurple()
        )
        embed.add_field(
            name="/help",
            value="Show this help message.",
            inline=False
        )
        embed.add_field(
            name="/level",
            value="Show a user's level and XP.",
            inline=False
        )
        embed.add_field(
            name="/leaderboard",
            value="Show the server's leaderboard.",
            inline=False
        )
        embed.add_field(
            name="/create_command",
            value="Create a custom command for your server.",
            inline=False
        )
        embed.add_field(
            name="/create_dropdown",
            value="Create a dropdown role menu.",
            inline=False
        )
        embed.add_field(
            name="/create_reactionrole",
            value="Create a reaction role menu.",
            inline=False
        )
        embed.add_field(
            name="/create_button",
            value="Create a button role menu.",
            inline=False
        )
        embed.set_footer(text="Ask a server admin for more details.")

        await interaction.response.send_message(embed=embed, ephemeral=True)

    async def custom_command_handler(self, interaction: discord.Interaction, cmd_data: dict):
        debug_print(f"Entering custom_command_handler with interaction: {interaction}, cmd_data: {cmd_data}", level="all")
        """Handler for database-stored commands"""
        try:
            await interaction.response.send_message(
                content=cmd_data['content'],
                ephemeral=bool(cmd_data.get('ephemeral', True))
            )
        except Exception as e:
            await interaction.response.send_message("Command error!", ephemeral=True)
            debug_print(f"[Custom Command Error]: {str(e)}")

async def setup(bot):
    await bot.add_cog(UtilitiesCog(bot))