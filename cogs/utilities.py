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
        """
        No-op fallback for a debug printing function.
        
        Accepts any positional and keyword arguments but performs no action. Intended as a safe default replacement when a debug logging/printing utility is not available so callers can call `debug_print(...)` without conditional checks.
        """
        pass

def random_id(length=6):
    """
    Return a random alphanumeric identifier.
    
    Parameters:
        length (int): Number of characters to generate (default 6).
    
    Returns:
        str: A random string of ASCII letters (upper- and lowercase) and digits.
    """
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
        """
        Handle the Cancel button press: mark the view as canceled, stop the view, and defer the interaction response.
        
        Parameters:
            interaction (discord.Interaction): The interaction triggered by clicking the Cancel button.
        """
        self.value = False
        self.stop()
        await interaction.response.defer()

@app_commands.autocomplete(permissions=True)
async def permissions_autocomplete(
    interaction: discord.Interaction,
    current: str
) -> list[app_commands.Choice[str]]:
    """
    Provide autocomplete choices for Discord permission flags.
    
    Filters the known permission flag names by the user's current input (case-insensitive)
    and returns up to 25 suggestions. Each suggestion's display name replaces underscores
    with spaces and title-cases the flag (e.g., "manage_roles" -> "Manage Roles").
    
    Parameters:
        current (str): The user's current autocomplete input used to filter permission names.
    
    Returns:
        list[app_commands.Choice[str]]: Up to 25 matching choices with human-friendly names and
        the raw permission flag as the value.
    """
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
        """
        Initialize the UtilitiesCog.
        
        Stores a reference to the bot instance and the bot's database handle for use by the cog's commands and helpers. Also emits an initialization trace via debug_print.
        """
        debug_print(f"Entering UtilitiesCog.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.db = bot.db
        
    @staticmethod
    def validate_command_name(name: str) -> bool:
        """
        Return True if `name` is a valid custom command identifier.
        
        A valid command name is 1–32 characters long and may contain ASCII letters, digits,
        underscores, or hyphens (matches the pattern `^[\w-]{1,32}$`).
        
        Parameters:
            name (str): Candidate command name.
        
        Returns:
            bool: True when `name` conforms to the allowed pattern, False otherwise.
        """
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
        """
        Create a new guild-scoped custom slash command and register it with the bot.
        
        This validates the provided command name, checks for duplicates, persists the command to the database, builds a callback that forwards invocations to handle_custom_command, registers the new command in the bot's command tree for the current guild, and syncs the tree. On success sends an ephemeral confirmation to the user; on failure sends an ephemeral error message.
        
        Parameters:
            command_name (str): Desired name for the slash command (1–32 chars; letters, digits, underscores or hyphens).
            content (str): The response text or URL that the custom command should send when invoked.
            description (str, optional): Short description shown in the command UI. Defaults to "Custom command".
            ephemeral (bool, optional): Whether the command's response should be sent ephemerally. Defaults to True.
        """
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
            """
            Callback used for dynamically created custom commands; forwards the interaction and the captured command data to UtilitiesCog.handle_custom_command.
            
            Parameters:
                interaction (discord.Interaction): The interaction triggered by the user. The command's configuration is supplied via the captured `cmd_data` closure.
            """
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
        """
        Send a stored custom command response to the invoking interaction.
        
        cmd_data should contain:
        - "content" (str): message text or a URL to send.
        - "ephemeral" (bool, optional): whether the response is ephemeral; defaults to True.
        
        If "content" is an HTTP(S) URL that ends with an image extension (png, jpg, jpeg, gif) an embed with that image is sent; otherwise the content is sent as plain text. Exceptions are caught and an ephemeral error message is sent.
        """
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
        """
        Delete a custom slash command from storage and unregister it from the bot.
        
        Removes the command record for the given name (preferring the guild-specific record if present)
        from the database, then attempts to remove the command from the bot's app command tree and
        sync the tree. Handles both global (guild_id '0') and guild-scoped commands. Sends ephemeral
        feedback to the invoking interaction for not-found, partial failures (deleted but sync failed),
        and successful deletion.
        """
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
        """
        Give or remove a role from a guild member based on the provided action.
        
        This command handler applies the requested action ('give' or 'take') to the target member:
        - Verifies the bot has Manage Roles permission and that the target role is lower than the bot's top role.
        - For "give": adds the role if the member doesn't already have it.
        - For "take": removes the role if the member currently has it.
        Sends ephemeral confirmation or error messages to the interaction for success, permission problems, hierarchy issues, or invalid actions.
        
        Parameters:
            interaction (discord.Interaction): The interaction that triggered the command.
            action (app_commands.Choice[str]): Choice object whose `.value` should be "give" or "take".
            role (discord.Role): The role to add or remove.
            user (discord.Member): The member to modify.
        
        Side effects:
            Modifies the member's roles when permitted and sends ephemeral interaction responses.
        
        Note:
            The function handles discord.Forbidden when the bot lacks permission to modify roles and responds accordingly; it does not raise exceptions for those cases.
        """
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
        """
        Create a new Discord role in the current guild.
        
        Creates a role with the given name, optional color and permissions. The command must be run in a guild (server); if invoked in DMs the function responds with an ephemeral error. Color may be provided as a hex string (with or without a leading '#'); invalid hex returns an ephemeral error. Permissions can be supplied either as a comma-separated list of permission flag names (e.g. "manage_messages, kick_members") or as a numeric bitmask via perms_integer. If any permission names are invalid the command returns an ephemeral error listing them. On success the created role is announced ephemerally.
        
        Parameters:
            name (str): Role name.
            color (Optional[str]): Hex color string (e.g. "#7289da" or "7289da"). If omitted, the default role color is used.
            permissions (Optional[str]): Comma-separated Discord permission flag names to enable on the role.
            mentionable (bool): Whether the role should be mentionable.
            hoist (bool): Whether the role should be shown separately in the member list.
            perms_integer (Optional[int]): Numeric permissions bitmask; if provided it overrides `permissions`.
        """
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
        """
        Delete a guild role after validating permissions and role hierarchy.
        
        Deletes the specified role in the invoking interaction's guild. The command verifies that it is used in a server, that the bot has the Manage Roles permission, and that the target role is lower than the bot's top role. Sends ephemeral success or error messages to the command invoker; failures (including permission errors and other exceptions) are caught and reported to the user.
        """
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
        """
        Edit a guild role's attributes (name, color, permissions, mentionable, hoist).
        
        Edits the provided role in the guild where the interaction was invoked. Performs
        permission and hierarchy checks (requires the bot to have Manage Roles and the
        target role to be lower than the bot's top role). Either an explicit
        perms_integer may be provided (takes precedence) or comma-separated
        allow_perms / deny_perms strings can be used to enable/disable individual
        permission flags. Color should be a hex string (e.g. "#7289da" or "7289da").
        
        Parameters:
            interaction: The Discord interaction that invoked the command.
            role: The role to edit.
            name: New name for the role (optional).
            color: Hex color string for the role (optional).
            allow_perms: Comma-separated permission flag names to enable (optional).
            deny_perms: Comma-separated permission flag names to deny/disable (optional).
            mentionable: Whether the role should be mentionable (optional).
            hoist: Whether the role should be displayed separately in the member list (optional).
            perms_integer: Integer bitfield of permissions; if provided it overrides allow/deny lists (optional).
        
        Behavior:
            - Validates server context, bot permissions, and role hierarchy; responds
              ephemerally to the interaction on error or success.
            - If color parsing fails, responds with an ephemeral error and aborts.
            - Invalid permission flag names in allow_perms/deny_perms are reported and
              abort the edit.
            - Exceptions from Discord permissions (e.g., Forbidden) are handled by
              sending an appropriate ephemeral message; other errors are reported
              with the exception message.
        
        Returns:
            None
        """
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
        """
        Create a new text or voice channel in the current guild.
        
        Creates a channel named `name` of the specified `type` (expects a Choice with value "text" or "voice"), optionally placing it in `category`. If `perms_integer` is provided, it is used to build a PermissionOverwrite for @everyone from that integer. Requires the bot to be used in a guild and to have the Manage Channels permission; user-facing ephemeral responses are sent for success, permission failures, invalid input, and other errors.
        """
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
        """
        Delete a guild channel if the bot has permission.
        
        Deletes the provided guild channel and responds to the invoking interaction with an ephemeral confirmation or error message.
        The command only runs in a guild context and requires the bot to have the Manage Channels permission; if those conditions are not met the user receives an ephemeral explanation.
        
        Parameters:
            channel (discord.abc.GuildChannel): The channel to delete (must belong to the guild where the command is invoked).
        
        Returns:
            None
        """
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
        """
        Edit a guild channel's basic properties and optionally update permission overwrites for a specific role or member.
        
        Edits name, topic (text channels only), and position when provided. If a target role or member is supplied along with either a numeric permissions integer or comma-separated
        allow/deny permission names, the command will compute a PermissionOverwrite for that target and apply it to the channel's overwrites (replacing/setting the overwrite for that target).
        Responses are sent to the invoking interaction (ephemeral).
        
        Parameters that need extra context:
        - target: A discord.Role or discord.Member to receive the permission overwrite.
        - allow_perms / deny_perms: Comma-separated permission flag names (e.g. "send_messages, read_messages"). Flags must match Discord's Permission attribute names; flags listed in `allow_perms` are set to True, those in `deny_perms` set to False. If a name is invalid the command responds with an error and aborts.
        - perms_integer: If provided, used to construct a discord.Permissions object directly; its full set of flags becomes the overwrite (overrides allow/deny string arguments).
        
        Side effects:
        - Modifies the provided channel via channel.edit.
        - Sends ephemeral responses to the interaction to report success or validation/errors.
        
        Error handling:
        - Handles missing guild context and missing Manage Channels permission by responding to the interaction.
        - Invalid permission names or missing target produce an interaction response and abort.
        - Permission or other edit failures are reported to the interaction; exceptions are not re-raised by this function.
        """
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
        """
        Purge up to `amount` messages from the current channel, optionally filtering by author or substring, and log the action.
        
        Deletes up to `amount` messages from the channel where the command was invoked. If `user` is provided, only messages authored by that user are considered. If `contains` is provided, only messages whose content contains that substring (case-insensitive) are considered. The command responds ephemerally with the number of messages deleted and emits a log event describing the purge.
        
        Parameters:
            interaction (discord.Interaction): The invoking interaction (used to determine channel, guild, and moderator).
            amount (int): Number of messages to consider for deletion (must be between 1 and 100).
            user (discord.User | None): If provided, only delete messages from this user.
            contains (str | None): If provided, only delete messages whose content includes this substring (case-insensitive).
        
        Returns:
            None
        """
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
        """
        Handle errors raised by the `/purge` command and send a user-facing ephemeral message.
        
        Sends a permission-specific ephemeral message when the error is an app_commands.CheckFailure;
        for any other AppCommandError it sends a generic ephemeral error message and records the error for debugging.
        
        Parameters:
            error (app_commands.AppCommandError): The error raised by the command invocation.
        """
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
        """
        Delete up to `count` messages posted after a specified message ID in the current channel.
        
        Looks up the message with `message_id` in the interaction's channel and removes up to `count` messages that were created after that message. Replies to the interaction with an ephemeral status message and logs the purge via log_event on success. Input validation (count range and numeric message ID) and common fetch/delete errors are handled and reported to the user.
        
        Parameters:
            message_id (str): The ID of the message to start after; must be parseable as an integer.
            count (int): Maximum number of messages to delete (1–100). Defaults to 100.
        """
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
        """
        Handle errors raised by the /purge_after command by sending an appropriate ephemeral response.
        
        If the error is an app_commands.CheckFailure, informs the user they need Manage Messages permission; otherwise sends a generic error notice and logs the error for debugging.
        """
        debug_print(f"Entering purge_after_error with interaction: {interaction}, error: {error}", level="all")
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message("❌ You need manage messages permissions to use this command.", ephemeral=True)
        else:
            await interaction.response.send_message("⚠️ An error occurred while processing this command.", ephemeral=True)
            debug_print(f"[Purge After Error]: {str(error)}")

    async def _create_role_menu(self, interaction, menu_type):
        """
        Create a new role-menu placeholder, persist it in the database, and reply with a one-time setup URL.
        
        This generates a short random menu ID, builds a frontend setup URL using FRONTEND_URL and the invoking guild/channel IDs, inserts a placeholder record into the `role_menus` database table (config stored as an empty JSON object), and sends an ephemeral message to the command invoker containing the setup URL and generated menu ID.
        
        Parameters:
            interaction (discord.Interaction): The invoking interaction (must be in a guild channel).
            menu_type (str): Type of role menu to create (e.g., "dropdown", "reactionrole", "button").
        
        Side effects:
            - Inserts a row into the `role_menus` table with columns (id, guild_id, type, channel_id, config, created_by).
            - Sends an ephemeral interaction response with the setup URL and menu ID.
        """
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
        """
        Create a placeholder dropdown role menu and respond with its frontend setup URL.
        
        Delegates to the internal _create_role_menu to create a DB record and send the ephemeral setup link for a "dropdown" role menu.
        
        Parameters:
            interaction (discord.Interaction): The invoking interaction used to reply to the user.
        """
        debug_print(f"Entering /create_dropdown with interaction: {interaction}", level="all")
        await self._create_role_menu(interaction, "dropdown")

    @app_commands.command(name="create_reactionrole", description="Create a reaction role menu")
    @command_permission_check("create_reactionrole")
    async def create_reactionrole(self, interaction: discord.Interaction):
        """
        Create a reaction-role menu entry and return a setup URL.
        
        This application command registers a placeholder reaction-role menu (stored in the bot's database)
        and responds to the invoker with an ephemeral setup URL and menu ID for configuring the menu
        in the external frontend.
        """
        debug_print(f"Entering /create_reactionrole with interaction: {interaction}", level="all")
        await self._create_role_menu(interaction, "reactionrole")

    @app_commands.command(name="create_button", description="Create a button role menu")
    @command_permission_check("create_button")
    async def create_button(self, interaction: discord.Interaction):
        """
        Create a placeholder "button" role menu and reply with a setup URL and generated menu ID.
        
        This command initializes a button-based role menu entry in the database (placeholder config) and sends an ephemeral response containing the frontend setup URL and the new menu ID so the user can finish configuration on the dashboard.
        
        Parameters:
            interaction (discord.Interaction): The interaction that invoked the command.
        """
        debug_print(f"Entering /create_button with interaction: {interaction}", level="all")
        await self._create_role_menu(interaction, "button")

    @app_commands.command(name="setlogchannel", description="Set the channel for logging events")
    @command_permission_check("setlogchannel")
    @app_commands.describe(channel="The channel to use for logging")
    async def set_log_channel(self, interaction: discord.Interaction, channel: discord.TextChannel):
        """
        Set the guild's log channel.
        
        Updates the persistent log configuration for the invoking guild, sends a confirmation to the command invoker, and emits a log event recording who configured the channel.
        
        Parameters:
            channel (discord.TextChannel): The text channel to use for logging (must be a TextChannel).
        """
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
        """
        Display an ephemeral help embed listing commonly used bot commands and a link to the documentation.
        
        Sends an embed to the invoking interaction that summarizes common commands (e.g., /help, /level, /leaderboard, /create_command, /create_dropdown, /create_reactionrole, /create_button) and points users to the full docs.
        """
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
        """
        Send the stored custom command response for an interaction.
        
        cmd_data must contain a 'content' string to send and may include an 'ephemeral' boolean (defaults to True).
        If sending fails, the handler replies with a short ephemeral error message.
        """
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
    """
    Register the UtilitiesCog with the bot.
    
    This async setup function is the entry point for the extension loader and adds UtilitiesCog to the bot's cog registry so its commands and listeners become available.
    """
    await bot.add_cog(UtilitiesCog(bot))