import discord
from discord import app_commands
from discord.ext import commands
from datetime import datetime, timedelta, timezone
from bot.bot import log_event, load_log_config, send_custom_form_dm
from config import Config
import uuid
import traceback
import sqlite3
import json
import time
from shared import command_permission_check
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        """
        No-op fallback for debug printing.
        
        Accepts any positional and keyword arguments but does nothing. Intended as a safe placeholder when a real `debug_print` implementation (from the bot) is unavailable so callers can call `debug_print(...)` without conditional checks.
        """
        pass

class ModerationCog(commands.Cog):
    def __init__(self, bot):
        """
        Initialize the ModerationCog, storing the bot reference and its database handle.
        
        Sets self.bot to the provided bot instance and self.db to bot.db for use by cog methods.
        """
        debug_print(f"Entering ModerationCog.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.db = bot.db
        
    @app_commands.command(name="warn", description="Warn a user")
    @command_permission_check("warn")
    @app_commands.describe(member="User to warn", reason="Reason for warning")
    async def warn(self, interaction: discord.Interaction, member: discord.Member, reason: str):
        """
        Issue a server warning to a member, record it in the database, optionally apply configured moderation actions (timeout, kick, ban), DM the member, log the event, and reply to the moderator.
        
        Details:
        - Adds a warning record for the target user in the guild database and computes the new total warning count.
        - Checks guild membership and role hierarchy before acting.
        - If a warning-action is configured for the new warning count, attempts the action:
          - timeout: applies a timeout for the configured duration (requires moderate_members).
          - kick: kicks the member (requires kick_members).
          - ban: bans the member (requires ban_members) and clears their warnings in the database.
        - Sends a DM to the target with the reason, total warnings, and any action taken; best-effort DM is attempted and failures are reported to the moderator.
        - Sends additional custom form DMs for warn/timeout/kick/ban where applicable.
        - Logs the moderation event via log_event and responds to the invoking moderator with what occurred, including a note if the bot lacked the required permission for a configured action.
        
        Parameters:
            interaction: The discord.Interaction that invoked the command.
            member: The discord.Member being warned.
            reason: The reason text for the warning.
        
        Returns:
            None
        """
        debug_print(f"Entering /warn with interaction: {interaction}, member: {member}, reason: {reason}", level="all")
        guild_id = str(interaction.guild.id)
        user_id = str(member.id)

        # Check if the user is still in the server
        if interaction.guild.get_member(member.id) is None:
            await interaction.response.send_message(
                "❌ That user is no longer in the server.",
                ephemeral=True
            )
            return

        # Check role hierarchy
        if interaction.guild.me.top_role <= member.top_role:
            await interaction.response.send_message(
                "I cannot moderate this user because their role is equal to or higher than mine.",
                ephemeral=True
            )
            return

        # Check if the user is in the server
        if member not in interaction.guild.members:
            await interaction.response.send_message(
                "This user is not in the server.",
                ephemeral=True
            )
            return

        # Add warning to database
        warning_id = self.db.add_warning(guild_id, user_id, reason)

        # Get current warnings from database
        user_warnings = self.db.get_warnings(guild_id, user_id)
        warning_count = len(user_warnings)

        # Send DM to the user
        dm_embed = discord.Embed(
            title="You have been warned!",
            description=f"**Reason:** {reason}",
            color=discord.Color.orange()
        )
        dm_embed.add_field(name="Total Warnings", value=str(warning_count))

        # Track if moderation action was attempted and if permission was missing
        action_attempted = False
        missing_permission = None

        # Check for configured warning actions
        warning_actions = self.db.get_warning_actions(guild_id)
        action_row = next((a for a in warning_actions if a['warning_count'] == warning_count), None)

        action_text = ""
        if action_row:
            action_attempted = True
            action_type = action_row['action']
            duration_seconds = action_row.get('duration_seconds')
            if action_type == "timeout":
                if interaction.guild.me.guild_permissions.moderate_members:
                    try:
                        timeout_until = discord.utils.utcnow() + timedelta(seconds=duration_seconds or 3600)
                        await member.timeout(timeout_until, reason=f"Reached {warning_count} warnings")
                        action_text = f"Timeout applied for {duration_seconds//60 if duration_seconds else 60} minutes"
                        await send_custom_form_dm(member, interaction.guild, "timeout")
                    except discord.Forbidden:
                        missing_permission = "timeout"
                else:
                    missing_permission = "timeout"
            elif action_type == "kick":
                if interaction.guild.me.guild_permissions.kick_members:
                    try:
                        await member.kick(reason=f"Reached {warning_count} warnings")
                        action_text = "User kicked"
                        await send_custom_form_dm(member, interaction.guild, "kick")
                    except discord.Forbidden:
                        missing_permission = "kick"
                else:
                    missing_permission = "kick"
            elif action_type == "ban":
                if interaction.guild.me.guild_permissions.ban_members:
                    try:
                        await member.ban(reason=f"Reached {warning_count} warnings")
                        action_text = "User banned"
                        # Clear warnings after ban
                        self.db.conn.execute('DELETE FROM warnings WHERE guild_id = ? AND user_id = ?', 
                                      (guild_id, user_id))
                        self.db.conn.commit()
                        await send_custom_form_dm(member, interaction.guild, "ban")
                    except discord.Forbidden:
                        missing_permission = "ban"
                else:
                    missing_permission = "ban"

        if action_text:
            dm_embed.add_field(name="Action Taken", value=action_text, inline=False)

        dm_embed.set_footer(text=f"Server: {interaction.guild.name}")
        try:
            await member.send(embed=dm_embed)
        except discord.Forbidden:
            await interaction.followup.send(
                "Couldn't DM user warning details", 
                ephemeral=True
            )

        await send_custom_form_dm(member, interaction.guild, "warn")

        # Log the warning event
        await log_event(interaction.guild, "member_warn", "Member Warned", 
                        f"**Member:** {member.mention}\n**Reason:** {reason}\n**Total Warnings:** {warning_count}",
                        color=discord.Color.orange())

        # Respond to the moderator
        if action_row:
            action_past = {
                "timeout": "timed out",
                "kick": "kicked",
                "ban": "banned"
            }.get(action_row['action'], action_row['action'])
            response = (
                f"{member.mention} warned. They now have {warning_count} warning(s). "
                f"They have also been {action_past}."
            )
        else:
            response = f"{member.mention} warned. They now have {warning_count} warning(s)."

        if missing_permission:
            response += (
                f"\n⚠️ RuleKeeper does not have permission to {missing_permission} this user, so no moderation action was taken."
            )
        await interaction.response.send_message(
            response,
            ephemeral=True
        )

    @app_commands.command(name="warnings", description="View all warnings for a user")
    @command_permission_check("warnings")
    @app_commands.describe(member="User to check")
    async def view_warnings(self, interaction: discord.Interaction, member: discord.Member):
        """
        Show a member's recorded warnings to the invoking moderator as an ephemeral embed.
        
        Fetches warnings for the specified member from the cog's database and, if any exist, sends an ephemeral embed listing each warning with its date and reason. If no warnings are found, sends an ephemeral message stating that the member has no warnings.
        
        Notes:
        - The displayed date is taken from the warning's `timestamp` field (first 10 characters).
        - This function sends responses via the provided Interaction and does not return a value.
        """
        debug_print(f"Entering /view_warnings with interaction: {interaction}, member: {member}", level="all")
        guild_id = str(interaction.guild.id)
        user_id = str(member.id)
            
        # Get warnings from database
        warnings = self.db.get_warnings(guild_id, user_id)
            
        if not warnings:
            await interaction.response.send_message(
                f"{member.display_name} has no warnings.",
                ephemeral=True
            )
            return
            
        embed = discord.Embed(
            title=f"Warnings for {member.display_name}",
            color=discord.Color.orange()
        )
            
        for idx, warning in enumerate(warnings, 1):
            embed.add_field(
                name=f"Warning #{idx}",
                value=f"**Date:** {warning['timestamp'][:10]}\n**Reason:** {warning['reason']}",
                inline=False
            )
            
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="unwarn", description="Remove a warning from a user")
    @command_permission_check("unwarn")
    @app_commands.describe(
        member="User to unwarn",
        warning_number="Warning number to remove"
    )
    async def unwarn(self, interaction: discord.Interaction, member: discord.Member, warning_number: int):
        """
        Remove a specific warning from a guild member and adjust any associated moderation state.
        
        This command handler removes the warning at the given 1-based warning_number for the specified member from the bot's warnings database, updates the stored warning count, and — if the removed warning causes a previously-applied timeout action to no longer apply — attempts to clear the member's timeout. It logs the unwarn event to the guild log and replies to the invoking interaction with an ephemeral confirmation or error message.
        
        Parameters:
            interaction: The Discord interaction that invoked the command.
            member: The guild member whose warning will be removed.
            warning_number (int): 1-based index of the warning to remove (must be between 1 and the member's current warning count).
        
        Side effects:
            - Removes a warning record from persistent storage.
            - May remove a timeout from the member if applicable and permitted.
            - Sends an ephemeral response to the command invoker and logs the action to the guild logging system.
        
        Notes:
            - If the member has no warnings or the warning_number is out of range, the handler responds ephemerally and does nothing.
            - If the bot lacks permission to clear a timeout, it informs the invoker.
            - Errors during removal are caught; the invoker receives a generic error message and a debug message is emitted.
        """
        debug_print(f"Entering /unwarn with interaction: {interaction}, member: {member}, warning_number: {warning_number}", level="all")
        guild_id = str(interaction.guild.id)
        user_id = str(member.id)
        
        # Get warnings from database
        warnings = self.db.get_warnings(guild_id, user_id)
            
        if not warnings:
            await interaction.response.send_message(
                f"{member.display_name} has no warnings to remove.",
                ephemeral=True
            )
            return
            
        if warning_number < 1 or warning_number > len(warnings):
            await interaction.response.send_message(
                f"Invalid warning number. Please use a number between 1 and {len(warnings)}.",
                ephemeral=True
            )
            return
            
        # Get the specific warning to remove
        warning_to_remove = warnings[warning_number - 1]
            
        try:
            # Remove warning from database
            self.db.remove_warning(guild_id, user_id, warning_to_remove['warning_id'])
                
            # Get updated count
            new_count = len(warnings) - 1
                
            # Check if we need to remove moderation actions
            warning_actions = self.db.get_warning_actions(guild_id)
            prev_action_row = next((a for a in warning_actions if a['warning_count'] == (new_count + 1)), None)
            if prev_action_row and prev_action_row['action'] == "timeout":
                try:
                    await member.timeout(None, reason="Warning removed")
                except discord.Forbidden:
                    await interaction.response.send_message(
                        "I don't have permission to remove the timeout for this user.",
                        ephemeral=True
                    )
                    return
                
            # Log the action
            await log_event(
                interaction.guild,
                "member_unwarn",
                "Member Unwarned",
                f"**Member:** {member.mention}\nRemoved warning #{warning_number}\n**New total warnings:** {new_count}",
                color=discord.Color.blue()
            )
                
            await interaction.response.send_message(
                f"Removed warning #{warning_number} from {member.display_name}\n"
                f"**Reason:** {warning_to_remove['reason']}\n"
                f"**New total warnings:** {new_count}",
                ephemeral=True
            )
                
        except Exception as e:
            await interaction.response.send_message(
                "An error occurred while removing the warning.",
                ephemeral=True
            )
            debug_print(f"[Warning Error]: {str(e)}")
            
    @app_commands.command(name="ban", description="Ban a user from the server")
    @command_permission_check("ban")
    @app_commands.describe(user="The user to ban", reason="The reason for the ban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def ban(self, interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
        """
        Ban a user from the guild, attempt to DM them the reason, and log the action.
        
        Defers the interaction, verifies the bot has ban permissions and that role hierarchy allows the ban
        (if the target is a Member), sends a ban notification DM when possible, performs the guild ban,
        and logs a "member_ban" event. Replies to the invoking moderator with an ephemeral summary that
        indicates whether the DM was delivered and reports permission or execution failures.
        
        Parameters:
            user (discord.User | discord.Member): The account to ban. If a Member, role-hierarchy checks are applied.
            reason (str): Reason recorded for the ban (defaults to "No reason provided").
        
        Returns:
            None
        """
        debug_print(f"Entering /ban with interaction: {interaction}, user: {user}, reason: {reason}", level="all")
        try:
            await interaction.response.defer()

            # Check bot permissions
            if not interaction.guild.me.guild_permissions.ban_members:
                await interaction.followup.send("❌ I don't have permission to ban users.", ephemeral=True)
                return

            # Check role hierarchy if user is a member
            if isinstance(user, discord.Member):
                if interaction.user.top_role <= user.top_role:
                    await interaction.followup.send("❌ You can't ban someone with equal/higher role.", ephemeral=True)
                    return
                if interaction.guild.me.top_role <= user.top_role:
                    await interaction.followup.send("❌ I can't ban someone with equal/higher role than me.", ephemeral=True)
                    return

            guild = interaction.guild

            # Create ban embed
            ban_embed = discord.Embed(
                title="🔨 Account Banned",
                description=f"You've been banned from **{guild.name}**",
                color=discord.Color.red()
            )
            ban_embed.add_field(name="Reason", value=reason, inline=False)

            # Execute ban
            try:
                await user.send(embed=ban_embed)
                dm_success = True
            except discord.Forbidden:
                dm_success = False

            await guild.ban(user, reason=reason, delete_message_days=0)

            # Send response
            response = f"✅ {user.mention} has been banned"
            response += "\n📩 DM sent" if dm_success else "\n⚠️ Couldn't send DM"
            await interaction.followup.send(response, ephemeral=True)

            # Log event
            await log_event(
                guild,
                "member_ban",
                "Member Banned",
                f"**User:** {user.mention}\n**Reason:** {reason}",
                color=discord.Color.red()
            )

        except discord.Forbidden:
            await interaction.followup.send("❌ Missing permissions to ban this user", ephemeral=True)
        except Exception as e:
            await interaction.followup.send(f"❌ Ban failed: {str(e)}", ephemeral=True)
            debug_print(f"[Ban Error] {str(e)}")

    @app_commands.command(name="unban", description="Unban a user from the server")
    @command_permission_check("unban")
    @app_commands.describe(user="The user to unban", reason="The reason for the unban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def unban(self, interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
        """
        Unban a user from the guild, notify the moderator, and log the action.
        
        Attempts to unban the provided user from the interaction's guild. Verifies the bot has the
        ban_members permission and that the invoking moderator is higher than the target if the
        target is a Member. Sends an ephemeral response to the moderator indicating success or that
        the user was not banned, and records the unban in the moderation log.
        
        Parameters:
            interaction (discord.Interaction): The command interaction (used for guild context and responses).
            user (discord.User | discord.Member): The user to unban; may be a Member object if the user is in cache.
            reason (str): Reason recorded for the unban (defaults to "No reason provided").
        """
        debug_print(f"Entering /unban with interaction: {interaction}, user: {user}, reason: {reason}", level="all")
        if not interaction.guild.me.guild_permissions.ban_members:
            await interaction.response.send_message("I don't have permission to unban users.", ephemeral=True)
            return
            
        if isinstance(user, discord.Member) and interaction.user.top_role <= user.top_role:
            await interaction.response.send_message(
                "Target user has higher/equal role to you",
                ephemeral=True
            )
            return

        try:
            await interaction.guild.unban(user, reason=reason)
            await interaction.response.send_message(f"{user.mention} has been unbanned. Reason: {reason}", ephemeral=True)
            await log_event(
                    interaction.guild,
                "member_unban",
                "Member Unbanned",
                f"**User:** {user.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.green()
            )
        except discord.NotFound:
            await interaction.response.send_message("This user is not banned.", ephemeral=True)

    @app_commands.command(name="kick", description="Kick a user from the server")
    @command_permission_check("kick")
    @app_commands.describe(member="The member to kick", reason="The reason for the kick")
    @app_commands.checks.has_permissions(kick_members=True)
    async def kick(self, interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
        """
        Kick a guild member, notify them, send a custom follow-up DM, and log the action.
        
        Performs permission and role-hierarchy checks before attempting the kick. If allowed, the command will:
        - attempt to DM the member with a kick notice,
        - kick the member from the guild with the provided reason,
        - send a confirmation to the moderator (ephemeral),
        - send a custom form DM via send_custom_form_dm,
        - and log the action via log_event.
        
        Parameters:
            reason (str): Human-readable reason recorded with the kick and shown to the user; defaults to "No reason provided".
        """
        debug_print(f"Entering /kick with interaction: {interaction}, member: {member}, reason: {reason}", level="all")
        try:
            if not interaction.guild.me.guild_permissions.kick_members:
                await interaction.response.send_message("I don't have permission to kick users.", ephemeral=True)
                return

            if interaction.user.top_role <= member.top_role:
                await interaction.response.send_message(
                    "Target has equal/higher role than you",
                    ephemeral=True
                )
                return
            if interaction.guild.me.top_role <= member.top_role:
                await interaction.response.send_message(
                    "Target has equal/higher role than me",
                    ephemeral=True
                )
                return

            # Create kick embed
            kick_embed = discord.Embed(
                title="You have been kicked!",
                description=f"**Reason:** {reason}\n\nYou have been kicked from {interaction.guild.name}.",
                color=discord.Color.orange()
            )

            try:
                await member.send(embed=kick_embed)
            except discord.Forbidden:
                pass

            await member.kick(reason=reason)
            await interaction.response.send_message(
                f"{member.mention} has been kicked. Reason: {reason}",
                ephemeral=True
            )

            await send_custom_form_dm(member, interaction.guild, "kick")

            await log_event(
                interaction.guild,
                "member_kick",
                "Member Kicked",
                f"**User:** {member.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.orange()
            )

        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to kick this user.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"An error occurred: {str(e)}", ephemeral=True)
            debug_print(f"[Kick Error]: {str(e)}")

    @app_commands.command(name="deafen", description="Deafen a user in voice channels")
    @command_permission_check("deafen")
    @app_commands.describe(member="The member to deafen", reason="The reason for deafening")
    @app_commands.checks.has_permissions(deafen_members=True)
    async def deafen(self, interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
        """
        Deafen a guild member: applies a server-side deaf and notifies moderator and logs the action.
        
        Checks that the target is in a voice channel and that the bot has the `deafen_members` permission, then sets the member's voice state to deafened, sends an ephemeral confirmation to the command invoker, and logs the moderation event.
        
        Parameters:
            interaction (discord.Interaction): The command interaction invoking the command.
            member (discord.Member): The guild member to deafen.
            reason (str): Optional reason recorded for the action (default: "No reason provided").
        
        Returns:
            None
        """
        debug_print(f"Entering /deafen with interaction: {interaction}, member: {member}, reason: {reason}", level="all")
        guild_id = str(interaction.guild.id)
        if not member.voice or not member.voice.channel:
            await interaction.response.send_message("The user is not in a voice channel.", ephemeral=True)
            return

        if not interaction.guild.me.guild_permissions.deafen_members:
            await interaction.response.send_message("I don't have permission to deafen members.", ephemeral=True)
            return

        await member.edit(deafen=True, reason=reason)
        await interaction.response.send_message(
            f"{member.mention} has been deafened. Reason: {reason}",
            ephemeral=True
        )
        await log_event(
            interaction.guild,
            "member_deafen",
            "Member Deafened",
            f"**User:** {member.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
            color=discord.Color.blue()
        )

    @app_commands.command(name="undeafen", description="Undeafen a user in voice channels")
    @command_permission_check("undeafen")
    @app_commands.describe(member="The member to undeafen", reason="The reason for undeffening")
    @app_commands.checks.has_permissions(deafen_members=True)
    async def undeafen(self, interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
        """
        Undeafen a member in voice, notify the moderator, and log the action.
        
        If the target is not in a voice channel or the bot lacks the deafen_members permission,
        an ephemeral error message is sent and no change is made. Otherwise the member's
        deafen flag is cleared (audit reason set), the moderator is sent an ephemeral
        confirmation, and a "member_undeafen" log event is emitted.
        
        Parameters:
            member (discord.Member): The guild member to undeafen.
            reason (str): Human-readable reason included in the audit entry and notifications.
        """
        debug_print(f"Entering /undeafen with interaction: {interaction}, member: {member}, reason: {reason}", level="all")
        guild_id = str(interaction.guild.id)
        if not member.voice or not member.voice.channel:
            await interaction.response.send_message("The user is not in a voice channel.", ephemeral=True)
            return

        if not interaction.guild.me.guild_permissions.deafen_members:
            await interaction.response.send_message("I don't have permission to undeafen members.", ephemeral=True)
            return

        await member.edit(deafen=False, reason=reason)
        await interaction.response.send_message(
            f"{member.mention} has been undeafened. Reason: {reason}",
            ephemeral=True
        )
        await log_event(
            interaction.guild,
            "member_undeafen",
            "Member Undeafened",
            f"**User:** {member.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
            color=discord.Color.blue()
        )

    @app_commands.command(name="timeout", description="Timeout a user (restrict interactions)")
    @command_permission_check("timeout")
    @app_commands.describe(
        member="The member to timeout",
        duration="Duration (e.g., 5m, 1h, 1d) - defaults to 5m",
        reason="The reason for timing out"
    )
    @app_commands.checks.has_permissions(moderate_members=True)
    async def timeout(
        self, interaction: discord.Interaction,
        member: discord.Member,
        duration: str = "5m",
        reason: str = "No reason provided"
    ):
        """
        Timeout a guild member for a given duration.
        
        Attempts to DM the member, apply a Discord timeout (requires the bot to have the `moderate_members` permission),
        log the action, and send a custom follow-up DM form.
        
        Parameters:
            member: The guild Member to time out.
            duration: Timeout length using the format `[number][m/h/d]` (e.g., `30m`, `2h`, `1d`). Maximum allowed is 4 weeks.
            reason: Optional reason recorded for the timeout (displayed to the user and included in logs).
        """
        debug_print(f"Entering /timeout with interaction: {interaction}, member: {member}, duration: {duration}, reason: {reason}", level="all")
        try:
            if not interaction.guild.me.guild_permissions.moderate_members:
                await interaction.response.send_message("I don't have permission to timeout members.", ephemeral=True)
                return

            # Parse duration
            time_units = {"m": 60, "h": 3600, "d": 86400}
            try:
                duration_num = int(duration[:-1])
                unit = duration[-1].lower()
                if unit not in time_units:
                    raise ValueError
                seconds = duration_num * time_units[unit]
                if seconds > 2419200:
                    raise ValueError
            except (ValueError, IndexError):
                await interaction.response.send_message(
                    "Invalid duration format! Use: [number][m/h/d] (e.g., 30m, 2h, 1d)",
                    ephemeral=True
                )
                return

            timeout_duration = discord.utils.utcnow() + timedelta(seconds=seconds)

            # Create timeout embed
            timeout_embed = discord.Embed(
                title="You have been timed out!",
                description=f"**Duration:** {duration}\n**Reason:** {reason}",
                color=discord.Color.orange()
            )

            try:
                await member.send(embed=timeout_embed)
            except discord.Forbidden:
                pass
            await member.timeout(timeout_duration, reason=reason)
            await interaction.response.send_message(
                f"{member.mention} has been timed out for {duration}. Reason: {reason}",
                ephemeral=True
            )

            await send_custom_form_dm(member, interaction.guild, "timeout")

            await log_event(
                interaction.guild,
                "member_timeout",
                "Member Timed Out",
                f"**User:** {member.mention}\n**Duration:** {duration}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.orange()
            )
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to timeout this member.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"An error occurred: {str(e)}", ephemeral=True)
            debug_print(f"[Timeout Error]: {str(e)}")

    @app_commands.command(name="untimeout", description="Remove timeout from a user")
    @command_permission_check("untimeout")
    @app_commands.describe(
        member="The member to untimeout",
        reason="The reason for removing timeout"
    )
    @app_commands.checks.has_permissions(moderate_members=True)
    async def untimeout(
        self, interaction: discord.Interaction,
        member: discord.Member,
        reason: str = "No reason provided"
    ):
        """
        Remove a member's timeout (server mute) and log the action.
        
        If the bot lacks the Moderate Members permission or the target is not timed out, the command replies ephemerally and returns without changing state. On success the member's timeout is cleared, a confirmation is sent to the invoking moderator, and a `member_untimeout` log event is created.
        
        Parameters:
            member (discord.Member): The guild member whose timeout will be removed.
            reason (str): Optional reason recorded for the untimeout and shown to the moderator. Defaults to "No reason provided".
        """
        debug_print(f"Entering /untimeout with interaction: {interaction}, member: {member}, reason: {reason}", level="all")
        guild_id = str(interaction.guild.id)
        if not interaction.guild.me.guild_permissions.moderate_members:
            await interaction.response.send_message("I don't have permission to remove timeouts.", ephemeral=True)
            return
        if not member.is_timed_out():
            await interaction.response.send_message("This user is not currently timed out.", ephemeral=True)
            return
        try:
            await member.timeout(None, reason=reason)
            await interaction.response.send_message(
                f"Timeout removed from {member.mention}.\nReason: {reason}",
                ephemeral=True
            )
            await log_event(
                interaction.guild,
                "member_untimeout",
                "Timeout Removed",
                f"**User:** {member.mention}\n**Reason:** {reason}\n**Moderator:** {interaction.user.mention}",
                color=discord.Color.green()
            )
        except discord.Forbidden:
            await interaction.response.send_message("Failed to remove timeout - check role hierarchy.", ephemeral=True)

    @app_commands.command(name="softban", description="Ban and immediately unban a user to delete their messages")
    @command_permission_check("softban")
    @app_commands.describe(user="The user to softban", reason="The reason for softban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def softban(self, interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
        """
        Softban a user: briefly ban to purge messages, then immediately unban so they can rejoin.
        
        Performs the following actions when invoked by a moderator in a guild:
        - Verifies the bot has the `ban_members` permission and that role hierarchy allows the action.
        - Attempts to create a single-use rejoin invite for the channel; falls back to a staff-contact message if invite creation is forbidden.
        - Sends the target a DM with the softban reason and the rejoin link (best-effort; DM failures are ignored).
        - Adds a "Softban: <reason>" entry to the warnings database (best-effort; DB errors are logged).
        - Bans the user with delete_message_days=7 to remove recent messages, then immediately unbans them.
        - Logs the softban event to the configured guild log.
        
        Exceptions and error conditions:
        - Sends an ephemeral response when the bot lacks guild ban permissions, when role hierarchy prevents the action, or when other Discord errors occur (Forbidden, NotFound).
        - DM or invite creation failures do not stop the ban/unban step.
        - Any unexpected exception results in an ephemeral error message to the invoker and a debug log.
        """
        debug_print(f"Entering /softban with interaction: {interaction}, user: {user}, reason: {reason}", level="all")
        if not interaction.guild.me.guild_permissions.ban_members:
            await interaction.response.send_message("I don't have permission to ban users.", ephemeral=True)
            return
            
        if isinstance(user, discord.Member):
            if interaction.user.top_role <= user.top_role:
                await interaction.response.send_message(
                    "Target user has higher/equal role to you",
                    ephemeral=True
                )
                return
                
            if interaction.guild.me.top_role <= user.top_role:
                await interaction.response.send_message(
                    "Target has equal/higher role than me",
                    ephemeral=True
                )
                return
    
        try:
            guild_id = str(interaction.guild.id)
            log_config = load_log_config(guild_id)
            
            # Create an invite for rejoining
            try:
                invite = await interaction.channel.create_invite(
                    max_uses=1,
                    unique=True,
                    reason=f"Rejoin invite for softbanned user {user}"
                )
                invite_link = invite.url
            except discord.Forbidden:
                invite_link = "Contact server staff for a new invite"
            # DM the user
            embed = discord.Embed(
                title=f"You were softbanned from {interaction.guild.name}",
                description="Your messages have been cleared but you can rejoin immediately.",
                color=discord.Color.orange()
            )
            embed.add_field(name="Reason", value=reason, inline=False)
            embed.add_field(name="Rejoin Link", value=invite_link, inline=False)
            try:
                await user.send(embed=embed)
            except discord.Forbidden:
                pass  # Couldn't send DM
           # Database operations
            try:
                # Add to warnings table
                self.db.add_warning(
                    guild_id=guild_id,
                    user_id=str(user.id),
                    reason=f"Softban: {reason}"
                )
            except Exception as e:
                debug_print(f"[Softban Error]: {str(e)}")
            # Ban to delete messages (7 days worth)
            await interaction.guild.ban(user, reason=reason, delete_message_days=7)
            # Unban immediately
            await interaction.guild.unban(user, reason="Softban removal")
            await interaction.response.send_message(
                f"{user.mention} has been softbanned. They received a rejoin link.\nReason: {reason}",
                ephemeral=True
            )
            # Log the action
            await log_event(
                interaction.guild,
                "member_softban",
                "Member Softbanned",
                f"**User:** {user.mention}\n**Reason:** {reason}\n" +
                f"**Rejoin Sent:** {'Yes' if invite_link else 'No'}\n" +
                f"**Moderator:** {interaction.user.mention}",
                color=discord.Color.purple()
            )
        except discord.NotFound:
            await interaction.response.send_message("User not found.", ephemeral=True)
        except discord.Forbidden:
            await interaction.response.send_message("I don't have permission to ban/unban this user.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"An error occurred: {str(e)}", ephemeral=True)
            debug_print(f"[Softban Error]: {str(e)}")

async def setup(bot):
    """
    Register the ModerationCog with the given bot.
    
    This async setup entrypoint adds an instance of ModerationCog to the bot via bot.add_cog(...).
    """
    await bot.add_cog(ModerationCog(bot))