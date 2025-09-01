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

class ModerationCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.db = bot.db
        
    @app_commands.command(name="warn", description="Warn a user")
    @app_commands.describe(member="User to warn", reason="Reason for warning")
    async def warn(self, interaction: discord.Interaction, member: discord.Member, reason: str):
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

        # --- NEW: Check for configured warning actions ---
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
    @app_commands.describe(member="User to check")
    async def view_warnings(self, interaction: discord.Interaction, member: discord.Member):
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
    @app_commands.describe(
        member="User to unwarn",
        warning_number="Warning number to remove"
    )
    async def unwarn(self, interaction: discord.Interaction, member: discord.Member, warning_number: int):
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
            print(f"Error removing warning: {str(e)}")
            
    @app_commands.command(name="ban", description="Ban a user from the server")
    @app_commands.describe(user="The user to ban", reason="The reason for the ban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def ban(self, interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
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
            print(f"[BAN ERROR] {traceback.format_exc()}")

    @app_commands.command(name="unban", description="Unban a user from the server")
    @app_commands.describe(user="The user to unban", reason="The reason for the unban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def unban(self, interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
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
    @app_commands.describe(member="The member to kick", reason="The reason for the kick")
    @app_commands.checks.has_permissions(kick_members=True)
    async def kick(self, interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
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
            print(f"Kick error: {str(e)}")

    @app_commands.command(name="deafen", description="Deafen a user in voice channels")
    @app_commands.describe(member="The member to deafen", reason="The reason for deafening")
    @app_commands.checks.has_permissions(deafen_members=True)
    async def deafen(self, interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
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
    @app_commands.describe(member="The member to undeafen", reason="The reason for undeffening")
    @app_commands.checks.has_permissions(deafen_members=True)
    async def undeafen(self, interaction: discord.Interaction, member: discord.Member, reason: str = "No reason provided"):
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
            print(f"Timeout error: {str(e)}")

    @app_commands.command(name="untimeout", description="Remove timeout from a user")
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
    @app_commands.describe(user="The user to softban", reason="The reason for softban")
    @app_commands.checks.has_permissions(ban_members=True)
    async def softban(self, interaction: discord.Interaction, user: discord.User, reason: str = "No reason provided"):
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
                print(f"Error saving softban to database: {str(e)}")
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
            print(f"Softban error: {str(e)}")      
        
async def setup(bot):
    await bot.add_cog(ModerationCog(bot))