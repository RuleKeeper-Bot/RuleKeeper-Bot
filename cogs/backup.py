import discord
from discord import app_commands
from discord.ext import commands
from bot.bot import log_event
import re
import random
import os
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
        No-op fallback for an optional debug printing function.
        
        Accepts any positional and keyword arguments and intentionally does nothing.
        Used as a drop-in replacement when a real `debug_print` implementation is not available.
        """
        pass

class ConfirmRestoreView(discord.ui.View):
    def __init__(self, timeout=30):
        """
        Initialize the ConfirmRestoreView.
        
        Parameters:
            timeout (int): Time in seconds before the view stops automatically (default 30).
        
        Description:
            Sets the view's interaction timeout and initializes `self.value` to None.
            `self.value` will be set to True when the confirm button is pressed and left as
            None if the view times out without confirmation.
        """
        super().__init__(timeout=timeout)
        self.value = None

    @discord.ui.button(label="Restore from Backup", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        """
        Handle the Confirm button click: mark the view as confirmed, stop the view, and defer the interaction response.
        
        Parameters:
            interaction (discord.Interaction): The interaction triggered by the button click.
            button (discord.ui.Button): The button that was pressed.
        """
        self.value = True
        self.stop()
        await interaction.response.defer()  # Prevents "This interaction failed" message

class ContinueCancelView(discord.ui.View):
    def __init__(self, timeout=60):
        """
        Initialize the ContinueCancelView.
        
        Parameters:
            timeout (int | float): Optional view timeout in seconds (default 60). When reached the view will stop and become inactive.
        
        Initial state:
            self.value is set to None and will be updated to True or False by the view's buttons.
        """
        super().__init__(timeout=timeout)
        self.value = None

    @discord.ui.button(label="Continue", style=discord.ButtonStyle.danger)
    async def continue_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """
        Handle the "Continue" button: mark the view as confirmed, stop the view, and defer the interaction response.
        
        Sets self.value to True, calls self.stop() to end the view, and defers the interaction response so Discord does not display an automatic error message.
        """
        self.value = True
        self.stop()
        await interaction.response.defer()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        """
        Handle the "Cancel" button: mark the view as cancelled, stop it, and defer the interaction response.
        
        Sets self.value to False to indicate cancellation, stops the view so it stops listening for input, and defers the interaction response to prevent Discord from showing an "interaction failed" message.
        """
        self.value = False
        self.stop()
        await interaction.response.defer()

class BackupCog(commands.Cog):
    def __init__(self, bot):
        """
        Initialize the BackupCog and capture shared bot resources.
        
        Stores the provided bot instance on self.bot and the bot's database connection on self.db. Emits a debug print on construction.
        """
        debug_print(f"Entering BackupCog.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.db = bot.db
    
    def get_permission_checks(self, guild):
        """
        Return a list of human-readable permission or configuration warnings the bot needs to create or restore a guild backup.
        
        The returned list contains strings describing missing permissions or problematic server configuration that may prevent a full backup/restore. Messages cover:
        - Required guild-level permissions (Manage Server, Manage Roles, View Audit Log, Manage Channels).
        - Emoji/sticker-related permissions when the guild has emojis or stickers.
        - A warning when one or more roles have the Administrator permission but the bot itself lacks Administrator.
        - A suggestion if a role named "RuleKeeper" is not the highest role.
        
        Returns:
            list[str]: Zero or more user-facing warning messages; empty if no issues detected.
        """
        bot_member = guild.me
        perms = bot_member.guild_permissions
        checks = []
        if not perms.manage_guild:
            checks.append("❌ I need the **Manage Server** permission to create or restore a backup.")
        if not perms.manage_roles:
            checks.append("❌ I need the **Manage Roles** permission to backup and restore roles.")
        if not perms.view_audit_log:
            checks.append("❌ I need the **View Audit Log** permission to fully backup server settings.")
        has_emojis = len(getattr(guild, "emojis", [])) > 0
        has_stickers = hasattr(guild, "stickers") and len(getattr(guild, "stickers", [])) > 0
        missing_perms = []
        if (has_emojis or has_stickers):
            if not perms.manage_emojis_and_stickers:
                missing_perms.append("Create Expressions")
            if not perms.manage_expressions:
                missing_perms.append("Manage Expressions")
        if missing_perms:
            checks.append(
                "❌ I need the following permission(s) to backup/restore emojis/stickers: **" +
                ", ".join(missing_perms) + "**"
            )
        if not perms.manage_channels:
            checks.append("❌ I need the **Manage Channels** permission to backup and restore channels and categories.")
        admin_roles = [role for role in guild.roles if role.permissions.administrator and not role.is_default()]
        if admin_roles and not perms.administrator:
            admin_role_names = ", ".join([role.name for role in admin_roles])
            checks.append(
                "❌ One or more roles in this server have the **Administrator** permission "
                f"({admin_role_names}).\n"
                "I need the **Administrator** permission to properly back up and restore these roles."
            )
        rulekeeper_role = discord.utils.get(guild.roles, name="RuleKeeper")
        if rulekeeper_role and rulekeeper_role != guild.roles[-1]:
            checks.append(
                "⚠️ The **RuleKeeper** role is not the highest role in the server. For best results, please move it to the top of the role list."
            )
        return checks
    
    # Autocompletes
    @app_commands.autocomplete(backup_id=True)
    async def backup_id_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str
    ) -> list[app_commands.Choice[str]]:
        """
        Return up to 25 app command autocomplete choices for backup IDs in the current guild.
        
        Each choice value is the backup ID (string) and the choice label includes the ID, the backup's creation time converted to the guild's preferred timezone (or UTC if unavailable/invalid), the timezone name, and the backup file's basename. Matches are included when the user's current input is a substring of the backup ID. If the guild has no saved timezone preference the function falls back to UTC.
        """
        guild_id = str(interaction.guild.id)
        with get_conn() as conn:
            backups = conn.execute(
                'SELECT id, created_at, file_path FROM backups WHERE guild_id = ? ORDER BY created_at DESC',
                (guild_id,)
            ).fetchall()
        # Try to get the guild's preferred timezone from the latest schedule, fallback to UTC
        with get_conn() as conn:
            sched = conn.execute(
                'SELECT timezone FROM schedules WHERE guild_id = ? ORDER BY id DESC LIMIT 1', (guild_id,)
            ).fetchone()
        tz_str = sched['timezone'] if sched and sched['timezone'] else 'UTC'
        try:
            local_tz = pytz_timezone(tz_str)
        except Exception:
            local_tz = pytz_timezone('UTC')
            tz_str = 'UTC'
        choices = []
        for b in backups:
            # Convert from UTC timestamp to local time in the preferred timezone
            dt_utc = datetime.utcfromtimestamp(b['created_at']).replace(tzinfo=pytz_timezone('UTC'))
            dt_local = dt_utc.astimezone(local_tz)
            dt_str = dt_local.strftime('%Y-%m-%d %I:%M %p')
            label = f"ID: {b['id']} | Created: {dt_str} ({tz_str}) | File: {os.path.basename(b['file_path'])}"
            if current in str(b['id']):
                choices.append(app_commands.Choice(name=label, value=str(b['id'])))
            if len(choices) >= 25:
                break
        return choices

    @app_commands.autocomplete(schedule_id=True)
    async def schedule_id_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str
    ) -> list[app_commands.Choice[str]]:
        """Autocomplete for schedule IDs with info (local time, pretty label)."""
        guild_id = str(interaction.guild.id)
        with get_conn() as conn:
            schedules = conn.execute(
                'SELECT * FROM schedules WHERE guild_id = ? ORDER BY start_date, start_time',
                (guild_id,)
            ).fetchall()
        choices = []
        for s in schedules:
            tz_str = s['timezone'] if 'timezone' in s.keys() and s['timezone'] else 'UTC'
            try:
                local_tz = pytz_timezone(tz_str)
            except Exception:
                local_tz = pytz_timezone('UTC')
            # Parse local start datetime
            try:
                start_dt_local = local_tz.localize(datetime.strptime(f"{s['start_date']} {s['start_time']}", "%Y-%m-%d %H:%M"))
                dt_str = start_dt_local.strftime('%Y-%m-%d %I:%M %p')
            except Exception:
                dt_str = f"{s['start_date']} {s['start_time']}"
            label = (
                f"ID: {s['id']} | Start: {dt_str} | Every {s['frequency_value']} {s['frequency_unit']} "
                f"({tz_str}) {'(enabled)' if s['enabled'] else '(disabled)'}"
            )
            if current in str(s['id']):
                choices.append(app_commands.Choice(name=label, value=str(s['id'])))
            if len(choices) >= 25:
                break
        return choices
    
    @app_commands.autocomplete(timezone=True)
    async def timezone_autocomplete(
        self,
        interaction: discord.Interaction,
        current: str
    ) -> list[app_commands.Choice[str]]:
        # Show up to 25 matching timezones
        """
        Provide autocomplete suggestions for timezones.
        
        Performs a case-insensitive substring match of `current` against pytz's
        `all_timezones` and returns up to 25 matching choices.
        
        Parameters:
            current (str): Partial user input used to filter timezone names.
        
        Returns:
            list[app_commands.Choice[str]]: Up to 25 timezone choices where each choice's
            name and value are the timezone string (e.g., "America/New_York").
        """
        matches = [tz for tz in all_timezones if current.lower() in tz.lower()]
        return [app_commands.Choice(name=tz, value=tz) for tz in matches[:25]]
    
    
    @app_commands.command(name="create_backup", description="Create a server backup now")
    @command_permission_check("create_backup")
    async def create_backup(self, interaction: discord.Interaction):
        """
        Create a full guild backup and send progress/status to the invoking interaction.
        
        Prompts the user to sequentially bypass any detected permission issues (each must be explicitly continued or the operation is cancelled), then starts an asynchronous backup of the current guild. Progress is reported by editing an ephemeral follow-up message; on success the newest backup ID is reported and a `backup_created` event is logged. On failure the user is notified with the error message.
        
        Parameters:
            interaction (discord.Interaction): The command interaction that initiated the backup (used to reply/drive the UI).
        
        Returns:
            None
        """
        debug_print(f"Entering /create_backup with interaction: {interaction}", level="all")
        await interaction.response.defer(ephemeral=True)
        guild = interaction.guild
        if not guild:
            await interaction.followup.send(content="This command can only be used in a server.", ephemeral=True)
            return

        # Use the helper for permission checks
        checks = self.get_permission_checks(guild)

        # Sequentially prompt for each failed check, requiring explicit continue for each
        prev_msg = None
        for reason in checks:
            view = ContinueCancelView(timeout=120)
            msg = await interaction.followup.send(
                content=(
                    f"{reason}\n\n"
                    "Click the **Continue** button to proceed (not recommended), or click **Cancel** to stop the backup."
                ),
                view=view,
                ephemeral=True
            )
            await view.wait()
            if prev_msg:
                try:
                    await prev_msg.delete()
                except Exception:
                    pass
            if view.value is None or view.value is False:
                await msg.edit(content="Backup cancelled.", view=None)
                return
            await msg.edit(content="Bypassed. Checking next requirement...", view=None)
            prev_msg = msg
            await asyncio.sleep(0.5)
        if prev_msg:
            try:
                await prev_msg.delete()
            except Exception:
                pass

        # Now start the backup
        progress_msg = await interaction.followup.send(content="Starting backup...", ephemeral=True)

        progress = {"val": 0, "step": "Preparing backup..."}
        done = False

        async def progress_updater():
            """
            Background coroutine that monitors the `progress` mapping and updates `progress_msg` with a throttled progress display.
            
            Runs until the outer `done` flag becomes true. When `progress["val"]` changes, edits `progress_msg` to show
            "Backup progress: {val}% - {step}". Edit exceptions are ignored to avoid cancelling the updater. Sleeps 0.5s between checks.
            """
            last_val = -1
            while not done:
                if progress["val"] != last_val:
                    try:
                        await progress_msg.edit(
                            content=f"Backup progress: {progress['val']}% - {progress['step']}"
                        )
                    except Exception:
                        pass
                    last_val = progress["val"]
                await asyncio.sleep(0.5)

        def set_progress(val, step_text=None):
            """
            Update the shared progress state used by the surrounding task.
            
            Parameters:
                val: New progress value (e.g., a numeric progress percentage or step index).
                step_text (str, optional): Human-readable description of the current step; when provided sets the `"step"` key.
            
            Side effects:
                Mutates the outer `progress` mapping by setting `progress["val"]` and, if `step_text` is given, `progress["step"]`.
            """
            progress["val"] = val
            if step_text:
                progress["step"] = step_text

        updater_task = asyncio.create_task(progress_updater())

        try:
            await save_guild_backup(guild, set_progress=set_progress)
            progress["val"] = 100
            progress["step"] = "Backup complete!"
            done = True
            await updater_task

            with get_conn() as conn:
                row = conn.execute(
                    'SELECT id FROM backups WHERE guild_id = ? ORDER BY created_at DESC LIMIT 1',
                    (str(guild.id),)
                ).fetchone()
                backup_id = row['id'] if row else "unknown"

            await progress_msg.edit(
                content=f"✅ Backup complete! Backup ID: `{backup_id}`"
            )
        except Exception as e:
            done = True
            await updater_task
            await progress_msg.edit(
                content=f"❌ Backup failed: {e}"
            )
        # Log backup creation
        await log_event(
            interaction.guild,
            event_key="backup_created",
            title="Backup Created",
            description=f"Backup `{backup_id}` was created.",
            color=discord.Color.orange()
        )

    @app_commands.command(name="delete_backup", description="Delete a backup by ID")
    @command_permission_check("delete_backup")
    @app_commands.describe(backup_id="The backup ID to delete")
    @app_commands.autocomplete(backup_id=backup_id_autocomplete)
    async def delete_backup(self, interaction: discord.Interaction, backup_id: str):
        """
        Delete a stored backup by ID for the current guild.
        
        Looks up the backup for the invoking guild; if found, removes the backup file from disk (if present),
        deletes the database record, sends an ephemeral confirmation to the command invoker, and logs a
        "backup_deleted" event. If no matching backup is found, sends an ephemeral "Backup not found." reply.
        
        Parameters:
            interaction: The Discord interaction that invoked the command (provides guild context and response).
            backup_id: The backup identifier (string) to delete.
        
        Returns:
            None
        """
        debug_print(f"Entering /delete_backup with interaction: {interaction}, backup_id: {backup_id}", level="all")
        guild_id = str(interaction.guild.id)
        backup = get_backup(backup_id, guild_id)
        if not backup:
            await interaction.response.send_message("Backup not found.", ephemeral=True)
            return
        # Remove file from disk
        if backup['file_path'] and os.path.exists(backup['file_path']):
            os.remove(backup['file_path'])
        # Remove from DB
        with get_conn() as conn:
            conn.execute('DELETE FROM backups WHERE id = ? AND guild_id = ?', (backup_id, guild_id))
        await interaction.response.send_message(f"Backup `{backup_id}` deleted.", ephemeral=True)
        # Log backup deletion
        await log_event(
            interaction.guild,
            event_key="backup_deleted",
            title="Backup Deleted",
            description=f"Backup `{backup_id}` was deleted.",
            color=discord.Color.orange()
        )

    @app_commands.command(name="restore_backup", description="Restore a backup by ID (DANGEROUS: overwrites server settings, roles, channels, etc.)")
    @command_permission_check("restore_backup")
    @app_commands.describe(backup_id="The backup ID to restore")
    @app_commands.autocomplete(backup_id=backup_id_autocomplete)
    async def restore_backup(self, interaction: discord.Interaction, backup_id: str):
        """
        Restore a guild from a saved backup file, guiding the user through permission checks, confirmation, and progress reporting.
        
        This command handler locates the specified backup for the invoking guild, verifies the backup file exists on disk, prompts the user to bypass any missing-permission warnings (one-by-one), requires a final confirmation, and then runs the restore procedure while streaming progress to the user (via ephemeral followups and optional direct messages). On completion it notifies the user of success or failure and records a "backup_restored" event.
        
        Behavior notes:
        - If the backup ID is not found or the file is missing, an ephemeral error is sent and the command returns.
        - For each permission warning returned by get_permission_checks(guild) the user is prompted with a Continue/Cancel view; cancelling stops the restore.
        - A 30s confirmation button is required before the actual restore begins.
        - Progress updates are throttled and sent to the user's DM when possible; the implementation tolerates missing/deleted channels and DM failures.
        - Any exceptions raised during restore are reported to the user (ephemeral followup or DM) and the function still attempts cleanup of progress messages.
        
        Parameters:
        - interaction: The Discord Interaction that invoked the command.
        - backup_id: The identifier of the backup to restore.
        
        Returns:
        - None
        """
        debug_print(f"Entering /restore_backup with interaction: {interaction}, backup_id: {backup_id}", level="all")
        guild = interaction.guild
        guild_id = str(guild.id)
        backup = get_backup(backup_id, guild_id)
        if not backup:
            await interaction.response.send_message("Backup not found.", ephemeral=True)
            return
        file_path = backup['file_path']
        if not file_path or not os.path.exists(file_path):
            await interaction.response.send_message("Backup file not found on disk.", ephemeral=True)
            return

        # Permission checks
        checks = self.get_permission_checks(guild)
        prev_msg = None
        for reason in checks:
            view = ContinueCancelView(timeout=120)
            msg = await interaction.response.send_message(
                content=(
                    f"{reason}\n\n"
                    "Click the **Continue** button to proceed (not recommended), or click **Cancel** to stop the restore."
                ),
                view=view,
                ephemeral=True
            )
            await view.wait()
            if prev_msg:
                try:
                    await prev_msg.delete()
                except Exception:
                    pass
            if view.value is None or view.value is False:
                await interaction.edit_original_response(content="Restore cancelled.", view=None)
                return
            await interaction.edit_original_response(content="Bypassed. Checking next requirement...", view=None)
            prev_msg = msg
            await asyncio.sleep(0.5)
        if prev_msg:
            try:
                await prev_msg.delete()
            except Exception:
                pass

        # Confirmation Button
        view = ConfirmRestoreView(timeout=30)
        await interaction.response.send_message(
            "⚠️ **WARNING:** This will overwrite your server's roles, channels, and settings with the backup.\n"
            "Click the button below within 30 seconds to confirm.",
            ephemeral=True,
            view=view
        )

        timeout = await view.wait()
        if not view.value:
            await interaction.edit_original_response(
                content="Restore cancelled (no confirmation received).",
                view=None
            )
            return

        await interaction.edit_original_response(
            content="Restore confirmed. Proceeding...",
            view=None
        )

        # DM Progress
        try:
            dm = await interaction.user.create_dm()
            msg1 = await dm.send("Restoring backup... This may take a while.")
            msg2 = await dm.send("Starting...")
        except Exception:
            dm = None
            msg1 = None
            msg2 = None

        last_progress = {"content": None, "time": 0}

        async def progress_callback(step_text):
            """
            Update the in-progress message with a new step text, throttled to avoid rapid edits.
            
            Parameters:
                step_text (str): Short status text describing the current progress step.
            
            Behavior:
                - If `msg2` is set, edits that message to "🔄 {step_text}" only when the text differs from the last sent content and at least 1 second has elapsed since the last update.
                - On a successful edit, updates `last_progress["content"]` and `last_progress["time"]`, then awaits 2.5 seconds to further throttle updates.
                - Any exceptions raised while editing are caught and ignored.
            
            Returns:
                None
            """
            if msg2:
                now = time.monotonic()
                # Only update if content changed and at least 1s since last update
                if step_text != last_progress["content"] and now - last_progress["time"] > 1:
                    try:
                        await msg2.edit(content=f"🔄 {step_text}")
                        last_progress["content"] = step_text
                        last_progress["time"] = now
                        await asyncio.sleep(2.5)  # Throttle to avoid rate limits
                    except Exception:
                        pass

        try:
            await interaction.followup.send("Restoring backup... This may take a while.", ephemeral=True)
        except discord.HTTPException as e:
            if e.code == 10003:
                try:
                    await interaction.user.send("Restoring backup... This may take a while. (original channel was deleted)")
                except Exception:
                    pass
            else:
                raise

        try:
            result = await restore(interaction.guild, file_path, progress_callback=progress_callback)
            # Delete progress messages
            for m in (msg2, msg1):
                if m:
                    try:
                        await m.delete()
                        await asyncio.sleep(1)
                    except Exception:
                        pass
            if dm:
                try:
                    if result:
                        await dm.send("✅ Backup restored successfully!")
                    else:
                        await dm.send("❌ Restore failed. Check logs for details.")
                except Exception:
                    pass
            if result:
                try:
                    await interaction.followup.send("✅ Backup restored successfully!", ephemeral=True)
                except discord.HTTPException as e:
                    if e.code == 10003:
                        try:
                            await interaction.user.send("✅ Backup restored successfully!")
                        except Exception:
                            pass
                    else:
                        raise
            else:
                try:
                    await interaction.followup.send("❌ Restore failed. Check logs for details.", ephemeral=True)
                except discord.HTTPException as e:
                    if e.code == 10003:
                        try:
                            await interaction.user.send("❌ Restore failed. Check logs for details. (original channel was deleted)")
                        except Exception:
                            pass
                    else:
                        raise
        except Exception as e:
            for m in (msg2, msg1):
                if m:
                    try:
                        await m.delete()
                        await asyncio.sleep(2)
                    except Exception:
                        pass
            if dm:
                try:
                    await dm.send(f"❌ Restore failed: {e}")
                except Exception:
                    pass
            try:
                await interaction.followup.send(f"❌ Restore failed: {e}", ephemeral=True)
            except discord.HTTPException as e2:
                if e2.code == 10003:
                    try:
                        await interaction.user.send(f"❌ Restore failed: {e} (original channel was deleted)")
                    except Exception:
                        pass
                else:
                    raise
        # Log restore result
        if result:
            await log_event(
                guild,
                event_key="backup_restored",
                title="Backup Restored",
                description=f"Backup `{backup_id}` was restored.",
                color=discord.Color.blurple()
            )
        else:
            await log_event(
                guild,
                event_key="backup_restore_failed",
                title="Backup Restore Failed",
                description=f"Backup `{backup_id}` restore failed or was cancelled.",
                color=discord.Color.red()
            )

    @app_commands.command(name="schedule_backup", description="Schedule regular backups")
    @command_permission_check("schedule_backup")
    @app_commands.describe(
        frequency_value="How often to backup (number)",
        frequency_unit="Unit (days, weeks, months, years)",
        start_date="Start date (YYYY-MM-DD, in your local time)",
        start_time="Start time (HH:MM, 24h, in your local time)",
        timezone="Your timezone (e.g. UTC, America/Denver, Europe/London)"
    )
    @app_commands.autocomplete(timezone=timezone_autocomplete)
    async def schedule_backup(
        self,
        interaction: discord.Interaction,
        frequency_value: int,
        frequency_unit: str,
        start_date: str,
        start_time: str,
        timezone: str = "UTC"
    ):
        """
        Create a recurring backup schedule for the guild.
        
        Validates the provided timezone (IANA name) and start date/time, inserts a new schedule row into the schedules database table, reloads the in-memory schedules, sends an ephemeral confirmation to the user, and logs the creation.
        
        Parameters:
            interaction (discord.Interaction): The command interaction (must be invoked in a guild).
            frequency_value (int): Positive integer for the recurrence interval.
            frequency_unit (str): Unit for the recurrence interval (e.g., minutes/hours/days).
            start_date (str): Start date in YYYY-MM-DD format.
            start_time (str): Start time in 24-hour HH:MM format.
            timezone (str): IANA timezone name (defaults to "UTC").
        
        Behavior and side effects:
            - If the timezone is invalid, replies ephemerally with an error and returns.
            - If the date/time cannot be parsed or localized, replies ephemerally with an error and returns.
            - On success, stores a new schedule with a generated 5-digit numeric schedule ID, calls load_schedules(), sends an ephemeral success message including the Schedule ID, and emits a "backup_schedule_created" log event.
        """
        debug_print(f"Entering /schedule_backup with interaction: {interaction}, frequency_value: {frequency_value}, frequency_unit: {frequency_unit}, start_date: {start_date}, start_time: {start_time}, timezone: {timezone}", level="all")
        # Validate timezone
        try:
            tz = pytz_timezone(timezone)
        except Exception:
            await interaction.response.send_message(
                f"Invalid timezone. See https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for valid names.",
                ephemeral=True
            )
            return

        # Validate date and time
        try:
            local_dt = tz.localize(datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M"))
        except Exception:
            await interaction.response.send_message(
                "Invalid date or time format. Use YYYY-MM-DD for date and HH:MM (24h) for time.",
                ephemeral=True
            )
            return

        guild_id = str(interaction.guild.id)
        schedule_id = ''.join(random.choices('0123456789', k=5))
        with get_conn() as conn:
            conn.execute(
                'INSERT INTO schedules (id, guild_id, start_date, start_time, timezone, frequency_value, frequency_unit, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (schedule_id, guild_id, start_date, start_time, timezone, frequency_value, frequency_unit, 1)
            )
        load_schedules()
        await interaction.response.send_message(
            f"Scheduled backups every {frequency_value} {frequency_unit} starting {start_date} {start_time} ({timezone}). Schedule ID: `{schedule_id}`",
            ephemeral=True
        )
        # Log schedule creation
        await log_event(
            interaction.guild,
            event_key="backup_schedule_created",
            title="Backup Schedule Created",
            description=f"Scheduled backups every {frequency_value} {frequency_unit} starting {start_date} {start_time} ({timezone}). Schedule ID: `{schedule_id}`",
            color=discord.Color.green()
        )

    @app_commands.command(name="delete_scheduled_backup", description="Delete a scheduled backup by schedule ID")
    @command_permission_check("delete_scheduled_backup")
    @app_commands.describe(schedule_id="The schedule ID to delete (see /list_backup)")
    @app_commands.autocomplete(schedule_id=schedule_id_autocomplete)
    async def delete_scheduled_backup(self, interaction: discord.Interaction, schedule_id: int):
        """
        Delete a scheduled backup for the current guild by its numeric ID.
        
        Checks for a schedule row matching the provided schedule_id and the invoking guild; if found the row is removed from the database, an ephemeral confirmation is sent to the user, and a `backup_schedule_deleted` event is logged. If no matching schedule exists, an ephemeral "Schedule not found." message is sent.
        
        Parameters:
            schedule_id (int): Numeric identifier of the schedule to delete (must belong to the guild of the interaction).
        
        Returns:
            None
        """
        debug_print(f"Entering /delete_scheduled_backup with interaction: {interaction}, schedule_id: {schedule_id}", level="all")
        guild_id = str(interaction.guild.id)
        with get_conn() as conn:
            result = conn.execute(
                'SELECT * FROM schedules WHERE id = ? AND guild_id = ?', (schedule_id, guild_id)
            ).fetchone()
            if not result:
                await interaction.response.send_message("Schedule not found.", ephemeral=True)
                return
            conn.execute('DELETE FROM schedules WHERE id = ? AND guild_id = ?', (schedule_id, guild_id))
        await interaction.response.send_message(f"Schedule `{schedule_id}` deleted.", ephemeral=True)
        # Log schedule deletion
        await log_event(
            interaction.guild,
            event_key="backup_schedule_deleted",
            title="Backup Schedule Deleted",
            description=f"Backup schedule `{schedule_id}` was deleted.",
            color=discord.Color.orange()
        )

    @app_commands.command(name="list_backup", description="List all backups and schedules for this server")
    @command_permission_check("list_backup")
    async def list_backup(self, interaction: discord.Interaction):
        """
        List stored backups and scheduled backups for the current guild and send the result as ephemeral Discord messages.
        
        Fetches backups and schedules from the database, formats creation and schedule start times in the preferred timezone (falls back to UTC when missing or invalid), and splits the output into Discord-safe chunks (≤2000 characters). Sends the first chunk as the initial ephemeral interaction response and any remaining chunks as ephemeral follow-ups.
        """
        debug_print(f"Entering /list_backup with interaction: {interaction}", level="all")
        guild_id = str(interaction.guild.id)
        # Get preferred timezone from latest schedule, fallback to UTC
        with get_conn() as conn:
            sched = conn.execute(
                'SELECT timezone FROM schedules WHERE guild_id = ? ORDER BY id DESC LIMIT 1', (guild_id,)
            ).fetchone()
            backups = conn.execute(
                'SELECT id, created_at, file_path FROM backups WHERE guild_id = ? ORDER BY created_at DESC', (guild_id,)
            ).fetchall()
            schedules = conn.execute(
                'SELECT * FROM schedules WHERE guild_id = ?', (guild_id,)
            ).fetchall()
        tz_str = sched['timezone'] if sched and sched['timezone'] else 'UTC'
        try:
            local_tz = pytz_timezone(tz_str)
        except Exception:
            local_tz = pytz_timezone('UTC')
            tz_str = 'UTC'

        msg = ""
        if backups:
            msg += "**Backups:**\n"
            for b in backups:
                dt_utc = datetime.utcfromtimestamp(b['created_at']).replace(tzinfo=pytz_timezone('UTC'))
                dt_local = dt_utc.astimezone(local_tz)
                dt_str = dt_local.strftime('%Y-%m-%d %I:%M %p')
                msg += f"- ID: `{b['id']}` | Created: {dt_str} ({tz_str}) | File: `{os.path.basename(b['file_path'])}`\n"
        else:
            msg += "No backups found.\n"
        if schedules:
            msg += "\n**Schedules:**\n"
            for s in schedules:
                sched_tz_str = s['timezone'] if 'timezone' in s.keys() and s['timezone'] else 'UTC'
                try:
                    sched_local_tz = pytz_timezone(sched_tz_str)
                except Exception:
                    sched_local_tz = pytz_timezone('UTC')
                    sched_tz_str = 'UTC'
                try:
                    start_dt_local = sched_local_tz.localize(datetime.strptime(f"{s['start_date']} {s['start_time']}", "%Y-%m-%d %H:%M"))
                    dt_str = start_dt_local.strftime('%Y-%m-%d %I:%M %p')
                except Exception:
                    dt_str = f"{s['start_date']} {s['start_time']}"
                msg += (
                    f"- ID: `{s['id']}` | Start: {dt_str} ({sched_tz_str}) | Every {s['frequency_value']} {s['frequency_unit']} "
                    f"{'(enabled)' if s['enabled'] else '(disabled)'}\n"
                )
        else:
            msg += "\nNo schedules found."

        # Split the message into chunks of 2000 characters or less
        def split_message(text, limit=2000):
            """
            Split a string into a list of messages no longer than `limit` characters, breaking only at newline boundaries.
            
            The input text is split on '\n' and lines are joined into chunks that do not exceed `limit` by length. Lines are preserved and not broken; if a single line is longer than `limit`, that line will be returned as a chunk that may exceed the limit.
            
            Parameters:
                text (str): The input string to split.
                limit (int): Maximum allowed characters per chunk (default 2000).
            
            Returns:
                list[str]: A list of text chunks, each formed by joining whole lines and suitable for posting where a character limit applies.
            """
            lines = text.split('\n')
            chunks = []
            current = ""
            for line in lines:
                if len(current) + len(line) + 1 > limit:
                    chunks.append(current)
                    current = ""
                if current:
                    current += '\n' + line
                else:
                    current = line
            if current:
                chunks.append(current)
            return chunks

        msg_chunks = split_message(msg)
        # Send the first chunk as the initial response, the rest as followups
        if msg_chunks:
            await interaction.response.send_message(msg_chunks[0], ephemeral=True)
            for chunk in msg_chunks[1:]:
                await interaction.followup.send(chunk, ephemeral=True)
        else:
            await interaction.response.send_message("No backup or schedule data found.", ephemeral=True)

    @app_commands.command(name="next_backup", description="Show when the next scheduled backup will run")
    @command_permission_check("next_backup")
    async def next_backup(self, interaction: discord.Interaction):
        """
        Compute the next scheduled backup for the current guild and reply ephemerally with when it will occur.
        
        Scans enabled schedules in the database for the invoking guild, parses each schedule's start date/time and frequency, advances each schedule from its start until it is in the future (months and years are approximated as 30 and 365 days respectively), selects the soonest upcoming time, and sends an ephemeral message with the scheduled UTC time and a compact human-readable time delta. Malformed schedule rows are skipped; if no enabled schedules exist or no valid next time can be determined, an appropriate ephemeral message is sent.
        """
        debug_print(f"Entering /next_backup with interaction: {interaction}", level="all")
        guild_id = str(interaction.guild.id)
        now = datetime.utcnow()
        with get_conn() as conn:
            schedules = conn.execute(
                'SELECT * FROM schedules WHERE guild_id = ? AND enabled = 1', (guild_id,)
            ).fetchall()
        if not schedules:
            await interaction.response.send_message("No backup schedules set for this server.", ephemeral=True)
            return

        soonest_time = None
        soonest_sched = None
        for sched in schedules:
            try:
                start_dt = datetime.strptime(f"{sched['start_date']} {sched['start_time']}", "%Y-%m-%d %H:%M")
            except Exception:
                continue
            freq_val = int(sched['frequency_value'])
            freq_unit = sched['frequency_unit']
            next_backup = start_dt
            while next_backup < now:
                if freq_unit == 'days':
                    next_backup += timedelta(days=freq_val)
                elif freq_unit == 'weeks':
                    next_backup += timedelta(weeks=freq_val)
                elif freq_unit == 'months':
                    next_backup += timedelta(days=30 * freq_val)  # Approximate
                elif freq_unit == 'years':
                    next_backup += timedelta(days=365 * freq_val)  # Approximate
            if soonest_time is None or next_backup < soonest_time:
                soonest_time = next_backup
                soonest_sched = sched

        if soonest_time:
            seconds = int((soonest_time - now).total_seconds())
            if seconds < 60:
                time_str = f"{seconds} seconds"
            elif seconds < 3600:
                time_str = f"{seconds // 60} minutes"
            elif seconds < 86400:
                time_str = f"{seconds // 3600} hours"
            else:
                time_str = f"{seconds // 86400} days"
            msg = (
                f"Next backup is scheduled for **{soonest_time.strftime('%Y-%m-%d %H:%M UTC')}** "
                f"(in {time_str})."
            )
        else:
            msg = "Could not determine the next backup time."

        await interaction.response.send_message(msg, ephemeral=True)
        
async def setup(bot):
    """
    Register the BackupCog with the bot.
    
    This asynchronous setup hook adds the BackupCog to the provided bot so its commands,
    views, and background behavior are registered.
    """
    await bot.add_cog(BackupCog(bot))