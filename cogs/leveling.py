import discord
from discord import app_commands
from discord.ext import commands
import logging
import traceback
from bot.bot import get_level_data, save_level_data, get_level_config, calculate_xp_for_level, calculate_level, calculate_progress, calculate_xp_with_boost, handle_level_up
from shared import command_permission_check
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        """
        No-op fallback replacement for an optional debug_print function.
        
        This function accepts the same arguments and keyword arguments as built-in `print`
        so it can be used interchangeably where a `debug_print` callable may or may not
        be available. It performs no action and returns None.
        """
        pass

class LevelingCog(commands.Cog):
    def __init__(self, bot):
        """
        Initialize the LevelingCog and store references to the bot and its database.
        
        Sets self.bot to the provided bot instance and self.db to bot.db.
        """
        debug_print(f"Entering LevelingCog.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.db = bot.db

    @app_commands.command(name="level", description="Check your current level and XP")
    @command_permission_check("level")
    @app_commands.guild_only()
    async def level(self, interaction: discord.Interaction, user: discord.Member = None):
        """
        Show a user's leveling profile as a Discord embed.
        
        If `user` is omitted, shows the profile for the invoking user. Retrieves stored XP/level for the member from the bot database (defaults to 0 if missing), computes progress toward the next level using the formula `xp_required = 100 * (level ** 1.7)`, and builds an embed containing level, total XP, a 10-segment progress bar with percentage to the next level, and a comma-separated list of non-default roles (up to 15 shown, with a "+N more" note if applicable). Sends the embed via the interaction response. On unexpected errors, replies with an ephemeral failure message.
        """
        debug_print(f"Entering /level with interaction: {interaction}, user: {user}", level="all")
        """Show level profile with Discord integration"""
        try:
            user = user or interaction.user
            guild_id = str(interaction.guild.id)
            user_id = str(user.id)

            # Fetch base user data
            user_data = self.bot.db.get_user_level(guild_id, user_id) or {}
            xp = user_data.get('xp', 0)
            level = user_data.get('level', 0)

            # Calculate progress
            current_level_xp = 100 * (level ** 1.7)
            next_level_xp = 100 * ((level + 1) ** 1.7)
            progress = min(((xp - current_level_xp) / (next_level_xp - current_level_xp)) * 100, 100) if next_level_xp > current_level_xp else 0

            # Build embed
            embed = discord.Embed(
                title=f"{user.display_name}'s Profile",
                color=user.color
            )
            embed.set_thumbnail(url=user.display_avatar.url)

            # Core stats
            embed.add_field(name="Level", value=str(level), inline=True)
            embed.add_field(name="XP", value=f"{xp:.0f}", inline=True)
            
            # Progress bar
            progress_bar = "▓" * int(progress / 10) + "░" * (10 - int(progress / 10))
            embed.add_field(
                name="Progress", 
                value=f"{progress_bar}\n{progress:.1f}% to level {level + 1}", 
                inline=False
            )

            # Roles
            roles = [role.mention for role in reversed(user.roles) if not role.is_default()]
            roles_text = ", ".join(roles[:15])
            if len(roles) > 15:
                roles_text += f"... (+{len(roles)-15} more)"
            embed.add_field(
                name=f"Roles ({len(roles)})", 
                value=roles_text[:1024] or "No roles", 
                inline=False
            )

            await interaction.response.send_message(embed=embed)

        except Exception as e:
            logging.error(f"Level command error: {str(e)}")
            await interaction.response.send_message(
                "❌ Failed to load profile. Please try again later.",
                ephemeral=True
            )

    @app_commands.command(name="leaderboard", description="Show the server level leaderboard")
    @command_permission_check("leaderboard")
    async def leaderboard(self, interaction: discord.Interaction):
        """
        Create and send a server leaderboard embed showing the top 10 users by XP for the invoking guild.
        
        Builds an embed titled "🏆 Server Leaderboard" containing up to 10 entries ordered by descending XP from the `user_levels` table for the current guild. For each entry, the function resolves the member in the guild (falling back to the stored username if the member is not present), computes the display level with `calculate_level`, and adds a field with rank, display name, level, and XP. Sends the embed as the interaction response.
        """
        debug_print(f"Entering /leaderboard with interaction: {interaction}", level="all")
        guild_id = str(interaction.guild.id)
        
        cursor = self.db.conn.execute('''
            SELECT user_id, xp, username 
            FROM user_levels 
            WHERE guild_id = ?
            ORDER BY xp DESC 
            LIMIT 10
        ''', (guild_id,))
         
        top_users = cursor.fetchall()
         
        embed = discord.Embed(
            title="🏆 Server Leaderboard",
            color=discord.Color.gold()
        )
         
        for idx, user in enumerate(top_users, 1):
            member = interaction.guild.get_member(int(user['user_id']))
            display_name = member.display_name if member else user['username']
            level = calculate_level(float(user['xp']))
            
            embed.add_field(
                name=f"{idx}. {display_name}",
                value=f"Level {level} | XP {user['xp']:.0f}",
                inline=False
            )
           
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="setxp", description="Set a user's XP")
    @command_permission_check("setxp")
    @app_commands.describe(user="User to modify", xp="New XP value to set")
    async def set_xp(self, interaction: discord.Interaction, user: discord.User, xp: int):
        """
        Set a user's XP for the current guild and send an ephemeral confirmation embed.
        
        Ensures a Member object is used when possible (attempts to fetch the guild member for the provided user),
        then upserts the user's XP and username into the `user_levels` table (stored as a float) and commits the change.
        Finally sends an ephemeral embed to the interaction confirming the new XP.
        
        Parameters:
            user (discord.User | discord.Member): Target user; if a plain User is provided and the interaction is in a guild,
                the guild member will be fetched when available so mentions and member attributes work as expected.
            xp (int): New XP value to store (will be saved as a float and replaces any existing XP for that guild).
        """
        debug_print(f"Entering /set_xp with interaction: {interaction}, user: {user}, xp: {xp}", level="all")
        guild_id = str(interaction.guild.id)
        user_id = str(user.id)
        # Ensure we have a Member object for .roles and other member attributes
        if not isinstance(user, discord.Member) and interaction.guild is not None:
            try:
                user = await interaction.guild.fetch_member(user.id)
            except Exception:
                pass  # fallback to User if not found

        self.db.conn.execute('''
            INSERT OR REPLACE INTO user_levels 
            (guild_id, user_id, xp, username)
            VALUES (?, ?, ?, ?)
        ''', (guild_id, user_id, float(xp), user.name))
        self.db.conn.commit()
         
        embed = discord.Embed(
            title="XP Updated",
            description=f"{user.mention}'s XP has been set to **{xp}**",
            color=discord.Color.green()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="addxp", description="Add XP to a user")
    @command_permission_check("addxp")
    @app_commands.describe(
        user="The user to add XP to",
        xp="The amount of XP to add"
    )
    async def add_xp(self, interaction: discord.Interaction, user: discord.Member, xp: int):
        """
        Add a specified amount of XP to a guild member, update their stored XP/level, and trigger level-up handling if applicable.
        
        Adds xp (must be > 0) to the user's stored XP for the current guild, recalculates level progression using the server's XP formula (thresholds computed as 100 * ((level + 1) ** 1.7)), upserts the resulting xp/level/username into the database, and sends an ephemeral confirmation to the invoking interaction. If one or more levels are gained, calls the global level-up handler to perform announcements/embeds.
        
        Parameters:
            xp (int): Amount of XP to add; must be a positive integer.
        
        Returns:
            None
        """
        debug_print(f"Entering /add_xp with interaction: {interaction}, user: {user}, xp: {xp}", level="all")
        """Add XP to a user and handle level progression"""
        if xp <= 0:
            await interaction.response.send_message("❌ XP amount must be positive!", ephemeral=True)
            return

        try:
            guild_id = str(interaction.guild.id)
            user_id = str(user.id)
            levels_gained = 0

            with self.bot.db.conn:
                # Get current data
                data = self.bot.db.conn.execute(
                    '''SELECT xp, level FROM user_levels 
                    WHERE guild_id = ? AND user_id = ?''',
                    (guild_id, user_id)
                ).fetchone()

                current_xp = data[0] if data else 0
                current_level = data[1] if data else 0

                # Update XP
                new_xp = current_xp + xp
                new_level = current_level

                # Calculate level progression
                while True:
                    next_level_xp = 100 * ((new_level + 1) ** 1.7)
                    if new_xp >= next_level_xp:
                        new_level += 1
                        levels_gained += 1
                    else:
                        break

                # Update database
                self.bot.db.conn.execute('''
                    INSERT OR REPLACE INTO user_levels 
                    (guild_id, user_id, xp, level, username)
                    VALUES (?, ?, ?, ?, ?)
                ''', (guild_id, user_id, new_xp, new_level, user.name))

            response = [
                f"✅ Added {xp} XP to {user.mention}",
                f"**New Total:** {new_xp:.0f} XP",
                f"**Level:** {new_level} (+{levels_gained})" if levels_gained else ""
            ]

            await interaction.response.send_message("\n".join(filter(None, response)), ephemeral=True)

            # Use main leveling logic for level up announcement and embed
            if levels_gained > 0:
                # Call the main handler from bot.py
                await handle_level_up(user, interaction.guild, interaction.channel)

        except Exception as e:
            await interaction.response.send_message("❌ Failed to add XP. Check logs.", ephemeral=True)
            logging.error(f"AddXP error: {str(e)}")
            traceback.print_exc()

    @app_commands.command(name="setlevel", description="Set a user's level")
    @command_permission_check("setlevel")
    @app_commands.describe(user="User to modify", level="New level (0-1000)")
    async def setlevel(self, interaction: discord.Interaction, user: discord.Member, level: app_commands.Range[int, 0, 1000]):
        """
        Set a user's level and persist the corresponding XP for the current guild.
        
        Defers the interaction, computes required XP using the formula `xp = 100 * level ** 1.7`,
        upserts the (guild_id, user_id, level, xp, username) row into the `user_levels` table, and
        sends an ephemeral follow-up confirming the change.
        
        Parameters:
            user (discord.Member): The guild member whose level will be set.
            level (int): Target level (0–1000).
        """
        debug_print(f"Entering /setlevel with interaction: {interaction}, user: {user}, level: {level}", level="all")
        """Set a user's level"""
        try:
            # Immediately acknowledge the interaction
            await interaction.response.defer(ephemeral=True)
            
            # Calculate XP for target level
            xp_required = 100 * (level ** 1.7)
            
            # Update database
            self.bot.db.conn.execute('''
                INSERT OR REPLACE INTO user_levels 
                (guild_id, user_id, level, xp, username)
                VALUES (?, ?, ?, ?, ?)
            ''', (str(interaction.guild.id), str(user.id), level, xp_required, user.name))
            
            self.bot.db.conn.commit()
            
            # Send follow-up response
            await interaction.followup.send(
                f"✅ Set {user.mention}'s level to {level} with {xp_required:.0f} XP!",
                ephemeral=True
            )
            
        except Exception as e:
            logging.error(f"Setlevel error: {str(e)}", exc_info=True)
            await interaction.followup.send(
                "❌ Failed to update level. Check logs.",
                ephemeral=True
            )

    @add_xp.error
    @set_xp.error
    @setlevel.error
    async def xp_commands_error(self, interaction: discord.Interaction, error):
        """
        Handle errors raised by XP-related slash commands.
        
        If the error is an app_commands.CheckFailure (permission denied), sends an ephemeral reply informing the user they need administrator permissions. Designed to be used as an error handler for the cog's XP commands.
        
        Parameters:
            interaction (discord.Interaction): The interaction that triggered the command.
            error (Exception): The exception raised by the command.
        """
        debug_print(f"Entering /xp_commands_error with interaction: {interaction}, error: {error}", level="all")
        if isinstance(error, app_commands.CheckFailure):
            await interaction.response.send_message(
                "❌ You need administrator permissions to use this command!",
                ephemeral=True
            )
            
async def setup(bot):
    await bot.add_cog(LevelingCog(bot))