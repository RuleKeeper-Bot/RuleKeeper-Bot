import discord
from discord import app_commands
from discord.ext import commands
from typing import Optional, Union, List
import calendar
import os
import random
import asyncio
from datetime import datetime, date
from shared.colors import red
from shared import command_permission_check
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

class FunAndMiscCog(commands.Cog):
    def __init__(self, bot):
        debug_print(f"Entering FunAndMiscCog.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.db = bot.db
        
    @staticmethod
    def validate_date(month: int, day: int, year: int = None) -> bool:
        """Validate if the given date is valid"""
        try:
            if year:
                date(year, month, day)
            else:
                # Check if it's valid for any year (handle leap year case)
                # Use current year for validation
                current_year = datetime.now().year
                date(current_year, month, day)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def format_birthday_display(birthday_data: dict) -> str:
        """Format birthday data for display"""
        month_name = calendar.month_name[birthday_data['birthday_month']]
        day = birthday_data['birthday_day']
        
        # Add ordinal suffix to day
        if 10 <= day % 100 <= 20:
            suffix = 'th'
        else:
            suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(day % 10, 'th')
        
        date_str = f"{month_name} {day}{suffix}"
        
        if birthday_data.get('birthday_year'):
            year = birthday_data['birthday_year']
            current_year = datetime.now().year
            age = current_year - year
            date_str += f", {year} (Age {age})"
            
        return date_str

    @app_commands.command(name="birthday", description="View your birthday or someone else's birthday")
    @command_permission_check("birthday")
    @app_commands.describe(user="User whose birthday to view (optional, defaults to yourself)")
    async def view_birthday(self, interaction: discord.Interaction, user: Optional[discord.Member] = None):
        """View a user's birthday"""
        debug_print(f"Birthday command called by {interaction.user.id}", level="all")
        
        target_user = user or interaction.user
        guild_id = str(interaction.guild.id)
        user_id = str(target_user.id)
        
        try:
            birthday_data = self.db.get_user_birthday(guild_id, user_id)
            
            if not birthday_data:
                if target_user == interaction.user:
                    await interaction.response.send_message(
                        "🎂 You haven't set your birthday yet! Use `/set_birthday` to add it.",
                        ephemeral=True
                    )
                else:
                    await interaction.response.send_message(
                        f"🎂 {target_user.display_name} hasn't set their birthday yet.",
                        ephemeral=True
                    )
                return
            
            birthday_str = self.format_birthday_display(birthday_data)
            
            embed = discord.Embed(
                title="🎂 Birthday Information",
                color=discord.Color.blue()
            )
            embed.add_field(
                name=f"{target_user.display_name}'s Birthday",
                value=birthday_str,
                inline=False
            )
            
            # Add days until next birthday
            today = datetime.now().date()
            try:
                birthday_this_year = date(today.year, birthday_data['birthday_month'], birthday_data['birthday_day'])
                if birthday_this_year < today:
                    birthday_this_year = date(today.year + 1, birthday_data['birthday_month'], birthday_data['birthday_day'])
                
                days_until = (birthday_this_year - today).days
                
                if days_until == 0:
                    embed.add_field(name="🎉", value="It's their birthday TODAY!", inline=False)
                else:
                    embed.add_field(name="Days until next birthday", value=f"{days_until} days", inline=False)
                    
            except ValueError:
                # Handle leap year edge case (Feb 29)
                pass
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in view_birthday: {e}", level="all"))
            await interaction.response.send_message(
                "❌ An error occurred while retrieving the birthday information.",
                ephemeral=True
            )

    @app_commands.command(name="set_birthday", description="Set your birthday")
    @command_permission_check("set_birthday")
    @app_commands.describe(
        month="Birthday month (1-12)",
        day="Birthday day (1-31)",
        year="Birth year (optional)"
    )
    @app_commands.choices(month=[
        app_commands.Choice(name="January", value=1),
        app_commands.Choice(name="February", value=2),
        app_commands.Choice(name="March", value=3),
        app_commands.Choice(name="April", value=4),
        app_commands.Choice(name="May", value=5),
        app_commands.Choice(name="June", value=6),
        app_commands.Choice(name="July", value=7),
        app_commands.Choice(name="August", value=8),
        app_commands.Choice(name="September", value=9),
        app_commands.Choice(name="October", value=10),
        app_commands.Choice(name="November", value=11),
        app_commands.Choice(name="December", value=12)
    ])
    async def set_birthday(self, interaction: discord.Interaction, month: int, day: int, year: Optional[int] = None):
        """Set your birthday"""
        debug_print(f"Set birthday command called by {interaction.user.id}", level="all")
        
        # Validate the date
        if not (1 <= day <= 31):
            await interaction.response.send_message(
                "❌ Invalid day. Please enter a day between 1 and 31.",
                ephemeral=True
            )
            return
            
        if year and (year < 1900 or year > datetime.now().year):
            await interaction.response.send_message(
                "❌ Invalid year. Please enter a year between 1900 and the current year.",
                ephemeral=True
            )
            return
        
        if not self.validate_date(month, day, year):
            await interaction.response.send_message(
                "❌ Invalid date. Please check your month and day combination.",
                ephemeral=True
            )
            return
        
        guild_id = str(interaction.guild.id)
        user_id = str(interaction.user.id)
        username = interaction.user.display_name
        
        try:
            # Check if birthday already exists
            existing_birthday = self.db.get_user_birthday(guild_id, user_id)
            
            if existing_birthday:
                # Update existing birthday
                self.db.update_user_birthday(
                    guild_id, user_id, username, month, day, year
                )
                action = "updated"
            else:
                # Add new birthday
                self.db.add_user_birthday(
                    guild_id, user_id, username, month, day, year
                )
                action = "set"
            
            # Create confirmation message
            birthday_str = self.format_birthday_display({
                'birthday_month': month,
                'birthday_day': day,
                'birthday_year': year
            })
            
            embed = discord.Embed(
                title="🎂 Birthday Set Successfully!",
                description=f"Your birthday has been {action} to **{birthday_str}**",
                color=discord.Color.green()
            )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in set_birthday: {e}", level="all"))
            await interaction.response.send_message(
                "❌ An error occurred while setting your birthday.",
                ephemeral=True
            )

    @app_commands.command(name="remove_birthday", description="Remove your birthday")
    @command_permission_check("remove_birthday")
    async def remove_birthday(self, interaction: discord.Interaction):
        """Remove your birthday"""
        debug_print(f"Remove birthday command called by {interaction.user.id}", level="all")
        
        guild_id = str(interaction.guild.id)
        user_id = str(interaction.user.id)
        
        try:
            # Check if birthday exists
            existing_birthday = self.db.get_user_birthday(guild_id, user_id)
            
            if not existing_birthday:
                await interaction.response.send_message(
                    "🎂 You don't have a birthday set to remove.",
                    ephemeral=True
                )
                return
            
            # Remove the birthday
            self.db.remove_user_birthday(guild_id, user_id)
            
            embed = discord.Embed(
                title="🗑️ Birthday Removed",
                description="Your birthday has been successfully removed.",
                color=discord.Color.red()
            )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in remove_birthday: {e}", level="all"))
            await interaction.response.send_message(
                "❌ An error occurred while removing your birthday.",
                ephemeral=True
            )

    @app_commands.command(name="edit_birthday", description="Edit your birthday")
    @command_permission_check("edit_birthday")
    @app_commands.describe(
        month="New birthday month (1-12, optional)",
        day="New birthday day (1-31, optional)",
        year="New birthday year (optional, set to 0 to remove year)"
    )
    @app_commands.choices(month=[
        app_commands.Choice(name="January", value=1),
        app_commands.Choice(name="February", value=2),
        app_commands.Choice(name="March", value=3),
        app_commands.Choice(name="April", value=4),
        app_commands.Choice(name="May", value=5),
        app_commands.Choice(name="June", value=6),
        app_commands.Choice(name="July", value=7),
        app_commands.Choice(name="August", value=8),
        app_commands.Choice(name="September", value=9),
        app_commands.Choice(name="October", value=10),
        app_commands.Choice(name="November", value=11),
        app_commands.Choice(name="December", value=12)
    ])
    async def edit_birthday(self, interaction: discord.Interaction, 
                            month: Optional[int] = None, 
                            day: Optional[int] = None, 
                            year: Optional[int] = None):
        """Edit your birthday"""
        debug_print(f"Edit birthday command called by {interaction.user.id}", level="all")
        
        guild_id = str(interaction.guild.id)
        user_id = str(interaction.user.id)
        username = interaction.user.display_name
        
        try:
            # Check if birthday exists
            existing_birthday = self.db.get_user_birthday(guild_id, user_id)
            
            if not existing_birthday:
                await interaction.response.send_message(
                    "🎂 You don't have a birthday set. Use `/set_birthday` to add one first.",
                    ephemeral=True
                )
                return
            
            if not month and not day and year is None:
                await interaction.response.send_message(
                    "❌ Please specify at least one field to edit (month, day, or year).",
                    ephemeral=True
                )
                return
            
            # Use existing values if not provided
            new_month = month if month is not None else existing_birthday['birthday_month']
            new_day = day if day is not None else existing_birthday['birthday_day']
            new_year = year if year is not None else existing_birthday['birthday_year']
            
            # Handle year = 0 as removal
            if year == 0:
                new_year = None
            
            # Validate the new date
            if day and not (1 <= day <= 31):
                await interaction.response.send_message(
                    "❌ Invalid day. Please enter a day between 1 and 31.",
                    ephemeral=True
                )
                return
                
            if new_year and (new_year < 1900 or new_year > datetime.now().year):
                await interaction.response.send_message(
                    "❌ Invalid year. Please enter a year between 1900 and the current year.",
                    ephemeral=True
                )
                return
            
            if not self.validate_date(new_month, new_day, new_year):
                await interaction.response.send_message(
                    "❌ Invalid date. Please check your month and day combination.",
                    ephemeral=True
                )
                return
            
            # Update the birthday
            self.db.update_user_birthday(
                guild_id, user_id, username, new_month, new_day, new_year
            )
            
            # Create confirmation message
            birthday_str = self.format_birthday_display({
                'birthday_month': new_month,
                'birthday_day': new_day,
                'birthday_year': new_year
            })
            
            embed = discord.Embed(
                title="🎂 Birthday Updated Successfully!",
                description=f"Your birthday has been updated to **{birthday_str}**",
                color=discord.Color.blue()
            )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in edit_birthday: {e}", level="all"))
            await interaction.response.send_message(
                "❌ An error occurred while editing your birthday.",
                ephemeral=True
            )

    @app_commands.command(name="list_birthdays", description="View all birthdays in this server")
    @command_permission_check("list_birthdays")
    async def list_birthdays(self, interaction: discord.Interaction):
        """List all birthdays in the server"""
        debug_print(f"List birthdays command called by {interaction.user.id}", level="all")
        
        guild_id = str(interaction.guild.id)
        
        try:
            all_birthdays = self.db.get_guild_birthdays(guild_id)
            
            if not all_birthdays:
                embed = discord.Embed(
                    title="🎂 Server Birthdays",
                    description="No birthdays have been set in this server yet!",
                    color=discord.Color.blue()
                )
                await interaction.response.send_message(embed=embed)
                return
            
            # Group birthdays by month
            months = {}
            for birthday in all_birthdays:
                month = birthday['birthday_month']
                if month not in months:
                    months[month] = []
                months[month].append(birthday)
            
            embed = discord.Embed(
                title="🎂 Server Birthdays",
                description=f"Found {len(all_birthdays)} birthday(s) in this server",
                color=discord.Color.blue()
            )
            
            # Add each month as a field
            for month_num in sorted(months.keys()):
                month_name = calendar.month_name[month_num]
                birthday_list = []
                
                for birthday in sorted(months[month_num], key=lambda x: x['birthday_day']):
                    username = birthday['username']
                    day = birthday['birthday_day']
                    
                    if birthday.get('birthday_year'):
                        year = birthday['birthday_year']
                        current_year = datetime.now().year
                        age = current_year - year
                        birthday_list.append(f"• {username} - {day} ({age} years old)")
                    else:
                        birthday_list.append(f"• {username} - {day}")
                
                embed.add_field(
                    name=f"{month_name} ({len(birthday_list)})",
                    value="\n".join(birthday_list),
                    inline=True
                )
            
            # Add footer with web dashboard info
            web_url = os.getenv('FRONTEND_URL', 'http://localhost:5000')
            birthday_config = self.db.get_birthday_config(guild_id)
            
            if birthday_config.get('public_calendar'):
                embed.set_footer(text=f"Visit {web_url} for a calendar view and management options! 🌐 Calendar is publicly viewable")
            else:
                embed.set_footer(text=f"Visit {web_url} for a calendar view and management options! 🔒 Calendar viewing requires permissions")
            
            await interaction.response.send_message(embed=embed)
            
        except Exception as e:
            debug_print(red(f"Error in list_birthdays: {e}", level="all"))
            await interaction.response.send_message(
                "❌ An error occurred while retrieving the birthdays.",
                ephemeral=True
            )

    @app_commands.command(name="upcoming_birthdays", description="View upcoming birthdays in the next week")
    @command_permission_check("upcoming_birthdays")
    async def upcoming_birthdays(self, interaction: discord.Interaction, days_ahead: Optional[int] = 7):
        """View upcoming birthdays"""
        debug_print(f"Upcoming birthdays command called by {interaction.user.id}", level="all")
        
        if days_ahead < 1 or days_ahead > 365:
            await interaction.response.send_message(
                "❌ Days ahead must be between 1 and 365.",
                ephemeral=True
            )
            return
        
        guild_id = str(interaction.guild.id)
        
        try:
            upcoming = self.db.get_upcoming_birthdays(guild_id, days_ahead)
            
            if not upcoming:
                embed = discord.Embed(
                    title="🎂 Upcoming Birthdays",
                    description=f"No birthdays in the next {days_ahead} days!",
                    color=discord.Color.blue()
                )
                await interaction.response.send_message(embed=embed, ephemeral=True)
                return
            
            embed = discord.Embed(
                title="🎂 Upcoming Birthdays",
                description=f"Birthdays in the next {days_ahead} days:",
                color=discord.Color.blue()
            )
            
            today = datetime.now().date()
            
            for birthday in upcoming:
                username = birthday['username']
                birthday_str = self.format_birthday_display(birthday)
                
                # Calculate days until birthday
                try:
                    birthday_this_year = date(today.year, birthday['birthday_month'], birthday['birthday_day'])
                    if birthday_this_year < today:
                        birthday_this_year = date(today.year + 1, birthday['birthday_month'], birthday['birthday_day'])
                    
                    days_until = (birthday_this_year - today).days
                    
                    if days_until == 0:
                        status = "🎉 TODAY!"
                    elif days_until == 1:
                        status = "Tomorrow"
                    else:
                        status = f"In {days_until} days"
                    
                    embed.add_field(
                        name=f"{username}",
                        value=f"{birthday_str}\n*{status}*",
                        inline=True
                    )
                    
                except ValueError:
                    # Handle leap year edge case
                    embed.add_field(
                        name=f"{username}",
                        value=birthday_str,
                        inline=True
                    )
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in upcoming_birthdays: {e}", level="all"))
            await interaction.response.send_message(
                "❌ An error occurred while retrieving upcoming birthdays.",
                ephemeral=True
            )

    @app_commands.command(name="birthday_config", description="Configure birthday settings for this server")
    @command_permission_check("birthday_config")
    @app_commands.describe(
        birthday_message="Custom birthday message (use {user} for mention, {age} for age if year provided)",
        birthday_channel="Channel to announce birthdays in",
        birthday_role="Role to mention in birthday announcements",
        birthday_role_to_give="Role to give users on their birthday",
        announce_birthdays="Enable/disable automatic birthday announcements",
        show_age="Show age in birthday messages (if birth year is provided)",
        embed_enabled="Send birthday messages as embeds",
        embed_title="Title for birthday embed messages",
        embed_color="Color for birthday embeds (hex code like #ff0000)",
        public_calendar="Allow any server member to view the birthday calendar"
    )
    async def birthday_config(self, interaction: discord.Interaction,
                              birthday_message: Optional[str] = None,
                              birthday_channel: Optional[discord.TextChannel] = None,
                              birthday_role: Optional[discord.Role] = None,
                              birthday_role_to_give: Optional[discord.Role] = None,
                              announce_birthdays: Optional[bool] = None,
                              show_age: Optional[bool] = None,
                              embed_enabled: Optional[bool] = None,
                              embed_title: Optional[str] = None,
                              embed_color: Optional[str] = None,
                              public_calendar: Optional[bool] = None):
        """Configure birthday settings for the server"""
        debug_print(f"Birthday config command called by {interaction.user.id}", level="all")
        
        guild_id = str(interaction.guild.id)
        
        try:
            # Get current config
            current_config = self.db.get_birthday_config(guild_id)
            
            # If no parameters provided, show current config
            if all(param is None for param in [birthday_message, birthday_channel, birthday_role, birthday_role_to_give,
                                             announce_birthdays, show_age, embed_enabled, 
                                             embed_title, embed_color, public_calendar]):
                embed = discord.Embed(
                    title="🎂 Birthday Configuration",
                    description=f"Current birthday settings for {interaction.guild.name}",
                    color=discord.Color.blue()
                )
                
                # Current settings
                channel_name = "Not set"
                if current_config.get('birthday_channel_id'):
                    channel = interaction.guild.get_channel(int(current_config['birthday_channel_id']))
                    channel_name = f"#{channel.name}" if channel else "Invalid channel"
                
                role_name = "Not set"
                if current_config.get('birthday_role_id'):
                    role = interaction.guild.get_role(int(current_config['birthday_role_id']))
                    role_name = f"@{role.name}" if role else "Invalid role"
                
                role_to_give_name = "Not set"
                if current_config.get('birthday_role_to_give_id'):
                    role_to_give = interaction.guild.get_role(int(current_config['birthday_role_to_give_id']))
                    role_to_give_name = f"@{role_to_give.name}" if role_to_give else "Invalid role"
                
                embed.add_field(name="Birthday Channel", value=channel_name, inline=True)
                embed.add_field(name="Birthday Role (Mention)", value=role_name, inline=True)
                embed.add_field(name="Birthday Role (To Give)", value=role_to_give_name, inline=True)
                embed.add_field(name="Announcements Enabled", 
                              value="✅ Yes" if current_config.get('announce_birthdays') else "❌ No", inline=True)
                embed.add_field(name="Show Age", 
                              value="✅ Yes" if current_config.get('show_age') else "❌ No", inline=True)
                embed.add_field(name="Use Embeds", 
                              value="✅ Yes" if current_config.get('birthday_embed_enabled') else "❌ No", inline=True)
                embed.add_field(name="Public Calendar", 
                              value="✅ Yes" if current_config.get('public_calendar') else "❌ No", inline=True)
                embed.add_field(name="Embed Title", 
                              value=current_config.get('birthday_embed_title', 'Default'), inline=True)
                embed.add_field(name="Birthday Message", 
                              value=current_config.get('birthday_message', 'Default message'), inline=False)
                
                # Available placeholders
                embed.add_field(name="Available Placeholders", 
                              value="`{user}` - User mention\n`{username}` - Username\n`{age}` - Age (if birth year provided)", 
                              inline=False)
                
                await interaction.response.send_message(embed=embed, ephemeral=True)
                return
            
            # Prepare update data
            update_data = {}
            changes = []
            
            if birthday_message is not None:
                update_data['birthday_message'] = birthday_message
                changes.append(f"Message: {birthday_message[:50]}...")
                
            if birthday_channel is not None:
                update_data['birthday_channel_id'] = str(birthday_channel.id)
                changes.append(f"Channel: #{birthday_channel.name}")
                
            if birthday_role is not None:
                update_data['birthday_role_id'] = str(birthday_role.id)
                changes.append(f"Role (Mention): @{birthday_role.name}")
                
            if birthday_role_to_give is not None:
                update_data['birthday_role_to_give_id'] = str(birthday_role_to_give.id)
                changes.append(f"Role (To Give): @{birthday_role_to_give.name}")
                
            if announce_birthdays is not None:
                update_data['announce_birthdays'] = announce_birthdays
                changes.append(f"Announcements: {'Enabled' if announce_birthdays else 'Disabled'}")
                
            if show_age is not None:
                update_data['show_age'] = show_age
                changes.append(f"Show Age: {'Yes' if show_age else 'No'}")
                
            if embed_enabled is not None:
                update_data['birthday_embed_enabled'] = embed_enabled
                changes.append(f"Use Embeds: {'Yes' if embed_enabled else 'No'}")
                
            if embed_title is not None:
                update_data['birthday_embed_title'] = embed_title
                changes.append(f"Embed Title: {embed_title}")
                
            if public_calendar is not None:
                update_data['public_calendar'] = public_calendar
                changes.append(f"Public Calendar: {'Enabled' if public_calendar else 'Disabled'}")
                
            if embed_color is not None:
                # Parse hex color
                try:
                    if embed_color.startswith('#'):
                        color_int = int(embed_color[1:], 16)
                    else:
                        color_int = int(embed_color, 16)
                    update_data['birthday_embed_color'] = color_int
                    changes.append(f"Embed Color: {embed_color}")
                except ValueError:
                    await interaction.response.send_message(
                        "❌ Invalid color format. Please use hex format like #ff0000 or ff0000",
                        ephemeral=True
                    )
                    return
            
            # Update configuration
            self.db.update_birthday_config(guild_id, **update_data)
            
            # Create confirmation embed
            embed = discord.Embed(
                title="🎂 Birthday Configuration Updated!",
                description="The following settings have been updated:",
                color=discord.Color.green()
            )
            
            embed.add_field(name="Changes Made", value="\n".join(changes), inline=False)
            
            await interaction.response.send_message(embed=embed, ephemeral=True)
            
        except Exception as e:
            debug_print(red(f"Error in birthday_config: {e}", level="all"))
            await interaction.response.send_message(
                "❌ An error occurred while updating birthday configuration.",
                ephemeral=True
            )

    @app_commands.command(name="roll", description="Roll dice with customizable sides and count")
    @command_permission_check("roll")
    @app_commands.describe(
        dice="Number of dice to roll (1-200)",
        sides="Number of sides on each die (2-1000)",
        preset="Use a preset for popular games",
        modifier="Add/subtract a modifier to the total"
    )
    @app_commands.choices(preset=[
        app_commands.Choice(name="D&D Standard (1d20)", value="dnd_standard"),
        app_commands.Choice(name="D&D Advantage (2d20, keep highest)", value="dnd_advantage"),
        app_commands.Choice(name="D&D Disadvantage (2d20, keep lowest)", value="dnd_disadvantage"),
        app_commands.Choice(name="D&D Ability Score (4d6, drop lowest)", value="dnd_ability"),
        app_commands.Choice(name="D&D Damage (2d6)", value="dnd_damage"),
        app_commands.Choice(name="Yahtzee (5d6)", value="yahtzee"),
        app_commands.Choice(name="Fudge/FATE (4dF)", value="fudge"),
        app_commands.Choice(name="Coin Flip", value="coin"),
        app_commands.Choice(name="Percentile (d100)", value="percentile")
    ])
    async def roll_dice(self, interaction: discord.Interaction, 
                       dice: Optional[int] = None, 
                       sides: Optional[int] = None,
                       preset: Optional[str] = None,
                       modifier: Optional[int] = None):
        """Roll dice with various options and game presets"""
        debug_print(f"Roll command called by {interaction.user.id}", level="all")
        
        try:
            # Handle presets
            if preset:
                dice, sides, modifier, special_rule = self._get_preset_config(preset)
                preset_name = self._get_preset_name(preset)
            else:
                special_rule = None
                preset_name = None
                
                # Use defaults if not specified
                if dice is None:
                    dice = 1
                if sides is None:
                    sides = 6
            
            # Validate input
            if dice < 1 or dice > 200:
                await interaction.response.send_message(
                    "❌ Number of dice must be between 1 and 200.",
                    ephemeral=True
                )
                return
                
            if sides < 2 or sides > 1000:
                await interaction.response.send_message(
                    "❌ Number of sides must be between 2 and 1000.",
                    ephemeral=True
                )
                return
            
            # Roll the dice
            if special_rule:
                results, total, description = self._handle_special_roll(dice, sides, special_rule, modifier)
            else:
                results = [random.randint(1, sides) for _ in range(dice)]
                total = sum(results)
                if modifier:
                    total += modifier
                description = None
            
            # Create embed
            embed = discord.Embed(
                title="🎲 Dice Roll Results",
                color=discord.Color.blue()
            )
            
            # Add preset info if used
            if preset_name:
                embed.add_field(name="Preset Used", value=preset_name, inline=False)
            
            # Format dice notation
            dice_notation = f"{dice}d{sides}"
            if modifier:
                if modifier > 0:
                    dice_notation += f"+{modifier}"
                else:
                    dice_notation += str(modifier)
            
            embed.add_field(name="Roll", value=dice_notation, inline=True)
            
            # Show individual results if reasonable number of dice
            if len(results) <= 50:
                if sides == 2:  # Coin flip
                    result_display = ", ".join(["Heads" if r == 2 else "Tails" for r in results])
                else:
                    result_display = ", ".join(map(str, results))
                embed.add_field(name="Individual Results", value=result_display, inline=False)
            else:
                embed.add_field(name="Individual Results", value="Too many dice to display individually", inline=False)
            
            # Add total
            embed.add_field(name="Total", value=f"**{total}**", inline=True)
            
            # Add special description if applicable
            if description:
                embed.add_field(name="Special Rule", value=description, inline=False)
            
            # Add some flavor based on the roll
            flavor = self._get_roll_flavor(total, dice, sides, preset)
            if flavor:
                embed.set_footer(text=flavor)
            
            await interaction.response.send_message(embed=embed)
            
        except Exception as e:
            debug_print(red(f"Error in roll_dice: {e}", level="all"))
            await interaction.response.send_message(
                "❌ An error occurred while rolling the dice.",
                ephemeral=True
            )
    
    def _get_preset_config(self, preset: str) -> tuple:
        """Get dice configuration for presets"""
        preset_configs = {
            "dnd_standard": (1, 20, None, None),
            "dnd_advantage": (2, 20, None, "advantage"),
            "dnd_disadvantage": (2, 20, None, "disadvantage"),
            "dnd_ability": (4, 6, None, "drop_lowest"),
            "dnd_damage": (2, 6, None, None),
            "yahtzee": (5, 6, None, None),
            "fudge": (4, 3, None, "fudge"),
            "coin": (1, 2, None, "coin"),
            "percentile": (1, 100, None, None)
        }
        return preset_configs.get(preset, (1, 6, None, None))
    
    def _get_preset_name(self, preset: str) -> str:
        """Get display name for presets"""
        preset_names = {
            "dnd_standard": "D&D Standard (1d20)",
            "dnd_advantage": "D&D Advantage (2d20, keep highest)",
            "dnd_disadvantage": "D&D Disadvantage (2d20, keep lowest)",
            "dnd_ability": "D&D Ability Score (4d6, drop lowest)",
            "dnd_damage": "D&D Damage (2d6)",
            "yahtzee": "Yahtzee (5d6)",
            "fudge": "Fudge/FATE (4dF)",
            "coin": "Coin Flip",
            "percentile": "Percentile (d100)"
        }
        return preset_names.get(preset, "Unknown Preset")
    
    def _handle_special_roll(self, dice: int, sides: int, special_rule: str, modifier: Optional[int]) -> tuple:
        """Handle special rolling rules"""
        results = []
        description = None
        
        if special_rule == "advantage":
            # Roll 2d20, keep highest
            rolls = [random.randint(1, 20), random.randint(1, 20)]
            results = rolls
            total = max(rolls)
            description = f"Rolled {rolls[0]} and {rolls[1]}, keeping the higher: {total}"
            
        elif special_rule == "disadvantage":
            # Roll 2d20, keep lowest
            rolls = [random.randint(1, 20), random.randint(1, 20)]
            results = rolls
            total = min(rolls)
            description = f"Rolled {rolls[0]} and {rolls[1]}, keeping the lower: {total}"
            
        elif special_rule == "drop_lowest":
            # Roll 4d6, drop lowest
            rolls = [random.randint(1, 6) for _ in range(4)]
            rolls.sort(reverse=True)
            kept = rolls[:3]
            dropped = rolls[3]
            results = rolls
            total = sum(kept)
            description = f"Rolled {', '.join(map(str, rolls))}, dropped {dropped}, keeping {', '.join(map(str, kept))}"
            
        elif special_rule == "fudge":
            # Fudge dice: -1, 0, +1
            fudge_results = []
            for _ in range(4):
                roll = random.randint(1, 3)
                if roll == 1:
                    fudge_results.append(-1)
                elif roll == 2:
                    fudge_results.append(0)
                else:
                    fudge_results.append(1)
            results = fudge_results
            total = sum(fudge_results)
            fudge_display = ['+' if r == 1 else '0' if r == 0 else '-' for r in fudge_results]
            description = f"Fudge dice results: {', '.join(fudge_display)}"
            
        elif special_rule == "coin":
            # Coin flip
            results = [random.randint(1, 2)]
            total = results[0]
            description = None  # Will be handled in main function
            
        else:
            # Standard roll
            results = [random.randint(1, sides) for _ in range(dice)]
            total = sum(results)
        
        # Apply modifier
        if modifier:
            total += modifier
            
        return results, total, description
    
    def _get_roll_flavor(self, total: int, dice: int, sides: int, preset: Optional[str]) -> Optional[str]:
        """Get flavor text based on roll results"""
        if preset == "dnd_standard":
            if total == 20:
                return "🔥 Natural 20! Critical Success!"
            elif total == 1:
                return "💀 Natural 1! Critical Failure!"
            elif total >= 15:
                return "⭐ Great roll!"
            elif total <= 5:
                return "😅 Better luck next time!"
                
        elif preset in ["dnd_advantage", "dnd_disadvantage"]:
            if total == 20:
                return "🔥 Natural 20!"
            elif total == 1:
                return "💀 Natural 1!"
                
        elif preset == "coin":
            if total == 2:
                return "🪙 Heads!"
            else:
                return "🪙 Tails!"
                
        elif preset == "percentile" or (dice == 1 and sides == 100):
            if total >= 95:
                return "🎯 Excellent! (95+)"
            elif total >= 80:
                return "👍 Very Good! (80+)"
            elif total <= 5:
                return "😱 Oh no! (5 or less)"
            elif total <= 20:
                return "😬 Not great (20 or less)"
                
        # General flavor for high/low rolls
        max_possible = dice * sides
        percentage = (total / max_possible) * 100
        
        if percentage >= 90:
            return "🔥 Amazing roll!"
        elif percentage >= 75:
            return "⭐ Great roll!"
        elif percentage <= 10:
            return "😅 Ouch! That's rough!"
        elif percentage <= 25:
            return "😬 Could be better..."
            
        return None
    
    @app_commands.command(name="reaction_type", description="Type out text using reactions on a message")
    @command_permission_check("reaction_type")
    @app_commands.describe(
        message_id="The ID of the message to react to (right-click message -> Copy Message ID)",
        text="Text to type out in reactions (A-Z, 0-9, spaces allowed)"
    )
    async def reaction_type(self, interaction: discord.Interaction, message_id: str, text: str):
        """Type out text using reactions on a message"""
        debug_print(f"Reaction type command called by {interaction.user.id} for message {message_id} with text '{text}'", level="all")
        
        # Try to fetch the message
        try:
            message_id_int = int(message_id)
            message = None
            
            # Try to find the message in the current channel first
            try:
                message = await interaction.channel.fetch_message(message_id_int)
            except discord.NotFound:
                # If not found, search through all text channels in the guild
                for channel in interaction.guild.text_channels:
                    try:
                        message = await channel.fetch_message(message_id_int)
                        break
                    except (discord.NotFound, discord.Forbidden):
                        continue
            
            if message is None:
                await interaction.response.send_message(
                    "❌ Could not find that message. Make sure the message ID is correct and the bot has access to that channel.",
                    ephemeral=True
                )
                return
                
        except ValueError:
            await interaction.response.send_message(
                "❌ Invalid message ID. Please provide a valid message ID (right-click message -> Copy Message ID).",
                ephemeral=True
            )
            return
        
        # Only allow A-Z, 0-9, and spaces
        allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
        text = text.upper()
        
        emojis = {
            "A": "🇦", "B": "🇧", "C": "🇨", "D": "🇩", "E": "🇪", "F": "🇫", "G": "🇬", "H": "🇭", 
            "I": "🇮", "J": "🇯", "K": "🇰", "L": "🇱", "M": "🇲", "N": "🇳", "O": "🇴", "P": "🇵", 
            "Q": "🇶", "R": "🇷", "S": "🇸", "T": "🇹", "U": "🇺", "V": "🇻", "W": "🇼", "X": "🇽", 
            "Y": "🇾", "Z": "🇿",
            "0": "0️⃣", "1": "1️⃣", "2": "2️⃣", "3": "3️⃣", "4": "4️⃣", 
            "5": "5️⃣", "6": "6️⃣", "7": "7️⃣", "8": "8️⃣", "9": "9️⃣",
            " ": "⬛"  # Black square for space
        }
        
        # Validate text
        invalid = [c for c in text if c not in allowed]
        if invalid:
            await interaction.response.send_message(
                f"❌ Invalid characters: {' '.join(set(invalid))}. Only A-Z, 0-9, and spaces are allowed.",
                ephemeral=True
            )
            return
        
        # Defer response since adding reactions might take a while
        await interaction.response.defer(ephemeral=True)
        
        # React to the message
        added_reactions = []
        sleep_after_each = len([c for c in text if c in emojis and emojis[c]]) > 5
        for c in text:
            emoji = emojis.get(c)
            if emoji:
                try:
                    await message.add_reaction(emoji)
                    added_reactions.append(c)
                    if sleep_after_each:
                        await asyncio.sleep(2.5)
                except discord.Forbidden:
                    await interaction.followup.send(
                        f"❌ Failed to add reactions. Bot lacks permission to add reactions in that channel.",
                        ephemeral=True
                    )
                    return
                except discord.HTTPException as e:
                    debug_print(red(f"Error adding reaction {emoji}: {e}", level="all"))
                    await interaction.followup.send(
                        f"❌ Failed to add reaction {emoji} for '{c}'. An error occurred: {e}",
                        ephemeral=True
                    )
                    return
        
        await interaction.followup.send(
            f"✅ Typed '{text}' on the message!",
            ephemeral=True
        )

async def setup(bot):
    debug_print(f"Setting up FunAndMiscCog", level="all")
    await bot.add_cog(FunAndMiscCog(bot))
