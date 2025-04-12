import os
import discord
from discord.ext import commands
from dotenv import load_dotenv
from bot.bot import bot_instance

load_dotenv()

class Shared:
    def __init__(self):
        self.token = os.getenv('BOT_TOKEN')
        
        if not self.token:
            raise ValueError("No BOT_TOKEN found in .env file!")
            
        self.bot = bot_instance

shared = Shared()