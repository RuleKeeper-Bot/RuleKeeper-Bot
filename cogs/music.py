import os
import sys
import discord
from discord import app_commands
from discord.ext import commands
from discord.ui import Button, View
import asyncio
import yt_dlp as youtube_dl
from urllib.parse import urlparse
from collections import defaultdict, deque
import random
from typing import Literal, Optional
from datetime import timedelta
#sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
#from dotenv import load_dotenv

# Suppress noise about console usage from yt-dlp
youtube_dl.utils.bug_reports_message = lambda: ''

ytdl_format_options = {
    'format': 'bestaudio/best',
    'outtmpl': '%(extractor)s-%(id)s-%(title)s.%(ext)s',
    'restrictfilenames': True,
    'noplaylist': True,
    'nocheckcertificate': False,
    'ignoreerrors': False,
    'logtostderr': False,
    'quiet': True,
    'no_warnings': True,
    'default_search': 'auto',
    'source_address': '0.0.0.0',
    'extract_flat': 'in_playlist',
    'cookiefile': 'cookies.txt',
#   'ssl_certfile': os.getenv('SSL_CERT_FILE', '/usr/lib/ssl/cert.pem'),
    'postprocessors': [{
        'key': 'FFmpegExtractAudio',
        'preferredcodec': 'wav',
        'preferredquality': '192',
    }],
}

ffmpeg_options = {
    'options': '-vn',
    'before_options': '-reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5',
    'executable': 'ffmpeg'
}


class YTDLSource(discord.PCMVolumeTransformer):
    def __init__(self, source, *, data, volume=0.5):
        super().__init__(source, volume)
        self.data = data
        self.title = data.get('title')
        self.url = data.get('webpage_url')
        self.duration = data.get('duration')
        self.uploader = data.get('uploader')
        self.start_time = 0
        self.original = source

    @classmethod
    async def from_url(cls, url, *, loop=None, stream=False, start_time=0):
        loop = loop or asyncio.get_event_loop()
        ytdl = youtube_dl.YoutubeDL(ytdl_format_options)
        
        try:
            data = await loop.run_in_executor(
                None, 
                lambda: ytdl.extract_info(url, download=not stream)
            )
        except Exception as e:
            raise Exception(f"Error extracting info: {str(e)}")

        if 'entries' in data:
            data = data['entries'][0]

        if stream:
            filename = data['url']
        else:
            filename = ytdl.prepare_filename(data)

        # Updated FFmpeg command with single audio config
        ffmpeg_params = {
            'options': f'-vn -acodec pcm_s16le -ar 48000 -ac 2 -ss {start_time}',
            'before_options': '-reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5',
            'executable': 'ffmpeg'
        }
        
        return cls(discord.FFmpegPCMAudio(filename, **ffmpeg_params), data=data)

class GuildMusicState:
    def __init__(self):
        self.search_results = []
        self.queue = []
        self.history = []
        self.now_playing = None
        self.voice_client = None
        self.text_channel = None
        self.loop_mode = 'off'  # off, all, single
        self.shuffle = False
        self.volume = 0.5
        self.votes = set()
        self.last_play_msg = None

class TrackSelectView(View):
    def __init__(self, cog, tracks):
        super().__init__(timeout=30)
        self.cog = cog
        self.tracks = tracks
        
        # Add 5 buttons for top 5 results
        for i in range(5):
            if i < len(tracks):
                self.add_item(TrackSelectButton(cog, i, tracks[i]))
            else:
                # Add disabled buttons for missing results
                btn = Button(label="×", style=discord.ButtonStyle.grey, disabled=True)
                self.add_item(btn)

class TrackSelectButton(Button):
    def __init__(self, cog, index, track):
        super().__init__(
            label=str(index+1),
            style=discord.ButtonStyle.primary
        )
        self.cog = cog
        self.index = index
        self.track = track
        
    async def callback(self, interaction: discord.Interaction):
        try:
            guild_id = interaction.guild.id
            state = self.cog.guild_states[guild_id]
            
            # Verify track exists in the original results
            if self.index >= len(self.cog.guild_states[guild_id].search_results):
                await interaction.response.send_message("Invalid selection", ephemeral=True)
                return
                
            track = self.cog.guild_states[guild_id].search_results[self.index]
            
            state.queue.append({
                'title': track['title'],
                'url': track['url'],
                'duration': track.get('duration'),
                'requester': interaction.user,
                'thumbnail': track.get('thumbnail')
            })
            
            await interaction.response.send_message(
                f"Added **{track['title']}** to queue",
                ephemeral=True
            )
            await interaction.message.edit(view=None)
            
            if not state.now_playing:
                await self.cog.play_next(interaction.guild)
        except Exception as e:
            await interaction.response.send_message("Failed to add track. Please try again.", ephemeral=True)
            print(f"Button callback error: {e}")

class Music(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.guild_states = defaultdict(GuildMusicState)
        
    async def play_next(self, guild, error=None):
        state = self.guild_states[guild.id]
        
        if error:
            print(f"Player error: {error}")
        
        if state.voice_client is None or not state.voice_client.is_connected():
            return
        
        if state.loop_mode == 'single' and state.now_playing:
            next_track = state.now_playing
        elif state.loop_mode == 'all' and state.now_playing:
            state.queue.append(state.now_playing)
            next_track = state.queue.pop(0) if state.queue else None
        else:
            next_track = state.queue.pop(0) if state.queue else None
        
        if not next_track:
            state.now_playing = None
            if state.text_channel:
                channel = guild.get_channel(state.text_channel)
                await channel.send("Queue finished!")
            return
        
        state.now_playing = next_track
        state.history.append(next_track)
        
        try:
            source = await YTDLSource.from_url(next_track['url'], loop=self.bot.loop, stream=True)
            source.volume = state.volume
            state.voice_client.play(source, after=lambda e: self.bot.loop.create_task(self.play_next(guild, e)))
            
            if state.text_channel:
                channel = guild.get_channel(state.text_channel)
                embed = discord.Embed(
                    title="Now Playing",
                    description=f"[{next_track['title']}]({next_track['url']})",
                    color=discord.Color.blurple()
                )
                embed.add_field(name="Duration", value=str(timedelta(seconds=next_track['duration'])), inline=True)
                embed.add_field(name="Requested by", value=next_track['requester'].mention, inline=True)
                embed.set_thumbnail(url=next_track.get('thumbnail', ''))
                state.last_play_msg = await channel.send(embed=embed)
        except Exception as e:
            if state.text_channel:
                channel = guild.get_channel(state.text_channel)
                await channel.send(f"Error playing track: {e}")
            await self.play_next(guild)

    @app_commands.command(name="play", description="Play music from SoundCloud")
    @app_commands.describe(query="Song name or SoundCloud URL")
    async def play(self, interaction: discord.Interaction, query: str):
        await interaction.response.defer()
        
        if not interaction.user.voice:
            await interaction.followup.send("You must be in a voice channel!", ephemeral=True)
            return
            
        state = self.guild_states[interaction.guild.id]
        was_playing = state.now_playing is not None
        
        voice_channel = interaction.user.voice.channel
        if state.voice_client is None:
            state.voice_client = await voice_channel.connect()
        elif state.voice_client.channel != voice_channel:
            await state.voice_client.move_to(voice_channel)
        
        state.text_channel = interaction.channel.id
        
        if urlparse(query).scheme in ('http', 'https'):
            if 'soundcloud.com' not in query.lower():
                await interaction.followup.send("Only SoundCloud URLs are supported", ephemeral=True)
                return
            
            try:
                data = await YTDLSource.from_url(query, loop=self.bot.loop, stream=True)
                track = {
                    'title': data.title,
                    'url': query,
                    'duration': data.duration,
                    'requester': interaction.user,
                    'thumbnail': data.data.get('thumbnail')
                }
                state.queue.append(track)
                await interaction.followup.send(f"Added **{track['title']}** to queue")
            except Exception as e:
                await interaction.followup.send(f"Error processing URL: {e}", ephemeral=True)
                return
        else:
            ytdl = youtube_dl.YoutubeDL(ytdl_format_options)
            try:
                data = await self.bot.loop.run_in_executor(
                    None, 
                    lambda: ytdl.extract_info(f"scsearch5:{query}", download=False)
                )
                entries = data.get('entries', [])[:5]
                
                if not entries:
                    await interaction.followup.send("No results found", ephemeral=True)
                    return
                
                tracks = []
                for e in entries:
                    # Handle different result formats
                    webpage_url = e.get('webpage_url') or e.get('url')
                    if not webpage_url:
                        continue
                        
                    tracks.append({
                        'title': e.get('title', 'Unknown Track'),
                        'url': webpage_url,
                        'duration': e.get('duration'),
                        'thumbnail': e.get('thumbnails', [{}])[0].get('url') if isinstance(e.get('thumbnails'), list) else None
                    })
                
                # Store results in state
                state = self.guild_states[interaction.guild.id]
                state.search_results = tracks
                
                embed = discord.Embed(
                    title=f"Search Results for '{query}'",
                    color=discord.Color.blue()
                )
                for idx, track in enumerate(tracks, 1):
                    duration = str(timedelta(seconds=track.get('duration', 0))) if track.get('duration') else "Live"
                    embed.add_field(
                        name=f"{idx}. {track['title'][:45]}",
                        value=f"`{duration}` • [Link]({track['url']})",
                        inline=False
                    )
                
                view = TrackSelectView(self, tracks)
                await interaction.followup.send(embed=embed, view=view)
            except Exception as e:
                await interaction.followup.send(f"Search error: {str(e)[:150]}", ephemeral=True)
                print(f"Search error: {e}")
        
        if not was_playing and not state.now_playing:
            await self.play_next(interaction.guild)

    @app_commands.command(name="pause", description="Pause the player")
    async def pause(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        if state.voice_client and state.voice_client.is_playing():
            state.voice_client.pause()
            await interaction.response.send_message("⏸️ Paused")
        else:
            await interaction.response.send_message("Not currently playing", ephemeral=True)

    @app_commands.command(name="resume", description="Resume the player")
    async def resume(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        if state.voice_client and state.voice_client.is_paused():
            state.voice_client.resume()
            await interaction.response.send_message("▶️ Resumed")
        else:
            await interaction.response.send_message("Player is not paused", ephemeral=True)

    @app_commands.command(name="stop", description="Stop the player and clear queue")
    async def stop(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        if state.voice_client:
            state.voice_client.stop()
            state.queue.clear()
            state.history.clear()
            state.now_playing = None
            await interaction.response.send_message("⏹️ Stopped and cleared queue")
        else:
            await interaction.response.send_message("Not currently playing", ephemeral=True)

    @app_commands.command(name="skip", description="Skip tracks in different ways")
    @app_commands.describe(
        target="What to skip",
        position="Track position (for number skip)",
        user="User to skip (for user skip)",
        start="Start position (for range skip)",
        end="End position (for range skip)"
    )
    async def skip(self, interaction: discord.Interaction,
                  target: Optional[Literal["first", "user", "number", "range"]] = None,
                  position: Optional[int] = None,
                  user: Optional[discord.Member] = None,
                  start: Optional[int] = None,
                  end: Optional[int] = None):
        state = self.guild_states[interaction.guild.id]
        
        if not state.now_playing and not state.queue:
            await interaction.response.send_message("Nothing is playing", ephemeral=True)
            return
        
        await interaction.response.defer()
        
        # Default skip current track
        if not target:
            if state.voice_client:
                state.voice_client.stop()
                await interaction.followup.send("⏭️ Skipped current track")
            return

        # Handle different skip types
        if target == "first":
            if state.queue:
                skipped = state.queue.pop(0)
                await interaction.followup.send(f"⏭️ Skipped **{skipped['title']}**")
            else:
                await interaction.followup.send("Queue is empty", ephemeral=True)

        elif target == "user":
            if not user:
                await interaction.followup.send("Please specify a user", ephemeral=True)
                return
                
            initial_count = len(state.queue)
            state.queue = [t for t in state.queue if t['requester'] != user]
            removed = initial_count - len(state.queue)
            await interaction.followup.send(f"🗑️ Removed {removed} tracks from {user.display_name}")

        elif target == "number":
            if not position:
                await interaction.followup.send("Please specify a position", ephemeral=True)
                return
                
            if position < 1 or position > len(state.queue):
                await interaction.followup.send(f"Invalid position (1-{len(state.queue)})", ephemeral=True)
                return
                
            # Convert 1-based to 0-based index
            pos = position - 1
            skipped = state.queue.pop(pos)
            await interaction.followup.send(f"⏭️ Skipped **{skipped['title']}** (position {position})")

        elif target == "range":
            if not start or not end:
                await interaction.followup.send("Please specify start and end positions", ephemeral=True)
                return
                
            if start < 1 or end > len(state.queue) or start > end:
                await interaction.followup.send(f"Invalid range (1-{len(state.queue)})", ephemeral=True)
                return
                
            # Convert to 0-based and slice
            del state.queue[start-1:end]
            await interaction.followup.send(f"🗑️ Removed tracks {start}-{end}")

        # If queue became empty and nothing is playing
        if not state.queue and not state.voice_client.is_playing():
            await self.play_next(interaction.guild)

    @app_commands.command(name="queue", description="Show current queue")
    async def list_queue(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        
        if not state.queue and not state.now_playing:
            await interaction.response.send_message("Queue is empty", ephemeral=True)
            return
            
        embed = discord.Embed(title="Music Queue", color=discord.Color.gold())
        
        if state.now_playing:
            embed.add_field(
                name="Now Playing",
                value=f"[{state.now_playing['title']}]({state.now_playing['url']})\n"
                      f"Requested by {state.now_playing['requester'].mention}",
                inline=False
            )
            
        if state.queue:
            queue_text = []
            for i, track in enumerate(state.queue[:10], 1):
                queue_text.append(
                    f"{i}. [{track['title']}]({track['url']}) - {track['requester'].mention}"
                )
            embed.add_field(
                name=f"Up Next ({len(state.queue)} tracks)",
                value="\n".join(queue_text),
                inline=False
            )
            
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="volume", description="Adjust player volume")
    @app_commands.describe(level="Volume level (1-200)")
    async def volume(self, interaction: discord.Interaction, level: int):
        state = self.guild_states[interaction.guild.id]
        vol = max(0, min(level / 200, 1.0))
        
        if state.voice_client:
            state.volume = vol
            if state.voice_client.source:
                state.voice_client.source.volume = vol
                
        await interaction.response.send_message(f"🔊 Volume set to {level}%")

    @app_commands.command(name="shuffle", description="Toggle shuffle mode")
    async def shuffle(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        state.shuffle = not state.shuffle
        if state.shuffle:
            random.shuffle(state.queue)
            await interaction.response.send_message("🔀 Shuffle enabled")
        else:
            await interaction.response.send_message("▶️ Shuffle disabled")
            
    @app_commands.command(name="reshuffle", description="Reshuffle the queue")
    async def reshuffle(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        if len(state.queue) < 2:
            await interaction.response.send_message("Need at least 2 tracks to shuffle", ephemeral=True)
            return
            
        random.shuffle(state.queue)
        await interaction.response.send_message("🔀 Queue reshuffled")

    @app_commands.command(name="repeat", description="Set repeat mode")
    @app_commands.describe(mode="Repeat mode")
    async def repeat(self, interaction: discord.Interaction, 
                    mode: Literal["off", "all", "single"]):
        state = self.guild_states[interaction.guild.id]
        state.loop_mode = mode
        await interaction.response.send_message(f"🔁 Repeat mode set to {mode}")

    @app_commands.command(name="nowplaying", description="Show current track info")
    async def nowplaying(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        
        if not state.now_playing:
            await interaction.response.send_message("Nothing is playing", ephemeral=True)
            return
            
        embed = discord.Embed(
            title="Now Playing",
            description=f"[{state.now_playing['title']}]({state.now_playing['url']})",
            color=discord.Color.blurple()
        )
        embed.add_field(name="Duration", value=str(timedelta(seconds=state.now_playing['duration'])), inline=True)
        embed.add_field(name="Requested by", value=state.now_playing['requester'].mention, inline=True)
        embed.set_thumbnail(url=state.now_playing.get('thumbnail', ''))
        
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="voteskip", description="Vote to skip current track")
    async def voteskip(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        
        if not state.now_playing:
            await interaction.response.send_message("Nothing is playing", ephemeral=True)
            return
            
        listeners = len([m for m in state.voice_client.channel.members if not m.bot])
        state.votes.add(interaction.user.id)
        
        if len(state.votes) >= (listeners // 2) + 1:
            state.voice_client.stop()
            state.votes.clear()
            await interaction.response.send_message("Vote passed! Skipping track...")
        else:
            await interaction.response.send_message(
                f"Vote recorded ({len(state.votes)}/{required} needed)"
            )

    @app_commands.command(name="join", description="Join voice channel")
    async def join(self, interaction: discord.Interaction):
        if not interaction.user.voice:
            await interaction.response.send_message("You must be in a voice channel!", ephemeral=True)
            return
            
        state = self.guild_states[interaction.guild.id]
        voice_channel = interaction.user.voice.channel
        
        if state.voice_client:
            await state.voice_client.move_to(voice_channel)
        else:
            state.voice_client = await voice_channel.connect()
            
        await interaction.response.send_message(f"Joined {voice_channel.mention}")

    @app_commands.command(name="leave", description="Leave voice channel")
    async def leave(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        
        if state.voice_client:
            await state.voice_client.disconnect()
            state.voice_client = None
            await interaction.response.send_message("Left voice channel")
        else:
            await interaction.response.send_message("Not in a voice channel", ephemeral=True)

    @app_commands.command(name="history", description="Show recently played tracks")
    async def history(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        
        if not state.history:
            await interaction.response.send_message("No history", ephemeral=True)
            return
            
        embed = discord.Embed(title="Play History", color=discord.Color.dark_gold())
        for track in reversed(state.history[-5:]):
            embed.add_field(
                name=track['title'],
                value=f"Requested by {track['requester'].mention}",
                inline=False
            )
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="restart", description="Restart current track")
    async def restart(self, interaction: discord.Interaction):
        state = self.guild_states[interaction.guild.id]
        
        if state.voice_client and state.now_playing:
            state.voice_client.stop()
            state.queue.insert(0, state.now_playing)
            await interaction.response.send_message("🔁 Restarting current track")
        else:
            await interaction.response.send_message("Nothing is playing", ephemeral=True)

async def setup(bot):
    await bot.add_cog(Music(bot))