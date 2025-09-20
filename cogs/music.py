import os
import sys
import discord
import time
from discord import app_commands
from discord.ext import commands
from discord.ui import Button, View
import asyncio
import re
import yt_dlp as youtube_dl
from urllib.parse import urlparse, quote_plus
try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover - optional at runtime
    aiohttp = None
from collections import defaultdict, deque
import random
from typing import Literal, Optional
from datetime import timedelta
from shared import command_permission_check
try:
    from bot.bot import debug_print, db
except ImportError:
    def debug_print(*args, **kwargs):
        pass
    db = None
#sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
#from dotenv import load_dotenv

# Suppress noise about console usage from yt-dlp
youtube_dl.utils.bug_reports_message = lambda: ''

ytdl_format_options = {
    'format': 'bestaudio[ext=mp3]/bestaudio/best',
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
    'prefer_ffmpeg': True,
    'cookiefile': 'cookies.txt',
#   'ssl_certfile': os.getenv('SSL_CERT_FILE', '/usr/lib/ssl/cert.pem'),
#    'postprocessors': [{
#        'key': 'FFmpegExtractAudio',
#        'preferredcodec': 'wav',
#        'preferredquality': '192',
#    }],
}

ffmpeg_options = {
    'options': '-vn',
    'before_options': '-reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5',
    'executable': 'ffmpeg'
}


class YTDLSource(discord.PCMVolumeTransformer):
    def __init__(self, source, *, data, volume=0.5):
        debug_print(f"Entering YTDLSource.__init__ with source: {source}, data: {data}, volume: {volume}", level="all")
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
        debug_print(f"Entering YTDLSource.from_url with url: {url}, loop: {loop}, stream: {stream}, start_time: {start_time}", level="all")
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
        debug_print("Entering GuildMusicState.__init__", level="all")
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
        self.song_start_time = None  # Track when the current song started
        self.paused_at = None  # Track when the song was paused
        self.total_paused = 0  # Total seconds paused for current song

class TrackSelectView(View):
    def __init__(self, cog, tracks, offset=0, total_results=0):
        debug_print(f"Entering TrackSelectView.__init__ with cog: {cog}, tracks: {tracks}, offset: {offset}", level="all")
        super().__init__(timeout=30)
        self.cog = cog
        self.tracks = tracks
        self.offset = offset
        self.total_results = total_results or len(tracks)

        # Add up to 5 buttons for current page
        for i in range(5):
            idx = offset + i
            if idx < len(tracks):
                self.add_item(TrackSelectButton(cog, idx, tracks[idx]))
            else:
                # Add disabled buttons for missing results
                btn = Button(label="×", style=discord.ButtonStyle.grey, disabled=True)
                self.add_item(btn)

        # Add navigation buttons
        nav_buttons = []
        if offset > 0:
            nav_buttons.append(BackResultsButton(cog, offset, self.total_results))
        if offset + 5 < self.total_results:
            nav_buttons.append(MoreResultsButton(cog, offset, self.total_results))
        for btn in nav_buttons:
            self.add_item(btn)

class BackResultsButton(Button):
    def __init__(self, cog, offset, total_results):
        super().__init__(label="Back", style=discord.ButtonStyle.secondary)
        self.cog = cog
        self.offset = offset
        self.total_results = total_results

    async def callback(self, interaction: discord.Interaction):
        debug_print(f"BackResultsButton pressed at offset {self.offset}", level="all")
        state = self.cog.guild_states[interaction.guild.id]
        # Show previous 5 results (offset-5 to offset)
        new_offset = max(self.offset - 5, 0)
        tracks = state.search_results
        tracks_to_show = tracks[:self.total_results]
        view = TrackSelectView(self.cog, tracks_to_show, offset=new_offset, total_results=self.total_results)
        # Get the query string from state if available
        query = getattr(state, 'last_query', None)
        if not query and state.search_results:
            # Try to infer from the play command context (fallback)
            query = getattr(self.cog, 'last_query', None) or ''
        embed = discord.Embed(
            title=f"Search Results for '{query}' (Results {new_offset+1}-{min(new_offset+5, self.total_results)})",
            color=discord.Color.blue()
        )
        for idx in range(new_offset, min(new_offset+5, self.total_results)):
            track = tracks_to_show[idx]
            duration = self.cog._format_duration(track.get('duration'))
            embed.add_field(
                name=f"{idx+1}. {track['title'][:45]}",
                value=f"`{duration}` • [Link]({track['url']})",
                inline=False
            )
        await interaction.response.edit_message(embed=embed, view=view)

class MoreResultsButton(Button):
    def __init__(self, cog, offset, total_results):
        super().__init__(label="More", style=discord.ButtonStyle.secondary)
        self.cog = cog
        self.offset = offset
        self.total_results = total_results

    async def callback(self, interaction: discord.Interaction):
        debug_print(f"MoreResultsButton pressed at offset {self.offset}", level="all")
        state = self.cog.guild_states[interaction.guild.id]
        # Show next 5 results (offset+5 to offset+10)
        new_offset = self.offset + 5
        tracks = state.search_results
        # Defensive: only show up to total_results
        tracks_to_show = tracks[:self.total_results]
        view = TrackSelectView(self.cog, tracks_to_show, offset=new_offset, total_results=self.total_results)
        # Get the query string from state if available
        query = getattr(state, 'last_query', None)
        if not query and state.search_results:
            query = getattr(self.cog, 'last_query', None) or ''
        embed = discord.Embed(
            title=f"Search Results for '{query}' (Results {new_offset+1}-{min(new_offset+5, self.total_results)})",
            color=discord.Color.blue()
        )
        for idx in range(new_offset, min(new_offset+5, self.total_results)):
            track = tracks_to_show[idx]
            duration = self.cog._format_duration(track.get('duration'))
            embed.add_field(
                name=f"{idx+1}. {track['title'][:45]}",
                value=f"`{duration}` • [Link]({track['url']})",
                inline=False
            )
        await interaction.response.edit_message(embed=embed, view=view)

class TrackSelectButton(Button):
    def __init__(self, cog, index, track):
        debug_print(f"Entering TrackSelectButton.__init__ with cog: {cog}, index: {index}, track: {track}", level="all")
        super().__init__(
            label=str(index+1),
            style=discord.ButtonStyle.primary
        )
        self.cog = cog
        self.index = index
        self.track = track
        
    async def callback(self, interaction: discord.Interaction):
        debug_print(f"Entering TrackSelectButton.callback with interaction: {interaction}", level="all")
        try:
            guild_id = interaction.guild.id
            state = self.cog.guild_states[guild_id]
            
            # Verify track exists in the original results
            if self.index >= len(self.cog.guild_states[guild_id].search_results):
                await interaction.response.send_message("Invalid selection", ephemeral=True)
                return
                
            track = self.cog.guild_states[guild_id].search_results[self.index]
            
            # Validate URL before adding to queue
            track_url = track['url']
            if (
                not track_url.startswith('https://soundcloud.com/')
                or 'api.soundcloud.com' in track_url.lower()
                or 'soundcloud:tracks:' in track_url
                or 'soundcloud%3Atracks%3A' in track_url.lower()
                or '/api/' in track_url.lower()
            ):
                debug_print(f"Button callback: Invalid URL blocked: {track_url}")
                await interaction.response.send_message("Invalid track URL detected. Please try a different track.", ephemeral=True)
                return
            
            state.queue.append({
                'title': track['title'],
                'url': track['url'],
                'duration': track.get('duration'),
                'requester': interaction.user,
                'thumbnail': track.get('thumbnail')
            })
            
            # Edit the original message to confirm selection and remove buttons
            await interaction.response.edit_message(
                content=f"Added **{track['title']}** to queue.",
                embed=None, # Remove embed
                view=None   # Remove buttons
            )
            
            if not state.now_playing:
                await self.cog.play_next(interaction.guild)
        except Exception as e:
            # Use followup if the initial response has been sent
            if not interaction.response.is_done():
                await interaction.response.send_message("Failed to add track. Please try again.", ephemeral=True)
            else:
                await interaction.followup.send("Failed to add track. Please try again.", ephemeral=True)
            debug_print(f"Button callback error: {e}")

class Music(commands.Cog):
    def _format_duration(self, seconds):
        if seconds is None:
            return "Live"
        try:
            seconds = int(seconds)
        except Exception:
            return str(seconds)
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        if h > 0:
            return f"{h}:{m:02}:{s:02}"
        else:
            return f"{m}:{s:02}"
    # URL validation and fallback search
    def _is_valid_sc_public_url(self, url: str) -> bool:
        if not isinstance(url, str):
            return False
        u = url.strip()
        if not u.startswith('https://soundcloud.com/'):
            return False
        lu = u.lower()
        if 'api.soundcloud.com' in lu or '/api/' in lu:
            return False
        if 'soundcloud%3a' in lu or 'soundcloud:tracks:' in u:
            return False
        if '/you/' in lu:
            return False
        # Basic pattern: https://soundcloud.com/<user>/<track>
        return re.match(r'^https://soundcloud\.com/[^/]+/[^/]+/?$', u) is not None

    async def _sc_web_search(self, query: str, limit: int = 10):
        # Fallback search by scraping public search page and using oEmbed for metadata
        results = []
        seen = set()
        search_url = f"https://soundcloud.com/search?q={quote_plus(query)}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'
        }
        html_text = None
        try:
            if aiohttp is not None:
                async with aiohttp.ClientSession(headers=headers) as session:
                    async with session.get(search_url, timeout=12) as resp:
                        html_text = await resp.text()
            else:
                # Synchronous fallback in thread to avoid blocking loop
                import requests  # type: ignore
                def _get():
                    return requests.get(search_url, headers=headers, timeout=12).text
                html_text = await asyncio.get_event_loop().run_in_executor(None, _get)
        except Exception as e:
            debug_print(f"Fallback SC search fetch failed: {e}")
            return []

        if not html_text:
            return []

        # Extract candidate hrefs that look like /user/track
        try:
            candidates = re.findall(r'href=[\"\'](/[^/\"\']+/[^/\"\']+)/?[\"\']', html_text)
        except Exception:
            candidates = []

        for path in candidates:
            if len(results) >= limit:
                break
            url = f"https://soundcloud.com{path}"
            if url in seen:
                continue
            if not self._is_valid_sc_public_url(url):
                continue
            seen.add(url)
            results.append({'url': url})

        # Enrich with oEmbed for title/thumbnail when possible
        enriched = []
        for item in results:
            url = item['url']
            oembed = None
            try:
                oembed_url = f"https://soundcloud.com/oembed?format=json&url={quote_plus(url)}"
                if aiohttp is not None:
                    async with aiohttp.ClientSession(headers=headers) as session:
                        async with session.get(oembed_url, timeout=10) as resp:
                            if resp.status == 200:
                                oembed = await resp.json()
                else:
                    import requests  # type: ignore
                    def _get_json():
                        r = requests.get(oembed_url, headers=headers, timeout=10)
                        if r.status_code == 200:
                            return r.json()
                        return None
                    oembed = await asyncio.get_event_loop().run_in_executor(None, _get_json)
            except Exception:
                oembed = None

            enriched.append({
                'title': (oembed.get('title') if isinstance(oembed, dict) else None) or url.rsplit('/', 1)[-1].replace('-', ' '),
                'url': url,
                'duration': None,
                'thumbnail': (oembed.get('thumbnail_url') if isinstance(oembed, dict) else None)
            })

        return enriched
    async def update_now_playing_embed(self, guild_id):
        state = self.guild_states[guild_id]
        if not state.last_play_msg or not state.now_playing or not state.song_start_time:
            return
        duration = state.now_playing.get('duration') or 0
        # Calculate elapsed time, accounting for pause
        if state.paused_at:
            elapsed = int(state.paused_at - state.song_start_time - state.total_paused)
        else:
            elapsed = int(time.time() - state.song_start_time - state.total_paused)
        elapsed = min(max(elapsed, 0), duration) if duration else 0
        bar_length = 20
        if duration and duration > 0:
            progress = int((elapsed / duration) * bar_length)
            bar = '▬' * progress + '🔘' + '▬' * (bar_length - progress - 1)
            time_str = f"`{self._format_duration(elapsed)}` / `{self._format_duration(duration)}`"
        else:
            bar = '🔘' + '▬' * (bar_length - 1)
            time_str = "`Live`"
        embed = discord.Embed(
            title="Now Playing",
            description=f"[{state.now_playing['title']}]({state.now_playing['url']})\n{bar}\n{time_str}",
            color=discord.Color.blurple()
        )
        embed.add_field(name="Duration", value=self._format_duration(duration), inline=True)
        embed.add_field(name="Requested by", value=state.now_playing['requester'].mention, inline=True)
        embed.set_image(url=state.now_playing.get('thumbnail', ''))
        try:
            await state.last_play_msg.edit(embed=embed)
        except Exception:
            pass

    async def now_playing_updater(self, guild_id):
        state = self.guild_states[guild_id]
        while state.now_playing and state.last_play_msg:
            await self.update_now_playing_embed(guild_id)
            await asyncio.sleep(4)
    def __init__(self, bot):
        debug_print(f"Entering Music.__init__ with bot: {bot}", level="all")
        self.bot = bot
        self.guild_states = defaultdict(GuildMusicState)
        
    async def play_next(self, guild, error=None):
        debug_print(f"Entering play_next with guild: {guild}, error: {error}", level="all")
        state = self.guild_states[guild.id]

        # Before moving on, update the embed for the song that just finished.
        if state.last_play_msg and state.now_playing:
            duration = state.now_playing.get('duration') or 0
            if duration > 0:
                bar_length = 20
                bar = '▬' * bar_length + '🔘'
                time_str = f"`{self._format_duration(duration)}` / `{self._format_duration(duration)}`"
                
                embed = discord.Embed(
                    title="Finished Playing",
                    description=f"[{state.now_playing['title']}]({state.now_playing['url']})\n{bar}\n{time_str}",
                    color=discord.Color.green()
                )
                embed.add_field(name="Duration", value=self._format_duration(duration), inline=True)
                embed.add_field(name="Requested by", value=state.now_playing['requester'].mention, inline=True)
                embed.set_image(url=state.now_playing.get('thumbnail', ''))
                try:
                    await state.last_play_msg.edit(embed=embed)
                except Exception:
                    pass # Ignore if message was deleted

        if error:
            debug_print(f"Player error: {error}")
        if state.voice_client is None or not state.voice_client.is_connected():
            return

        # Determine the next track
        if state.loop_mode == 'single' and state.now_playing:
            next_track = state.now_playing
        elif state.loop_mode == 'all' and state.now_playing:
            state.queue.append(state.now_playing)
            next_track = state.queue.pop(0) if state.queue else None
        else:
            next_track = state.queue.pop(0) if state.queue else None

        # Only send 'Queue finished!' if there was something playing before and now there is nothing left to play
        queue_was_active = state.now_playing is not None or state.queue

        # Skip tracks with invalid URLs
        while next_track and (
            not isinstance(next_track.get('url'), str) 
            or 'api.soundcloud.com' in next_track['url'].lower()
            or 'soundcloud:tracks:' in next_track['url']
            or 'soundcloud%3Atracks%3A' in next_track['url'].lower()
            or not next_track['url'].startswith('https://soundcloud.com/')
            or '/api/' in next_track['url'].lower()
        ):
            debug_print(f"Skipping invalid track URL: {next_track.get('url')}")
            if state.queue:
                next_track = state.queue.pop(0)
            else:
                next_track = None

        if not next_track:
            state.now_playing = None
            state.song_start_time = None
            state.last_play_msg = None
            state.paused_at = None
            state.total_paused = 0
            if state.text_channel and queue_was_active:
                channel = guild.get_channel(state.text_channel)
                await channel.send("Queue finished!")
            return

        state.now_playing = next_track
        state.history.append(next_track)
        state.paused_at = None
        state.total_paused = 0
        try:
            source = await YTDLSource.from_url(next_track['url'], loop=self.bot.loop, stream=True)
            source.volume = state.volume
            state.voice_client.play(source, after=lambda e: self.bot.loop.create_task(self.play_next(guild, e)))
            state.song_start_time = int(time.time())
            # Now Playing embed with progress bar
            if state.text_channel:
                channel = guild.get_channel(state.text_channel)
                duration = next_track.get('duration') or 0
                elapsed = 0
                bar_length = 20
                if duration and duration > 0:
                    progress = int((elapsed / duration) * bar_length)
                    bar = '▬' * progress + '🔘' + '▬' * (bar_length - progress - 1)
                    time_str = f"`{self._format_duration(elapsed)}` / `{self._format_duration(duration)}`"
                else:
                    bar = '🔘' + '▬' * (bar_length - 1)
                    time_str = "`Live`"
                embed = discord.Embed(
                    title="Now Playing",
                    description=f"[{next_track['title']}]({next_track['url']})\n{bar}\n{time_str}",
                    color=discord.Color.blurple()
                )
                embed.add_field(name="Duration", value=self._format_duration(duration), inline=True)
                embed.add_field(name="Requested by", value=next_track['requester'].mention, inline=True)
                embed.set_image(url=next_track.get('thumbnail', ''))
                # If there is an old message, try to delete it
                if state.last_play_msg:
                    try:
                        await state.last_play_msg.delete()
                    except Exception:
                        pass
                state.last_play_msg = await channel.send(embed=embed)
                # Start background updater
                self.bot.loop.create_task(self.now_playing_updater(guild.id))
        except Exception as e:
            if state.text_channel:
                channel = guild.get_channel(state.text_channel)
                await channel.send(f"Error playing track: {e}")
            await self.play_next(guild)

    @app_commands.command(name="play", description="Play music from SoundCloud")
    @command_permission_check("play")
    @app_commands.describe(query="Song name or SoundCloud URL")
    async def play(self, interaction: discord.Interaction, query: str):
        debug_print(f"Entering /play with interaction: {interaction}, query: {query}", level="all")
        await interaction.response.defer(ephemeral=True)

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
                # Use the largest thumbnail available from data.data['thumbnails'] if present
                thumbnails = data.data.get('thumbnails', [])
                largest_thumb = None
                if isinstance(thumbnails, list) and thumbnails:
                    try:
                        largest_thumb = max(
                            thumbnails,
                            key=lambda t: (t.get('width', 0) or 0) * (t.get('height', 0) or 0)
                        ).get('url')
                    except Exception:
                        largest_thumb = thumbnails[-1].get('url')
                else:
                    largest_thumb = data.data.get('thumbnail')
                # Always use the public SoundCloud URL for playback
                public_url = data.data.get('webpage_url') or data.data.get('permalink_url') or query
                track = {
                    'title': data.title,
                    'url': public_url,
                    'duration': data.duration,
                    'requester': interaction.user,
                    'thumbnail': largest_thumb
                }
                state.queue.append(track)
                await interaction.followup.send(f"Added **{track['title']}** to queue", ephemeral=True)
            except Exception as e:
                await interaction.followup.send(f"Error processing URL: {e}", ephemeral=True)
                return
        else:
            tracks = []
            try:
                search_options = {
                    'quiet': True,
                    'no_warnings': True,
                    'extract_flat': True,
                    'skip_download': True,
                    'default_search': 'auto',
                    'source_address': '0.0.0.0',
                    'cookiefile': 'cookies.txt',
                }
                ytdl = youtube_dl.YoutubeDL(search_options)
                data = await self.bot.loop.run_in_executor(
                    None,
                    lambda: ytdl.extract_info(f"scsearch10:{query}", download=False)
                )
                entries = data.get('entries', [])[:10]
                for e in entries:
                    public_url = e.get('webpage_url') or e.get('permalink_url')
                    if public_url and self._is_valid_sc_public_url(public_url):
                        title = e.get('title') or public_url.rsplit('/', 1)[-1].replace('-', ' ')
                        thumb = None
                        thumbs = e.get('thumbnails') or []
                        if isinstance(thumbs, list) and thumbs:
                            try:
                                thumb = max(thumbs, key=lambda t: (t.get('width', 0) or 0) * (t.get('height', 0) or 0)).get('url')
                            except Exception:
                                thumb = thumbs[-1].get('url')
                        tracks.append({'title': title, 'url': public_url, 'duration': e.get('duration'), 'thumbnail': thumb})
            except Exception as e:
                debug_print(f"yt-dlp scsearch failed: {e}")

            # If yt-dlp yields no valid tracks, fallback to HTML scraping
            if not tracks:
                tracks = await self._sc_web_search(query, limit=10)

            if not tracks:
                await interaction.followup.send("No results found", ephemeral=True)
                return

            # Store results in state
            state = self.guild_states[interaction.guild.id]
            state.search_results = tracks
            state.last_query = query
            embed = discord.Embed(
                title=f"Search Results for '{query}' (Results 1-5)",
                color=discord.Color.blue()
            )
            for idx in range(0, min(5, len(tracks))):
                track = tracks[idx]
                duration = self._format_duration(track.get('duration'))
                embed.add_field(
                    name=f"{idx+1}. {track['title'][:45]}",
                    value=f"`{duration}` • [Link]({track['url']})",
                    inline=False
                )
            view = TrackSelectView(self, tracks, offset=0, total_results=len(tracks))
            await interaction.followup.send(embed=embed, view=view, ephemeral=True)
            return # Return here to not call play_next immediately

        if not was_playing and state.queue:
            # If nothing was playing but we just added a song, start playing
            await self.play_next(interaction.guild)

    @app_commands.command(name="pause", description="Pause the player")
    @command_permission_check("pause")
    async def pause(self, interaction: discord.Interaction):
        debug_print(f"Entering /pause with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        if state.voice_client and state.voice_client.is_playing():
            state.voice_client.pause()
            # Record pause time
            if not state.paused_at:
                state.paused_at = time.time()
            await interaction.response.send_message("⏸️ Paused", ephemeral=True)
        else:
            await interaction.response.send_message("Not currently playing", ephemeral=True)

    @app_commands.command(name="resume", description="Resume the player")
    @command_permission_check("resume")
    async def resume(self, interaction: discord.Interaction):
        debug_print(f"Entering /resume with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        if state.voice_client and state.voice_client.is_paused():
            state.voice_client.resume()
            # Adjust total_paused
            if state.paused_at:
                state.total_paused += time.time() - state.paused_at
                state.paused_at = None
            await interaction.response.send_message("▶️ Resumed", ephemeral=True)
        else:
            await interaction.response.send_message("Player is not paused", ephemeral=True)

    @app_commands.command(name="stop", description="Stop the player and clear queue")
    @command_permission_check("stop")
    async def stop(self, interaction: discord.Interaction):
        debug_print(f"Entering /stop with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        if state.voice_client:
            state.voice_client.stop()
            state.queue.clear()
            state.history.clear()
            state.now_playing = None
            await interaction.response.send_message("⏹️ Stopped and cleared queue", ephemeral=True)
        else:
            await interaction.response.send_message("Not currently playing", ephemeral=True)


    @app_commands.command(name="skip", description="Skip the current song or skip to a song in the queue")
    @command_permission_check("skip")
    @app_commands.describe(to="Song number in the queue to skip to")
    async def skip(self, interaction: discord.Interaction, to: Optional[int] = None):
        debug_print(f"Entering /skip with interaction: {interaction}, to: {to}", level="all")
        state = self.guild_states[interaction.guild.id]
        if not state.now_playing and not state.queue:
            await interaction.response.send_message("Nothing is playing", ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        if to is None:
            # Default: skip current song
            if state.voice_client:
                state.voice_client.stop()
                await interaction.followup.send("⏭️ Skipped current track", ephemeral=True)
            return
        # Skip to a specific song number in the queue
        if to < 1 or to > len(state.queue):
            await interaction.followup.send(f"Invalid song number (1-{len(state.queue)})", ephemeral=True)
            return
        # Move current song and all songs before the selected one to the end of the queue
        # The queue is: [track1, track2, ..., trackN], and now_playing is the current song
        # We want to move now_playing and queue[0:to-1] to the end, and play queue[to-1]
        if state.now_playing:
            move_tracks = [state.now_playing] + state.queue[:to-1]
        else:
            move_tracks = state.queue[:to-1]
        state.queue = state.queue[to-1:] + move_tracks
        if state.voice_client:
            state.voice_client.stop()
        await interaction.followup.send(f"⏭️ Skipped to track #{to} ({state.queue[0]['title']})", ephemeral=True)
        # If queue became empty and nothing is playing
        if not state.queue and not state.voice_client.is_playing():
            await self.play_next(interaction.guild)

    @skip.autocomplete("to")
    async def skip_to_autocomplete(self, interaction: discord.Interaction, current: str):
        """Autocomplete for the 'to' argument: list all songs in the queue with their number and title."""
        state = self.guild_states[interaction.guild.id]
        results = []
        for i, track in enumerate(state.queue, 1):
            label = f"{i}. {track['title'][:80]}"
            results.append(app_commands.Choice(name=label, value=i))
        # Filter by current input
        if current:
            results = [c for c in results if current in str(c.value) or current.lower() in c.name.lower()]
        return results[:25]

    @app_commands.command(name="queue", description="Show current queue")
    @command_permission_check("queue")
    async def list_queue(self, interaction: discord.Interaction):
        debug_print(f"Entering /queue with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        
        if not state.queue and not state.now_playing:
            await interaction.response.send_message("Queue is empty", ephemeral=True)
            return
            
        embed = discord.Embed(title="Music Queue", color=discord.Color.gold())
        
        if state.now_playing:
            duration = self._format_duration(state.now_playing.get('duration'))
            embed.add_field(
                name="Now Playing",
                value=f"[{state.now_playing['title']}]({state.now_playing['url']})\n"
                      f"`{duration}`\nRequested by {state.now_playing['requester'].mention}",
                inline=False
            )
            
        if state.queue:
            queue_text = []
            for i, track in enumerate(state.queue[:10], 1):
                duration = self._format_duration(track.get('duration'))
                queue_text.append(
                    f"{i}. [{track['title']}]({track['url']}) - `{duration}` - {track['requester'].mention}"
                )
            embed.add_field(
                name=f"Up Next ({len(state.queue)} tracks)",
                value="\n".join(queue_text),
                inline=False
            )
            
        await interaction.response.send_message(embed=embed)
        
    @app_commands.command(name="remove_from_queue", description="Remove a song from the queue by its number")
    @command_permission_check("remove_from_queue")
    @app_commands.describe(song="The song number in the queue to remove")
    async def remove_from_queue(self, interaction: discord.Interaction, song: int):
        debug_print(f"Entering /remove_from_queue with interaction: {interaction}, song: {song}", level="all")
        state = self.guild_states[interaction.guild.id]
        queue_len = len(state.queue)
        if queue_len == 0:
            await interaction.response.send_message("Queue is empty.", ephemeral=True)
            return
        if song < 1 or song > queue_len:
            await interaction.response.send_message(f"Invalid song number (1-{queue_len})", ephemeral=True)
            return
        removed = state.queue.pop(song - 1)
        await interaction.response.send_message(f"Removed **{removed['title']}** from the queue (position {song}).")

    @remove_from_queue.autocomplete("song")
    async def remove_from_queue_song_autocomplete(self, interaction: discord.Interaction, current: str):
        state = self.guild_states[interaction.guild.id]
        results = []
        for i, track in enumerate(state.queue, 1):
            label = f"{i}. {track['title'][:80]}"
            results.append(app_commands.Choice(name=label, value=i))
        if current:
            results = [c for c in results if current in str(c.value) or current.lower() in c.name.lower()]
        return results[:25]
    
    @app_commands.command(name="create_playlist", description="Create a new playlist (per user, global)")
    @command_permission_check("create_playlist")
    @app_commands.describe(name="Name of the playlist")
    async def create_playlist(self, interaction: discord.Interaction, name: str):
        debug_print(f"/create_playlist called by {interaction.user.id} with name: {name}", level="all")
        await interaction.response.defer(thinking=True, ephemeral=True)
        if not name or len(name.strip()) < 2:
            await interaction.followup.send("Playlist name must be at least 2 characters.", ephemeral=True)
            return
        # Check for duplicate name for this user
        playlists = db.get_user_playlists(str(interaction.user.id))
        if any(p['name'].lower() == name.strip().lower() for p in playlists):
            await interaction.followup.send(f"You already have a playlist named '{name}'.", ephemeral=True)
            return
        playlist_id = db.create_playlist(str(interaction.user.id), name.strip())
        await interaction.followup.send(f"✅ Playlist **{name}** created!\n(ID: `{playlist_id}`)", ephemeral=True)
    
    @app_commands.command(name="delete_playlist", description="Delete one of your playlists")
    @command_permission_check("delete_playlist")
    @app_commands.describe(playlist="Select a playlist to delete")
    async def delete_playlist(self, interaction: discord.Interaction, playlist: str):
        debug_print(f"/delete_playlist called by {interaction.user.id} for playlist {playlist}", level="all")
        await interaction.response.defer(thinking=True, ephemeral=True)
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        pl = next((p for p in playlists if p['playlist_id'] == playlist), None)
        if not pl:
            await interaction.followup.send("Playlist not found.", ephemeral=True)
            return
        db.delete_playlist(playlist, user_id)
        await interaction.followup.send(f"🗑️ Playlist **{pl['name']}** deleted.", ephemeral=True)

    @delete_playlist.autocomplete("playlist")
    async def delete_playlist_autocomplete(self, interaction: discord.Interaction, current: str):
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        results = []
        for p in playlists:
            if not current or current.lower() in p['name'].lower():
                results.append(app_commands.Choice(name=p['name'], value=p['playlist_id']))
        return results[:25]

    @app_commands.command(name="edit_playlist", description="Rename one of your playlists")
    @command_permission_check("edit_playlist")
    @app_commands.describe(playlist="Select a playlist to rename", new_name="New name for the playlist")
    async def edit_playlist(self, interaction: discord.Interaction, playlist: str, new_name: str):
        debug_print(f"/edit_playlist called by {interaction.user.id} for playlist {playlist} to '{new_name}'", level="all")
        await interaction.response.defer(thinking=True, ephemeral=True)
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        pl = next((p for p in playlists if p['playlist_id'] == playlist), None)
        if not pl:
            await interaction.followup.send("Playlist not found.", ephemeral=True)
            return
        if not new_name or len(new_name.strip()) < 2:
            await interaction.followup.send("New name must be at least 2 characters.", ephemeral=True)
            return
        # Prevent duplicate name
        if any(p['name'].lower() == new_name.strip().lower() for p in playlists):
            await interaction.followup.send(f"You already have a playlist named '{new_name}'.", ephemeral=True)
            return
        db.edit_playlist(playlist, user_id, new_name.strip())
        await interaction.followup.send(f"✅ Playlist renamed to **{new_name}**.", ephemeral=True)

    @edit_playlist.autocomplete("playlist")
    async def edit_playlist_autocomplete(self, interaction: discord.Interaction, current: str):
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        results = []
        for p in playlists:
            if not current or current.lower() in p['name'].lower():
                results.append(app_commands.Choice(name=p['name'], value=p['playlist_id']))
        return results[:25]
    
    @app_commands.command(name="playlists", description="Show all your playlists and their songs")
    @command_permission_check("playlists")
    async def playlists(self, interaction: discord.Interaction):
        debug_print(f"/playlists called by {interaction.user.id}", level="all")
        await interaction.response.defer(thinking=True, ephemeral=True)
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        if not playlists:
            await interaction.followup.send("You have no playlists.", ephemeral=True)
            return
        embeds = []
        for pl in playlists:
            tracks = db.get_playlist_tracks(pl['playlist_id'], user_id)
            desc = ""
            if tracks:
                for i, t in enumerate(tracks, 1):
                    duration = self._format_duration(t.get('duration'))
                    desc += f"**{i}.** [{t['title']}]({t['url']})"
                    if duration and duration != "Live":
                        desc += f" (`{duration}`)"
                    desc += "\n"
            else:
                desc = "*No songs in this playlist.*"
            embed = discord.Embed(
                title=f"Playlist: {pl['name']}",
                description=desc,
                color=discord.Color.purple()
            )
            embed.set_footer(text=f"Playlist ID: {pl['playlist_id']}")
            embeds.append(embed)
        # If only one playlist, just send it
        if len(embeds) == 1:
            await interaction.followup.send(embed=embeds[0], ephemeral=True)
            return
        # If multiple, paginate
        class PlaylistPages(View):
            def __init__(self, embeds):
                super().__init__(timeout=60)
                self.embeds = embeds
                self.index = 0
                self.prev_button = Button(label="Prev", style=discord.ButtonStyle.secondary, row=0)
                self.next_button = Button(label="Next", style=discord.ButtonStyle.secondary, row=0)
                self.prev_button.callback = self.prev
                self.next_button.callback = self.next
                self.add_item(self.prev_button)
                self.add_item(self.next_button)
                self.update_buttons()

            def update_buttons(self):
                self.prev_button.disabled = self.index == 0
                self.next_button.disabled = self.index >= len(self.embeds) - 1

            async def prev(self, interaction: discord.Interaction):
                if self.index > 0:
                    self.index -= 1
                    self.update_buttons()
                    await interaction.response.edit_message(embed=self.embeds[self.index], view=self)

            async def next(self, interaction: discord.Interaction):
                if self.index < len(self.embeds) - 1:
                    self.index += 1
                    self.update_buttons()
                    await interaction.response.edit_message(embed=self.embeds[self.index], view=self)

            async def interaction_check(self, interaction: discord.Interaction):
                # Only allow the user who invoked the command to interact
                return interaction.user.id == interaction.user.id

        view = PlaylistPages(embeds)
        await interaction.followup.send(embed=embeds[0], view=view, ephemeral=True)

        # Make all page changes ephemeral
        async def prev_ephemeral(interaction):
            if view.index > 0:
                view.index -= 1
                view.update_buttons()
                await interaction.response.edit_message(embed=view.embeds[view.index], view=view, ephemeral=True)
        async def next_ephemeral(interaction):
            if view.index < len(view.embeds) - 1:
                view.index += 1
                view.update_buttons()
                await interaction.response.edit_message(embed=view.embeds[view.index], view=view, ephemeral=True)
        view.prev = prev_ephemeral
        view.next = next_ephemeral
    
    @app_commands.command(name="add_playlist_to_queue", description="Add all or selected songs from a playlist to the queue")
    @command_permission_check("add_playlist_to_queue")
    @app_commands.describe(playlist="Select a playlist", tracks="(Optional) Select specific tracks to add (leave empty for all)")
    async def add_playlist_to_queue(self, interaction: discord.Interaction, playlist: str, tracks: Optional[str] = None):
        debug_print(f"/add_playlist_to_queue called by {interaction.user.id} for playlist {playlist} tracks {tracks}", level="all")
        await interaction.response.defer(thinking=True, ephemeral=True)
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        pl = next((p for p in playlists if p['playlist_id'] == playlist), None)
        if not pl:
            await interaction.followup.send("Playlist not found.", ephemeral=True)
            return
        all_tracks = db.get_playlist_tracks(playlist, user_id)
        if not all_tracks:
            await interaction.followup.send("This playlist is empty.", ephemeral=True)
            return
        # If tracks param is provided, filter
        selected_tracks = all_tracks
        if tracks:
            track_ids = [t.strip() for t in tracks.split(",") if t.strip().isdigit()]
            selected_tracks = [t for i, t in enumerate(all_tracks, 1) if str(i) in track_ids]
            if not selected_tracks:
                await interaction.followup.send("No valid tracks selected.", ephemeral=True)
                return
        state = self.guild_states[interaction.guild.id]
        for t in selected_tracks:
            state.queue.append({
                'title': t['title'],
                'url': t['url'],
                'duration': t.get('duration'),
                'requester': interaction.user,
                'thumbnail': t.get('thumbnail')
            })
        await interaction.followup.send(f"▶️ Added {len(selected_tracks)} track(s) from **{pl['name']}** to the queue.", ephemeral=True)
        if not state.now_playing:
            await self.play_next(interaction.guild)

    @add_playlist_to_queue.autocomplete("playlist")
    async def add_playlist_to_queue_playlist_autocomplete(self, interaction: discord.Interaction, current: str):
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        results = []
        for p in playlists:
            if not current or current.lower() in p['name'].lower():
                results.append(app_commands.Choice(name=p['name'], value=p['playlist_id']))
        return results[:25]

    @add_playlist_to_queue.autocomplete("tracks")
    async def add_playlist_to_queue_tracks_autocomplete(self, interaction: discord.Interaction, current: str):
        user_id = str(interaction.user.id)
        playlist = interaction.namespace.playlist if hasattr(interaction.namespace, 'playlist') else None
        if not playlist:
            return []
        tracks = db.get_playlist_tracks(playlist, user_id)
        results = []
        for i, t in enumerate(tracks, 1):
            label = f"{i}. {t['title'][:80]}"
            if not current or current.lower() in label.lower():
                results.append(app_commands.Choice(name=label, value=str(i)))
        return results[:25]

    @app_commands.command(name="play_playlist", description="Play all songs from one of your playlists")
    @command_permission_check("play_playlist")
    @app_commands.describe(playlist="Select a playlist to play")
    async def play_playlist(self, interaction: discord.Interaction, playlist: str):
        debug_print(f"/play_playlist called by {interaction.user.id} for playlist {playlist}", level="all")
        await interaction.response.defer(thinking=True, ephemeral=True)
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        pl = next((p for p in playlists if p['playlist_id'] == playlist), None)
        if not pl:
            await interaction.followup.send("Playlist not found.", ephemeral=True)
            return
        tracks = db.get_playlist_tracks(playlist, user_id)
        if not tracks:
            await interaction.followup.send("This playlist is empty.", ephemeral=True)
            return
        if not interaction.user.voice:
            await interaction.followup.send("You must be in a voice channel!", ephemeral=True)
            return
        state = self.guild_states[interaction.guild.id]
        voice_channel = interaction.user.voice.channel
        if state.voice_client is None:
            state.voice_client = await voice_channel.connect()
        elif state.voice_client.channel != voice_channel:
            await state.voice_client.move_to(voice_channel)
        state.text_channel = interaction.channel.id
        # Add all tracks to queue
        for t in tracks:
            state.queue.append({
                'title': t['title'],
                'url': t['url'],
                'duration': t.get('duration'),
                'requester': interaction.user,
                'thumbnail': t.get('thumbnail')
            })
        await interaction.followup.send(f"▶️ Added {len(tracks)} tracks from **{pl['name']}** to the queue.", ephemeral=True)
        if not state.now_playing:
            await self.play_next(interaction.guild)

    @play_playlist.autocomplete("playlist")
    async def play_playlist_autocomplete(self, interaction: discord.Interaction, current: str):
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        results = []
        for p in playlists:
            if not current or current.lower() in p['name'].lower():
                results.append(app_commands.Choice(name=p['name'], value=p['playlist_id']))
        return results[:25]

    @app_commands.command(name="add_to_playlist", description="Add the currently playing song to one of your playlists")
    @command_permission_check("add_to_playlist")
    @app_commands.describe(playlist="Select a playlist to add the current song to")
    async def add_to_playlist(self, interaction: discord.Interaction, playlist: str):
        debug_print(f"/add_to_playlist called by {interaction.user.id} for playlist {playlist}", level="all")
        await interaction.response.defer(thinking=True, ephemeral=True)
        user_id = str(interaction.user.id)
        state = self.guild_states[interaction.guild.id]
        current = state.now_playing
        if not current:
            await interaction.followup.send("Nothing is currently playing.", ephemeral=True)
            return
        playlists = db.get_user_playlists(user_id)
        pl = next((p for p in playlists if p['playlist_id'] == playlist), None)
        if not pl:
            await interaction.followup.send("Playlist not found.", ephemeral=True)
            return
        db.add_track_to_playlist(
            playlist_id=playlist,
            user_id=user_id,
            title=current['title'],
            url=current['url'],
            duration=current.get('duration'),
            thumbnail=current.get('thumbnail')
        )
        await interaction.followup.send(f"✅ Added **{current['title']}** to playlist **{pl['name']}**.", ephemeral=True)

    @add_to_playlist.autocomplete("playlist")
    async def add_to_playlist_autocomplete(self, interaction: discord.Interaction, current: str):
        user_id = str(interaction.user.id)
        playlists = db.get_user_playlists(user_id)
        results = []
        for p in playlists:
            if not current or current.lower() in p['name'].lower():
                results.append(app_commands.Choice(name=p['name'], value=p['playlist_id']))
        return results[:25]
    
    @app_commands.command(name="reposition", description="Move a song in the queue to a new position")
    @command_permission_check("reposition")
    @app_commands.describe(song_number="The song number in the queue to move", position="The new position in the queue")
    async def reposition(self, interaction: discord.Interaction, song_number: int, position: int):
        debug_print(f"Entering /reposition with interaction: {interaction}, song_number: {song_number}, position: {position}", level="all")
        state = self.guild_states[interaction.guild.id]
        queue_len = len(state.queue)
        if queue_len < 2:
            await interaction.response.send_message("Need at least 2 tracks in the queue to reposition.", ephemeral=True)
            return
        if song_number < 1 or song_number > queue_len:
            await interaction.response.send_message(f"Invalid song number (1-{queue_len})", ephemeral=True)
            return
        if position < 1 or position > queue_len:
            await interaction.response.send_message(f"Invalid position (1-{queue_len})", ephemeral=True)
            return
        if song_number == position:
            await interaction.response.send_message("Song is already at that position.", ephemeral=True)
            return
        # Move the song
        track = state.queue.pop(song_number - 1)
        state.queue.insert(position - 1, track)
        await interaction.response.send_message(f"Moved **{track['title']}** from position {song_number} to {position}.", ephemeral=True)

    @reposition.autocomplete("song_number")
    async def reposition_song_number_autocomplete(self, interaction: discord.Interaction, current: str):
        state = self.guild_states[interaction.guild.id]
        results = []
        for i, track in enumerate(state.queue, 1):
            label = f"{i}. {track['title'][:80]}"
            results.append(app_commands.Choice(name=label, value=i))
        if current:
            results = [c for c in results if current in str(c.value) or current.lower() in c.name.lower()]
        return results[:25]

    @reposition.autocomplete("position")
    async def reposition_position_autocomplete(self, interaction: discord.Interaction, current: str):
        state = self.guild_states[interaction.guild.id]
        queue_len = len(state.queue)
        results = [app_commands.Choice(name=f"{i}", value=i) for i in range(1, queue_len+1)]
        if current:
            results = [c for c in results if current in str(c.value)]
        return results[:25]

    @app_commands.command(name="volume", description="Adjust player volume")
    @command_permission_check("volume")
    @app_commands.describe(level="Volume level (1-200)")
    async def volume(self, interaction: discord.Interaction, level: int):
        debug_print(f"Entering /volume with interaction: {interaction}, level: {level}", level="all")
        state = self.guild_states[interaction.guild.id]
        vol = max(0, min(level / 200, 1.0))
        
        if state.voice_client:
            state.volume = vol
            if state.voice_client.source:
                state.voice_client.source.volume = vol
                
        await interaction.response.send_message(f"🔊 Volume set to {level}%")

    @app_commands.command(name="shuffle", description="Toggle shuffle mode")
    @command_permission_check("shuffle")
    async def shuffle(self, interaction: discord.Interaction):
        debug_print(f"Entering /shuffle with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        state.shuffle = not state.shuffle
        if state.shuffle:
            random.shuffle(state.queue)
            await interaction.response.send_message("🔀 Shuffle enabled")
        else:
            await interaction.response.send_message("▶️ Shuffle disabled")
            
    @app_commands.command(name="reshuffle", description="Reshuffle the queue")
    @command_permission_check("reshuffle")
    async def reshuffle(self, interaction: discord.Interaction):
        debug_print(f"Entering /reshuffle with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        if len(state.queue) < 2:
            await interaction.response.send_message("Need at least 2 tracks to shuffle", ephemeral=True)
            return
            
        random.shuffle(state.queue)
        await interaction.response.send_message("🔀 Queue reshuffled", ephemeral=True)

    @app_commands.command(name="loop", description="Set loop mode")
    @command_permission_check("loop")
    @app_commands.describe(mode="Loop mode")
    async def loop(self, interaction: discord.Interaction, 
                  mode: Literal["off", "all", "single"]):
        debug_print(f"Entering /loop with interaction: {interaction}, mode: {mode}", level="all")
        state = self.guild_states[interaction.guild.id]
        state.loop_mode = mode
        await interaction.response.send_message(f"🔁 Loop mode set to {mode}")

    @app_commands.command(name="voteskip", description="Vote to skip current track")
    @command_permission_check("voteskip")
    async def voteskip(self, interaction: discord.Interaction):
        debug_print(f"Entering /voteskip with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        
        if not state.now_playing:
            await interaction.response.send_message("Nothing is playing", ephemeral=True)
            return
            
        listeners = len([m for m in state.voice_client.channel.members if not m.bot])
        state.votes.add(interaction.user.id)
        
        required = (listeners // 2) + 1
        if len(state.votes) >= required:
            state.voice_client.stop()
            state.votes.clear()
            await interaction.response.send_message("Vote passed! Skipping track...")
        else:
            await interaction.response.send_message(
                f"Vote recorded ({len(state.votes)}/{required} needed)"
            )

    @app_commands.command(name="join", description="Join voice channel")
    @command_permission_check("join")
    async def join(self, interaction: discord.Interaction):
        debug_print(f"Entering /join with interaction: {interaction}", level="all")
        if not interaction.user.voice:
            await interaction.response.send_message("You must be in a voice channel!", ephemeral=True)
            return
            
        state = self.guild_states[interaction.guild.id]
        voice_channel = interaction.user.voice.channel
        
        if state.voice_client:
            await state.voice_client.move_to(voice_channel)
        else:
            state.voice_client = await voice_channel.connect()
            
        await interaction.response.send_message(f"Joined {voice_channel.mention}", ephemeral=True)

    @app_commands.command(name="leave", description="Leave voice channel")
    @command_permission_check("leave")
    async def leave(self, interaction: discord.Interaction):
        debug_print(f"Entering /leave with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        
        if state.voice_client:
            await state.voice_client.disconnect()
            state.voice_client = None
            state.queue.clear()
            state.history.clear()
            state.now_playing = None
            await interaction.response.send_message("Left voice channel and cleared the queue.", ephemeral=True)
        else:
            await interaction.response.send_message("Not in a voice channel", ephemeral=True)

    @app_commands.command(name="history", description="Show recently played tracks")
    @command_permission_check("history")
    async def history(self, interaction: discord.Interaction):
        debug_print(f"Entering /history with interaction: {interaction}", level="all")
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
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @app_commands.command(name="restart", description="Restart current track")
    @command_permission_check("restart")
    async def restart(self, interaction: discord.Interaction):
        debug_print(f"Entering /restart with interaction: {interaction}", level="all")
        state = self.guild_states[interaction.guild.id]
        
        if state.voice_client and state.now_playing:
            state.voice_client.stop()
            state.queue.insert(0, state.now_playing)
            await interaction.response.send_message("🔁 Restarting current track", ephemeral=True)
        else:
            await interaction.response.send_message("Nothing is playing", ephemeral=True)

async def setup(bot):
    await bot.add_cog(Music(bot))