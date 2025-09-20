# Standard Library
import asyncio
import json
import logging
import os
import re
import sqlite3
import sys
import threading
import time
import traceback
import uuid
import random
import io
import zipfile
import tempfile
from datetime import datetime, timedelta
from functools import wraps

# Third-Party Libraries
import bcrypt
import requests
import jwt
from pytz import timezone as pytz_timezone, all_timezones
from authlib.integrations.flask_client import OAuth
from cachetools import TTLCache
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort, render_template_string, send_file
from markupsafe import Markup
from flask.sessions import SecureCookieSessionInterface
from flask_discord import DiscordOAuth2Session, Unauthorized
from flask_discord.exceptions import RateLimited
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.exceptions import BadRequestKeyError
from werkzeug.middleware.proxy_fix import ProxyFix

# Local Imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config
from database import Database
from shared import shared
from bot.bot import bot_instance, load_schedules
from backups.backups import get_backups, get_backup, init_db, get_conn, set_backup_share_id, import_backup_file, import_backup_file_from_bytes, get_backup_by_share_id
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        """
        No-op debug print hook.
        
        This function is a placeholder debug logging hook that accepts the same calling convention as Python's built-in `print` (any positional and keyword arguments) but does nothing by default. Call sites can safely invoke `debug_print(...)` without side effects; the symbol may be reassigned at runtime to a real debug logger or printer to enable diagnostic output.
        """
        pass

# Runtime Config
load_dotenv()
init_db()

# Initialize database
Config.verify_paths()
db = Database(str(Config.DATABASE_PATH))
db.initialize_db()
try:
    db.validate_schema()
    debug_print(f"🌐 Web using database: {db.db_path}")
except RuntimeError as e:
    debug_print(f"❌ Database schema validation failed: {str(e)}")
    raise

# Initialize Flask app
app = Flask(__name__)
csrf = CSRFProtect(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)
app.secret_key = os.getenv('SECRET_KEY')
app.config['DISCORD_CLIENT_ID'] = os.getenv('DISCORD_CLIENT_ID')
app.config['DISCORD_CLIENT_SECRET'] = os.getenv('DISCORD_CLIENT_SECRET')
app.config['DISCORD_REDIRECT_URI'] = os.getenv('FRONTEND_URL') + '/callback'
app.config["DISCORD_OAUTH2_SESSION_PROXIED"] = True
app.config["DISCORD_SESSION_COOKIE_SECURE"] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 14400  # 4 hour expiration
app.config["DISCORD_SCOPE"] = ["identify", "guilds"]
app.config.update({
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'PERMANENT_SESSION_LIFETIME': 14400, # 4 hour expiration
    'WTF_CSRF_CHECK_DEFAULT': True,
    'WTF_CSRF_SSL_STRICT': False
})

# Initialize Discord OAuth
discord = DiscordOAuth2Session(app)

# Configuration
API_URL = os.getenv('API_URL', 'http://localhost:5003')
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
JWT_SECRET = os.getenv('JWT_SECRET')
JWT_ALGORITHM = 'HS256'

# JWT Helper
def generate_jwt():
    """
    Generate a short-lived JWT used by the dashboard for privileged admin requests.
    
    The token has an issuer of "dashboard", a role of "admin", and expires 60 seconds after creation.
    
    Returns:
        str: Encoded JWT suitable for use as a Bearer token in Authorization headers.
    """
    debug_print("Entering generate_jwt", level="all")
    import time
    payload = {
        "iss": "dashboard",
        "exp": int(time.time()) + 60,  # 1 minute expiry
        "role": "admin"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# Requests wrapper to inject JWT
class JWTSession(requests.Session):
    def __init__(self, *args, **kwargs):
        """
        Initialize a JWTSession instance.
        
        Forwards all positional and keyword arguments to the superclass initializer (e.g., requests.Session).
        """
        debug_print(f"Entering JWTSession.__init__ with args: {args}, kwargs: {kwargs}", level="all")
        super().__init__(*args, **kwargs)
    def request(self, method, url, **kwargs):
        """
        Send an HTTP request, automatically injecting a short-lived Bearer JWT into the Authorization header.
        
        This method behaves like requests.Session.request but ensures an Authorization header is present by calling generate_jwt() and setting 'Authorization: Bearer <token>'. Any headers passed in via kwargs are preserved; the Authorization header will be overwritten if present in the provided headers. Returns the Response object from the underlying requests implementation.
        """
        debug_print(f"Entering JWTSession.request with method: {method}, url: {url}, kwargs: {kwargs}", level="all")
        headers = kwargs.pop('headers', {}) or {}
        headers['Authorization'] = f'Bearer {generate_jwt()}'
        kwargs['headers'] = headers
        return super().request(method, url, **kwargs)

jwt_requests = JWTSession()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Caching
channel_cache = TTLCache(maxsize=100, ttl=120) # 2 minutes
role_cache = TTLCache(maxsize=100, ttl=120) # 2 minutes

class Guild:
    """Mock Guild class for cached guilds"""
    def __init__(self, data):
        self.id = int(data['id'])
        self.name = data['name']
        self.icon_url = data['icon']
        self.permissions = type('Permissions', (), {'value': data['permissions']})

@app.template_filter('json_loads')
def json_loads_filter(s):
    return json.loads(s)

# Authentication and Authorization
def login_required(f):
    """
    Decorator that requires an authenticated session to access a view.
    
    If the Flask session does not contain 'user', 'admin', or 'head_admin', the wrapper flashes
    a warning and redirects the client to the login page (preserving the original URL in the
    `next` query parameter). Otherwise the original view function is called with its arguments.
    
    Returns:
        function: A wrapped view function suitable for use as a Flask route decorator.
    """
    def wrapper(*args, **kwargs):
        debug_print(f"Entering login_required wrapper for {f.__name__}", level="all")
        if not session.get('user') and not session.get('admin') and not session.get('head_admin'):
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def guild_required(f):
    """
    Decorator that ensures the current request is authorized to access a guild-scoped route.
    
    Checks performed (in order):
    - A `guild_id` keyword argument is present; otherwise aborts 404.
    - If an admin session is active, access is allowed.
    - Verifies the bot is present in the guild using `get_bot_guild_ids()`; otherwise aborts 404.
    - Verifies the current user is a member of the guild using `get_user_guilds()`; otherwise aborts 404.
    - Verifies the user has the Discord "Manage Server" permission (permission bit 0x20); otherwise aborts 403.
    
    Side effects:
    - Reads `session`.
    - Calls `get_user_guilds()` and `get_bot_guild_ids()`.
    - May call `abort()` to terminate the request with 404 or 403.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        debug_print(f"Entering guild_required wrapper for {f.__name__}", level="all")
        guild_id = kwargs.get('guild_id')
        if not guild_id:
            abort(404, description="Missing guild ID")

        if session.get('admin'):
            return f(*args, **kwargs)

        user_guilds = get_user_guilds()
        bot_guild_ids = get_bot_guild_ids()

        # Check if bot is in the server
        if str(guild_id) not in bot_guild_ids:
            abort(404, description="Bot not in server")

        # Check if user is in the server
        guild = next(
            (guild for guild in user_guilds if str(guild.id) == str(guild_id)),
            None
        )
        if not guild:
            abort(404, description="Server not found in your accessible guilds")

        # Check if user has manage server permissions
        if not (guild.permissions.value & 0x20):
            abort(403, description="You don't have manage server permissions")

        return f(*args, **kwargs)
    return wrapper

def get_user_guilds():
    """
    Return the list of guilds the current logged-in user shares with the bot.
    
    Short-circuits and caching:
    - If an admin session is active, returns an empty list.
    - Uses a per-session cache of serializable guild dicts (5 minute TTL) and will return cached Guild wrappers when valid.
    
    Behavior:
    - On a successful fetch, stores a serializable representation of guilds (id, name, icon, permissions) in the session cache and returns the original guild objects fetched from Discord.
    - If the Discord API raises Unauthorized, clears the session and returns an empty list.
    - If the Discord API rate-limits the request, returns Guild wrappers reconstructed from the session cache (if available).
    
    Returns:
        list: A list of guild objects (original Discord guild objects on success; Guild wrapper instances reconstructed from cached data in cached or rate-limited paths).
    """
    debug_print("Entering get_user_guilds", level="all")
    if session.get('admin'):
        return []

    # Check cache first
    if 'guilds_cache' in session:
        cached = session['guilds_cache']
        if cached['expires'] > time.time():
            return [Guild(g) for g in cached['guilds']]  # Reconstruct objects

    try:
        user_guilds = discord.fetch_guilds()
        bot_guild_ids = get_bot_guild_ids()

        # Convert to serializable dictionaries
        valid_guilds = [
            {
                'id': str(g.id),
                'name': g.name,
                'icon': g.icon_url or '',
                'permissions': g.permissions.value
            }
            for g in user_guilds 
            if str(g.id) in bot_guild_ids and (g.permissions.value & 0x20)
        ]
        
        session['guilds_cache'] = {
            'guilds': valid_guilds,
            'expires': time.time() + 300
        }
        
        return user_guilds  # Return original objects for permission checks

    except Unauthorized:
        session.clear()
        return []
    except RateLimited as e:
        logger.warning(f"Rate limited: {e}")
        # Return reconstructed guilds from cache
        return [Guild(g) for g in session.get('guilds_cache', {}).get('guilds', [])]

def get_guild_users(guild_id):
    """
    Fetch a guild's users, preferring data from the bot API and falling back to the local database.
    
    Attempts to retrieve user objects from the bot API endpoint; each returned user is normalized to a dict with keys `id` (string) and `name` (display name if available, otherwise username, otherwise the id). If the API call fails, returns users from the local `users` table. On unexpected errors an empty list is returned.
    
    Parameters:
        guild_id (int|str): The guild identifier to query.
    
    Returns:
        list[dict]: A list of user dictionaries with keys `id` and `name`. Returns an empty list on error or when no users are found.
    """
    debug_print(f"Entering get_guild_users with guild_id: {guild_id}", level="all")
    try:
        api_url = f"{API_URL}/api/get_guild_users"
        resp = jwt_requests.post(api_url, json={"guild_id": str(guild_id)}, timeout=10)
        if resp.status_code == 200:
            users = resp.json()
            if users:
                # Use display_name if available, fallback to username, then ID
                return [{"id": u["id"], "name": u.get("display_name") or u.get("username") or u["id"]} for u in users]
        # Fallback to DB users
        db_users = db.execute_query(
            'SELECT user_id as id, username as name FROM users WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        return db_users or []
    except Exception as e:
        logger.error(f"Error fetching users for guild {guild_id}: {e}")
        return []

def get_builtin_commands(guild_id):
    """
    Fetch the guild's built-in command definitions from the internal API.
    
    This performs an HTTP POST to the backend `/api/get_guild_commands` endpoint (10s timeout)
    and returns the parsed JSON response on success. If the request fails or the response
    status is not 200, an empty list is returned.
    
    Parameters:
        guild_id (int | str): Discord guild ID to fetch built-in commands for.
    
    Returns:
        list: Parsed JSON list of built-in command definitions, or an empty list on error.
    """
    debug_print(f"Entering get_builtin_commands with guild_id: {guild_id}", level="all")
    try:
        api_url = f"{API_URL}/api/get_guild_commands"
        resp = jwt_requests.post(api_url, json={"guild_id": str(guild_id)}, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            return []
    except Exception as e:
        logger.error(f"Error fetching built-in commands for guild {guild_id}: {e}")
        return []
    
def get_backup_schedules(guild_id):
    """
    Return all backup schedule rows for a guild.
    
    Parameters:
        guild_id (int | str): Discord guild (server) ID to query schedules for.
    
    Returns:
        list[dict]: List of schedule rows from the `schedules` table, each row represented as a dict (column name -> value).
    """
    from backups.backups import get_conn
    with get_conn() as conn:
        return [dict(row) for row in conn.execute('SELECT * FROM schedules WHERE guild_id = ?', (guild_id,)).fetchall()]
    
def get_bot_guild_ids():
    """
    Return the set of guild IDs where the bot is a member.
    
    Queries the database for all stored guild records and returns a set of their IDs (typically Discord snowflake strings).
    """
    debug_print("Entering get_bot_guild_ids", level="all")
    bot_guilds = db.get_all_guilds()
    return {g['id'] for g in bot_guilds}

def get_guild_or_404(guild_id):
    """
    Return the guild record for the given guild_id or abort with HTTP 404 if not found.
    
    Parameters:
        guild_id (int | str): ID of the guild to look up.
    
    Returns:
        dict: Guild record as returned by db.get_guild.
    
    Raises:
        werkzeug.exceptions.HTTPException: Aborts the request with a 404 error ("Bot not in server") when the guild is not present.
    """
    debug_print(f"Entering get_guild_or_404 with guild_id: {guild_id}", level="all")
    guild = db.get_guild(guild_id)
    if not guild:
        abort(404, "Bot not in server")
    return guild
    
def admin_required(f):
    """
    Decorator that restricts a view to requests with an active admin session.
    
    If the Flask session does not contain an 'admin' truthy value, the wrapper aborts the request with a 403 status and description "Admin privileges required". Otherwise it calls and returns the wrapped view's result.
    
    Parameters:
        f (callable): The view function to wrap.
    
    Returns:
        callable: A wrapped view function that enforces admin-only access.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        debug_print(f"Entering admin_required wrapper for {f.__name__}", level="all")
        if not session.get('admin'):
            abort(403, description="Admin privileges required")
        return f(*args, **kwargs)
    return decorated_function

def head_admin_required(f):
    """
    Decorator that restricts access to handlers to users with a head-admin session flag.
    
    When applied to a Flask view or handler, the wrapper checks Flask's `session` for the key
    'head_admin'. If the key is missing/false, the request is aborted with HTTP 403 and the
    message "Head admin privileges required". Otherwise the original function is called and
    its result returned.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        debug_print(f"Entering head_admin_required wrapper for {f.__name__}", level="all")
        if not session.get('head_admin'):
            abort(403, "Head admin privileges required")
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_admin_status():
    """
    Expose admin status helpers to templates.
    
    Returns two zero-argument callables for Jinja2 templates:
    - is_head_admin(): returns True if the current session has the 'head_admin' flag.
    - log_bot_admin(): returns True if the current session has the 'admin' flag.
    
    Both read directly from Flask's session and return False when the keys are absent.
    """
    debug_print("Entering inject_admin_status", level="all")
    def check_head_admin():
        """
        Return True if the current session is marked as a head admin.
        
        Checks the Flask session for the 'head_admin' flag and returns its truthy value (defaults to False).
        """
        return session.get('head_admin', False)
    
    def check_bot_admin():
        return session.get('admin', False)
    
    return {
        'is_head_admin': check_head_admin,
        'log_bot_admin': check_bot_admin
    }

# Map export option to data fetcher and filename
EXPORT_MAP = {
    'server-configuration/commands.json': lambda guild_id: db.get_guild_commands_list(guild_id),
    'server-configuration/command-permissions.json': lambda guild_id: db.execute_query('SELECT * FROM command_permissions WHERE guild_id = ?', (guild_id,), fetch='all'),
    'server-configuration/blocked-words.json': lambda guild_id: db.get_blocked_words(guild_id),
    'server-configuration/logging.json': lambda guild_id: db.get_log_config(guild_id),
    'server-configuration/welcome-message.json': lambda guild_id: db.get_welcome_config(guild_id),
    'server-configuration/goodbye-message.json': lambda guild_id: db.get_goodbye_config(guild_id),
    'server-configuration/auto-assign-role.json': lambda guild_id: db.get_autoroles(guild_id),
    'server-configuration/spam.json': lambda guild_id: db.get_spam_config(guild_id),
    'server-configuration/warning-actions.json': lambda guild_id: db.get_warning_actions(guild_id),
    'server-configuration/role-menus.json': lambda guild_id: db.execute_query('SELECT * FROM role_menus WHERE guild_id = ?', (guild_id,), fetch='all'),
    'leveling-system/leveling.json': lambda guild_id: db.get_level_config(guild_id),
    'custom-forms/forms.json': lambda guild_id: db.execute_query('SELECT * FROM custom_forms WHERE guild_id = ?', (guild_id,), fetch='all'),
    'social-pings/twitch-pings.json': lambda guild_id: db.execute_query('SELECT * FROM twitch_announcements WHERE guild_id = ?', (guild_id,), fetch='all'),
    'social-pings/youtube-pings.json': lambda guild_id: db.execute_query('SELECT * FROM youtube_announcements WHERE guild_id = ?', (guild_id,), fetch='all'),
    'fun-miscellaneous/game-roles.json': lambda guild_id: db.get_game_roles(guild_id),
    'backup-restore/backup-schedules.json': lambda guild_id: get_backup_schedules(guild_id),
}

# def resolve_youtube_handle(identifier: str) -> tuple:
#     debug_print(f"Entering resolve_youtube_handle with identifier: {identifier}", level="all")
#     """Convert YouTube handle to channel ID with quota check"""
#     API_KEY = os.getenv('YOUTUBE_API_KEY')
#     if not API_KEY:
#         return identifier, "API key not configured"
    
#     try:
#         # Handle @channel format
#         if identifier.startswith('@'):
#             handle = identifier[1:]
#         else:
#             handle = identifier
            
#         # Resolve handle to channel ID
#         url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&type=channel&q={handle}&key={API_KEY}"
#         response = requests.get(url)
#         data = response.json()
        
#         # Check for quota errors
#         if 'error' in data:
#             if any(e.get('reason') == 'quotaExceeded' for e in data['error'].get('errors', [])):
#                 logger.error("YouTube API QUOTA EXCEEDED during handle resolution")
#                 return identifier, "YouTube API quota exceeded - try again later"
            
#             error_msg = data['error'].get('message', 'Unknown YouTube API error')
#             return identifier, f"YouTube API error: {error_msg}"
        
#         if 'items' in data and len(data['items']) > 0:
#             return data['items'][0]['snippet']['channelId'], None
            
#         return identifier, "Channel not found"
#     except Exception as e:
#         logger.error(f"Error resolving YouTube handle: {str(e)}")
#         return identifier, "Connection error"

# TEMPORARY ROUTE
# @app.route('/update-guild-icons')
# def update_guild_icons():
#     debug_print("Entering update_guild_icons", level="all")
#     if not session.get('admin'):
#         abort(403)
#
#     try:
#         guilds = db.execute_query('SELECT guild_id FROM guilds', fetch='all')
#
#         updated = 0
#         for g in guilds:
#             # Use 'guild_id' instead of 'id'
#             guild_id = int(g['guild_id'])
#             guild = shared.bot.get_guild(guild_id)

#             if guild:
#                 icon = str(guild.icon.url) if guild.icon else None
#                 db.execute_query(
#                     'UPDATE guilds SET icon = ? WHERE guild_id = ?',
#                     (icon, guild_id)
#                 )
#                 updated += 1
#                 debug_print(f"Updated icon for guild {guild_id}")
#             else:
#                 debug_print(f"Guild {guild_id} not found in bot cache")
#         time.sleep(1)  # Rate limit handling
#         debug_print(f"Updated icons for {updated}/{len(guilds)} guilds")
#         return f"Updated icons for {updated}/{len(guilds)} guilds"

#      except Exception as e:
#         logger.error(f"Error updating guild icons: {str(e)}")
#         return f"Error: {str(e)}", 500


# Before Requests
@app.before_request
def refresh_session():
    """
    Ensure every request has a persistent session and, when no user or admin is present, create a stable anonymous session id.
    
    Sets session.permanent = True so the session uses the app's permanent-session lifetime. If neither 'user' nor 'admin' is in the session and no '_anon_session' key exists, a UUID string is stored at session['_anon_session'] and session.modified is set to True to force the cookie to be saved.
    """
    debug_print("Entering refresh_session", level="all")
    # Ensure all requests get a session cookie
    session.permanent = True
    if 'user' not in session and 'admin' not in session:
        if not session.get('_anon_session'):
            session['_anon_session'] = str(uuid.uuid4())
            session.modified = True
def log_real_ip():
    """
    Record the client's apparent IP address (preferring Cloudflare's header) and emit a debug entry.
    
    Reads the "CF-Connecting-IP" request header and falls back to Flask's request.remote_addr if the header is absent, then logs the resolved IP and request path via the debug_print helper.
    """
    debug_print("Entering log_real_ip", level="all")
    real_ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    debug_print(f"Real IP: {real_ip} -> Path: {request.path}")

# Routes
@app.route('/')
def index():
    """
    Render the application's homepage.
    
    Returns:
        A Flask response rendering the 'index.html' template.
    """
    debug_print("Entering index route", level="all")
    return render_template('index.html')

@app.route("/privacy-policy")
def privacy_policy():
    """
    Render and return the site's privacy policy page.
    
    Returns:
        A Flask response object containing the rendered "privacy.html" template.
    """
    debug_print("Entering privacy_policy route", level="all")
    return render_template("privacy.html")

@app.route("/terms-of-service")
def terms_of_service():
    """
    Render and return the site's Terms of Service page.
    
    Returns:
        Response: A Flask HTML response rendering the "terms.html" template.
    """
    debug_print("Entering terms_of_service route", level="all")
    return render_template("terms.html")
    
@app.route("/end-user-license-agreement")
def end_user_license_agreement():
    """
    Render the End User License Agreement page.
    
    Returns:
        A Flask response with the rendered "eula.html" template.
    """
    debug_print("Entering end_user_license_agreement route", level="all")
    return render_template("eula.html")

@app.route('/login')
def login():
    """
    Start a Discord OAuth2 login flow for the current user.
    
    Clears the current Flask session, ensures the session cookie is permanent and saved, then initiates a Discord OAuth2 authorization request with the scopes `identify` and `guilds` and `prompt="none"`. Returns the response produced by the OAuth client (typically a redirect to Discord's authorization page).
    """
    debug_print("Entering login route", level="all")
    session.clear()
    session.permanent = True
    session.modified = True  # Force session save
    return discord.create_session(
        scope=["identify", "guilds"],
        prompt="none"
    )
    
@app.route('/admin/login', methods=['GET', 'POST'])
def login_admin():
    """
    Render and handle the admin login page.
    
    For GET requests this returns the admin login template. For POST requests it validates the CSRF token and authenticates either a head admin (credentials compared to HEAD_BOT_ADMIN_* environment variables) or a stored bot admin (password verified with bcrypt via db.get_bot_admin). On successful authentication sets session keys:
    - 'admin' = True
    - 'admin_username' = the provided username
    - 'head_admin' = True (only for head admin)
    
    On success redirects to the admin dashboard. On failure flashes an error and redirects back to the login page. CSRF token failures flash a security message and redirect. Returns a Flask response (redirect or rendered template).
    """
    debug_print("Entering login_admin route", level="all")
    error = None
    if request.method == 'POST':
        try:
            csrf.protect()
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Head Admin login
            if (username == os.getenv('HEAD_BOT_ADMIN_USERNAME') and 
                request.form['password'] == os.getenv('HEAD_BOT_ADMIN_PASSWORD')):
                session['head_admin'] = True
                session['admin'] = True
                session['admin_username'] = username  # Store username
                return redirect(url_for('admin_dashboard'))
                
            # Bot Admin login
            admin = db.get_bot_admin(username)
            if admin and bcrypt.checkpw(request.form['password'].encode(), admin['password_hash']):
                session['admin'] = True
                session['admin_username'] = username  # Store username
                return redirect(url_for('admin_dashboard'))
                
            error = "Invalid credentials"
            
            flash('Invalid credentials')
            return redirect(url_for('login_admin'))
        
        except CSRFError:
            flash('Security token expired')
            return redirect(url_for('login_admin'))
    
    return render_template('login_admin.html', error=error)

@app.route('/logout')
def logout():
    """
    Log the current user out by clearing the session.
    
    Clears all session data, adds a success flash message, and redirects the client to the login page.
    
    Returns:
        A Flask redirect response to the login route.
    """
    debug_print("Entering logout route", level="all")
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('login'))
    
@app.route('/admin/logout')
@login_required
def logout_admin():
    """
    Log out the current admin session while preserving the user's Discord session.
    
    Removes admin-related session keys ('admin', 'head_admin', 'admin_username', '_fresh') so the user loses admin privileges but remains logged in to Discord. Flashes a success message when an admin session was terminated, or a warning if no admin session existed. Redirects to the guild selection page.
    
    Returns:
        A Flask redirect response to the guild selection route.
    
    Errors:
        On unexpected errors, logs the error and aborts with HTTP 500.
    """
    debug_print("Entering logout_admin route", level="all")
    """Log out from admin access while preserving Discord session"""
    try:
        if session.get('admin'):
            # Only remove admin privileges
            session.pop('head_admin', None)
            session.pop('admin', None)
            session.pop('admin_username', None)
            session.pop('_fresh', None)  # Remove freshness marker
            session.modified = True
            flash('Admin session terminated. Regular login preserved.', 'success')
        else:
            flash('No admin session found', 'warning')
            
        return redirect(url_for('select_guild'))
        
    except Exception as e:
        logger.error(f"Admin logout error: {str(e)}")
        abort(500)

@app.route('/callback')
def callback():
    """
    Handle the Discord OAuth2 callback, finalize login, and store the authenticated user's session.
    
    This endpoint is called after Discord redirects back from the OAuth flow. It validates the callback via the discord client, fetches the user's Discord profile, saves a minimal user object and the access token into the Flask session, marks the session permanent, and redirects to the guild selection page on success.
    
    On failure (missing token or any authorization/error during callback) the session is cleared, a flash error is set, and the client is redirected to the login page.
    
    Returns:
        A Flask redirect response to either the guild selection page on success or the login page on failure.
    """
    debug_print("Entering callback route", level="all")
    try:
        # Let flask_discord handle state validation
        state = session.get('DISCORD_OAUTH2_STATE')
        discord.callback()
        user = discord.fetch_user()
        
        # Store user session
        session["user"] = {
            "id": str(user.id),
            "name": user.name,
            "avatar": user.avatar_url or ""
        }
        # Get the access token from the session
        token_data = session.get('DISCORD_OAUTH2_TOKEN')
        if token_data and "access_token" in token_data:
            session["discord_token"] = token_data["access_token"]
        else:
            logger.error("No access token found in session after Discord OAuth callback.")
            flash("Login failed. Please try again.", "danger")
            return redirect(url_for("login"))
        session.permanent = True
        
        return redirect(url_for("select_guild"))
        
    except Unauthorized as e:
        logger.error(f"Authorization failed: {str(e)}")
        session.clear()
        flash("Login failed. Please try again.", "danger")
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        session.clear()
        flash("Login failed. Please try again.", "danger")
        return redirect(url_for('login'))

@app.route('/delete-data', methods=['GET', 'POST'])
@login_required
def delete_my_data():
    """
    Delete the current user's stored data for selected guilds (or all mutual guilds).
    
    Handles GET and POST for the "delete my data" page: on GET it renders a confirmation page listing mutual guilds; on POST it deletes the user's records from guild-scoped tables for each selected guild and removes the global users row. Requires an authenticated Discord session (user id present in session). Success and error outcomes are reported via flash messages and the route redirects back to itself after a successful deletion.
    
    Returns:
        A Flask response: rendered template for GET, or a redirect after processing POST.
    """
    debug_print("Entering delete_my_data route", level="all")
    user_id = session['user']['id']
    guilds = get_mutual_guilds(user_id)

    if request.method == 'POST':
        selected_guilds = request.form.getlist('guild_ids')
        if 'all' in selected_guilds:
            selected_guilds = [g['id'] for g in guilds]
        for guild_id in selected_guilds:
            try:
                # Remove from all relevant tables
                tables = [
                    ('users', True),
                    ('user_levels', True),
                    ('pending_role_changes', True),
                    ('user_game_time', True)
                ]
                for table, has_guild in tables:
                    if has_guild:
                        db.execute_query(f'DELETE FROM {table} WHERE guild_id = ? AND user_id = ?', (guild_id, user_id))
                    else:
                        db.execute_query(f'DELETE FROM {table} WHERE user_id = ?', (user_id,))
            except Exception as e:
                logger.error(f"Error deleting user data for {user_id} in guild {guild_id}: {str(e)}")
                flash(f"Failed to delete data for server {guild_id}.", "danger")
        # Remove from users table (global)
        db.execute_query('DELETE FROM users WHERE user_id = ?', (user_id,))
        flash('Your data has been deleted from the selected server(s).', 'success')
        return redirect(url_for('delete_my_data'))

    return render_template('delete_my_data.html', guilds=guilds)

@app.route('/guilds')
@login_required
def select_guild():
    """
    Render the guild selection page showing mutual guilds for the current user or all guilds for an admin.
    
    If the session has 'admin' set, the function loads all guild records from the database; otherwise it uses get_user_guilds() to build a list of the user's mutual guilds. Each non-admin guild entry includes:
    - id (str)
    - name
    - icon (URL or empty string)
    - permissions (integer bitfield)
    - joined_at (may be None)
    
    Returns:
        A Flask response rendering the 'guilds.html' template with the context variable `guilds`.
    """
    debug_print("Entering select_guild route", level="all")
    user_guilds = get_user_guilds()
    common_guilds = [{
        'id': str(g.id),
        'name': g.name,
        'icon': g.icon_url or '',
        'permissions': g.permissions.value,
        'joined_at': getattr(g, 'joined_at', None)
    } for g in user_guilds]
    if session.get('admin'):
        common_guilds = db.execute_query(
            'SELECT guild_id as id, name, icon, joined_at FROM guilds',
            fetch='all'
        )
    return render_template('guilds.html', guilds=common_guilds)
    
@app.route('/admin/guilds')
@login_required
@admin_required
def admin_guilds():
    """
    Render the admin guilds overview page.
    
    Raises:
        werkzeug.exceptions.Forbidden: if the current session is not an admin (HTTP 403).
    
    Returns:
        Response: Rendered 'admin_guilds.html' template with `guilds`, where each guild dict includes:
            - id: guild_id
            - name
            - owner_id
            - icon
            - joined_at
            - member_count: number of users in the guild
    """
    debug_print("Entering admin_guilds route", level="all")
    if not session.get('admin'):
        abort(403)
    
    guilds = db.execute_query('''
        SELECT 
            guild_id as id, 
            name, 
            owner_id, 
            icon, 
            joined_at,
            (SELECT COUNT(*) FROM users WHERE guild_id = guilds.guild_id) as member_count
        FROM guilds
    ''', fetch='all')
    
    return render_template('admin_guilds.html', guilds=guilds)

@app.route('/admin/guilds/<guild_id>/invite', methods=['POST'])
@admin_required
def get_guild_invite(guild_id):
    """
    Get or create an invite link for a guild via the bot's API and redirect back to the admin guilds page.
    
    Attempts to create or fetch an invite by POSTing the guild ID to the bot web API. On success flashes a clickable invite link to the user; on failure flashes an error message. The request is CSRF-protected and errors are logged.
    
    Parameters:
        guild_id (int | str): ID of the guild to get or create an invite for.
    
    Returns:
        werkzeug.wrappers.Response: A redirect response to the admin guilds listing (url_for('admin_guilds')).
    """
    debug_print(f"Entering get_guild_invite route with guild_id: {guild_id}", level="all")
    """Get or create an invite link for a guild via the bot's webserver API."""
    try:
        csrf.protect()
        api_url = f"{API_URL}/api/get_guild_invite"
        resp = jwt_requests.post(api_url, json={"guild_id": str(guild_id)}, timeout=10)
        data = resp.json()
        if resp.status_code == 200 and "invite" in data:
            flash(Markup(f'Invite link: <a href="{data["invite"]}" target="_blank">{data["invite"]}</a>'), "success")
        else:
            flash(data.get("error", "Failed to get invite."), "danger")
    except CSRFError:
        flash('Security token expired', 'danger')
    except Exception as e:
        logger.error(f"Error getting invite for guild {guild_id}: {e}")
        flash('Failed to get or create invite.', 'danger')
    return redirect(url_for('admin_guilds'))

@app.route('/admin/guilds/<guild_id>/audit-log', methods=['POST'])
@admin_required
def get_guild_audit_log(guild_id):
    """
    Render the guild's audit log by fetching it from the bot's API.
    
    On success returns a rendered 'audit_log.html' template populated with the audit log.
    On failure flashes an error message and redirects to the admin guilds page.
    Performs CSRF protection and may raise a CSRFError (handled internally) or other HTTP/JSON-related errors while contacting the bot API.
    Returns:
        A Flask response: rendered template on success or a redirect on failure.
    """
    debug_print(f"Entering get_guild_audit_log route with guild_id: {guild_id}", level="all")
    """Fetch and display the audit log for a guild via the bot's webserver API."""
    try:
        csrf.protect()
        api_url = f"{API_URL}/api/get_guild_audit_log"
        resp = jwt_requests.post(api_url, json={"guild_id": str(guild_id)}, timeout=10)
        data = resp.json()
        if resp.status_code == 200 and "log" in data:
            audit_log = data["log"]
            return render_template('audit_log.html', guild_id=guild_id, audit_log=audit_log)
        else:
            flash(data.get("error", "Failed to fetch audit log."), "danger")
    except CSRFError:
        flash('Security token expired', 'danger')
    except Exception as e:
        logger.error(f"Error getting audit log for guild {guild_id}: {e}")
        flash('Failed to fetch audit log.', 'danger')
    return redirect(url_for('admin_guilds'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """
    Render the admin dashboard page with summary counts and recent audit logs.
    
    Gathers total guilds, bot admin count, and form submission count from the database, fetches the 10 most recent audit log entries, and returns the rendered 'admin_dashboard.html' template populated with:
    - guild_count: total number of guilds
    - admin_count: total number of bot admins
    - submission_count: total number of form submissions
    - recent_logs: list of the most recent audit log rows
    
    Returns:
        A Flask response (rendered template) for the admin dashboard.
    """
    debug_print("Entering admin_dashboard route", level="all")
    # Get guild count
    guild_count_result = db.execute_query('SELECT COUNT(*) as count FROM guilds', fetch='one')
    guild_count = guild_count_result['count'] if guild_count_result else 0
    
    # Get admin count
    admin_count_result = db.execute_query('SELECT COUNT(*) as count FROM bot_admins', fetch='one')
    admin_count = admin_count_result['count'] if admin_count_result else 0
    
    # Get custom for submission count
    submission_count_result = db.execute_query(
        'SELECT COUNT(*) as count FROM form_submissions',
        fetch='one'
    )
    submission_count = submission_count_result['count'] if submission_count_result else 0
    
    # Get recent logs
    recent_logs = db.execute_query('''
        SELECT action, details, changes, user_id, timestamp 
        FROM audit_log 
        ORDER BY timestamp DESC 
        LIMIT 10
    ''', fetch='all')
    
    return render_template('admin_dashboard.html',
                         guild_count=guild_count,
                         admin_count=admin_count,
                         submission_count=submission_count,
                         recent_logs=recent_logs)

@app.route('/admin/bot-admins', methods=['GET', 'POST'])
@head_admin_required
def manage_bot_admins():
    """
    Manage bot admin users.
    
    GET: Render the bot admin management page with the current list of bot admins and their privileges.
    POST: Create a new bot admin after verifying CSRF, validating required form fields, and ensuring the username is unique.
    On successful POST the password is hashed and the new admin is persisted; an audit log entry is created and the user is redirected back to the management page with a success flash. If validation or CSRF checks fail, the request is redirected with an appropriate flash message.
    
    Side effects:
    - Inserts a new row into the bot_admins table and (implicitly) admin_privileges as applicable.
    - Writes an audit log entry via log_action().
    - Emits flash messages and issues redirects.
    """
    debug_print("Entering manage_bot_admins route", level="all")
    if request.method == 'POST':
        try:
            csrf.protect()  # Verify CSRF token
        except CSRFError:
            flash('Security token expired. Please try again.', 'danger')
            return redirect(url_for('manage_bot_admins'))
            
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Both fields are required', 'danger')
            return redirect(url_for('manage_bot_admins'))
            
        if db.get_bot_admin(username):
            flash('Username already exists', 'danger')
            return redirect(url_for('manage_bot_admins'))
            
        hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        db.create_bot_admin(username, hashed_pw)
        
        log_action(
            action="BOT_ADMIN_ADDED",
            details=f"Added new bot admin: {username}",
            changes=f"New admin created with username: {username}"
        )
        
        flash('Bot admin created successfully', 'success')
        return redirect(url_for('manage_bot_admins'))
    
    admins = db.execute_query(
        '''SELECT ba.username, ba.created_at, 
           COALESCE(ap.can_manage_servers, 1) AS can_manage_servers,
           COALESCE(ap.can_edit_config, 1) AS can_edit_config,
           COALESCE(ap.can_remove_bot, 0) AS can_remove_bot
        FROM bot_admins ba
        LEFT JOIN admin_privileges ap ON ba.username = ap.username''',
        fetch='all'
    )
    
    return render_template('manage_bot_admins.html', admins=admins)

@app.route('/admin/delete-bot-admin/<username>')
@head_admin_required
def delete_bot_admin(username):
    """
    Delete a bot admin by username and redirect back to the bot-admins management page.
    
    Performs the deletion from persistent storage, records an audit log entry, flashes a success message to the user, and returns a redirect response to the bot-admins list.
    
    Parameters:
        username (str): The bot admin's username to remove.
    
    Returns:
        werkzeug.wrappers.Response: A redirect response to the manage_bot_admins page.
    """
    debug_print(f"Entering delete_bot_admin route with username: {username}", level="all")
    db.delete_bot_admin(username)
    
    log_action(
        action="BOT_ADMIN_DELETED",
        details=f"Deleted bot admin: {username}",
        changes=f"Bot Admin deleted with username: {username}"
    )
    
    flash('Bot admin deleted successfully', 'success')
    return redirect(url_for('manage_bot_admins'))

@app.route('/update-privileges/<username>', methods=['POST'])
@head_admin_required
def update_privileges(username):
    """
    Update a bot admin's privilege flags from submitted form data and redirect to the bot-admins page.
    
    Reads `manage_servers`, `edit_config`, and `remove_bot` from the current request form, updates the stored privileges for `username`, records a human-readable audit entry via log_action, and flashes a success or security error message before redirecting.
    
    Parameters:
        username (str): The bot admin's username whose privileges will be updated.
    
    Returns:
        A Flask redirect response to the `manage_bot_admins` view.
    """
    debug_print(f"Entering update_privileges route with username: {username}", level="all")
    try:
        csrf.protect()
        privileges = {
            'manage_servers': 'manage_servers' in request.form,
            'edit_config': 'edit_config' in request.form,
            'remove_bot': 'remove_bot' in request.form
        }
        
        old_priv = db.get_admin_privileges(username) or {}
        db.update_admin_privileges(username, privileges)
        
        # Create human-readable changes
        changes = []
        for key in ['manage_servers', 'edit_config', 'remove_bot']:
            status = "ENABLED" if privileges[key] else "DISABLED"
            changes.append(f"{key.replace('_', ' ').title()}: {status}")
        
        log_action(
            action="PRIVILEGES_UPDATED",
            details=f"Updated privileges for {username}",
            changes=" | ".join(changes) if changes else "No changes detected"
        )
        
        flash('Privileges updated successfully', 'success')
    except CSRFError:
        flash('Security token expired', 'danger')
    return redirect(url_for('manage_bot_admins'))

def log_action(action: str, details: str, changes: str = ""):
    """
    Log an administrative action to the application's audit_log table.
    
    Determines the acting identity from the current session (prefers head admin, then bot admin, otherwise "system")
    and inserts a record into the `audit_log` database table with the provided action, details, and optional changes.
    
    Parameters:
        action (str): Short identifier of the action performed (e.g., "create_command", "delete_backup").
        details (str): Human-readable details describing the action context (e.g., which guild or object).
        changes (str, optional): Optional machine- or human-readable summary of changes made; defaults to empty string.
    """
    debug_print(f"Entering log_action with action: {action}, details: {details}, changes: {changes}", level="all")
    # Get current admin identity
    admin_identity = "system"
    if session.get('head_admin'):
        admin_identity = f"HEAD-ADMIN:{os.getenv('HEAD_BOT_ADMIN_USERNAME')}"
    elif session.get('admin'):
        admin_identity = f"BOT-ADMIN:{session.get('admin_username', 'unknown')}"
    
    db.execute_query(
        '''INSERT INTO audit_log 
        (action, details, changes, user_id)
        VALUES (?, ?, ?, ?)''',
        (action, details, changes, admin_identity)
    )

@app.route('/api/admin/<guild_id>/remove-all-data-and-bot', methods=['POST'])
@admin_required
def remove_guild(guild_id):
    """
    Remove all stored data for a guild and instruct the bot to leave that server.
    
    Deletes rows referencing the guild from a fixed set of tables (commands, configs, role menus, forms, warnings, announcements, backups of related features, etc.), calls the bot API to leave the guild, and redirects back to the admin guilds page. CSRF protection is enforced and user-facing flash messages indicate success, partial success (data deleted but bot leave failed), or failure.
    
    Parameters:
        guild_id (int | str): Guild identifier (Discord snowflake or numeric ID) whose data should be removed.
    
    Returns:
        A Flask redirect response to the admin guilds listing page.
    """
    debug_print(f"Entering remove_guild route with guild_id: {guild_id}", level="all")
    try:
        csrf.protect()

        # Delete all data as before
        tables = [
            'guilds',
            'log_config',
            'blocked_words',
            'blocked_word_embeds',
            'commands',
            'level_config',
            'level_rewards',
            'user_levels',
            'warnings',
            'warning_actions',
            'welcome_config',
            'goodbye_config',
            'spam_detection_config',
            'autoroles',
            'game_roles',
            'user_game_time',
            'twitch_announcements',
            'youtube_announcements',
            'role_menus',
            'custom_forms',
            'form_submissions',
            'pending_role_changes'
        ]
        for table in tables:
            db.execute_query(f'DELETE FROM {table} WHERE guild_id = ?', (guild_id,))

        api_url = f"{API_URL}/api/leave_guild"
        resp = jwt_requests.post(api_url, json={"guild_id": str(guild_id)}, timeout=10)
        data = resp.json()
        if resp.status_code == 200 and data.get("success"):
            flash(f'Successfully removed guild {guild_id} and left the server.', 'success')
        else:
            flash(f"Data deleted, but failed to leave server: {data.get('error', 'Unknown error')}", 'warning')

        return redirect(url_for('admin_guilds'))

    except CSRFError:
        flash('Security token expired', 'danger')
        return redirect(url_for('admin_guilds'))
    except Exception as e:
        logger.error(f"Error removing guild: {str(e)}")
        flash('Failed to remove guild', 'danger')
        return redirect(url_for('admin_guilds'))

@app.route('/dashboard/<guild_id>')
@login_required
@guild_required
def guild_dashboard(guild_id):
    """
    Render the main dashboard page for a specific guild.
    
    Looks up the guild by ID (will abort with 404 if the guild is not accessible) and returns the rendered 'dashboard.html' template populated with the guild object.
    
    Parameters:
        guild_id (str|int): Discord guild ID (snowflake) identifying which guild's dashboard to display.
    
    Returns:
        Response: Flask response rendering the 'dashboard.html' template.
    """
    debug_print(f"Entering guild_dashboard route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    return render_template('dashboard.html', guild=guild)

@app.route('/api/<guild_id>/remove-all-data', methods=['POST'])
@login_required
@guild_required
def remove_all_guild_data(guild_id):
    """
    Remove all stored data for a guild and return a JSON response indicating success or failure.
    
    This performs destructive deletion of rows associated with the provided guild_id across multiple application tables
    (e.g., commands, configs, forms, announcements, roles, warnings, leveling data, backups-related tables, etc.).
    On success it flashes a success message and returns a JSON response {"success": True}.
    
    Parameters:
        guild_id (int | str): ID of the guild whose data will be removed.
    
    Returns:
        Flask Response: A JSON response with {"success": True} on success. On failure returns JSON {"success": False, "error": "<message>"}
        and an appropriate HTTP status code (403 for invalid CSRF token, 500 for other errors).
    
    Side effects:
        - Permanently deletes rows for the guild from multiple database tables.
        - Emits a flash message on successful deletion.
    """
    debug_print(f"Entering remove_all_guild_data route with guild_id: {guild_id}", level="all")
    try:
        csrf.protect()

        tables = [
            'guilds',
            'log_config',
            'blocked_words',
            'blocked_word_embeds',
            'commands',
            'level_config',
            'level_rewards',
            'user_levels',
            'warnings',
            'warning_actions',
            'welcome_config',
            'goodbye_config',
            'spam_detection_config',
            'autoroles',
            'game_roles',
            'user_game_time',
            'twitch_announcements',
            'youtube_announcements',
            'role_menus',
            'custom_forms',
            'form_submissions',
            'pending_role_changes'
        ]
        for table in tables:
            db.execute_query(f'DELETE FROM {table} WHERE guild_id = ?', (guild_id,))

        flash('All server data deleted successfully.', 'success')
        return jsonify({'success': True})
    except CSRFError:
        return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
    except Exception as e:
        logger.error(f"Error deleting all data for guild {guild_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/<guild_id>/remove-all-user-data', methods=['POST'])
@login_required
@guild_required
def remove_all_user_data(guild_id):
    """
    Delete all stored data for a single user within a guild and redirect back to the guild dashboard.
    
    This handler reads `user_id` from the POST form (key: `'user_id'`), enforces CSRF protection, and removes rows matching that user from several guild-scoped tables (user_levels, warnings, warning_actions, form_submissions, pending_role_changes, user_game_time, user_connections) and from the global `users` table. On success it flashes a success message and redirects to the guild dashboard; on CSRF failure or other errors it flashes an error message and redirects to the guild dashboard.
    
    Notes:
    - Expects to be called as a POST route with form data.
    - Requires a valid CSRF token.
    - Returns a Flask redirect response to the guild dashboard.
    """
    debug_print(f"Entering remove_all_user_data route with guild_id: {guild_id}", level="all")
    try:
        csrf.protect()
        user_id = request.form.get('user_id', '').strip()
        if not user_id:
            flash('User ID is required.', 'danger')
            return redirect(url_for('guild_dashboard', guild_id=guild_id))

        # List of tables with user_id and guild_id
        tables = [
            ('user_levels', True),
            ('warnings', True),
            ('warning_actions', True),
            ('form_submissions', True),
            ('pending_role_changes', True),
            ('user_game_time', True),
            ('user_connections', True)
        ]
        # Remove from each table where both guild_id and user_id match
        for table, has_guild in tables:
            if has_guild:
                db.execute_query(f'DELETE FROM {table} WHERE guild_id = ? AND user_id = ?', (guild_id, user_id))
            else:
                db.execute_query(f'DELETE FROM {table} WHERE user_id = ?', (user_id,))
        # Remove from users table (global)
        db.execute_query('DELETE FROM users WHERE user_id = ?', (user_id,))
        flash(f'All data for user {user_id} in this server has been deleted.', 'success')
        return redirect(url_for('guild_dashboard', guild_id=guild_id))
    except CSRFError:
        flash('Security token expired', 'danger')
        return redirect(url_for('guild_dashboard', guild_id=guild_id))
    except Exception as e:
        logger.error(f"Error deleting all user data for {user_id} in guild {guild_id}: {str(e)}")
        flash('Failed to delete user data.', 'danger')
        return redirect(url_for('guild_dashboard', guild_id=guild_id))

# Commands Management
@app.route('/dashboard/<guild_id>/commands', methods=['GET', 'POST'])
@login_required
@guild_required
def guild_commands(guild_id):
    """
    Render and manage custom commands for a guild.
    
    Handles GET to render the commands management page for the specified guild (including the list of commands and the last sync time) and POST to create a new custom command for that guild.
    
    Parameters:
        guild_id (str|int): Discord guild (server) identifier for which commands are displayed or created.
    
    Returns:
        Flask response: On GET, renders the 'commands.html' template with guild data, commands list, and last_synced timestamp. On successful POST, returns JSON {"success": True}. On validation failure returns a 400 JSON error; on unexpected errors renders the error template with a 500 status.
    """
    debug_print(f"Entering guild_commands route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    if request.method == 'POST':
        data = request.get_json(force=True)
        command_name = data.get('command_name', '').strip()
        description = data.get('description', '').strip()
        content = data.get('content', '').strip()
        ephemeral = bool(data.get('ephemeral', False))
        if not command_name or not content:
            return jsonify({'error': 'Command name and content required'}), 400
        db.add_command(guild_id, command_name, content, description, ephemeral)
        return jsonify({'success': True})
    try:
        commands = db.get_guild_commands_list(guild_id)
        for cmd in commands:
            if 'modified_at' not in cmd:
                cmd['modified_at'] = None
        sync_info = db.execute_query('SELECT last_synced FROM guilds WHERE guild_id = ?', (guild_id,), fetch='one')
        last_synced = sync_info['last_synced'] if sync_info and 'last_synced' in sync_info else datetime.utcnow().timestamp()
        # Convert float timestamp to datetime object
        if isinstance(last_synced, float) or isinstance(last_synced, int):
            last_synced_dt = datetime.fromtimestamp(last_synced)
        else:
            last_synced_dt = last_synced  # Already a datetime
        return render_template('commands.html',
            guild_id=guild_id,
            guild=guild,
            commands=commands,
            last_synced=last_synced_dt
        )
    except Exception as e:
        logger.error(f"Commands fetch error: {e}")
        return render_template('error.html', error=str(e)), 500

# Command Management API Endpoints
@app.route('/api/<guild_id>/commands/<command_name>/delete', methods=['POST'])
@login_required
@guild_required
def delete_command_api(guild_id, command_name):
    """
    Delete a custom command for a guild and return a JSON result.
    
    Parameters:
        guild_id: ID of the guild whose command should be removed.
        command_name: Name of the command to delete (case-sensitive).
    
    Returns:
        A Flask JSON response: on success {'success': True}; on failure {'error': <message>} with HTTP 500.
    """
    debug_print(f"Entering delete_command_api route with guild_id: {guild_id}, command_name: {command_name}", level="all")
    try:
        db.remove_command(guild_id, command_name)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Delete command error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/<guild_id>/commands/sync', methods=['POST'])
@login_required
@guild_required
def sync_commands(guild_id):
    """
    Trigger a remote command sync and update the guild's last_synced timestamp on success.
    
    Sends a POST to the configured internal sync API and, if the API responds with HTTP 200, updates the guild's
    last_synced column to the current UTC timestamp. On non-200 responses or exceptions the function returns a JSON
    error payload and an HTTP 500 status.
    
    Parameters:
        guild_id (int | str): ID of the guild whose last_synced timestamp should be updated on a successful sync.
    
    Returns:
        flask.Response: JSON response with {'success': True} on success, or {'error': <message>} and HTTP 500 on failure.
    """
    debug_print(f"Entering sync_commands route with guild_id: {guild_id}", level="all")
    try:
        api_url = f"{API_URL}/api/sync"
        resp = jwt_requests.post(api_url, timeout=60)
        if resp.status_code != 200:
            logger.error(f"Sync API error: {resp.status_code} {resp.text}")
            error_msg = resp.text
            try:
                data = resp.json()
                error_msg = str(data.get("error", resp.text))
            except Exception:
                pass
            return jsonify({'error': error_msg}), 500
        db.execute_query('UPDATE guilds SET last_synced = ? WHERE guild_id = ?', (datetime.utcnow().timestamp(), guild_id))
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Sync commands error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/<guild_id>/commands/export', methods=['GET'])
@login_required
@guild_required
def export_commands(guild_id):
    """
    Export all custom commands for a guild as a downloadable JSON file.
    
    Retrieves the guild's command list from the database, removes internal IDs, and returns a Flask Response containing the commands JSON with a Content-Disposition header to prompt file download.
    
    Parameters:
        guild_id (int | str): Discord guild (server) ID whose commands will be exported.
    
    Returns:
        flask.Response: Attachment response with JSON payload named "commands_<guild_id>.json". On failure returns a JSON error and HTTP 500.
    """
    debug_print(f"Entering export_commands route with guild_id: {guild_id}", level="all")
    try:
        commands = db.get_guild_commands_list(guild_id)
        for cmd in commands:
            cmd.pop('id', None)
        from flask import Response
        import json
        return Response(json.dumps(commands, indent=2), mimetype='application/json', headers={
            'Content-Disposition': f'attachment;filename=commands_{guild_id}.json'
        })
    except Exception as e:
        logger.error(f"Export commands error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/<guild_id>/commands/import', methods=['POST'])
@login_required
@guild_required
def import_commands(guild_id):
    """
    Import a list of custom commands for a guild from the request JSON and persist them to the database.
    
    Expects the request body to be a JSON array of command objects. Each command may include the keys:
    `command_name`, `content`, `description`, and `ephemeral`. Missing fields use sensible defaults
    (`''` for strings, `'Custom command'` for description, `False` for ephemeral).
    
    Parameters:
        guild_id (int | str): Discord guild identifier for which the commands will be created.
    
    Returns:
        A Flask JSON response:
          - 200 with `{'success': True}` on successful import.
          - 400 with `{'error': 'Invalid format'}` if the request body is not a JSON list.
          - 500 with `{'error': <message>}` on unexpected errors.
    
    Side effects:
        Inserts one or more commands into persistent storage via `db.add_command`.
    """
    debug_print(f"Entering import_commands route with guild_id: {guild_id}", level="all")
    try:
        import json
        commands = request.get_json(force=True)
        if not isinstance(commands, list):
            return jsonify({'error': 'Invalid format'}), 400
        for cmd in commands:
            db.add_command(
                guild_id,
                cmd.get('command_name', ''),
                cmd.get('content', ''),
                cmd.get('description', 'Custom command'),
                bool(cmd.get('ephemeral', False))
            )
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Import commands error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/<guild_id>/commands/delete-all', methods=['POST'])
@login_required
@guild_required
def delete_all_commands(guild_id):
    """
    Delete all custom commands for the specified guild.
    
    Deletes every row in the `commands` table for the given guild_id and returns a JSON response indicating success.
    On failure returns a JSON error message with HTTP 500.
    
    Parameters:
        guild_id (int | str): ID of the guild whose commands should be removed.
    
    Returns:
        Flask Response: JSON `{ "success": True }` on success or `{ "error": "<message>" }` with status 500 on failure.
    """
    debug_print(f"Entering delete_all_commands route with guild_id: {guild_id}", level="all")
    try:
        db.execute_query('DELETE FROM commands WHERE guild_id = ?', (guild_id,))
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Delete all commands error: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/dashboard/<guild_id>/commands/<command_name>/edit', methods=['GET', 'POST'])
@login_required
@guild_required
def edit_command(guild_id, command_name):
    """
    Render and handle editing of a custom command for a guild.
    
    On GET, renders the edit form populated with the existing command. On POST, validates CSRF, updates (upserts) the command's content, description, and ephemeral flag in the database, then redirects to the guild's commands page with an "updated" indicator.
    
    Parameters:
        guild_id (str|int): ID of the guild containing the command.
        command_name (str): Name/identifier of the command to edit.
    
    Returns:
        A Flask response: the edit page template (GET) or a redirect (POST). 
    
    Behavior:
    - If the command does not exist, responds with 404.
    - If CSRF validation fails on POST, flashes a message and redirects back to the edit page.
    - On database update errors, flashes an error and redirects back to the edit page.
    """
    debug_print(f"Entering edit_command route with guild_id: {guild_id}, command_name: {command_name}", level="all")
    guild = get_guild_or_404(guild_id)
    command = db.get_command(guild_id, command_name)
    
    if not command:
        abort(404, description="Command not found")
    
    if request.method == 'POST':
        # Verify CSRF token first
        try:
            csrf.protect()
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('edit_command', guild_id=guild_id, command_name=command_name))
        try:
            # Update command in database using add_command (upsert)
            new_content = request.form['content']
            new_description = request.form['description']
            new_ephemeral = 'ephemeral' in request.form
            
            db.add_command(
                guild_id=guild_id,
                command_name=command_name,
                content=new_content,
                description=new_description,
                ephemeral=new_ephemeral
            )
            
            # Redirect with updated=1 query param
            return redirect(url_for('guild_commands', guild_id=guild_id, updated=1))
            
        except Exception as e:
            logger.error(f"Error updating command: {str(e)}")
            flash('Error updating command', 'danger')
            return redirect(url_for('edit_command', guild_id=guild_id, command_name=command_name))

    return render_template('edit_command.html',
        guild_id=guild_id,
        guild=guild,
        command_name=command_name,
        command=command
    )

@app.route('/dashboard/<guild_id>/command-permissions', methods=['GET', 'POST'])
@login_required
@guild_required
def command_permissions(guild_id):
    """
    Render and update command-level permission settings for a guild.
    
    Displays current allow-lists for both built-in and custom commands (roles and users) and, on POST, saves submitted permissions for each command into persistent storage and redirects back to the same page.
    
    Parameters:
        guild_id (str|int): Discord guild (server) identifier.
    
    Returns:
        Flask response: On GET, renders the 'command_permissions.html' template populated with commands, current permissions, roles, users, and guild info. On successful POST, redirects to the same route after persisting updates.
    """
    debug_print(f"Entering command_permissions route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    # Get all built-in commands
    builtins = [cmd['name'] for cmd in get_builtin_commands(guild_id)]
    custom_cmds = [cmd['command_name'] for cmd in db.get_guild_commands_list(guild_id)]
    all_commands = [{"name": c, "is_custom": False} for c in builtins] + [{"name": c, "is_custom": True} for c in custom_cmds]
    roles = get_roles(guild_id)
    users = get_guild_users(guild_id)

    if request.method == 'POST':
        for cmd in all_commands:
            prefix = f"{cmd['name']}_{'custom' if cmd['is_custom'] else 'builtin'}"
            allow_roles = request.form.getlist(f"{prefix}_allow_roles")
            allow_users = request.form.getlist(f"{prefix}_allow_users")
            db.set_command_permissions(
                guild_id, cmd['name'],
                allow_roles, allow_users, is_custom=cmd['is_custom']
            )
        flash("Permissions updated!", "success")
        return redirect(url_for('command_permissions', guild_id=guild_id))

    # Load current permissions
    permissions = {
        cmd['name']: db.get_command_permissions(guild_id, cmd['name'])
        for cmd in all_commands
    }
    return render_template(
        'command_permissions.html',
        guild_id=guild_id,
        commands=all_commands,
        permissions=permissions,
        roles=roles,
        users=users,
        guild=guild
    )

# Log Configuration
@app.route('/dashboard/<guild_id>/log-config', methods=['GET', 'POST'])
@login_required
@guild_required
def log_config(guild_id):
    """
    Render and handle updates to a guild's logging configuration.
    
    GET: Loads the current logging configuration (merged with sensible defaults), available text channels, roles, and guild users, normalizes user entries into dicts with keys 'id', 'username', and 'discriminator', and renders the 'log_config.html' template.
    
    POST: Validates the CSRF token, reads form fields to build an updated log configuration (converting list fields to JSON strings where stored), updates the database via db.update_log_config, flashes a success message, and redirects back to the same settings page. If CSRF protection fails, flashes an error and redirects to the settings page.
    
    Parameters:
        guild_id (int | str): Discord guild (server) identifier for which the logging configuration is being viewed or updated.
    
    Returns:
        A Flask response: either a rendered template on GET, a redirect after a successful POST or CSRF failure, or a 500 abort on unexpected errors.
    
    Side effects:
        - May update persistent logging configuration in the database.
        - Emits flash messages for user feedback.
        - Normalizes and exposes guild user objects for template rendering.
    """
    debug_print(f"Entering log_config route with guild_id: {guild_id}", level="all")
    try:
        guild = get_guild_or_404(guild_id)
        config = db.get_log_config(guild_id) or {}
        channels = get_text_channels(guild_id)
        roles = get_roles(guild_id)
        guild_users = get_guild_users(guild_id)
        if request.method == 'POST':
            try:
                csrf.protect()
            except CSRFError:
                flash('Security token expired. Please submit the form again.', 'danger')
                return redirect(url_for('log_config', guild_id=guild_id))
            new_config = dict(config)
            for key in config:
                if key in ['guild_id', 'log_channel_id', 'excluded_users', 'excluded_roles', 'excluded_channels', 'log_bots', 'log_self']:
                    continue
                new_config[key] = bool(request.form.get(key))
            new_config['log_channel_id'] = request.form.get('log_channel_id') or None
            new_config['excluded_users'] = request.form.getlist('excluded_users')
            new_config['excluded_roles'] = request.form.getlist('excluded_roles')
            new_config['excluded_channels'] = request.form.getlist('excluded_channels')
            new_config['log_bots'] = bool(request.form.get('log_bots'))
            new_config['log_self'] = bool(request.form.get('log_self'))
            # Remove guild_id from new_config if present to avoid duplicate argument
            if 'guild_id' in new_config:
                new_config.pop('guild_id')
            # Convert lists to JSON strings for SQLite
            for k, v in new_config.items():
                if isinstance(v, list):
                    new_config[k] = json.dumps(v)
            db.update_log_config(guild_id, **new_config)
            flash('Logging configuration updated!', 'success')
            return redirect(url_for('log_config', guild_id=guild_id))
        merged_config = dict(
            log_channel_id=None,
            log_config_update=True,
            message_delete=True,
            bulk_message_delete=True,
            message_edit=True,
            invite_create=True,
            invite_delete=True,
            member_role_add=True,
            member_role_remove=True,
            member_timeout=True,
            member_warn=True,
            member_unwarn=True,
            member_ban=True,
            member_unban=True,
            role_create=True,
            role_delete=True,
            role_update=True,
            channel_create=True,
            channel_delete=True,
            channel_update=True,
            emoji_create=True,
            emoji_name_change=True,
            emoji_delete=True,
            excluded_users=[],
            excluded_roles=[],
            excluded_channels=[],
            log_bots=True,
            log_self=False
        )
        merged_config.update(config)
        # Normalize user dicts for template (id, username, discriminator)
        normalized_users = []
        for u in guild_users:
            if 'username' in u and 'discriminator' in u:
                normalized_users.append(u)
            elif 'name' in u:
                name = u['name']
                if '#' in name:
                    username, discriminator = name.rsplit('#', 1)
                else:
                    username, discriminator = name, '0000'
                normalized_users.append({
                    'id': u['id'],
                    'username': username,
                    'discriminator': discriminator
                })
        return render_template(
            'log_config.html',
            config=merged_config,
            guild_id=guild_id,
            guild=guild,
            channels=channels,
            roles=roles,
            guild_users=normalized_users
        )
    except Exception as e:
        logger.error(f"Error in log config: {str(e)}")
        abort(500)

# Welcome Message Config
@app.route('/dashboard/<guild_id>/welcome-config', methods=['GET', 'POST'])
@login_required
@guild_required
def welcome_config(guild_id):
    """
    Render and update the welcome message configuration for a guild.
    
    Handles GET to display the current welcome configuration (falls back to sensible defaults)
    and POST to validate and save updated settings. On POST the request is CSRF-checked,
    the configuration is written to the database (INSERT OR REPLACE), and the user is redirected
    back to the same configuration page with a flash message; on failure a danger flash is shown
    and the form re-renders.
    
    Parameters:
        guild_id (str|int): ID of the guild whose welcome settings are being viewed or modified.
    
    Returns:
        A Flask response: on GET it renders the "welcome_config.html" template with the current
        configuration, guild data, and available text channels; on successful POST it redirects
        to the same route (with a success flash); on POST failure it re-renders the template
        with an error flash.
    """
    debug_print(f"Entering welcome_config route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    config = db.execute_query('SELECT * FROM welcome_config WHERE guild_id = ?', (guild_id,), fetch='one') or {
        'message_type': 'text',
        'enabled': False,
        'embed_color': 0x0013ff  # Default to blue
    }
    
    # Get channels from Discord API
    text_channels = get_text_channels(guild_id)

    if request.method == 'POST':
        try:
            csrf.protect()
            new_config = {
                'enabled': 'enabled' in request.form,
                'channel_id': request.form.get('channel_id'),
                'message_type': request.form.get('message_type', 'text'),
                'message_content': request.form.get('message_content', ''),
                'embed_title': request.form.get('embed_title', ''),
                'embed_description': request.form.get('embed_description', ''),
                'embed_color': int(request.form.get('embed_color', '#00FF00').lstrip('#'), 16),
                'embed_thumbnail': 'embed_thumbnail' in request.form,
                'show_server_icon': 'show_server_icon' in request.form
            }

            # Update database
            db.execute_query('''
                INSERT OR REPLACE INTO welcome_config 
                (guild_id, enabled, channel_id, message_type, message_content, 
                 embed_title, embed_description, embed_color, embed_thumbnail, show_server_icon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (guild_id, *new_config.values()))
            
            flash('Welcome configuration updated!', 'success')
            return redirect(url_for('welcome_config', guild_id=guild_id))
        
        except Exception as e:
            logger.error(f"Welcome config error: {str(e)}")
            flash('Error saving configuration', 'danger')

    return render_template('welcome_config.html',
                         config=config or {},
                         guild_id=guild_id,
                         guild=guild,
                         channels=text_channels)

# Goodbye Message Config
@app.route('/dashboard/<guild_id>/goodbye-config', methods=['GET', 'POST'])
@login_required
@guild_required
def goodbye_config(guild_id):
    """
    Render and update the goodbye message configuration for a guild.
    
    On GET: renders the goodbye configuration page populated from the database (falls back to a default config).
    On POST: validates CSRF, reads form fields (enabled, channel_id, message_type, message_content, embed_title,
    embed_description, embed_color, embed_thumbnail, show_server_icon), converts `embed_color` from a hex string
    to an integer, and upserts the configuration into the `goodbye_config` table. On success it flashes a success
    message and redirects back to the same page; on failure it logs the error and flashes an error message.
    
    Parameters:
        guild_id (str|int): ID of the guild whose goodbye configuration is being viewed or updated.
    
    Returns:
        A Flask response object: either a rendered template for the configuration page (GET or failed POST)
        or a redirect response after a successful POST.
    """
    debug_print(f"Entering goodbye_config route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    config = db.execute_query('SELECT * FROM goodbye_config WHERE guild_id = ?', (guild_id,), fetch='one') or {
        'message_type': 'text',
        'enabled': False,
        'embed_color': 0xFF0000  # Default to red
    }
    text_channels = get_text_channels(guild_id)

    if request.method == 'POST':
        try:
            csrf.protect()
            new_config = {
                'enabled': 'enabled' in request.form,
                'channel_id': request.form.get('channel_id'),
                'message_type': request.form.get('message_type', 'text'),
                'message_content': request.form.get('message_content', ''),
                'embed_title': request.form.get('embed_title', ''),
                'embed_description': request.form.get('embed_description', ''),
                'embed_color': int(request.form.get('embed_color', '#FF0000').lstrip('#'), 16),
                'embed_thumbnail': 'embed_thumbnail' in request.form,
                'show_server_icon': 'show_server_icon' in request.form
            }

            db.execute_query('''
                INSERT OR REPLACE INTO goodbye_config 
                (guild_id, enabled, channel_id, message_type, message_content, 
                 embed_title, embed_description, embed_color, embed_thumbnail, show_server_icon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (guild_id, *new_config.values()))
            
            flash('Goodbye configuration updated!', 'success')
            return redirect(url_for('goodbye_config', guild_id=guild_id))
        
        except Exception as e:
            logger.error(f"Goodbye config error: {str(e)}")
            flash('Error saving configuration', 'danger')

    return render_template('goodbye_config.html',
                         config=config or {},
                         guild_id=guild_id,
                         guild=guild,
                         channels=text_channels)

# Blocked Words Management
@app.route('/dashboard/<guild_id>/blocked-words', methods=['GET', 'POST'])
@login_required
@guild_required
def blocked_words(guild_id):
    """
    Render and manage the blocked-words configuration for a guild.
    
    Handles GET to display the current blocked words and their embed configuration, and POST to update them.
    On POST the route:
    - Verifies CSRF and flashes a user-visible error if the token is invalid.
    - Replaces the guild's blocked-words list and upserts the blocked-word embed configuration inside a single database transaction.
    - Normalizes color input (hex string → integer), falling back to red on parse errors.
    
    Parameters:
        guild_id: Guild identifier (snowflake) for which to load or update blocked-word settings.
    
    Returns:
        A rendered template on GET or after successful POST redirect; redirects back to the same page on validation/CSRF/database errors, or aborts with HTTP 500 for unexpected failures.
    
    Side effects:
        Writes to the blocked_words and blocked_word_embeds tables in the database when processing a POST.
    
    Error handling:
        Database errors flash a message and redirect back to the settings page; unexpected exceptions result in a 500 response.
    """
    debug_print(f"Entering blocked_words route with guild_id: {guild_id}", level="all")
    try:
        guild = get_guild_or_404(guild_id)
        
        if request.method == 'POST':
            # Verify CSRF token first
            try:
                csrf.protect()
            except CSRFError:
                flash('Security token expired. Please submit the form again.', 'danger')
                return redirect(url_for('blocked_words', guild_id=guild_id))
            # Process form data
            words = [w.strip() for w in request.form.getlist('words') if w.strip()]
            embed_data = {
                'title': request.form.get('title', 'Blocked Word Detected!'),
                'description': request.form.get('description', 'You have used a word that is not allowed.'),
                'color': request.form.get('color', '#ff0000').lstrip('#')
            }

            # Convert color to integer
            try:
                embed_data['color'] = int(embed_data['color'], 16)
            except ValueError:
                embed_data['color'] = 0xff0000  # Default red

            # Update database in transaction
            with db.conn:
                # Update blocked words
                db.execute_query(
                    'DELETE FROM blocked_words WHERE guild_id = ?',
                    (guild_id,)
                )
                
                if words:
                    db.execute_query(
                        'INSERT INTO blocked_words (guild_id, word) VALUES (?, ?)',
                        [(guild_id, word) for word in words],
                        many=True
                    )

                # Update embed configuration
                db.execute_query('''
                    INSERT OR REPLACE INTO blocked_word_embeds 
                    (guild_id, title, description, color)
                    VALUES (?, ?, ?, ?)
                ''', (guild_id, embed_data['title'], embed_data['description'], embed_data['color']))

            flash('Blocked words settings updated successfully', 'success')
            return redirect(url_for('blocked_words', guild_id=guild_id))

        # GET Request - Load existing data
        words = db.execute_query(
            'SELECT word FROM blocked_words WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        )
        words_list = [word['word'] for word in words] if words else []

        embed = db.execute_query(
            'SELECT * FROM blocked_word_embeds WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )

        return render_template('blocked_words.html',
                            words=words_list,
                            embed=dict(embed) if embed else None,
                            guild_id=guild_id,
                            guild=guild)

    except sqlite3.Error as e:
        logger.error(f"Database error in blocked words: {str(e)}")
        flash('A database error occurred. Changes were not saved.', 'danger')
        return redirect(url_for('blocked_words', guild_id=guild_id))
        
    except Exception as e:
        logger.error(f"Unexpected error in blocked words: {str(e)}")
        abort(500)

# Banned Users
@app.route('/dashboard/<guild_id>/banned-users')
@login_required
@guild_required
def banned_users(guild_id):
    """
    Render a page showing users banned in a guild.
    
    Queries the warnings table for entries with a ban action (new schema) and falls back to a legacy query that matches 'ban' in the reason if the action_type column is not available. Renders the 'banned_users.html' template with a list of ban records (each as a dict), plus guild and guild_id for the template.
    
    Parameters:
        guild_id (str|int): Guild identifier used to scope the query and load guild metadata.
    
    Returns:
        A Flask response rendering 'banned_users.html'.
    
    Errors:
        Aborts with HTTP 500 if the ban list or guild data cannot be retrieved.
    """
    debug_print(f"Entering banned_users route with guild_id: {guild_id}", level="all")
    try:
        # Try the modern query first
        try:
            bans = db.execute_query('''
                SELECT w.*, u.username 
                FROM warnings w
                LEFT JOIN users u ON w.user_id = u.user_id
                WHERE w.guild_id = ? AND w.action_type = 'ban'
                ORDER BY w.timestamp DESC
            ''', (guild_id,))
        except sqlite3.OperationalError:
            # Fallback to legacy query if action_type doesn't exist
            bans = db.execute_query('''
                SELECT w.*, u.username 
                FROM warnings w
                LEFT JOIN users u ON w.user_id = u.user_id
                WHERE w.guild_id = ? AND w.reason LIKE '%ban%'
                ORDER BY w.timestamp DESC
            ''', (guild_id,))
        
        guild = get_guild_or_404(guild_id)
        return render_template('banned_users.html',
                            bans=[dict(b) for b in bans],
                            guild_id=guild_id,
                            guild=guild)
    except Exception as e:
        logger.error(f"Error fetching banned users: {str(e)}")
        abort(500, description="Could not retrieve banned users")

# Server Leaderboard
@app.route('/dashboard/<guild_id>/leaderboard')
@login_required
@guild_required
def leaderboard(guild_id):
    """
    Render the XP/level leaderboard for a guild.
    
    Loads the guild (404 if not found), queries up to the top 100 users by level and XP from the user_levels table, and returns the rendered leaderboard page.
    
    Parameters:
        guild_id (int|str): ID of the guild to show the leaderboard for.
    
    Returns:
        A Flask response rendering 'leaderboard.html' with context keys:
          - users: list of rows from `user_levels` ordered by level then xp
          - guild_id: the provided guild ID
          - guild: guild metadata returned by `get_guild_or_404`
    
    Raises:
        404: If the guild does not exist (propagated from get_guild_or_404).
    """
    debug_print(f"Entering leaderboard route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    
    users = db.execute_query('''
        SELECT * FROM user_levels 
        WHERE guild_id = ?
        ORDER BY level DESC, xp DESC
        LIMIT 100
    ''', (guild_id,), fetch='all')
    
    return render_template('leaderboard.html',
                         users=users,
                         guild_id=guild_id,
                         guild=guild)

# Level System Configuration
@app.route('/dashboard/<guild_id>/leveling', methods=['GET', 'POST'])
@login_required
@guild_required
def level_config(guild_id):
    """
    Render and handle the leveling configuration page for a guild.
    
    On GET: loads guild info, merges stored level config with sensible defaults, loads level rewards, channels, and roles, and renders the "level_config.html" template populated with that data.
    
    On POST: protects against CSRF, handles two actions:
    - Adding a reward: validates numeric level and role existence, then stores a new level reward.
    - Updating settings: parses and validates form fields (integers for cooldown/xp bounds, JSON for `xp_boost_roles`, hex color parsing, and filtering `excluded_channels` against available text channels), persists the merged configuration to the database, and flashes success or error messages.
    
    On query param delete (GET): deletes a configured reward for the given level after validation.
    
    Returns a Flask response: either a rendered template (GET) or a redirect back to the same page after POST/delete actions. Error conditions produce user-facing flash messages; unexpected errors are logged and result in an error flash and redirect.
    """
    debug_print(f"Entering level_config route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    text_channels = get_text_channels(guild_id)
    roles = get_roles(guild_id)
    
    # Get existing config
    db_config = db.get_level_config(guild_id)
    config = dict(db_config) if db_config else {}
    
    # Create merged configuration
    default_config = {
        'cooldown': 60,
        'xp_min': 15,
        'xp_max': 25,
        'level_channel': None,
        'announce_level_up': True,
        'excluded_channels': [],
        'xp_boost_roles': {},
        'embed_title': '🎉 Level Up!',
        'embed_description': '{user} has reached level **{level}**!',
        'embed_color': 0xFFD700,
        'give_xp_to_bots': True,
        'give_xp_to_self': True
    }
    
    # Merge configurations properly
    merged_config = default_config.copy()
    if db_config:
        merged_config.update({
            'cooldown': db_config.get('cooldown', default_config['cooldown']),
            'xp_min': db_config.get('xp_min', default_config['xp_min']),
            'xp_max': db_config.get('xp_max', default_config['xp_max']),
            'level_channel': db_config.get('level_channel'),
            'announce_level_up': db_config.get('announce_level_up', True),
            'excluded_channels': db_config.get('excluded_channels', []),
            'xp_boost_roles': db_config.get('xp_boost_roles', {}),
            'embed_title': db_config.get('embed_title', default_config['embed_title']),
            'embed_description': db_config.get('embed_description', default_config['embed_description']),
            'embed_color': db_config.get('embed_color', default_config['embed_color']),
            'give_xp_to_bots': db_config.get('give_xp_to_bots', default_config['give_xp_to_bots']),
            'give_xp_to_self': db_config.get('give_xp_to_self', default_config['give_xp_to_self'])
        })
    
    # Handle rewards
    rewards = db.get_level_rewards(guild_id)
    rewards_dict = {str(level): role_id for level, role_id in rewards.items()}

    if request.method == 'POST':
        try:
            csrf.protect()
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('level_config', guild_id=guild_id))

        # Handle reward addition
        if 'add_reward' in request.form:
            reward_level = request.form.get('reward_level', '').strip()
            reward_role_id = request.form.get('reward_role_id', '').strip()

            if not reward_level.isdigit():
                flash('Invalid reward level', 'danger')
                return redirect(url_for('level_config', guild_id=guild_id))
                
            if not any(role['id'] == reward_role_id for role in roles):
                flash('Invalid role selected', 'danger')
                return redirect(url_for('level_config', guild_id=guild_id))

            try:
                db.add_level_reward(guild_id, int(reward_level), reward_role_id)
                flash('Reward added successfully', 'success')
            except Exception as e:
                logger.error(f"Reward add error: {str(e)}")
                flash('Failed to add reward', 'danger')
            
            return redirect(url_for('level_config', guild_id=guild_id))

        # Main config update
        try:
            new_config = {
                'cooldown': int(request.form.get('cooldown', 60)),
                'xp_min': int(request.form.get('xp_min', 15)),
                'xp_max': int(request.form.get('xp_max', 25)),
                'level_channel': request.form.get('level_channel', ''),
                'announce_level_up': 'announce_level_up' in request.form,
                'excluded_channels': request.form.getlist('excluded_channels'),
                'xp_boost_roles': request.form.get('xp_boost_roles', '{}'),
                'embed_title': request.form.get('embed_title', '🎉 Level Up!'),
                'embed_description': request.form.get(
                    'embed_description', 
                    '{user} has reached level **{level}**!'
                ),
                'embed_color': int(request.form.get('embed_color', 'ffd700').lstrip('#'), 16),
                'give_xp_to_bots': bool(request.form.get('give_xp_to_bots', False)),
                'give_xp_to_self': bool(request.form.get('give_xp_to_self', False))
            }

            # Validate JSON fields
            try:
                # This is already a JSON string from the form
                boosts = new_config['xp_boost_roles']
                # Just parse to validate format
                parsed_boosts = json.loads(boosts)
                if not isinstance(parsed_boosts, dict):
                    raise ValueError()
                for k, v in parsed_boosts.items():
                    if not isinstance(v, int) or v < 0 or v > 300:
                        raise ValueError()
            except (json.JSONDecodeError, ValueError):
                flash('Invalid XP boost roles format', 'danger')
                return redirect(url_for('level_config', guild_id=guild_id))

            # Validate excluded channels
            valid_channels = [str(c['id']) for c in text_channels]
            new_config['excluded_channels'] = [
                c for c in new_config['excluded_channels']
                if c in valid_channels
            ]

            # Prepare update data
            update_data = {
                "cooldown": new_config["cooldown"],
                "xp_min": new_config["xp_min"],
                "xp_max": new_config["xp_max"],
                "level_channel": new_config["level_channel"],
                "announce_level_up": new_config["announce_level_up"],
                # Convert to JSON strings for storage
                "excluded_channels": json.dumps(new_config["excluded_channels"]),
                # Already a JSON string from form
                "xp_boost_roles": new_config["xp_boost_roles"],
                "embed_title": new_config["embed_title"],
                "embed_description": new_config["embed_description"],
                "embed_color": new_config["embed_color"],
                "give_xp_to_bots": new_config["give_xp_to_bots"],
                "give_xp_to_self": new_config["give_xp_to_self"]
            }

            db.update_level_config(guild_id, **update_data)
            flash('Settings saved successfully', 'success')
            
        except ValueError as e:
            logger.error(f"Config validation error: {str(e)}")
            flash('Invalid configuration values', 'danger')
        except Exception as e:
            logger.error(f"Config save error: {str(e)}")
            flash('Failed to save configuration', 'danger')

        return redirect(url_for('level_config', guild_id=guild_id))

    # Handle reward deletion
    if 'delete_reward' in request.args:
        try:
            level = int(request.args.get('delete_reward', 0))
            if level > 0:
                db.remove_level_reward(guild_id, level)
                flash('Reward deleted successfully', 'success')
        except ValueError:
            flash('Invalid reward level', 'danger')
        except Exception as e:
            logger.error(f"Reward delete error: {str(e)}")
            flash('Failed to delete reward', 'danger')
        
        return redirect(url_for('level_config', guild_id=guild_id))

    return render_template('level_config.html',
                         config=merged_config,
                         rewards=rewards_dict,
                         guild_id=guild_id,
                         guild=guild,
                         channels=text_channels,
                         roles=roles)

# Auto Roles Management
@app.route('/dashboard/<guild_id>/auto-roles-config', methods=['GET', 'POST'])
@login_required
@guild_required
def auto_roles_config(guild_id):
    """
    Render and update a guild's automatic role (auto-role) configuration.
    
    GET: render the auto-roles page showing available roles and the currently configured auto-roles.
    POST: accept a form field "autoroles" (one or more role IDs), update the stored auto-role list for the guild, flash a success message, and redirect back to the same page. If the CSRF check fails, a danger flash is shown and the page is re-rendered.
    
    Parameters:
        guild_id (int or str): ID of the guild whose auto-role settings are being viewed or modified.
    
    Returns:
        A Flask response: either the rendered auto_roles_config template (GET or failed CSRF) or a redirect response after a successful update.
    """
    debug_print(f"Entering auto_roles_config route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    roles = get_roles(guild_id)
    current_autoroles = db.get_autoroles(guild_id)

    if request.method == 'POST':
        try:
            csrf.protect()
            selected_roles = request.form.getlist('autoroles')
            db.update_autoroles(guild_id, selected_roles)
            flash('Auto-role settings updated successfully', 'success')
            return redirect(url_for('auto_roles_config', guild_id=guild_id))
        except CSRFError:
            flash('Security token expired. Please try again.', 'danger')
    
    return render_template('auto_roles_config.html',
                         guild_id=guild_id,
                         guild=guild,
                         roles=roles,
                         current_autoroles=current_autoroles)

# Auto Roles on Game Play Time
@app.route('/dashboard/<guild_id>/game-roles', methods=['GET', 'POST'])
@login_required
@guild_required
def game_roles_config(guild_id):
    """
    Render and handle the game-role configuration page for a guild.
    
    Displays existing game->role mappings, a list of top games from static configuration, and available guild roles. On POST it validates and persists new mappings or deletes an existing mapping, flashing a success or error message and redirecting back to the same page.
    
    Parameters:
        guild_id: ID of the guild whose game-role settings are being viewed/modified.
    
    Behavior notes:
    - Reads a static JSON file (static/other/rpc_games.json) to populate the top games list; if missing or invalid, an empty list is used and a flash message is emitted.
    - On POST, enforces CSRF protection. If the form contains 'delete' it removes the mapping for the submitted game name; otherwise it validates `game_name`, `role_id`, and `required_minutes` (must be a positive integer) and inserts or replaces the row in the `game_roles` table.
    - Uses the global `db` for queries and `flash` for user-facing messages.
    - Returns a rendered template ('game_roles.html') on GET or after successful operations; on unexpected errors it flashes an error and redirects to the guild selection page.
    """
    debug_print(f"Entering game_roles_config route with guild_id: {guild_id}", level="all")
    try:
        # Get guild and roles
        guild = get_guild_or_404(guild_id)
        roles = get_roles(guild_id)
        
        # Get absolute path to rpc_games.json
        current_dir = os.path.dirname(os.path.abspath(__file__))
        rpc_path = os.path.join(current_dir, 'static/other/rpc_games.json')
        
        # Load game list with error handling
        try:
            with open(rpc_path, 'r') as f:
                top_games = json.load(f)
        except FileNotFoundError:
            logger.error("Game list file not found at: %s", rpc_path)
            top_games = []
            flash('Game list configuration missing - using empty list', 'danger')
        except json.JSONDecodeError as e:
            logger.error("Invalid game list format: %s", str(e))
            top_games = []
            flash('Invalid game list format - using empty list', 'danger')

        # Handle form submission
        if request.method == 'POST':
            csrf.protect()
            
            if 'delete' in request.form:
                # Handle deletion
                game_name = request.form.get('game_name')
                if game_name:
                    db.execute_query(
                        'DELETE FROM game_roles WHERE guild_id = ? AND game_name = ?',
                        (guild_id, game_name)
                    )
                    flash(f'Removed configuration for {game_name}', 'success')
                    
            else:
                # Handle new configuration
                game_name = request.form.get('game_name', '').strip()
                role_id = request.form.get('role_id')
                required_minutes = request.form.get('required_minutes', 0)
                
                # Validate inputs
                if not all([game_name, role_id, required_minutes]):
                    flash('All fields are required', 'danger')
                elif not required_minutes.isdigit() or int(required_minutes) < 1:
                    flash('Playtime must be a positive number', 'danger')
                else:
                    # Save to database
                    db.execute_query('''
                        INSERT OR REPLACE INTO game_roles 
                        (guild_id, game_name, role_id, required_minutes)
                        VALUES (?, ?, ?, ?)
                    ''', (guild_id, game_name, role_id, int(required_minutes)))
                    flash(f'Added configuration for {game_name}', 'success')

            return redirect(url_for('game_roles_config', guild_id=guild_id))

        # Get current configurations
        current_config = db.execute_query(
            'SELECT * FROM game_roles WHERE guild_id = ?',
            (guild_id,),
            fetch='all'
        ) or []

        return render_template('game_roles.html',
                            guild_id=guild_id,
                            guild=guild,
                            roles=roles,
                            current_config=current_config,
                            top_games=top_games,
                            get_role_name=lambda rid: next(
                                (r['name'] for r in roles if r['id'] == rid), 'Unknown Role'
                            ))

    except Exception as e:
        logger.error("Error in game_roles_config: %s", str(e))
        flash('An error occurred while loading game role configurations', 'danger')
        return redirect(url_for('select_guild'))

# Stream Announcements
@app.route('/dashboard/<guild_id>/twitch-announcements', methods=['GET', 'POST'])
@login_required
@guild_required
def twitch_announcements_page(guild_id):
    """
    Render and handle the Twitch announcements configuration page for a guild.
    
    Displays existing Twitch announcement entries and processes form actions to add, edit, delete, or toggle announcements. Actions modify the `twitch_announcements` database table, enforce a per-user limit of 15 live stream entries, require a valid CSRF token for POST requests, and use Flask flash messages and redirects to report results.
    
    Parameters:
        guild_id (str|int): Discord guild (server) ID whose Twitch announcement settings are being viewed or modified.
    
    Returns:
        A Flask response rendering the 'twitch_announcements.html' template on GET, or a redirect/flash response after handling POST actions.
    """
    debug_print(f"Entering twitch_announcements_page route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    channels = get_text_channels(guild_id)
    roles = get_roles(guild_id)
    DEFAULT_STREAM_MESSAGE = "🔴 {streamer} is now live! Watch here: {url} {role}"

    twitch_announcements = db.execute_query(
        'SELECT * FROM twitch_announcements WHERE guild_id = ?',
        (guild_id,),
        fetch='all'
    )
    def get_role_mention(role_id):
        """
        Return a Discord role mention string for a given role ID.
        
        If role_id is falsy or not found in the module-level `roles` list, an empty string is returned.
        
        Parameters:
            role_id: Role identifier (any type convertible to string) to look up in `roles`.
        
        Returns:
            str: A mention in the format "<@&{role_id}>" when found, otherwise an empty string.
        """
        if not role_id:
            return ''
        for r in roles:
            if str(r['id']) == str(role_id):
                return f"<@&{r['id']}>"
        return ''
    def get_channel_name(channel_id):
        """
        Return the display name for a channel id from the in-memory `channels` list.
        
        Parameters:
            channel_id: ID of the channel to look up (int or str).
        
        Returns:
            str: The channel's name if found; otherwise the string "Unknown (<channel_id>)".
        """
        for channel in channels:
            if str(channel['id']) == str(channel_id):
                return channel['name']
        return f"Unknown ({channel_id})"
    for ann in twitch_announcements:
        ann['role_mention'] = get_role_mention(ann.get('role_id'))

    # Get current user ID
    user_id = session.get('user', {}).get('id') or session.get('admin_username', 'admin')
    user_twitch_live_count = db.execute_query(
        'SELECT COUNT(*) as cnt FROM twitch_announcements WHERE guild_id = ? AND streamer_id IS NOT NULL AND created_by = ?',
        (guild_id, user_id),
        fetch='one'
    )['cnt']

    if request.method == 'POST':
        try:
            csrf.protect()
            action = request.form.get('action')
            if action == 'add_stream':
                streamer_id = request.form['streamer_id'].strip()
                channel_id = request.form['channel_id']
                message = request.form.get('message', '').strip() or DEFAULT_STREAM_MESSAGE
                role_id = request.form.get('role_id')
                # Enforce limits
                if user_twitch_live_count >= 15:
                    flash("You can only add up to 15 Twitch live channels.", "danger")
                    return redirect(url_for('twitch_announcements_page', guild_id=guild_id))
                db.execute_query(
                    '''INSERT INTO twitch_announcements 
                    (guild_id, channel_id, streamer_id, message, role_id, created_by)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (guild_id, channel_id, streamer_id, message, role_id, user_id)
                )
            elif action == 'edit_stream':
                stream_id = request.form.get('announcement_id') or request.form.get('stream_id')
                channel_id = request.form.get('channel_id')
                role_id = request.form.get('role_id') or None
                streamer_id = request.form.get('streamer_id')
                message = request.form.get('message')
                db.execute_query(
                    'UPDATE twitch_announcements SET channel_id=?, role_id=?, streamer_id=?, message=? WHERE id=? AND guild_id=?',
                    (channel_id, role_id, streamer_id, message, stream_id, guild_id)
                )
                flash('Twitch announcement updated!', 'success')
                return redirect(request.url)
            elif action == 'delete_stream':
                announcement_id = request.form['announcement_id']
                db.execute_query(
                    'DELETE FROM twitch_announcements WHERE id = ? AND guild_id = ?',
                    (announcement_id, guild_id)
                )
            elif action == 'toggle_stream':
                announcement_id = request.form['announcement_id']
                enabled = request.form['enabled'] == 'true'
                db.execute_query(
                    'UPDATE twitch_announcements SET enabled = ? WHERE id = ? AND guild_id = ?',
                    (int(enabled), announcement_id, guild_id)
                )
            flash('Settings updated successfully', 'success')
            return redirect(url_for('twitch_announcements_page', guild_id=guild_id))
        except Exception as e:
            logger.error(f"Twitch config error: {str(e)}")
            flash('Error saving configuration', 'danger')

    return render_template('twitch_announcements.html',
                         guild_id=guild_id,
                         guild=guild,
                         channels=channels,
                         roles=roles,
                         twitch_announcements=twitch_announcements,
                         get_channel_name=get_channel_name,
                         DEFAULT_STREAM_MESSAGE=DEFAULT_STREAM_MESSAGE)

# Video Announcements
@app.route('/dashboard/<guild_id>/youtube-announcements', methods=['GET', 'POST'])
@login_required
@guild_required
def youtube_announcements_page(guild_id):
    """
    Render and manage YouTube announcement configurations for a guild.
    
    Handles GET to render the YouTube announcements page (provides guild, text channels, roles,
    and existing announcements). Handles POST form actions to add, edit, delete, or toggle
    announcements in the `youtube_announcements` table. Adding enforces per-user limits
    (maximum 10 regular video channels and 5 live-stream channels). Requests are protected
    by CSRF and user-facing success or error messages are flashed.
    
    Parameters:
        guild_id (str|int): Guild (server) identifier for which announcements are managed.
    
    Returns:
        A Flask response: on GET renders 'youtube_announcements.html'; on successful POST redirects
        back to the page (or to the current URL after edits); on error flashes an error and renders/redirects accordingly.
    """
    debug_print(f"Entering youtube_announcements_page route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    channels = get_text_channels(guild_id)
    roles = get_roles(guild_id)
    DEFAULT_VIDEO_MESSAGE = "{role} {channel} uploaded a new video: {title} - {url}"

    youtube_announcements = db.execute_query(
        'SELECT * FROM youtube_announcements WHERE guild_id = ?',
        (guild_id,),
        fetch='all'
    )
    for ann in youtube_announcements:
        if 'announce_channel_id' not in ann or ann['announce_channel_id'] is None:
            ann['announce_channel_id'] = ann.get('announce_channel_id') or ann.get('channel_id')
        ann['channel_id'] = ann.get('channel_id')
    def get_role_mention(role_id):
        """
        Return a Discord role mention string for a given role ID.
        
        If role_id is falsy or not found in the module-level `roles` list, an empty string is returned.
        
        Parameters:
            role_id: Role identifier (any type convertible to string) to look up in `roles`.
        
        Returns:
            str: A mention in the format "<@&{role_id}>" when found, otherwise an empty string.
        """
        if not role_id:
            return ''
        for r in roles:
            if str(r['id']) == str(role_id):
                return f"<@&{r['id']}>"
        return ''
    def get_channel_name(channel_id):
        """
        Return the display name for a channel id from the in-memory `channels` list.
        
        Parameters:
            channel_id: ID of the channel to look up (int or str).
        
        Returns:
            str: The channel's name if found; otherwise the string "Unknown (<channel_id>)".
        """
        for channel in channels:
            if str(channel['id']) == str(channel_id):
                return channel['name']
        return f"Unknown ({channel_id})"
    for ann in youtube_announcements:
        ann['role_mention'] = get_role_mention(ann.get('role_id'))

    # Get current user ID
    user_id = session.get('user', {}).get('id') or session.get('admin_username', 'admin')
    user_youtube_video_count = db.execute_query(
        'SELECT COUNT(*) as cnt FROM youtube_announcements WHERE guild_id = ? AND created_by = ? AND (live_stream IS NULL OR live_stream = 0)',
        (guild_id, user_id),
        fetch='one'
    )['cnt']
    user_youtube_live_count = db.execute_query(
        'SELECT COUNT(*) as cnt FROM youtube_announcements WHERE guild_id = ? AND created_by = ? AND live_stream = 1',
        (guild_id, user_id),
        fetch='one'
    )['cnt']

    if request.method == 'POST':
        try:
            csrf.protect()
            action = request.form.get('action')
            if action == 'add_video':
                announce_channel_id = request.form['channel_id']
                target_channel_id = request.form['target_channel_id']
                message = request.form.get('message', '').strip() or DEFAULT_VIDEO_MESSAGE
                role_id = request.form.get('role_id')
                live_stream = 1 if request.form.get('live_stream') == '1' else 0
                # Enforce limits
                if live_stream:
                    if user_youtube_live_count >= 5:
                        flash("You can only add up to 5 YouTube live stream channels.", "danger")
                        return redirect(url_for('youtube_announcements_page', guild_id=guild_id))
                else:
                    if user_youtube_video_count >= 10:
                        flash("You can only add up to 10 YouTube video channels.", "danger")
                        return redirect(url_for('youtube_announcements_page', guild_id=guild_id))
                db.execute_query(
                    '''INSERT INTO youtube_announcements 
                    (guild_id, channel_id, announce_channel_id, message, role_id, created_by, live_stream)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (guild_id, target_channel_id, announce_channel_id, message, role_id, user_id, live_stream)
                )
            elif action == 'edit_video':
                video_id = request.form.get('announcement_id') or request.form.get('video_id')
                announce_channel_id = request.form.get('channel_id')
                target_channel_id = request.form.get('target_channel_id')
                message = request.form.get('message')
                role_id = request.form.get('role_id') or None
                live_stream = 1 if request.form.get('live_stream') == '1' else 0
                db.execute_query(
                    'UPDATE youtube_announcements SET channel_id=?, announce_channel_id=?, role_id=?, message=?, live_stream=? WHERE id=? AND guild_id=?',
                    (target_channel_id, announce_channel_id, role_id, message, live_stream, video_id, guild_id)
                )
                flash('YouTube announcement updated!', 'success')
                return redirect(request.url)
            elif action == 'delete_video':
                announcement_id = request.form['announcement_id']
                db.execute_query(
                    'DELETE FROM youtube_announcements WHERE id = ? AND guild_id = ?',
                    (announcement_id, guild_id)
                )
            elif action == 'toggle_video':
                announcement_id = request.form['announcement_id']
                enabled = request.form['enabled'] == 'true'
                db.execute_query(
                    'UPDATE youtube_announcements SET enabled = ? WHERE id = ? AND guild_id = ?',
                    (int(enabled), announcement_id, guild_id)
                )
            flash('Settings updated successfully', 'success')
            return redirect(url_for('youtube_announcements_page', guild_id=guild_id))
        except Exception as e:
            logger.error(f"YouTube config error: {str(e)}")
            flash('Error saving configuration', 'danger')

    return render_template('youtube_announcements.html',
                         guild_id=guild_id,
                         guild=guild,
                         channels=channels,
                         roles=roles,
                         youtube_announcements=youtube_announcements,
                         get_channel_name=get_channel_name,
                         DEFAULT_VIDEO_MESSAGE=DEFAULT_VIDEO_MESSAGE)

# Role Menus Management
@app.route('/dashboard/<guild_id>/role-menus')
@login_required
@guild_required
def role_menus(guild_id):
    """
    Render the role menus editor page for a guild.
    
    Loads the guild (404 if not found or inaccessible), fetches stored role menus and text channels for the guild,
    and returns the rendered 'role_menus.html' template.
    
    Parameters:
        guild_id (int | str): The guild's ID.
    
    Returns:
        Response: Rendered Flask template for the role menus page.
    """
    debug_print(f"Entering role_menus route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    menus = db.execute_query(
        'SELECT * FROM role_menus WHERE guild_id = ?',
        (guild_id,),
        fetch='all'
    )
    channels = get_text_channels(guild_id)
    return render_template('role_menus.html', guild=guild, guild_id=guild_id, menus=menus, channels=channels)

# Role Menu Editing
@app.route('/dashboard/<guild_id>/<menu_type>/<menu_id>', methods=['GET', 'POST'])
@login_required
@guild_required
def edit_role_menu(guild_id, menu_type, menu_id):
    """
    Render and handle edits for a role menu (dropdown, reaction role, or button) for a guild.
    
    On GET: load the menu config, available roles and text channels, generate a short-lived JWT for front-end API calls, and render the appropriate editor template for the given menu type.
    On POST: validate CSRF, persist the submitted JSON config to the database, flash a success message and redirect back to the same editor.
    
    Parameters:
        guild_id: ID of the guild the menu belongs to.
        menu_type: One of 'dropdown', 'reactionrole', or 'button' — selects which editor template and validates the stored menu type.
        menu_id: Database ID of the role menu to edit.
    
    Returns:
        A Flask response: rendered editor template on GET, or a redirect after successful POST.
    
    Side effects:
        - Aborts with 404 if menu_type is invalid or the menu row does not exist for the given guild.
        - Updates the role_menus.config column when a POST with valid CSRF is received.
    """
    debug_print(f"Entering edit_role_menu route with guild_id: {guild_id}, menu_type: {menu_type}, menu_id: {menu_id}", level="all")
    # Validate menu_type
    if menu_type not in ('dropdown', 'reactionrole', 'button'):
        abort(404)
    # Fetch menu config from DB
    menu = db.execute_query(
        'SELECT * FROM role_menus WHERE id = ? AND guild_id = ? AND type = ?',
        (menu_id, guild_id, menu_type),
        fetch='one'
    )
    if not menu:
        abort(404)
    config = json.loads(menu['config'] or '{}')
    roles = get_roles(guild_id, force_refresh=True)
    channels = get_text_channels(guild_id)

    if request.method == 'POST':
        try:
            csrf.protect()
        except CSRFError:
            flash('Security token expired. Please refresh and try again.', 'danger')
            return redirect(request.url)
        # Save config changes from form
        new_config = request.form.get('config_json')
        db.execute_query(
            'UPDATE role_menus SET config = ? WHERE id = ?',
            (new_config, menu_id)
        )
        flash('Saved!', 'success')
        return redirect(request.url)

    # Generate JWT for frontend API calls
    jwt_token = generate_jwt()
    return render_template(
        f'edit_{menu_type}.html',
        guild_id=guild_id,
        menu_id=menu_id,
        config=config,
        roles=roles,
        channels=channels,
        API_URL=API_URL,
        jwt_token=jwt_token
    )

@app.route('/api/<guild_id>/create_role_menu', methods=['POST'])
@login_required
@guild_required
def api_create_role_menu(guild_id=None):
    """
    Create a new placeholder role menu for a guild and return a setup URL.
    
    Accepts JSON with optional "guild_id" (overrides route param), required "menu_type" (one of "dropdown", "button", "reactionrole") and required "channel_id". The function inserts a new row into the `role_menus` table with an auto-generated menu id and an empty JSON config, setting the creator from the current session user or admin username. Returns JSON with a `setup_url` for editing the new menu.
    
    Returns:
        JSON response with:
          - success (bool)
          - setup_url (str) on success
          - error (str) on failure
    
    HTTP status codes:
        200 on success,
        400 when required fields are missing or menu_type is invalid,
        403 if CSRF protection fails,
        500 on unexpected errors.
    """
    debug_print(f"Entering api_create_role_menu route with guild_id: {guild_id}", level="all")
    try:
        csrf.protect()
        data = request.get_json(force=True)
        guild_id = data.get('guild_id') or guild_id
        menu_type = data.get('menu_type')
        channel_id = data.get('channel_id')
        creator_id = session.get('user', {}).get('id') or session.get('admin_username', 'admin')
        if not guild_id or not menu_type or not channel_id:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        if menu_type not in ('dropdown', 'button', 'reactionrole'):
            return jsonify({'success': False, 'error': 'Invalid menu type'}), 400

        import random, string
        def random_id(length=8):
            return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        menu_id = random_id()

        # Insert placeholder config
        db.execute_query(
            '''INSERT INTO role_menus (id, guild_id, type, channel_id, config, created_by)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (menu_id, guild_id, menu_type, channel_id, '{}', creator_id)
        )

        setup_url = url_for('edit_role_menu', guild_id=guild_id, menu_type=menu_type, menu_id=menu_id)
        return jsonify({'success': True, 'setup_url': setup_url})

    except CSRFError:
        return jsonify({'success': False, 'error': 'Security token expired. Please refresh and try again.'}), 403
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

# Delete Role Menu
@app.route('/api/<guild_id>/role_menus/<menu_id>/delete', methods=['POST'])
@login_required
@guild_required
def delete_role_menu(guild_id, menu_id):
    """
    Delete a role menu record for a guild and return a JSON response.
    
    Deletes the row in the `role_menus` table matching the provided `menu_id` and `guild_id`.
    On success returns a JSON object {"success": True}. On failure returns {"success": False, "error": "<message>"} with HTTP status 500.
    
    Parameters:
        guild_id (int | str): ID of the guild that owns the role menu.
        menu_id (int | str): ID of the role menu to delete.
    
    Returns:
        flask.Response: JSON response indicating success or failure. HTTP 200 on success, 500 on error.
    """
    debug_print(f"Entering delete_role_menu route with guild_id: {guild_id}, menu_id: {menu_id}", level="all")
    try:
        db.execute_query(
            'DELETE FROM role_menus WHERE id = ? AND guild_id = ?',
            (menu_id, guild_id)
        )
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting role menu {menu_id} for guild {guild_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Backups Management
@app.route('/dashboard/<guild_id>/backups', methods=['GET', 'POST'])
@login_required
@guild_required
def guild_backups(guild_id):
    """
    Render the backups page for a guild (GET) or start a backup (POST).
    
    GET: fetches backup metadata via get_backups(guild_id) and renders the 'backups.html' template with the results. If fetching backups fails the page is rendered with an empty list and a flashed error message.
    
    POST: requests a backup to be started by POSTing to the internal backup API. On success returns a JSON response with HTTP 202. On API failure flashes an error and redirects back to the backups page.
    
    Parameters:
        guild_id (int|str): ID of the guild whose backups are being viewed or started.
    
    Returns:
        A Flask response — either a rendered template, a redirect, or a JSON response with status 202 when a backup start is accepted.
    """
    debug_print(f"Entering guild_backups route with guild_id: {guild_id}", level="all")
    try:
        if request.method == 'POST':
            api_url = f"{API_URL}/api/start_backup"
            resp = jwt_requests.post(api_url, json={"guild_id": str(guild_id)}, timeout=10)
            data = resp.json()
            if resp.status_code != 200 or not data.get("success"):
                flash(data.get("error", "Failed to start backup."), "danger")
                return redirect(url_for('guild_backups', guild_id=guild_id))
            return jsonify({"success": True}), 202

        backups = []
        try:
            backups = get_backups(guild_id)
        except Exception as e:
            logger.error(f"Failed to fetch backups: {e}")
            flash('Failed to fetch backups: ' + str(e), 'danger')
        return render_template('backups.html', guild_id=guild_id, backups=backups, FRONTEND_URL=FRONTEND_URL)
    except Exception as e:
        logger.error(f"Unexpected error in backups page: {e}")
        flash('Unexpected error: ' + str(e), 'danger')
        return redirect(url_for('guild_dashboard', guild_id=guild_id))

@app.route('/api/<guild_id>/backups/progress')
@login_required
@guild_required
def backup_progress(guild_id):
    """
    Return the current backup progress for a guild as JSON.
    
    Calls the internal bot API to fetch backup progress for the given guild and proxies the JSON response. On error returns a JSON object with keys "progress" (0), "step_text" (empty string) and "error" (error message) with HTTP 200.
    
    Parameters:
        guild_id (str|int): ID of the guild to query.
    
    Returns:
        flask.Response: JSON response from the bot API or an error object as described above.
    """
    debug_print(f"Entering backup_progress route with guild_id: {guild_id}", level="all")
    try:
        api_url = f"{API_URL}/api/backup_progress?guild_id={guild_id}"
        resp = jwt_requests.get(api_url, timeout=1)
        return jsonify(resp.json())
    except Exception as e:
        logger.error(f"Error fetching backup progress: {e}")
        return jsonify({"progress": 0, "step_text": "", "error": str(e)}), 200

@app.route('/api/<guild_id>/backups/download/<backup_id>')
@login_required
@guild_required
def download_backup(guild_id, backup_id):
    """
    Download a stored guild backup file and return it as an attachment.
    
    Looks up the backup by backup_id for the given guild_id and streams the backup file
    to the client as an attachment. If the backup record is missing or the file is
    not present on disk, flashes an error message and aborts with a 404. On unexpected
    errors the function logs the error, flashes a failure message, and redirects to
    the guild backups page.
    
    Parameters:
        guild_id (int|str): ID of the guild that owns the backup.
        backup_id (int|str): Identifier of the backup to download.
    
    Returns:
        A Flask response that sends the backup file as an attachment on success,
        or a redirect response to the guild backups page on failure.
    """
    debug_print(f"Entering download_backup route with guild_id: {guild_id}, backup_id: {backup_id}", level="all")
    try:
        backup = get_backup(backup_id, guild_id)
        if not backup:
            flash('Backup not found.', 'danger')
            abort(404)
        if not os.path.exists(backup['file_path']):
            flash('Backup file missing on server.', 'danger')
            abort(404)
        return send_file(backup['file_path'], as_attachment=True)
    except Exception as e:
        logger.error(f"Error downloading backup: {e}")
        flash('Failed to download backup: ' + str(e), 'danger')
        return redirect(url_for('guild_backups', guild_id=guild_id))

@app.route('/api/<guild_id>/backups/restore/<backup_id>', methods=['POST'])
@login_required
@guild_required
def restore_backup(guild_id, backup_id):
    """
    Start a backup restore for a guild by requesting the bot API and redirecting to the backups page.
    
    Checks that the specified backup exists on disk, then posts a restore request to the bot API. On success, flashes an informational message; if the backup is missing or the API reports failure, flashes an error and redirects to the guild backups page. Unexpected exceptions are logged, flashed as errors, and also redirect to the guild backups page. May abort with a 404 if the backup record or file is missing.
    
    Parameters:
        guild_id: ID of the guild whose backup will be restored.
        backup_id: Identifier of the backup to restore.
    
    Side effects:
        - Calls the bot API endpoint to start a restore.
        - Uses Flask flash messages and redirects (or aborts 404) to communicate outcome.
    """
    debug_print(f"Entering restore_backup route with guild_id: {guild_id}, backup_id: {backup_id}", level="all")
    try:
        backup = get_backup(backup_id, guild_id)
        if not backup or not os.path.exists(backup['file_path']):
            flash('Backup not found or file missing.', 'danger')
            abort(404)

        # Call the bot's API to start the restore
        api_url = f"{API_URL}/api/start_restore"
        resp = jwt_requests.post(api_url, json={
            "guild_id": str(guild_id),
            "backup_path": backup['file_path']
        }, timeout=10)
        data = resp.json()
        if resp.status_code != 200 or not data.get("success"):
            flash(data.get("error", "Failed to start restore."), "danger")
            return redirect(url_for('guild_backups', guild_id=guild_id))

        flash('Restore started. The server owner will receive DM progress updates.', 'info')
        return redirect(url_for('guild_backups', guild_id=guild_id))
    except Exception as e:
        logger.error(f"Unexpected error in restore: {e}\n{traceback.format_exc()}")
        flash('Unexpected error: ' + str(e), 'danger')
        return redirect(url_for('guild_backups', guild_id=guild_id))

@app.route('/api/<guild_id>/backups/delete/<backup_id>', methods=['POST'])
@login_required
@guild_required
def delete_backup(guild_id, backup_id):
    """
    Delete a stored backup file and its database record for a guild, then redirect back to the backups page.
    
    Deletes the backup file on disk (if present) and removes the corresponding row from the `backups` table. On success a success flash message is set; on failure an error is flashed and logged. Always redirects to the guild backups view.
    
    Parameters:
        guild_id (int | str): ID of the guild that owns the backup.
        backup_id (int | str): Identifier of the backup to delete.
    
    Returns:
        werkzeug.wrappers.Response: A redirect response to the guild backups page.
    """
    debug_print(f"Entering delete_backup route with guild_id: {guild_id}, backup_id: {backup_id}", level="all")
    try:
        backup = get_backup(backup_id, guild_id)
        if not backup:
            flash('Backup not found.', 'danger')
            return redirect(url_for('guild_backups', guild_id=guild_id))
        # Remove file from disk
        if backup['file_path'] and os.path.exists(backup['file_path']):
            os.remove(backup['file_path'])
        # Remove from DB
        with get_conn() as conn:
            conn.execute('DELETE FROM backups WHERE id = ? AND guild_id = ?', (backup_id, guild_id))
        flash('Backup deleted.', 'success')
    except Exception as e:
        logger.error(f"Error deleting backup: {e}")
        flash('Failed to delete backup: ' + str(e), 'danger')
    return redirect(url_for('guild_backups', guild_id=guild_id))

@app.route('/api/<guild_id>/backups/share/<backup_id>', methods=['POST'])
@login_required
@guild_required
def share_backup(guild_id, backup_id):
    """
    Create a public share link for a guild backup and redirect back to the backups page.
    
    Creates a share identifier for the backup (via set_backup_share_id), flashes a success
    message with the public URL, and redirects to the guild's backups dashboard.
    
    Parameters:
        guild_id (int | str): ID of the guild that owns the backup.
        backup_id (int | str): ID of the backup to share.
    
    Returns:
        A Flask redirect response to the guild backups page.
    """
    debug_print(f"Entering share_backup route with guild_id: {guild_id}, backup_id: {backup_id}", level="all")
    share_id = set_backup_share_id(backup_id, guild_id)
    flash(f'Share link created: {FRONTEND_URL}/backup/{share_id}', 'success')
    return redirect(url_for('guild_backups', guild_id=guild_id))

@app.route('/api/<guild_id>/backups/import', methods=['POST'])
@login_required
@guild_required
def import_backup(guild_id):
    """
    Import a guild backup JSON uploaded via multipart form and register it for the guild.
    
    Expects a file field named 'backup_file' in the request containing a .json backup. Validates the filename, then delegates processing to import_backup_file(file, guild_id). On success or failure the function flashes a user-facing message and redirects back to the guild backups page.
    
    Parameters:
        guild_id (str|int): ID of the guild to import the backup into.
    
    Returns:
        werkzeug.wrappers.Response: A redirect response to the guild backups page. The response includes a flashed success or error message.
    """
    debug_print(f"Entering import_backup route with guild_id: {guild_id}", level="all")
    file = request.files.get('backup_file')
    if not file or not file.filename.endswith('.json'):
        flash('Please upload a valid backup JSON file.', 'danger')
        return redirect(url_for('guild_backups', guild_id=guild_id))
    # Save the file and register it as a backup for this guild
    try:
        import_backup_file(file, guild_id)
        flash('Backup imported successfully!', 'success')
    except Exception as e:
        flash(f'Failed to import backup: {e}', 'danger')
    return redirect(url_for('guild_backups', guild_id=guild_id))

@app.route('/api/<guild_id>/backups/import-url', methods=['POST'])
@login_required
@guild_required
def import_backup_url(guild_id):
    """
    Import a backup JSON from a public URL and register it for the specified guild.
    
    Validates the provided form field 'backup_url' (must be a non-empty HTTP/HTTPS URL), downloads the file, and registers it as a backup by calling import_backup_file_from_bytes. On success or failure the function sets a flash message and redirects back to the guild's backups page.
    
    Parameters:
        guild_id (int | str): Identifier of the guild to associate the imported backup with.
    
    Returns:
        A Flask redirect response to the guild_backups page for the given guild_id.
    """
    debug_print(f"Entering import_backup_url route with guild_id: {guild_id}", level="all")
    backup_url = request.form.get('backup_url', '').strip()
    if not backup_url or not backup_url.startswith('http'):
        flash('Please enter a valid backup share URL.', 'danger')
        return redirect(url_for('guild_backups', guild_id=guild_id))
    try:
        # Download the backup JSON from the share URL
        resp = requests.get(backup_url, timeout=10)
        if resp.status_code != 200:
            flash('Failed to download backup from the provided URL.', 'danger')
            return redirect(url_for('guild_backups', guild_id=guild_id))
        # Save the file and register it as a backup for this guild
        import_backup_file_from_bytes(resp.content, guild_id)
        flash('Backup imported successfully from URL!', 'success')
    except Exception as e:
        flash(f'Failed to import backup from URL: {e}', 'danger')
    return redirect(url_for('guild_backups', guild_id=guild_id))

@app.route('/share/backup/<share_id>')
def public_backup_download(share_id):
    """
    Serve a publicly shared backup file for a given share ID.
    
    Given a share_id, looks up the corresponding backup record and returns the backup file as an attachment if it exists. If no matching backup is found or the file is missing, returns a 404-style (message, status) response.
    
    Parameters:
        share_id (str): Public share identifier for the backup.
    
    Returns:
        A Flask response sending the backup file as an attachment on success, or a (message, status) tuple with HTTP 404 when the backup or file is not found.
    """
    debug_print(f"Entering public_backup_download route with share_id: {share_id}", level="all")
    backup = get_backup_by_share_id(share_id)
    if not backup or not os.path.exists(backup['file_path']):
        return "Backup not found or file missing.", 404
    return send_file(backup['file_path'], as_attachment=True)

@app.route('/dashboard/<guild_id>/backups/schedule', methods=['GET', 'POST'])
@login_required
@guild_required
def schedule_backup(guild_id):
    """
    Create, list, and preview scheduled backups for a guild.
    
    Handles both POST and GET:
    - POST: validates form fields from the request, inserts a new schedule row into the `schedules` table, flashes a success message, attempts to notify the bot to reload schedules, and redirects back to the same page.
    - GET: loads existing schedules for `guild_id`, computes each schedule's next local and UTC run times (approximating months as 30 days and years as 365 days), and renders the schedule management template with computed metadata and the list of timezones.
    
    Parameters:
        guild_id (str|int): ID of the guild for which schedules are managed.
    
    Side effects:
    - Writes a new schedule to the database on POST.
    - Attempts an HTTP POST to the bot API to trigger schedule reload (errors are logged but do not propagate).
    - Uses Flask `flash` to set a user-visible message on successful creation.
    
    Returns:
        A Flask response: a redirect after POST or a rendered template (schedule_backup.html) on GET containing `schedules` (with computed `next_backup_local`, `next_backup_utc`, and `seconds_until`) and `all_timezones`.
    """
    debug_print(f"Entering schedule_backup route with guild_id: {guild_id}", level="all")
    if request.method == 'POST':
        start_date = request.form.get('start_date')
        start_time = request.form.get('start_time')
        timezone_str = request.form.get('timezone', 'UTC')
        frequency_value = int(request.form.get('frequency_value'))
        frequency_unit = request.form.get('frequency_unit')
        enabled = 1 if request.form.get('enabled') == 'on' else 0
        schedule_id = ''.join(random.choices('0123456789', k=5))

        # Store the timezone string in the DB
        with get_conn() as conn:
            conn.execute(
                'INSERT INTO schedules (id, guild_id, start_date, start_time, timezone, frequency_value, frequency_unit, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (schedule_id, guild_id, start_date, start_time, timezone_str, frequency_value, frequency_unit, enabled)
            )
        flash(f'Backup schedule saved! Schedule ID: {schedule_id}', 'success')
    
        # Notify the bot process to reload schedules
        try:
            api_url = f"{API_URL}/api/reload_schedules"
            resp = jwt_requests.post(api_url, timeout=5)
        except Exception as e:
            debug_print(f"[WARNING] Could not notify bot to reload schedules: {e}")

        return redirect(url_for('schedule_backup', guild_id=guild_id))

    # For GET: fetch schedules and pass all_timezones for dropdown
    with get_conn() as conn:
        schedules = conn.execute(
            'SELECT * FROM schedules WHERE guild_id = ? ORDER BY start_date, start_time', (guild_id,)
        ).fetchall()

    now_utc = datetime.utcnow().replace(second=0, microsecond=0)
    processed_schedules = []
    for sched in schedules:
        # Parse start datetime, handle 24:00 edge case
        try:
            start_time = sched['start_time']
            start_date = sched['start_date']
            tz_str = sched['timezone'] if 'timezone' in sched.keys() and sched['timezone'] else 'UTC'
            if start_time == "24:00":
                dt = datetime.strptime(start_date, "%Y-%m-%d") + timedelta(days=1)
                start_date = dt.strftime("%Y-%m-%d")
                start_time = "00:00"
            local_tz = pytz_timezone(tz_str)
            start_dt_local = local_tz.localize(datetime.strptime(f"{start_date} {start_time}", "%Y-%m-%d %H:%M"))
            freq_val = int(sched['frequency_value'])
            freq_unit = sched['frequency_unit']
            next_backup_local = start_dt_local
            now_local = datetime.now(local_tz).replace(second=0, microsecond=0)
            # Calculate next_backup in the future (local time)
            while next_backup_local < now_local:
                if freq_unit == 'days':
                    next_backup_local += timedelta(days=freq_val)
                elif freq_unit == 'weeks':
                    next_backup_local += timedelta(weeks=freq_val)
                elif freq_unit == 'months':
                    next_backup_local += timedelta(days=30 * freq_val)  # Approximate
                elif freq_unit == 'years':
                    next_backup_local += timedelta(days=365 * freq_val)  # Approximate
            # Also calculate UTC for the scheduler
            next_backup_utc = next_backup_local.astimezone(pytz_timezone('UTC'))
            seconds_until = int((next_backup_local - now_local).total_seconds())
        except Exception as e:
            next_backup_local = now_local
            next_backup_utc = now_utc
            seconds_until = 0

        processed_schedules.append({
            **sched,
            'next_backup_local': next_backup_local,
            'next_backup_utc': next_backup_utc,
            'seconds_until': seconds_until,
            'timezone': sched['timezone'] if 'timezone' in sched.keys() and sched['timezone'] else 'UTC'
        })

    return render_template(
        'schedule_backup.html',
        guild_id=guild_id,
        schedules=processed_schedules,
        all_timezones=all_timezones
    )

@app.route('/dashboard/<guild_id>/backups/schedule/delete/<schedule_id>', methods=['POST'])
@login_required
@guild_required
def delete_schedule(guild_id, schedule_id):
    """
    Delete a scheduled backup job for a guild and redirect back to the backup schedule page.
    
    Deletes the schedule row matching `schedule_id` and `guild_id` from the database. On success a success flash message is added; on failure the error is logged and an error flash is shown. The function always returns a redirect response to the schedule backup view for the given guild.
    
    Parameters:
        guild_id (int|str): ID of the guild owning the schedule.
        schedule_id (int|str): ID of the schedule to delete.
    
    Returns:
        werkzeug.wrappers.Response: Redirect response to the schedule backup page for `guild_id`.
    """
    debug_print(f"Entering delete_schedule route with guild_id: {guild_id}, schedule_id: {schedule_id}", level="all")
    try:
        with get_conn() as conn:
            conn.execute('DELETE FROM schedules WHERE id = ? AND guild_id = ?', (schedule_id, guild_id))
        flash('Schedule deleted.', 'success')
    except Exception as e:
        logger.error(f"Error deleting schedule: {e}")
        flash('Failed to delete schedule: ' + str(e), 'danger')
    return redirect(url_for('schedule_backup', guild_id=guild_id))

@app.route('/dashboard/<guild_id>/backups/schedule/toggle/<schedule_id>', methods=['POST'])
@login_required
@guild_required
def toggle_schedule(guild_id, schedule_id):
    """
    Toggle the enabled state of a scheduled backup for a guild and redirect back to the schedule page.
    
    Looks up the schedule by schedule_id and guild_id; if found, flips its `enabled` boolean in the database and flashes a success message; if not found, flashes an error. Redirects to the schedule_backup view for the guild.
    
    Parameters:
        guild_id (int|str): ID of the guild owning the schedule.
        schedule_id (int|str): ID of the schedule to toggle.
    
    Returns:
        Response: A Flask redirect response to the schedule_backup page for the given guild.
    """
    debug_print(f"Entering toggle_schedule route with guild_id: {guild_id}, schedule_id: {schedule_id}", level="all")
    with get_conn() as conn:
        sched = conn.execute('SELECT enabled FROM schedules WHERE id = ? AND guild_id = ?', (schedule_id, guild_id)).fetchone()
        if sched:
            new_status = 0 if sched['enabled'] else 1
            conn.execute('UPDATE schedules SET enabled = ? WHERE id = ? AND guild_id = ?', (new_status, schedule_id, guild_id))
            flash('Schedule updated.', 'success')
        else:
            flash('Schedule not found.', 'danger')
    return redirect(url_for('schedule_backup', guild_id=guild_id))

# Warnings Management
@app.route('/dashboard/<guild_id>/warnings')
@login_required
@guild_required
def warnings(guild_id):
    """
    Render the warned users page for a guild.
    
    Updates stored usernames from Discord, aggregates warning counts per user for the given guild,
    and returns the rendered 'warned_users.html' template with the warnings list and guild info.
    
    Parameters:
        guild_id (int | str): Discord guild ID to load warnings for.
    
    Returns:
        A Flask response rendering 'warned_users.html' with keys:
          - warnings: list of dicts with keys 'user_id', 'username', and 'count'
          - guild_id, guild
    
    Errors:
        Aborts with HTTP 500 if warnings cannot be retrieved.
    """
    debug_print(f"Entering warnings route with guild_id: {guild_id}", level="all")
    try:
        # First try to update usernames from Discord API
        update_usernames_from_discord(guild_id)
        
        warnings = db.execute_query('''
            SELECT w.user_id, u.username, COUNT(*) as count 
            FROM warnings w
            LEFT JOIN users u ON w.user_id = u.user_id
            WHERE w.guild_id = ?
            GROUP BY w.user_id
            ORDER BY count DESC
        ''', (guild_id,))
        
        guild = get_guild_or_404(guild_id)
        return render_template('warned_users.html', 
                             warnings=[dict(w) for w in warnings],
                             guild_id=guild_id,
                             guild=guild)
    except Exception as e:
        logger.error(f"Error fetching warnings: {str(e)}")
        abort(500, description="Could not retrieve warnings")

def update_usernames_from_discord(guild_id):
    debug_print(f"Entering update_usernames_from_discord with guild_id: {guild_id}", level="all")
    """Update usernames from Discord API for users with warnings"""
    try:
        # Get unique user IDs with warnings
        user_ids = db.execute_query('''
            SELECT DISTINCT user_id FROM warnings 
            WHERE guild_id = ?
        ''', (guild_id,))
        
        for user in user_ids:
            user_id = user['user_id']
            try:
                headers = {'Authorization': f'Bot {os.getenv("BOT_TOKEN")}'}
                response = requests.get(
                    f'https://discord.com/api/v9/users/{user_id}',
                    headers=headers
                )
                if response.status_code == 200:
                    user_data = response.json()
                    db.execute_query('''
                        INSERT OR REPLACE INTO users (user_id, username, avatar_url)
                        VALUES (?, ?, ?)
                    ''', (user_id, user_data['username'], user_data.get('avatar')))
            except Exception as e:
                logger.warning(f"Could not fetch user {user_id}: {str(e)}")
    except Exception as e:
        logger.error(f"Error updating usernames: {str(e)}")

@app.route('/dashboard/<guild_id>/warnings/<user_id>', methods=['GET', 'POST'])
@login_required
@guild_required
def user_warnings(guild_id, user_id):
    """
    Display and manage a user's warnings for a guild (GET renders the page; POST updates or adds warnings).
    
    On GET: loads the guild (404 if not found) and renders the user_warnings.html template with the user's warnings.
    On POST: enforces CSRF protection, updates any existing warning reasons present in the form (fields named "reason_<warning_id>"),
    and optionally adds a new warning from form field "new_reason". Commits changes via the database helpers, flashes success or
    security messages, and redirects back to the same user warnings page.
    
    Parameters:
        guild_id (str|int): ID of the guild whose warnings are being viewed or modified.
        user_id (str|int): ID of the user whose warnings are being viewed or modified.
    
    Returns:
        A Flask response: either a rendered template (GET) or a redirect after processing (POST).
    
    Side effects:
        - Calls db.update_warning_reason and/or db.add_warning to persist changes.
        - Flashes messages to the session for user feedback.
        - May redirect the client after POST; CSRF failures flash an error and redirect without applying changes.
    """
    debug_print(f"Entering user_warnings route with guild_id: {guild_id}, user_id: {user_id}", level="all")
    if request.method == 'POST':
        # Verify CSRF token first
        try:
            csrf.protect()
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('user_warnings', guild_id=guild_id))
        # Handle existing warning updates
        for key in request.form:
            if key.startswith('reason_'):
                warning_id = key.split('_')[1]
                new_reason = request.form.get(key)
                if new_reason:
                    db.update_warning_reason(guild_id, user_id, warning_id, new_reason)
        
        # Handle new warning addition
        new_reason = request.form.get('new_reason')
        if new_reason:
            db.add_warning(guild_id, user_id, new_reason)
            flash('New warning added successfully', 'success')
        
        flash('Changes saved successfully', 'success')
        return redirect(url_for('user_warnings', guild_id=guild_id, user_id=user_id))
        
    guild = get_guild_or_404(guild_id)
    warnings = db.get_warnings(guild_id, user_id)
    return render_template('user_warnings.html',
                         warnings=warnings,
                         guild_id=guild_id,
                         user_id=user_id)

@app.route('/api/<guild_id>/warnings/<user_id>/delete/<warning_id>')
@login_required
@guild_required
def delete_warning(guild_id, user_id, warning_id):
    """
    Delete a specific warning for a user in a guild, flash a success message, and redirect back to that user's warnings page.
    
    Parameters:
        guild_id (int | str): ID of the guild containing the warning; will raise a 404 if the guild is not found.
        user_id (int | str): ID of the user whose warning will be removed.
        warning_id (int | str): Identifier of the warning to delete.
    
    Returns:
        werkzeug.wrappers.Response: A Flask redirect response to the user's warnings view.
    
    Side effects:
        - Removes the warning record from persistent storage.
        - Adds a success flash message.
        - Triggers a redirect to the user_warnings page.
    """
    debug_print(f"Entering delete_warning route with guild_id: {guild_id}, user_id: {user_id}, warning_id: {warning_id}", level="all")
    guild = get_guild_or_404(guild_id)
    db.remove_warning(guild_id, user_id, warning_id)
    flash('Warning deleted successfully', 'success')
    return redirect(url_for('user_warnings', 
                          guild_id=guild_id, 
                          user_id=user_id))

@app.route('/dashboard/<guild_id>/warning-actions', methods=['GET', 'POST'])
@login_required
@guild_required
def warning_actions_config(guild_id):
    """
    Render and process the warning actions configuration page for a guild.
    
    GET: Renders the warning actions editor showing existing rules.
    POST: Validates CSRF, parses up to 50 form rows of warning rules, and persists them:
    - Each rule requires a numeric warning count and an action name.
    - For timeout actions, a duration may be provided in formats like `45s`, `30m`, `1h`, `2d`, `1w` (seconds, minutes, hours, days, weeks). If parsing fails for a timeout duration, a default of 3600 seconds is used.
    - Saves or updates rules via the database and removes any previously stored rules that were deleted from the submitted form.
    On successful POST the user is redirected back to the same page and a success flash is shown; on failure a danger flash is shown and the error is logged.
    
    Side effects:
    - Reads and writes warning action records through the `db` API (set_warning_action, remove_warning_action).
    - Emits Flask flash messages and may return a redirect response.
    
    Parameters:
        guild_id: Identifier of the guild whose warning actions are being managed.
    
    Returns:
        A Flask response: either the rendered `warning_actions.html` template (GET or on error) or a redirect after successful update (POST).
    """
    debug_print(f"Entering warning_actions_config route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    actions = db.get_warning_actions(guild_id)

    if request.method == 'POST':
        try:
            csrf.protect()
            # Parse all rows from the form
            rows = []
            for idx in range(1, 51):  # Support up to 50 rules
                count = request.form.get(f'warning_count_{idx}')
                action = request.form.get(f'action_{idx}')
                duration = request.form.get(f'duration_{idx}')
                if not count or not action:
                    continue
                try:
                    count = int(count)
                except ValueError:
                    continue
                duration_seconds = None
                if action == "timeout" and duration:
                    # Accept the formats: "45s", "30m", "1h", "2d", or "1w"
                    m = re.match(r'^(\d+)([smhdw]?)$', duration.strip().lower())
                    if m:
                        val, unit = m.groups()
                        val = int(val)
                        if unit == 's' or unit == '':
                            duration_seconds = val
                        elif unit == 'm':
                            duration_seconds = val * 60
                        elif unit == 'h':
                            duration_seconds = val * 3600
                        elif unit == 'd':
                            duration_seconds = val * 86400
                        elif unit == 'w':
                            duration_seconds = val * 604800
                    else:
                        try:
                            duration_seconds = int(duration)
                        except Exception:
                            duration_seconds = 3600
                db.set_warning_action(guild_id, count, action, duration_seconds)
            # Remove deleted rules
            existing_counts = {int(request.form.get(f'warning_count_{idx}')) for idx in range(1, 21) if request.form.get(f'warning_count_{idx}')}
            for a in actions:
                if a['warning_count'] not in existing_counts:
                    db.remove_warning_action(guild_id, a['warning_count'])
            flash('Warning actions updated!', 'success')
            return redirect(url_for('warning_actions_config', guild_id=guild_id))
        except Exception as e:
            logger.error(f"Warning actions config error: {str(e)}")
            flash('Failed to update warning actions', 'danger')
    # Compute max_rows for the template
    max_rows = max(len(actions), 5) + 2
    return render_template('warning_actions.html', guild_id=guild_id, guild=guild, actions=actions, max_rows=max_rows)

# Spam Configuration
@app.route('/dashboard/<guild_id>/spam-config', methods=['GET', 'POST'])
@login_required
@guild_required
def spam_config(guild_id):
    """
    Render and process the spam configuration page for a guild.
    
    On GET: renders the spam configuration template populated with the current settings, text channels, and roles for the guild.
    On POST: validates CSRF, parses and validates numeric form fields and list fields, enforces minimums (all numeric thresholds/windows must be >= 1), merges values with sensible defaults, updates the guild's spam configuration in the database, and redirects back to the same page while flashing success or error messages.
    
    Parameters:
        guild_id (int | str): ID of the guild whose spam settings are being viewed or updated.
    
    Returns:
        A Flask response: on GET, the rendered "spam_config.html" template; on POST, a redirect back to the spam_config route (or the same template if validation fails).
    """
    debug_print(f"Entering spam_config route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    config = db.get_spam_config(guild_id)
    text_channels = get_text_channels(guild_id)
    roles = get_roles(guild_id)

    if request.method == 'POST':
        try:
            csrf.protect()
            enabled = request.form.get("enabled") == "on"
            new_config = {
                "spam_threshold": int(request.form.get("spam_threshold", 5)),
                "spam_time_window": int(request.form.get("spam_time_window", 10)),
                "mention_threshold": int(request.form.get("mention_threshold", 3)),
                "mention_time_window": int(request.form.get("mention_time_window", 30)),
                "excluded_channels": request.form.getlist("excluded_channels"),
                "excluded_roles": request.form.getlist("excluded_roles"),
                "enabled": enabled,
                "spam_strikes_before_warning": int(request.form.get("spam_strikes_before_warning", 1)),
                "no_xp_duration": int(request.form.get("no_xp_duration", 60))
            }

            if any(val < 1 for val in [
                new_config["spam_threshold"],
                new_config["spam_time_window"],
                new_config["mention_threshold"],
                new_config["mention_time_window"],
                new_config["spam_strikes_before_warning"],
                new_config["no_xp_duration"]
            ]):
                flash("All thresholds and windows must be at least 1", "danger")
                return redirect(url_for("spam_config", guild_id=guild_id))

            complete_config = {
                "spam_threshold": 5,
                "spam_time_window": 10,
                "mention_threshold": 3,
                "mention_time_window": 30,
                "excluded_channels": [],
                "excluded_roles": [],
                "enabled": True,
                "spam_strikes_before_warning": 1,
                "no_xp_duration": 60,
                **new_config
            }

            db.update_spam_config(guild_id, **complete_config)
            flash("Spam detection settings saved!", "success")
            return redirect(url_for("spam_config", guild_id=guild_id))

        except ValueError:
            flash("Invalid numerical values", "danger")
        except Exception as e:
            logger.error(f"Spam config error: {str(e)}")
            flash("Error saving settings", "danger")

    return render_template("spam_config.html",
                         config=config,
                         guild_id=guild_id,
                         guild=guild,
                         channels=text_channels,
                         roles=roles)

# Custom Forms Routes
@app.route('/dashboard/<guild_id>/forms')
@login_required
@guild_required
def custom_forms_dashboard(guild_id):
    """
    Render the custom forms dashboard for a guild.
    
    Fetches all custom forms that belong to the given guild plus global templates (is_template = 1), ordering templates first then by creation time, loads the guild (raises a 404 if not found), and returns the rendered 'form_dashboard.html' page populated with the guild, forms, guild_id, and FRONTEND_URL.
    """
    debug_print(f"Entering custom_forms_dashboard route with guild_id: {guild_id}", level="all")
    forms = db.execute_query(
        'SELECT * FROM custom_forms WHERE guild_id = ? OR is_template = 1 ORDER BY is_template DESC, created_at DESC',
        (guild_id,),
        fetch='all'
    )
    guild = get_guild_or_404(guild_id)
    return render_template('form_dashboard.html', guild=guild, forms=forms, guild_id=guild_id, FRONTEND_URL=FRONTEND_URL)

@app.route('/dashboard/<guild_id>/forms/new', methods=['GET', 'POST'])
@login_required
@guild_required
def create_custom_form(guild_id):
    """
    Create a new custom form (POST) or render the form builder page (GET) for a guild.
    
    On GET: loads prebuilt templates from web/static/other/prebuilt_templates.json, fetches the guild's text channels, and renders the form builder page.
    
    On POST: expects a JSON body with at least `name` and `config` keys (optional `description`). Creates a new custom_forms row with a generated UUID, the current session user's id as `created_by`, and returns JSON { "success": True, "form_id": "<uuid>" }.
    
    Parameters:
        guild_id (str|int): ID of the guild the form belongs to.
    
    Side effects:
        - Reads the prebuilt templates JSON file from disk.
        - Inserts a row into the `custom_forms` database table.
        - Relies on `session['user']['id']` to record the creator.
    
    Notes:
        - The POST handler uses request.get_json(force=True) so the request body must be valid JSON.
        - Does not perform explicit permission checks; caller should ensure the caller is authorized.
    """
    debug_print(f"Entering create_custom_form route with guild_id: {guild_id}", level="all")
    with open(os.path.join('web', 'static', 'other', 'prebuilt_templates.json'), 'r', encoding='utf-8') as f:
        prebuilt_templates = json.load(f)
    if request.method == 'POST':
        data = request.get_json(force=True)
        form_id = str(uuid.uuid4())
        db.execute_query(
            '''INSERT INTO custom_forms (id, guild_id, name, description, config, is_template, created_by)
               VALUES (?, ?, ?, ?, ?, 0, ?)''',
            (form_id, guild_id, data['name'], data.get('description', ''), json.dumps(data['config']), session['user']['id'])
        )
        return jsonify({'success': True, 'form_id': form_id})
    discord_channels = get_text_channels(guild_id)
    return render_template('form_builder.html', guild_id=guild_id, prebuilt_templates=prebuilt_templates, discord_channels=discord_channels)

@app.route('/dashboard/<guild_id>/forms/<form_id>/edit', methods=['GET', 'POST'])
@login_required
@guild_required
def edit_custom_form(guild_id, form_id):
    """
    Render and handle edits to an existing custom form for a guild.
    
    For GET requests, renders the form builder page populated with the saved form, available prebuilt templates, and the guild's text channels.
    For POST requests, expects a JSON body with keys:
    - "name" (str): new form name
    - "config" (dict/list): form configuration to store
    - "description" (str, optional): form description
    
    On POST the form record is updated and a JSON success object is returned.
    
    Parameters:
        guild_id: ID of the guild that owns the form.
        form_id: ID of the custom form to edit.
    
    Returns:
        A Flask response — either render_template(...) for GET or jsonify({'success': True}) for a successful POST.
    
    Raises:
        Aborts with 404 if the requested form does not exist for the given guild.
    """
    debug_print(f"Entering edit_custom_form route with guild_id: {guild_id}, form_id: {form_id}", level="all")
    with open(os.path.join('web', 'static', 'other', 'prebuilt_templates.json'), 'r', encoding='utf-8') as f:
        prebuilt_templates = json.load(f)
    form = db.execute_query(
        'SELECT * FROM custom_forms WHERE id = ? AND guild_id = ?',
        (form_id, guild_id),
        fetch='one'
    )
    if not form:
        abort(404)
    if request.method == 'POST':
        data = request.get_json(force=True)
        db.execute_query(
            'UPDATE custom_forms SET name = ?, description = ?, config = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND guild_id = ?',
            (data['name'], data.get('description', ''), json.dumps(data['config']), form_id, guild_id)
        )
        return jsonify({'success': True})
    discord_channels = get_text_channels(guild_id)
    return render_template('form_builder.html', guild_id=guild_id, form=form, prebuilt_templates=prebuilt_templates, discord_channels=discord_channels)

@app.route('/dashboard/<guild_id>/forms/<form_id>/delete', methods=['POST'])
@login_required
@guild_required
def delete_custom_form(guild_id, form_id):
    """
    Delete a custom form for a guild, flash a success message, and redirect to the forms dashboard.
    
    Deletes the database row in `custom_forms` matching the given guild and form IDs, adds a user-facing flash message, and returns a redirect response to the guild's custom forms dashboard.
    
    Parameters:
        guild_id (int or str): ID of the guild that owns the form.
        form_id (int or str): ID of the form to delete.
    
    Returns:
        Response: A Flask redirect response to the 'custom_forms_dashboard' for the given guild.
    """
    debug_print(f"Entering delete_custom_form route with guild_id: {guild_id}, form_id: {form_id}", level="all")
    db.execute_query('DELETE FROM custom_forms WHERE id = ? AND guild_id = ?', (form_id, guild_id))
    flash('Form deleted.', 'success')
    return redirect(url_for('custom_forms_dashboard', guild_id=guild_id))

# @app.route('/forms/import/<share_id>', methods=['GET', 'POST'])
# @login_required
# def import_shared_form(share_id):
#     debug_print(f"Entering import_shared_form route with share_id: {share_id}", level="all")
#     form = db.execute_query('SELECT * FROM custom_forms WHERE share_id = ?', (share_id,), fetch='one')
#     if not form:
#         abort(404)
#     if request.method == 'POST':
#         guild_id = request.form.get('guild_id')
#         new_id = str(uuid.uuid4())
#         db.execute_query(
#             '''INSERT INTO custom_forms (id, guild_id, name, description, config, is_template, template_source, created_by)
#                VALUES (?, ?, ?, ?, ?, 0, ?, ?)''',
#             (new_id, guild_id, form['name'], form['description'], form['config'], form['id'], session['user']['id'])
#         )
#         flash('Form imported!', 'success')
#         return redirect(url_for('custom_forms_dashboard', guild_id=guild_id))
#     return render_template('import_form.html', form=form)

@app.route('/api/forms/<form_id>/submit', methods=['POST'])
@login_required
def submit_custom_form(form_id):
    """
    Handle submission of a custom form: validate limits, persist the submission, and proxy the submission to the bot API.
    
    This endpoint:
    - Expects a JSON body with a "responses" mapping.
    - Looks up the form by `form_id` and enforces the configured `max_submissions` per user.
    - Inserts a new row into `form_submissions` (generates a UUID for the submission).
    - Proxies the submission to the bot API (includes a server-issued JWT and a user mention).
    - Returns the bot API response (status, headers, body) on success.
    
    Error behaviors:
    - 404 if the form_id does not exist.
    - 429 if the user has reached the form's `max_submissions`.
    - 502 if the bot API responds but its response cannot be interpreted as expected.
    - 500 for unexpected server-side errors.
    
    Parameters:
        form_id (str): Identifier of the custom form to submit (from the route).
    
    Returns:
        A Flask response: either the proxied bot API response (status, headers, body) or a JSON error response with an appropriate HTTP status code.
    """
    debug_print(f"Entering submit_custom_form route with form_id: {form_id}", level="all")
    try:
        data = request.get_json(force=True)
        user_id = session['user']['id']
        # Fetch form config to check max submissions and embed config
        form = db.execute_query(
            'SELECT config, guild_id FROM custom_forms WHERE id = ?',
            (form_id,),
            fetch='one'
        )
        if not form:
            return jsonify({'success': False, 'error': 'Form not found'}), 404
        config = json.loads(form['config'])
        max_submissions = int(config.get('max_submissions', 1))
        count = db.execute_query(
            'SELECT COUNT(*) as cnt FROM form_submissions WHERE form_id = ? AND user_id = ?',
            (form_id, user_id),
            fetch='one'
        )['cnt']
        if count >= max_submissions:
            return jsonify({'success': False, 'error': f'Maximum submissions reached ({max_submissions})'}), 429

        # Record the submission in the database
        submission_id = str(uuid.uuid4())
        db.execute_query(
            '''INSERT INTO form_submissions (id, form_id, guild_id, user_id, submission_data, submitted_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)''',
            (submission_id, form_id, form['guild_id'], user_id, json.dumps(data.get("responses", {})))
        )

        # Proxy to bot API, include @user in footer if logged in
        API_URL = os.getenv('API_URL', 'http://localhost:5003')
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {generate_jwt()}'
        }
        user_mention = f"<@{user_id}>"
        resp = requests.post(
            f"{API_URL}/api/forms/{form_id}/submit",
            headers=headers,
            json={
                "form_id": form_id,
                "guild_id": form['guild_id'],
                "user_id": user_id,
                "responses": data.get("responses", {}),
                "user_mention": user_mention
            },
            timeout=10
        )
        try:
            return (resp.content, resp.status_code, resp.headers.items())
        except Exception:
            logger.error(f"Bot API did not return JSON: {resp.text}")
            return jsonify({'success': False, 'error': 'Bot API error: ' + resp.text}), 502
    except Exception as e:
        logger.error(f"Error proxying form submission: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/dashboard/<guild_id>/forms/<form_id>/submissions')
@login_required
@guild_required
def view_form_submissions(guild_id, form_id):
    """
    Render the submissions page for a specific form in a guild.
    
    Fetches form submissions for the given form_id and guild_id (ordered newest first) and returns the rendered HTML page.
    
    Parameters:
        guild_id (int | str): ID of the guild whose form submissions to view.
        form_id (int | str): ID of the form.
    
    Returns:
        Response: Flask response object for the rendered 'form_submissions.html' template.
    
    Raises:
        404: If the guild does not exist (propagated from get_guild_or_404).
    """
    debug_print(f"Entering view_form_submissions route with guild_id: {guild_id}, form_id: {form_id}", level="all")
    guild = get_guild_or_404(guild_id)
    submissions = db.execute_query(
        'SELECT * FROM form_submissions WHERE form_id = ? AND guild_id = ? ORDER BY submitted_at DESC',
        (form_id, guild_id),
        fetch='all'
    )
    return render_template('form_submissions.html', submissions=submissions, guild=guild, guild_id=guild_id, form_id=form_id)

@app.route('/forms/<form_id>/fill', methods=['GET'])
@login_required
def public_form_fill(form_id):
    """
    Render the public form fill page for a given form ID.
    
    Looks up the form by id in the `custom_forms` table, parses its JSON `config`, and returns the rendered
    'public_form_fill.html' template with `form` and `config` in the template context.
    
    If no form is found for the provided `form_id`, this route aborts with a 404.
    """
    debug_print(f"Entering public_form_fill route with form_id: {form_id}", level="all")
    form = db.execute_query(
        'SELECT * FROM custom_forms WHERE id = ?',
        (form_id,),
        fetch='one'
    )
    if not form:
        abort(404)
    config = json.loads(form['config'])
    return render_template('public_form_fill.html', form=form, config=config)

# Export route
@app.route('/api/<guild_id>/export', methods=['POST'])
@login_required
@guild_required
def export_guild_data(guild_id):
    """
    Create and return a ZIP archive containing exported data for a guild.
    
    Expects a JSON request body with an "options" key (list of export keys). For each option:
    - If option == "backup-restore/backups": includes any backup files returned by get_backups(guild_id) as files under export/backup-restore/backups/.
    - If option is a key in EXPORT_MAP: calls EXPORT_MAP[option](guild_id), serializes the returned object to JSON and stores it as export/<option> inside the ZIP.
    
    If no options are provided, returns a 400 JSON error response. Files that are missing on disk or that raise errors while being added are skipped. The response is an attachment named "export.zip" with MIME type application/zip.
    
    Parameters:
        guild_id (int|str): Identifier of the guild to export.
    
    Returns:
        Flask response: a downloadable ZIP file stream, or a 400 JSON error when no options are selected.
    """
    options = request.json.get('options', [])
    if not options:
        return jsonify({'error': 'No export options selected.'}), 400
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for opt in options:
            if opt == 'backup-restore/backups':
                # Add all backup files for this guild
                backups = get_backups(guild_id)
                for b in backups:
                    path = b['file_path'] if 'file_path' in b.keys() else None
                    if path and os.path.isfile(path):
                        try:
                            arcname = f"export/backup-restore/backups/{os.path.basename(path)}"
                            zf.write(path, arcname)
                        except Exception:
                            continue
            elif opt in EXPORT_MAP:
                data = EXPORT_MAP[opt](guild_id)
                arcname = f"export/{opt}"
                zf.writestr(arcname, json.dumps(data, indent=2, default=str).encode('utf-8'))
    mem_zip.seek(0)
    return send_file(
        mem_zip,
        mimetype='application/zip',
        as_attachment=True,
        download_name='export.zip'
    )

# Import route
@app.route('/api/<guild_id>/import', methods=['POST'])
@login_required
@guild_required
def import_guild_data(guild_id):
    """
    Import server data into the given guild from an uploaded ZIP produced by the export endpoint.
    
    This endpoint expects a multipart file field named "import_file" containing a ZIP archive whose entries are under the "export/" prefix. Recognized files inside the archive are applied to the database and filesystem for the specified guild_id (examples include):
    - server-configuration/commands.json
    - server-configuration/command-permissions.json
    - server-configuration/blocked-words.json
    - server-configuration/logging.json
    - server-configuration/welcome-message.json
    - server-configuration/goodbye-message.json
    - server-configuration/auto-assign-role.json
    - server-configuration/spam.json
    - server-configuration/warning-actions.json
    - server-configuration/role-menus.json
    - leveling-system/leveling.json
    - custom-forms/forms.json
    - social-pings/twitch-pings.json
    - social-pings/youtube-pings.json
    - fun-miscellaneous/game-roles.json
    - backup-restore/backup-schedules.json
    - backup-restore/backups/*  (backup files are written to the local backups directory)
    
    Parameters:
        guild_id: Identifier of the guild to import data into.
    
    Returns:
        A Flask JSON response object:
          - 400 with an error message if no file was uploaded or the uploaded file is not a ZIP.
          - 200 JSON {"success": True} on completion.
    
    Side effects:
        - Persists various records into the application's database via the db helper and direct SQL.
        - Writes backup files from backup-restore/backups/ into the local "backups" directory.
        - Skips individual files that fail to parse or apply (errors for individual entries are ignored; the import continues).
    """
    if 'import_file' not in request.files:
        return jsonify({'error': 'No file uploaded.'}), 400
    file = request.files['import_file']
    if not file or not file.filename.endswith('.zip'):
        return jsonify({'error': 'Invalid file.'}), 400
    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, 'import.zip')
        file.save(zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.namelist():
                if not member.startswith('export/'):
                    continue
                rel_path = member[len('export/'):]
                if rel_path == 'backup-restore/backups/' or rel_path.endswith('/'):
                    continue
                content = zf.read(member)
                # Handle each file type
                if rel_path == 'server-configuration/commands.json':
                    try:
                        commands = json.loads(content)
                        for cmd in commands:
                            db.add_command(guild_id, cmd['command_name'], cmd['content'], cmd.get('description', ''), cmd.get('ephemeral', True))
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/command-permissions.json':
                    try:
                        perms = json.loads(content)
                        for p in perms:
                            db.set_command_permissions(guild_id, p['command_name'], p.get('allow_roles', []), p.get('allow_users', []), p.get('is_custom', False))
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/blocked-words.json':
                    try:
                        words = json.loads(content)
                        for w in words:
                            db.add_blocked_word(guild_id, w)
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/logging.json':
                    try:
                        config = json.loads(content)
                        db.update_log_config(guild_id, **config)
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/welcome-message.json':
                    try:
                        config = json.loads(content)
                        db.update_welcome_config(guild_id, **config)
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/goodbye-message.json':
                    try:
                        config = json.loads(content)
                        db.update_goodbye_config(guild_id, **config)
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/auto-assign-role.json':
                    try:
                        roles = json.loads(content)
                        db.update_autoroles(guild_id, roles)
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/spam.json':
                    try:
                        config = json.loads(content)
                        db.update_spam_config(guild_id, **config)
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/warning-actions.json':
                    try:
                        actions = json.loads(content)
                        for a in actions:
                            db.set_warning_action(guild_id, a['warning_count'], a['action'], a.get('duration_seconds'))
                    except Exception:
                        continue
                elif rel_path == 'server-configuration/role-menus.json':
                    try:
                        menus = json.loads(content)
                        for m in menus:
                            db.execute_query('INSERT OR REPLACE INTO role_menus (guild_id, menu_id, config) VALUES (?, ?, ?)', (guild_id, m['menu_id'], json.dumps(m['config'])))
                    except Exception:
                        continue
                elif rel_path == 'leveling-system/leveling.json':
                    try:
                        config = json.loads(content)
                        db.update_level_config(guild_id, **config)
                    except Exception:
                        continue
                elif rel_path == 'custom-forms/forms.json':
                    try:
                        forms = json.loads(content)
                        for f in forms:
                            db.execute_query('INSERT OR REPLACE INTO custom_forms (id, guild_id, name, description, config, is_template, template_source, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (f['id'], guild_id, f['name'], f.get('description', ''), f['config'], f.get('is_template', 0), f.get('template_source'), f.get('created_by')))
                    except Exception:
                        continue
                elif rel_path == 'social-pings/twitch-pings.json':
                    try:
                        pings = json.loads(content)
                        for p in pings:
                            db.execute_query('INSERT OR REPLACE INTO twitch_announcements (id, guild_id, config) VALUES (?, ?, ?)', (p['id'], guild_id, json.dumps(p['config'])))
                    except Exception:
                        continue
                elif rel_path == 'social-pings/youtube-pings.json':
                    try:
                        pings = json.loads(content)
                        for p in pings:
                            db.execute_query('INSERT OR REPLACE INTO youtube_announcements (id, guild_id, config) VALUES (?, ?, ?)', (p['id'], guild_id, json.dumps(p['config'])))
                    except Exception:
                        continue
                elif rel_path == 'fun-miscellaneous/game-roles.json':
                    try:
                        roles = json.loads(content)
                        for r in roles:
                            db.update_game_role(guild_id, r['game_name'], r['role_id'], r['required_time'])
                    except Exception:
                        continue
                elif rel_path == 'backup-restore/backup-schedules.json':
                    try:
                        schedules = json.loads(content)
                        with get_conn() as conn:
                            for s in schedules:
                                # Insert or replace into the schedules table in backups DB
                                conn.execute('''
                                    INSERT OR REPLACE INTO schedules 
                                    (id, guild_id, start_date, start_time, frequency_value, frequency_unit, enabled, timezone)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                ''', (
                                    s['id'], guild_id, s.get('start_date'), s.get('start_time'),
                                    s.get('frequency_value'), s.get('frequency_unit'),
                                    s.get('enabled', 1), s.get('timezone', 'UTC')
                                ))
                    except Exception:
                        continue
                elif rel_path.startswith('backup-restore/backups/'):
                    # Save backup file to backups dir
                    try:
                        os.makedirs('backups', exist_ok=True)
                        fname = os.path.basename(rel_path)
                        with open(os.path.join('backups', fname), 'wb') as f:
                            f.write(content)
                    except Exception:
                        continue
    return jsonify({'success': True})

def random_schedule_id():
    """
    Generate a 5-digit random numeric schedule ID.
    
    Returns:
        str: A string of exactly 5 numeric characters ('0'–'9'). Uses Python's non-cryptographic random generator and is intended only for unique identifiers (not for security-sensitive tokens).
    """
    debug_print("Entering random_schedule_id", level="all")
    return ''.join(random.choices('0123456789', k=5))

# Get text channels from Discord API
def get_text_channels(guild_id):
    """
    Return the list of text channels for a Discord guild, using an in-memory cache.
    
    If a cached value exists for the given guild_id it is returned immediately. On cache miss the function requests the guild's channels from the Discord API, filters for text channels (type == 0), stores the result in the cache, and returns it. If an error occurs while fetching, the function logs the error and returns any previously cached channels for the guild or an empty list if none exist.
    
    Parameters:
        guild_id (str|int): Discord guild (server) ID.
    
    Returns:
        list: A list of channel objects (dicts) for text channels. 
    """
    debug_print(f"Entering get_text_channels with guild_id: {guild_id}", level="all")
    """Fetch text channels with caching"""
    if guild_id in channel_cache:
        return channel_cache[guild_id]
        
    try:
        headers = {'Authorization': f'Bot {os.getenv("BOT_TOKEN")}'}
        response = requests.get(
            f'https://discord.com/api/v9/guilds/{guild_id}/channels',
            headers=headers
        )
        response.raise_for_status()
        channels = [c for c in response.json() if c['type'] == 0]
        channel_cache[guild_id] = channels
        return channels
    except Exception as e:
        logger.error(f"Channel fetch error: {str(e)}")
        return channel_cache.get(guild_id, [])  # Return cached version if available

# Get roles from Discord API
def get_roles(guild_id, force_refresh=False):
    """
    Return the list of roles for the given guild, using a short-lived cache.
    
    Fetches roles from the Discord API and caches the result in module-level `role_cache` (2-minute TTL). By default returns cached roles for a guild when available; set `force_refresh=True` to bypass the cache and fetch fresh data. The returned roles are sorted by `position` descending and exclude any role whose `id` equals the guild id.
    
    Parameters:
        guild_id (int | str): Discord guild (server) ID. Numeric or string IDs are accepted.
        force_refresh (bool): If True, ignore cached data and fetch from the API.
    
    Returns:
        list[dict]: List of role objects as returned by Discord (filtered and sorted). On HTTP or other errors, returns the previously cached roles for the guild if present, otherwise an empty list.
    
    Side effects:
        Updates the module-level `role_cache` with the fetched roles.
    """
    debug_print(f"Entering get_roles with guild_id: {guild_id}, force_refresh: {force_refresh}", level="all")
    """Fetch roles for a guild with optional cache bypass"""
    if not force_refresh and guild_id in role_cache:
        return role_cache[guild_id]
    try:
        headers = {'Authorization': f'Bot {os.getenv("BOT_TOKEN")}'}
        response = requests.get(
            f'https://discord.com/api/v9/guilds/{guild_id}/roles',
            headers=headers
        )
        response.raise_for_status()
        roles = response.json()
        filtered_roles = sorted(
            [r for r in roles if r['id'] != str(guild_id)],
            key=lambda x: x['position'],
            reverse=True
        )
        role_cache[guild_id] = filtered_roles
        return filtered_roles
    except requests.exceptions.HTTPError as e:
        logging.error(f"Roles fetch HTTP error for {guild_id}: {e.response.status_code}")
        return role_cache.get(guild_id, [])
    except Exception as e:
        logging.error(f"Roles fetch error for {guild_id}: {str(e)}")
        return role_cache.get(guild_id, [])

# Get mutual guilds for a user
def get_mutual_guilds(user_id, user_access_token=None):
    """
    Return the list of guilds the given user shares with the bot.
    
    If a user_access_token is not provided the function will look for one in the session. The function calls the Discord API to fetch the user's guilds and compares them to the bot's guild list from the database; guilds present in both are returned.
    
    Parameters:
        user_id (str): Discord user ID whose mutual guilds to compute.
        user_access_token (str, optional): OAuth2 access token for the user. If omitted, the session's stored token is used.
    
    Returns:
        list[dict]: List of mutual guild objects with keys:
            - id (str): Guild ID.
            - name (str): Guild name (from Discord API).
            - icon (str): Guild icon (sourced from the bot's stored guild record, empty string if unavailable).
    
    Notes:
        - Returns an empty list if no access token is available or if the Discord API request fails (non-200 response).
        - Performs an external HTTP request to Discord and reads guild data from the application's database.
    """
    debug_print(f"Entering get_mutual_guilds with user_id: {user_id}, user_access_token: {user_access_token}", level="all")
    """
    Returns a list of guilds (servers) the user shares with the bot.
    Each guild is a dict: {'id': '...', 'name': '...', 'icon': '...'}
    """
    if not user_access_token:
        user_access_token = session.get('discord_token')
    if not user_access_token:
        return []

    # Get user's guilds from Discord API
    headers = {
        "Authorization": f"Bearer {user_access_token}"
    }
    user_guilds_resp = requests.get("https://discord.com/api/v10/users/@me/guilds", headers=headers)
    if user_guilds_resp.status_code != 200:
        return []

    user_guilds = user_guilds_resp.json()  # List of dicts

    # Get bot's guilds (from your DB)
    bot_guilds = {g['id']: g for g in db.get_all_guilds()}  # id -> guild dict

    # Filter to mutual guilds and include icon
    mutual_guilds = []
    for g in user_guilds:
        gid = g["id"]
        if gid in bot_guilds:
            mutual_guilds.append({
                "id": gid,
                "name": g["name"],
                "icon": bot_guilds[gid].get("icon", "")
            })
    return mutual_guilds

@app.template_filter('get_username')
def get_username_filter(user_id):
    """
    Return the stored username for a given Discord user ID.
    
    Looks up the user in the local `users` table and returns the `username` field if found; returns None when no matching record exists.
    
    Parameters:
        user_id (int | str): Discord user ID to look up.
    
    Returns:
        str | None: The username associated with `user_id`, or None if not present.
    """
    debug_print(f"Entering get_username_filter with user_id: {user_id}", level="all")
    user = db.execute_query(
        'SELECT username FROM users WHERE user_id = ?',
        (user_id,),
        fetch='one'
    )
    return user['username'] if user else None
    
@app.template_filter('get_channel_name')
def get_channel_name_filter(channel_id, channels):
    """
    Return the display name for a channel given its ID.
    
    Searches the provided iterable of channel dicts (expected to contain 'id' and 'name' keys) and returns the matching channel's name. If no matching channel is found, returns None.
    
    Parameters:
        channel_id: Channel identifier (any type that can be stringified for comparison).
        channels: Iterable of dict-like objects with at least 'id' and 'name' keys.
    
    Returns:
        The channel name (str) if found, otherwise None.
    """
    debug_print(f"Entering get_channel_name_filter with channel_id: {channel_id}, channels: {channels}", level="all")
    for channel in channels:
        if str(channel['id']) == str(channel_id):
            return channel['name']
    return None

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    """
    Format a datetime-like value for display in templates.
    
    Accepts a datetime, a numeric POSIX timestamp (seconds or milliseconds), or an ISO/RFC-like datetime string.
    If `format` is the literal 'relative', returns a human-friendly relative time (e.g. "just now", "3 minutes ago",
    "2 hours ago", "5 days ago"). If `value` is falsy, returns 'unknown'. If string parsing fails, the original value
    is returned.
    
    Parameters:
        value (datetime|int|float|str): The value to format. Integers/floats are treated as POSIX timestamps;
            very large numbers are assumed to be milliseconds and are converted to seconds. Strings are first
            parsed with datetime.fromisoformat(), falling back to interpreting the string as a numeric timestamp.
        format (str): A strftime-format string used to format datetimes, or the special value 'relative' to
            produce a human-readable relative time.
    
    Returns:
        str: Formatted date/time string, relative time string, 'unknown' for falsy input, or the original value
        if parsing a string fails.
    """
    debug_print(f"Entering datetimeformat with value: {value}, format: {format}", level="all")
    """
    Jinja2 filter to format a datetime, timestamp, or ISO string for display.
    Handles int/float (timestamp), str (ISO or timestamp), and datetime objects.
    """
    if not value:
        return 'unknown'
    # Handle relative format
    if format == 'relative':
        now = datetime.utcnow()
        if isinstance(value, (int, float)):
            # If value is too large, assume it's in milliseconds
            if value > 1e12:
                value = value / 1000
            value = datetime.fromtimestamp(value)
        elif isinstance(value, str):
            try:
                value = datetime.fromisoformat(value)
            except ValueError:
                try:
                    value = datetime.fromtimestamp(float(value))
                except Exception:
                    return value
        diff = now - value
        seconds = int(diff.total_seconds())
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif seconds < 86400:
            hours = seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        else:
            days = seconds // 86400
            return f"{days} day{'s' if days != 1 else ''} ago"
    # Default formatting
    if isinstance(value, (int, float)):
        # If value is too large, assume it's in milliseconds
        if value > 1e12:
            value = value / 1000
        value = datetime.fromtimestamp(value)
    elif isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            try:
                value = datetime.fromtimestamp(float(value))
            except Exception:
                return value
    return value.strftime(format)

# Error Handlers
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """
    Handle a CSRF validation error by notifying the user and redirecting to a safe page.
    
    Flashes a danger-level message informing the user that the security token expired, then returns a redirect response to the request referrer if available or to the guild selection page as a fallback.
    
    Parameters:
        e: The CSRF error/exception object (unused except for logging).
    
    Returns:
        A Flask redirect response to the referring page or to the 'select_guild' route.
    """
    debug_print(f"Entering handle_csrf_error with error: {e}", level="all")
    flash('Security token expired. Please refresh the page and try again.', 'danger')
    return redirect(request.referrer or url_for('select_guild'))

@app.errorhandler(401)
def unauthorized(e):
    """
    Handle Unauthorized (401) errors by redirecting the client to the login page.
    
    Parameters:
        e: The exception or error object provided by Flask's error handler (unused).
    
    Returns:
        A Flask redirect response to the 'login' route.
    """
    debug_print(f"Entering unauthorized error handler with error: {e}", level="all")
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    """
    Handle 403 Forbidden errors by rendering the error page with a user-facing message.
    
    Renders the 'error.html' template with `error_message` taken from the provided exception and a short `help_message`, and returns the rendered response with HTTP status 403.
    
    Parameters:
        e: The exception or error object that triggered the 403; its string representation is shown to the user.
    
    Returns:
        A tuple of (Flask response, int) where the response is the rendered error page and the int is 403.
    """
    debug_print(f"Entering forbidden error handler with error: {e}", level="all")
    return render_template('error.html', 
                         error_message=str(e),
                         help_message="Contact your server administrator for access"), 403

@app.errorhandler(404)
def not_found(e):
    """
    Handle 404 Not Found errors by rendering the standard error template.
    
    Parameters:
        e (Exception): The original error (typically a Flask/werkzeug HTTPException); its
            .description attribute, if present, is used as the displayed error message.
    
    Returns:
        tuple: (rendered_template, int) - the rendered 'error.html' with `error_message` and
        `help_message` context, and an HTTP 404 status code.
    """
    debug_print(f"Entering not_found error handler with error: {e}", level="all")
    error_message = getattr(e, 'description', None) or "The page you requested does not exist."
    return render_template('error.html', 
                        error_message=error_message,
                        help_message="The page you requested does not exist."), 404

@app.errorhandler(500)
def internal_error(e):
    """
    Render the generic 500 Internal Server Error page.
    
    Parameters:
        e (Exception): The caught exception object (used for logging/debugging; not shown to the user).
    
    Returns:
        A tuple of (rendered template response, int): the 'error.html' page with a 500 HTTP status code.
    """
    debug_print(f"Entering internal_error handler with error: {e}", level="all")
    return render_template('error.html',
                        error_message="Internal Server Error",
                        help_message="Please try again later"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)