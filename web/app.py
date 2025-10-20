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
import pyotp
import qrcode
from pytz import timezone as pytz_timezone, all_timezones
from authlib.integrations.flask_client import OAuth
from cachetools import TTLCache
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort, render_template_string, send_file
from flask_mail import Mail, Message
from PIL import Image
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
from shared.crafty_api import CraftyManager
from shared.cloudflare_api import CloudflareManager
from shared.colors import red
from shared.version_check import check_for_update
from bot.bot import bot_instance, load_schedules
from backups.backups import get_backups, get_backup, init_db, get_conn, set_backup_share_id, import_backup_file, import_backup_file_from_bytes, get_backup_by_share_id
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
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
    debug_print(red(f"❌ Database schema validation failed: {str(e)}"))
    raise

# Initialize managers
crafty_manager = CraftyManager(db)
cloudflare_manager = CloudflareManager(db)

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
# Flask-Mail config (set these in your .env)
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@example.com')
mail = Mail(app)

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
        debug_print(f"Entering JWTSession.__init__ with args: {args}, kwargs: {kwargs}", level="all")
        super().__init__(*args, **kwargs)
    def request(self, method, url, **kwargs):
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
    def wrapper(*args, **kwargs):
        debug_print(f"Entering login_required wrapper for {f.__name__}", level="all")
        if not session.get('user') and not session.get('admin') and not session.get('head_admin'):
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        
        # Check MFA requirement for regular users (not admins)
        # Skip MFA check for certain routes that should be accessible
        mfa_exempt_routes = ['index', 'privacy_policy', 'terms_of_service', 'end_user_license_agreement', 
                            'mfa_verify_required', 'mfa_verify', 'mfa_qr', 'settings', 'logout']
        
        if (session.get('user') and not session.get('admin') and not session.get('head_admin') 
            and request.endpoint not in mfa_exempt_routes):
            user_id = session['user']['id']
            try:
                if db.is_mfa_enabled(user_id) and not session.get('mfa_verified'):
                    # Store the intended destination
                    session['mfa_redirect_url'] = request.url
                    flash('Please complete MFA verification to continue.', 'warning')
                    return redirect(url_for('mfa_verify_required'))
            except Exception as e:
                # Log the error but don't block access if there's a database issue
                logger.error(f"Error checking MFA status for user {user_id}: {str(e)}")
                # Continue without MFA check
        
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def guild_required(f):
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

def birthday_calendar_access_required(f):
    """Allow access if user is guild member OR if birthday calendar is public"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        debug_print(f"Entering birthday_calendar_access_required wrapper for {f.__name__}", level="all")
        guild_id = kwargs.get('guild_id')
        if not guild_id:
            abort(404, description="Missing guild ID")

        # Admin bypass
        if session.get('admin'):
            return f(*args, **kwargs)

        # Check if calendar is public
        if is_birthday_calendar_public(guild_id):
            # Still need to be logged in
            if not session.get('user'):
                return redirect(url_for('login'))
            return f(*args, **kwargs)

        # If not public, require guild membership with manage permissions
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
    from backups.backups import get_conn
    with get_conn() as conn:
        return [dict(row) for row in conn.execute('SELECT * FROM schedules WHERE guild_id = ?', (guild_id,)).fetchall()]
    
def get_bot_guild_ids():
    debug_print("Entering get_bot_guild_ids", level="all")
    bot_guilds = db.get_all_guilds()
    return {g['id'] for g in bot_guilds}

def get_guild_or_404(guild_id):
    debug_print(f"Entering get_guild_or_404 with guild_id: {guild_id}", level="all")
    guild = db.get_guild(guild_id)
    if not guild:
        abort(404, "Bot not in server")
    return guild

def is_birthday_calendar_public(guild_id):
    """Check if the birthday calendar is public for a guild"""
    try:
        config = db.get_birthday_config(guild_id)
        return config.get('public_calendar', False)
    except Exception:
        return False
    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        debug_print(f"Entering admin_required wrapper for {f.__name__}", level="all")
        if not session.get('admin'):
            abort(403, description="Admin privileges required")
        return f(*args, **kwargs)
    return decorated_function

def head_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        debug_print(f"Entering head_admin_required wrapper for {f.__name__}", level="all")
        if not session.get('head_admin'):
            abort(403, "Head admin privileges required")
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_admin_status():
    debug_print("Entering inject_admin_status", level="all")
    def check_head_admin():
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
    'fun-miscellaneous/birthdays.json': lambda guild_id: db.get_guild_birthdays(guild_id),
    'fun-miscellaneous/birthday-config.json': lambda guild_id: db.get_birthday_config(guild_id),
    'backup-restore/backup-schedules.json': lambda guild_id: get_backup_schedules(guild_id),
    'minecraft-servers/crafty-instances.json': lambda guild_id: db.get_crafty_instances(guild_id),
    'minecraft-servers/crafty-servers.json': lambda guild_id: db.get_guild_crafty_servers(guild_id),
    'minecraft-servers/crafty-permissions.json': lambda guild_id: db.execute_query('SELECT cp.* FROM crafty_permissions cp JOIN crafty_servers cs ON cp.crafty_server_id = cs.id JOIN crafty_instances ci ON cs.crafty_instance_id = ci.id WHERE ci.guild_id = ?', (guild_id,), fetch='all'),
    'minecraft-servers/cloudflare-config.json': lambda guild_id: db.get_cloudflare_config(guild_id) or {},
    'minecraft-servers/dns-records.json': lambda guild_id: db.get_minecraft_dns_records(guild_id),
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
def check_ip_ban():
    """Check if the requesting IP is banned"""
    debug_print("Entering check_ip_ban", level="all")
    real_ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    
    # Skip IP check for certain routes (static files, etc.)
    if request.endpoint and request.endpoint.startswith('static'):
        return None
    
    # Check if IP is banned
    if db.is_ip_banned(real_ip):
        ban_info = db.get_ip_ban_info(real_ip)
        logger.warning(f"Blocked request from banned IP: {real_ip}")
        
        # Return a simple forbidden page
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: #f5f5f5;
                    }
                    .container {
                        text-align: center;
                        padding: 40px;
                        background: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                        max-width: 500px;
                    }
                    h1 { color: #d32f2f; }
                    p { color: #666; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🚫 Access Denied</h1>
                    <p>Your IP address has been banned from accessing this service.</p>
                    {% if ban_info and ban_info.reason %}
                    <p><strong>Reason:</strong> {{ ban_info.reason }}</p>
                    {% endif %}
                    {% if ban_info and ban_info.expires_at %}
                    <p><strong>Expires:</strong> {{ ban_info.expires_at }}</p>
                    {% endif %}
                </div>
            </body>
            </html>
        ''', ban_info=ban_info), 403

@app.before_request
def refresh_session():
    debug_print("Entering refresh_session", level="all")
    # Ensure all requests get a session cookie
    session.permanent = True
    if 'user' not in session and 'admin' not in session:
        if not session.get('_anon_session'):
            session['_anon_session'] = str(uuid.uuid4())
            session.modified = True
    
    # Check MFA verification timeout (4 hours)
    if session.get('mfa_verified') and session.get('mfa_verified_at'):
        if int(time.time()) - session['mfa_verified_at'] > 14400:  # 4 hours
            session.pop('mfa_verified', None)
            session.pop('mfa_verified_at', None)
            # Only show flash message for non-exempt routes
            if (session.get('user') and not session.get('admin') and not session.get('head_admin') 
                and request.endpoint not in ['logout', 'login', 'mfa_verify_required', 'index', 
                                           'privacy_policy', 'terms_of_service', 'end_user_license_agreement']):
                flash('MFA verification has expired. Please verify again.', 'warning')
def log_real_ip():
    debug_print("Entering log_real_ip", level="all")
    real_ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    debug_print(f"Real IP: {real_ip} -> Path: {request.path}")

# Routes
@app.route('/')
def index():
    debug_print("Entering index route", level="all")
    mfa_status = None
    mfa_type = None
    
    # Check MFA status for logged-in users
    if session.get('user'):
        user_id = session['user']['id']
        mfa_enabled = db.is_mfa_enabled(user_id)
        mfa_verified = session.get('mfa_verified', False)
        
        if mfa_enabled:
            mfa_data = db.execute_query('SELECT mfa_type FROM user_mfa WHERE user_id = ?', (user_id,), fetch='one')
            mfa_type = mfa_data['mfa_type'] if mfa_data else None
            mfa_status = 'verified' if mfa_verified else 'pending'
        else:
            mfa_status = 'disabled'
    
    return render_template('index.html', mfa_status=mfa_status, mfa_type=mfa_type)

@app.route("/privacy-policy")
def privacy_policy():
    debug_print("Entering privacy_policy route", level="all")
    return render_template("privacy.html")

@app.route("/terms-of-service")
def terms_of_service():
    debug_print("Entering terms_of_service route", level="all")
    return render_template("terms.html")
    
@app.route("/end-user-license-agreement")
def end_user_license_agreement():
    debug_print("Entering end_user_license_agreement route", level="all")
    return render_template("eula.html")

@app.route('/login')
def login():
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
    debug_print("Entering login_admin route", level="all")
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
            
            flash('Invalid credentials')
            return redirect(url_for('login_admin'))
        
        except CSRFError:
            flash('Security token expired')
            return redirect(url_for('login_admin'))
    
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    debug_print("Entering logout route", level="all")
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('login'))
    
@app.route('/admin/logout')
@login_required
def logout_admin():
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
        
        # Check if user has MFA enabled and redirect accordingly
        user_id = str(user.id)
        try:
            if db.is_mfa_enabled(user_id):
                # MFA is enabled but not verified in this session
                session['mfa_redirect_url'] = url_for('select_guild')
                flash('MFA verification is required to continue.', 'info')
                return redirect(url_for('mfa_verify_required'))
        except Exception as e:
            # Log the error but continue login if there's a database issue
            logger.error(f"Error checking MFA status during login for user {user_id}: {str(e)}")
        
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
    debug_print("Entering delete_my_data route", level="all")
    
    # Double-check session has user data
    if 'user' not in session or 'id' not in session['user']:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('login'))
    
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

# Settings page route
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    # Handle different login types (user vs admin)
    if session.get('user'):
        user_id = session['user']['id']
    elif session.get('admin') or session.get('head_admin'):
        # For admins, we'll use a placeholder user_id or skip MFA features
        user_id = None
    else:
        # Fallback - shouldn't happen due to @login_required
        flash('Unable to determine user identity.', 'error')
        return redirect(url_for('select_guild'))
    
    mfa_error = None
    
    # Get current MFA status (only for regular users, not admins)
    if user_id:
        mfa_methods = db.get_mfa_methods(user_id)
    else:
        # Admins don't need MFA features in settings
        mfa_methods = {
            'totp_enabled': False,
            'email_enabled': False,
            'any_enabled': False
        }
    
    if request.method == 'POST':
        # MFA operations are only available for regular users, not admins
        if not user_id and ('disable_all_mfa' in request.form or 'enable_totp' in request.form or 
                           'disable_totp' in request.form or 'enable_email' in request.form or 
                           'disable_email' in request.form):
            flash('MFA features are not available for admin accounts.', 'info')
            return redirect(url_for('settings'))
            
        if 'disable_all_mfa' in request.form and user_id:
            # Handle disabling all MFA
            if mfa_methods['any_enabled']:
                db.disable_all_mfa(user_id)
                # Clear MFA verification from session
                session.pop('mfa_verified', None)
                session.pop('mfa_verified_at', None)
                flash('All Multi-Factor Authentication methods have been disabled for your account.', 'warning')
                return redirect(url_for('settings'))
            else:
                flash('MFA is not currently enabled.', 'info')
        
        elif 'enable_totp' in request.form and user_id:
            # Handle TOTP setup
            secret = pyotp.random_base32()
            db.set_totp_secret(user_id, secret)
            db.set_totp_enabled(user_id, True)
            session['mfa_setup_secret'] = secret
            flash('Authenticator App (TOTP) MFA setup started. Scan the QR code on the verification page.', 'info')
            return redirect(url_for('mfa_verify', type='totp'))
        
        elif 'disable_totp' in request.form and user_id:
            # Handle TOTP disabling
            if mfa_methods['totp_enabled']:
                db.set_totp_enabled(user_id, False)
                flash('Authenticator App (TOTP) MFA has been disabled.', 'warning')
                return redirect(url_for('settings'))
            else:
                flash('TOTP MFA is not currently enabled.', 'info')
        
        elif 'enable_email' in request.form and user_id:
            # Handle Email MFA setup
            email = request.form.get('email', '').strip()
            if not email:
                mfa_error = 'Email address is required for email MFA.'
            else:
                otp = str(random.randint(100000, 999999))
                expiry = int(time.time()) + 600
                db.set_email_otp(user_id, email, otp, expiry)
                db.set_email_mfa_enabled(user_id, True)
                try:
                    msg = Message('Your MFA Code', recipients=[email])
                    msg.body = f"Your MFA verification code is: {otp}"
                    mail.send(msg)
                    flash(f'Email MFA verification code has been sent to {email}. Please check your email.', 'info')
                    return redirect(url_for('mfa_verify', type='email'))

                except Exception as e:
                    mfa_error = f'Failed to send email: {str(e)}'
        
        elif 'disable_email' in request.form and user_id:
            # Handle Email MFA disabling
            if mfa_methods['email_enabled']:
                db.set_email_mfa_enabled(user_id, False)
                flash('Email MFA has been disabled.', 'warning')
                return redirect(url_for('settings'))
            else:
                flash('Email MFA is not currently enabled.', 'info')
        
        elif request.form.get('action') == 'update_announcement_config':
            # Handle announcement configuration update
            guild_id = request.args.get('guild_id')
            if guild_id:
                try:
                    guild = get_guild_or_404(guild_id)
                    channel_id = request.form.get('announcement_channel_id') or None
                    role_id = request.form.get('announcement_role_id') or None
                    enabled = bool(request.form.get('announcement_enabled'))
                    
                    # Validate channel exists if provided
                    if channel_id:
                        try:
                            debug_print(f"Validating channel_id: {channel_id} (type: {type(channel_id)}) for guild {guild_id}")
                            
                            # Use the same channel fetching logic as our API endpoint
                            if guild_id in channel_cache:
                                channels_data = channel_cache[guild_id]
                                debug_print(f"Using cached channels for guild {guild_id}")
                            else:
                                debug_print(f"Fetching fresh channels for guild {guild_id}")
                                response = jwt_requests.get(f'{API_URL}/api/{guild_id}/channels')
                                debug_print(f"Bot API response status: {response.status_code}")
                                if response.status_code == 200:
                                    channels_response = response.json()
                                    channels_data = channels_response.get('channels', channels_response) if isinstance(channels_response, dict) else channels_response
                                    channel_cache[guild_id] = channels_data
                                    debug_print(f"Retrieved {len(channels_data)} channels from bot API")
                                else:
                                    debug_print(red(f"Failed to fetch channels: {response.status_code} - {response.text}"))
                                    channels_data = []
                            
                            # Log channel IDs for debugging
                            channel_ids = [str(c['id']) for c in channels_data]
                            debug_print(f"Available channel IDs: {channel_ids}")
                            debug_print(f"Looking for channel_id: '{channel_id}' in available channels")

                            # Check if the selected channel exists
                            channel_exists = any(str(c['id']) == str(channel_id) for c in channels_data)
                            debug_print(f"Channel exists: {channel_exists}")
                            
                            if not channel_exists:
                                debug_print(f"Channel {channel_id} not found in guild {guild_id}. Available channels: {[(c['id'], c['name']) for c in channels_data]}")
                                flash('Selected channel not found. Please select a valid channel.', 'danger')
                                return redirect(url_for('settings', guild_id=guild_id))
                        except Exception as e:
                            debug_print(red(f"Error validating channel: {str(e)}"))
                            flash('Error validating channel. Please try again.', 'danger')
                            return redirect(url_for('settings', guild_id=guild_id))
                    
                    # Validate role exists if provided
                    if role_id:
                        try:
                            response = jwt_requests.get(f'{API_URL}/api/{guild_id}/roles')
                            if response.status_code == 200:
                                roles_data = response.json()
                                # Handle both direct array and wrapped response
                                roles = roles_data.get('roles', roles_data) if isinstance(roles_data, dict) else roles_data
                                role_exists = any(str(r['id']) == str(role_id) for r in roles)
                                if not role_exists:
                                    flash('Selected role not found. Please select a valid role.', 'danger')
                                    return redirect(url_for('settings', guild_id=guild_id))
                            else:
                                flash('Error validating role. Please try again.', 'danger')
                                return redirect(url_for('settings', guild_id=guild_id))
                        except Exception as e:
                            logger.error(f"Error validating role: {str(e)}")
                            flash('Error validating role. Please try again.', 'danger')
                            return redirect(url_for('settings', guild_id=guild_id))
                    
                    db.set_announcement_config(guild_id, channel_id, enabled, role_id)
                    
                    if enabled and channel_id:
                        flash('Announcement settings updated successfully!', 'success')
                    elif enabled and not channel_id:
                        flash('Announcements enabled, but no channel selected. Please select a channel to receive announcements.', 'warning')
                    else:
                        flash('Announcements disabled for this server.', 'info')
                    
                    return redirect(url_for('settings', guild_id=guild_id))
                    
                except Exception as e:
                    logger.error(f"Error updating announcement config: {str(e)}")
                    flash('Error updating announcement settings. Please try again.', 'danger')
                    return redirect(url_for('settings', guild_id=guild_id))
    
    # Handle GET requests or POST requests with errors
    # If user is an admin, give them access to all bot guilds; otherwise just their personal guilds
    if session.get('admin'):
        # Admin users can access all guilds the bot is in
        guild_data = db.execute_query('''
            SELECT guild_id as id, name FROM guilds ORDER BY name
        ''', fetch='all')
        guilds = [{'id': str(g['id']), 'name': g['name']} for g in guild_data]
    else:
        # Regular users only see guilds they personally belong to
        user_guilds = get_user_guilds()
        guilds = [{
            'id': str(g.id),
            'name': g.name
        } for g in user_guilds]
    
    selected_guild_id = request.args.get('guild_id') or (guilds[0]['id'] if guilds else None)
    
    # Get announcement config and channels for selected guild
    announcement_config = None
    channels = []
    roles = []
    if selected_guild_id:
        try:
            announcement_config = db.get_announcement_config(selected_guild_id)
            
            # Get channels for the selected guild using the same API as validation
            try:
                if selected_guild_id in channel_cache:
                    channels_data = channel_cache[selected_guild_id]
                else:
                    response = jwt_requests.get(f'{API_URL}/api/{selected_guild_id}/channels')
                    if response.status_code == 200:
                        channels_response = response.json()
                        channels_data = channels_response.get('channels', channels_response) if isinstance(channels_response, dict) else channels_response
                        channel_cache[selected_guild_id] = channels_data
                    else:
                        channels_data = []
                
                # Filter for text channels only (same logic as API endpoint)
                channels = [ch for ch in channels_data if ch.get('type') == 0]
                channels.sort(key=lambda x: x.get('position', 0))
                debug_print(f"Got {len(channels)} channels for guild {selected_guild_id}")
            except Exception as e:
                debug_print(red(f"Error getting channels for guild {selected_guild_id}: {str(e)}"))
                channels = []
            
            # Get roles for the selected guild
            response = jwt_requests.get(f'{API_URL}/api/{selected_guild_id}/roles')
            if response.status_code == 200:
                roles = response.json()
                debug_print(f"Got {len(roles)} roles for guild {selected_guild_id}")
            else:
                debug_print(red(f"Failed to get roles for guild {selected_guild_id}: {response.status_code}"))
                roles = []
        except Exception as e:
            debug_print(red(f"Error getting announcement config, channels, or roles: {str(e)}"))
            channels = []
            roles = []
    else:
        debug_print("No guild selected for announcements")
    
    # Check if admin can manage settings
    can_manage_settings = False
    if session.get('head_admin'):
        can_manage_settings = True
    elif session.get('admin'):
        admin_privileges = db.get_admin_privileges(session.get('admin_username', ''))
        can_manage_settings = admin_privileges and admin_privileges.get('can_manage_settings', False)
    
    return render_template('settings.html',
        guilds=guilds,
        selected_guild_id=selected_guild_id,
        export_map=EXPORT_MAP,
        mfa_error=mfa_error,
        mfa_methods=mfa_methods,
        announcement_config=announcement_config,
        channels=channels,
        roles=roles,
        is_admin=session.get('admin', False),
        is_head_admin=session.get('head_admin', False),
        can_manage_settings=can_manage_settings
    )

@app.route('/mfa/qr')
@login_required
def mfa_qr():
    user_id = session['user']['id']
    secret = session.get('mfa_setup_secret') or db.get_totp_secret(user_id)
    if not secret:
        flash('No TOTP secret found. Please start setup.', 'danger')
        return redirect(url_for('settings'))
    # Generate QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=f"{user_id}@RuleKeeper", issuer_name="RuleKeeper")
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/mfa/verify', methods=['GET', 'POST'])
@login_required
def mfa_verify():
    user_id = session['user']['id']
    mfa_type = request.args.get('type', 'totp')
    error = None
    secret = None
    
    # Get secret for TOTP setup
    if mfa_type == 'totp':
        secret = session.get('mfa_setup_secret') or db.get_totp_secret(user_id)
        if not secret:
            flash('No TOTP secret found. Please start MFA setup again.', 'danger')
            return redirect(url_for('settings'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        if mfa_type == 'totp':
            secret = db.get_totp_secret(user_id)
            totp = pyotp.TOTP(secret)
            if db.is_mfa_rate_limited(user_id, 'totp'):
                error = 'Too many attempts. Please try again later.'
            elif totp.verify(code):
                db.log_mfa_attempt(user_id, 'totp', True)
                db.set_totp_enabled(user_id, True)
                # Clear the setup secret from session since MFA is now enabled
                session.pop('mfa_setup_secret', None)
                # Mark MFA as verified in this session
                session['mfa_verified'] = True
                session['mfa_verified_at'] = int(time.time())
                flash('Authenticator App (TOTP) MFA has been successfully enabled for your account!', 'success')
                return redirect(url_for('settings'))
            else:
                db.log_mfa_attempt(user_id, 'totp', False)
                error = 'Invalid code.'
        elif mfa_type == 'email':
            otp_row = db.get_email_otp(user_id)
            if not otp_row or int(time.time()) > otp_row['email_otp_expiry']:
                error = 'OTP expired. Please request a new one.'
            elif db.is_mfa_rate_limited(user_id, 'email'):
                error = 'Too many attempts. Please try again later.'
            elif code == otp_row['email_otp']:
                db.log_mfa_attempt(user_id, 'email', True)
                db.set_email_mfa_enabled(user_id, True)
                db.clear_email_otp(user_id)
                # Mark MFA as verified in this session
                session['mfa_verified'] = True
                session['mfa_verified_at'] = int(time.time())
                flash('Email MFA has been successfully enabled for your account!', 'success')
                return redirect(url_for('settings'))
            else:
                db.log_mfa_attempt(user_id, 'email', False)
                error = 'Invalid code.'
    return render_template('mfa_verify.html', mfa_type=mfa_type, error=error, secret=secret)

@app.route('/mfa/verify-required', methods=['GET', 'POST'])
def mfa_verify_required():
    """MFA verification required to access protected pages"""
    if not session.get('user'):
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))
    
    user_id = session['user']['id']
    
    # Check if MFA is actually enabled for this user
    mfa_methods = db.get_mfa_methods(user_id)
    if not mfa_methods['any_enabled']:
        flash('MFA is not enabled for your account.', 'info')
        return redirect(url_for('index'))
    
    # Determine which method to use - allow user to choose or default to TOTP if available
    mfa_type = request.args.get('type') or request.form.get('mfa_method')
    
    # Default to TOTP if available, otherwise email
    if not mfa_type:
        if mfa_methods['totp_enabled']:
            mfa_type = 'totp'
        elif mfa_methods['email_enabled']:
            mfa_type = 'email'
        else:
            flash('No MFA methods are properly configured.', 'danger')
            return redirect(url_for('index'))
    
    # Validate the chosen method is actually enabled
    if mfa_type == 'totp' and not mfa_methods['totp_enabled']:
        flash('TOTP MFA is not enabled for your account.', 'warning')
        return redirect(url_for('mfa_verify_required'))
    elif mfa_type == 'email' and not mfa_methods['email_enabled']:
        flash('Email MFA is not enabled for your account.', 'warning')
        return redirect(url_for('mfa_verify_required'))
    
    error = None
    secret = None
    
    # Get secret for TOTP display
    if mfa_type == 'totp':
        secret = db.get_totp_secret(user_id)
        if not secret:
            flash('TOTP MFA setup is incomplete. Please reconfigure in settings.', 'danger')
            return redirect(url_for('settings'))
    
    if request.method == 'POST':
        # Handle sending email verification code
        if mfa_type == 'email' and 'send_email_code' in request.form:
            email_data = db.execute_query('SELECT email FROM user_mfa WHERE user_id = ?', (user_id,), fetch='one')
            if not email_data or not email_data['email']:
                error = 'Email MFA is not properly configured.'
            else:
                # Generate and send new OTP
                otp = str(random.randint(100000, 999999))
                expiry = int(time.time()) + 600  # 10 minutes
                db.set_email_otp(user_id, email_data['email'], otp, expiry)
                
                try:
                    msg = Message('MFA Verification Required', recipients=[email_data['email']])
                    msg.body = f"Your MFA verification code is: {otp}\n\nThis code will expire in 10 minutes."
                    mail.send(msg)
                    flash(f'Verification code sent to {email_data["email"]}', 'info')
                    # Stay on the same page to show code input
                    return redirect(url_for('mfa_verify_required', type='email'))
                except Exception as e:
                    error = f'Failed to send verification email: {str(e)}'
        
        # Handle code verification
        elif 'code' in request.form:
            code = request.form.get('code')
            if not code:
                error = 'Please enter a verification code.'
            elif mfa_type == 'totp':
                secret = db.get_totp_secret(user_id)
                if not secret:
                    error = 'TOTP MFA is not properly configured.'
                else:
                    totp = pyotp.TOTP(secret)
                    if db.is_mfa_rate_limited(user_id, 'totp'):
                        error = 'Too many attempts. Please try again later.'
                    elif totp.verify(code):
                        db.log_mfa_attempt(user_id, 'totp', True)
                        session['mfa_verified'] = True
                        session['mfa_verified_at'] = int(time.time())
                        flash('MFA verification successful!', 'success')
                        
                        # Redirect to original destination or index
                        redirect_url = session.pop('mfa_redirect_url', url_for('index'))
                        return redirect(redirect_url)
                    else:
                        db.log_mfa_attempt(user_id, 'totp', False)
                        error = 'Invalid verification code.'
            elif mfa_type == 'email':
                otp_row = db.get_email_otp(user_id)
                if not otp_row or int(time.time()) > otp_row['email_otp_expiry']:
                    error = 'Verification code expired. Please request a new one.'
                elif db.is_mfa_rate_limited(user_id, 'email'):
                    error = 'Too many attempts. Please try again later.'
                elif code == otp_row['email_otp']:
                    db.log_mfa_attempt(user_id, 'email', True)
                    db.clear_email_otp(user_id)
                    session['mfa_verified'] = True
                    session['mfa_verified_at'] = int(time.time())
                    flash('MFA verification successful!', 'success')
                    
                    # Redirect to original destination or index
                    redirect_url = session.pop('mfa_redirect_url', url_for('index'))
                    return redirect(redirect_url)
                else:
                    db.log_mfa_attempt(user_id, 'email', False)
                    error = 'Invalid verification code.'
    
    return render_template('mfa_verify_required.html', 
                         mfa_type=mfa_type, 
                         mfa_methods=mfa_methods,
                         error=error, 
                         secret=secret)

@app.route('/guilds')
@login_required
def select_guild():
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
    debug_print(f"Entering get_guild_audit_log route with guild_id: {guild_id}", level="all")
    """Fetch and display the audit log for a guild via the bot's webserver API."""
    try:
        csrf.protect()
        guild = get_guild_or_404(guild_id)
        api_url = f"{API_URL}/api/get_guild_audit_log"
        resp = jwt_requests.post(api_url, json={"guild_id": str(guild_id)}, timeout=10)
        data = resp.json()
        if resp.status_code == 200 and "log" in data:
            audit_log = data["log"]
            return render_template('guild_audit_log.html', guild=guild, guild_id=guild_id, audit_log=audit_log)
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

    # Version check for update notification
    update_info = check_for_update()

    return render_template('admin_dashboard.html',
                         guild_count=guild_count,
                         admin_count=admin_count,
                         submission_count=submission_count,
                         recent_logs=recent_logs,
                         update_info=update_info)

@app.route('/admin/audit-log')
@admin_required
def admin_audit_log():
    debug_print("Entering admin_audit_log route", level="all")
    
    # Get pagination parameters
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    
    # Build the base query
    base_query = '''
        SELECT action, details, changes, user_id, timestamp 
        FROM audit_log 
    '''
    
    conditions = []
    params = []
    
    # Add filters
    if action_filter:
        conditions.append('action LIKE ?')
        params.append(f'%{action_filter}%')
    
    if user_filter:
        conditions.append('user_id LIKE ?')
        params.append(f'%{user_filter}%')
    
    # Add WHERE clause if there are conditions
    if conditions:
        base_query += ' WHERE ' + ' AND '.join(conditions)
    
    # Get total count
    count_query = f'SELECT COUNT(*) as total FROM ({base_query})'
    total_result = db.execute_query(count_query, params, fetch='one')
    total_logs = total_result['total'] if total_result else 0
    
    # Calculate pagination
    total_pages = (total_logs + per_page - 1) // per_page
    offset = (page - 1) * per_page
    
    # Get paginated results
    paginated_query = base_query + ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
    logs = db.execute_query(paginated_query, params + [per_page, offset], fetch='all')
    
    # Get unique actions for filter dropdown
    unique_actions = db.execute_query(
        'SELECT DISTINCT action FROM audit_log ORDER BY action',
        fetch='all'
    )
    
    return render_template('admin_audit_log.html',
                         logs=logs,
                         current_page=page,
                         total_pages=total_pages,
                         per_page=per_page,
                         total_logs=total_logs,
                         action_filter=action_filter,
                         user_filter=user_filter,
                         unique_actions=unique_actions)

@app.route('/admin/announcements')
@admin_required
def admin_announcements():
    debug_print("Entering admin_announcements route", level="all")
    # Check if current admin can send announcements
    can_send_announcements = False
    if session.get('admin'):
        if session.get('head_admin'):
            can_send_announcements = True
        else:
            admin_privileges = db.get_admin_privileges(session.get('admin_username', ''))
            can_send_announcements = admin_privileges and admin_privileges.get('can_send_announcements', False)
    
    # Get recent announcements
    recent_announcements = db.execute_query('''
        SELECT guild_id, message_content, sent_by, sent_at 
        FROM announcements 
        ORDER BY sent_at DESC 
        LIMIT 20
    ''', fetch='all')
    
    return render_template('admin_announcements.html',
                         can_send_announcements=can_send_announcements,
                         recent_announcements=recent_announcements)

@app.route('/admin/bot-admins', methods=['GET', 'POST'])
@head_admin_required
def manage_bot_admins():
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
           COALESCE(ap.can_remove_bot, 0) AS can_remove_bot,
           COALESCE(ap.can_send_announcements, 1) AS can_send_announcements,
           COALESCE(ap.can_manage_settings, 0) AS can_manage_settings
        FROM bot_admins ba
        LEFT JOIN admin_privileges ap ON ba.username = ap.username''',
        fetch='all'
    )
    
    return render_template('manage_bot_admins.html', admins=admins)

@app.route('/admin/ip-bans', methods=['GET', 'POST'])
@head_admin_required
def manage_ip_bans():
    """Manage IP bans - Head Admin only"""
    debug_print("Entering manage_ip_bans route", level="all")
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add':
            ip_address = request.form.get('ip_address', '').strip()
            reason = request.form.get('reason', '').strip()
            expires_at = request.form.get('expires_at', '').strip() or None
            
            if not ip_address or not reason:
                flash('IP address and reason are required', 'danger')
            else:
                try:
                    # Basic IP validation
                    import ipaddress
                    ipaddress.ip_address(ip_address)
                    
                    admin_identity = f"HEAD-ADMIN:{os.getenv('HEAD_BOT_ADMIN_USERNAME')}"
                    db.add_ip_ban(ip_address, reason, admin_identity, expires_at)
                    
                    log_action(
                        action="IP_BAN_ADDED",
                        details=f"Banned IP: {ip_address}",
                        changes=f"Reason: {reason}, Expires: {expires_at or 'Never'}"
                    )
                    
                    flash(f'Successfully banned IP: {ip_address}', 'success')
                except ValueError:
                    flash('Invalid IP address format', 'danger')
                except Exception as e:
                    flash(f'Error adding IP ban: {str(e)}', 'danger')
                    logger.error(f"Error adding IP ban: {str(e)}")
        
        elif action == 'remove':
            ban_id = request.form.get('ban_id')
            if ban_id:
                try:
                    # Get IP info before removing for logging
                    ban_info = db.execute_query(
                        'SELECT ip_address FROM banned_ips WHERE id = ?',
                        (ban_id,),
                        fetch='one'
                    )
                    
                    db.remove_ip_ban(ban_id=int(ban_id))
                    
                    if ban_info:
                        log_action(
                            action="IP_BAN_REMOVED",
                            details=f"Unbanned IP: {ban_info['ip_address']}",
                            changes=""
                        )
                    
                    flash('IP ban removed successfully', 'success')
                except Exception as e:
                    flash(f'Error removing IP ban: {str(e)}', 'danger')
                    logger.error(f"Error removing IP ban: {str(e)}")
        
        return redirect(url_for('manage_ip_bans'))
    
    # GET request - display all bans
    try:
        # Deactivate expired bans first
        db.deactivate_expired_ip_bans()
        
        # Get all active bans
        bans = db.get_all_ip_bans(include_expired=False)
        
        # Get recently expired bans for reference
        all_bans = db.get_all_ip_bans(include_expired=True)
        expired_bans = [b for b in all_bans if not b['is_active']][:10]  # Last 10 expired
        
        return render_template('manage_ip_bans.html', 
                             bans=bans, 
                             expired_bans=expired_bans)
    except Exception as e:
        logger.error(f"Error loading IP bans: {str(e)}")
        flash(f'Error loading IP bans: {str(e)}', 'danger')
        return render_template('manage_ip_bans.html', bans=[], expired_bans=[])

@app.route('/admin/user-guild-bans', methods=['GET', 'POST'])
def manage_user_guild_bans():
    """Manage user and guild bans - Head Admin or admins with ban_users_guilds privilege"""
    debug_print("Entering manage_user_guild_bans route", level="all")
    
    # Check permissions
    can_ban = False
    if session.get('head_admin'):
        can_ban = True
    elif session.get('admin'):
        admin_privileges = db.get_admin_privileges(session.get('admin_username', ''))
        can_ban = admin_privileges and admin_privileges.get('can_ban_users_guilds', False)
    
    if not can_ban:
        abort(403)
    
    if request.method == 'POST':
        action = request.form.get('action')
        ban_type = request.form.get('ban_type')  # 'user' or 'guild'
        
        admin_identity = f"HEAD-ADMIN:{os.getenv('HEAD_BOT_ADMIN_USERNAME')}" if session.get('head_admin') else f"BOT-ADMIN:{session.get('admin_username', 'unknown')}"
        
        if action == 'add':
            reason = request.form.get('reason', '').strip()
            expires_at = request.form.get('expires_at', '').strip() or None
            
            if not reason:
                flash('Reason is required', 'danger')
            elif ban_type == 'user':
                user_id = request.form.get('user_id', '').strip()
                username = request.form.get('username', '').strip()
                
                if not user_id:
                    flash('User ID is required', 'danger')
                else:
                    try:
                        db.add_user_ban(user_id, reason, admin_identity, username, expires_at)
                        
                        log_action(
                            action="USER_BAN_ADDED",
                            details=f"Banned User: {username or user_id} (ID: {user_id})",
                            changes=f"Reason: {reason}, Expires: {expires_at or 'Never'}"
                        )
                        
                        flash(f'Successfully banned user: {username or user_id}', 'success')
                    except Exception as e:
                        flash(f'Error adding user ban: {str(e)}', 'danger')
                        logger.error(f"Error adding user ban: {str(e)}")
                        
            elif ban_type == 'guild':
                guild_id = request.form.get('guild_id', '').strip()
                guild_name = request.form.get('guild_name', '').strip()
                
                if not guild_id:
                    flash('Guild ID is required', 'danger')
                else:
                    try:
                        db.add_guild_ban(guild_id, reason, admin_identity, guild_name, expires_at)
                        
                        log_action(
                            action="GUILD_BAN_ADDED",
                            details=f"Banned Guild: {guild_name or guild_id} (ID: {guild_id})",
                            changes=f"Reason: {reason}, Expires: {expires_at or 'Never'}"
                        )
                        
                        flash(f'Successfully banned guild: {guild_name or guild_id}', 'success')
                        
                        # Check if bot is in the guild and make it leave
                        try:
                            import asyncio
                            guild_obj = shared.bot.get_guild(int(guild_id))
                            if guild_obj:
                                # Schedule the guild leave asynchronously
                                asyncio.create_task(guild_obj.leave())
                                flash(f'Bot is leaving the banned guild: {guild_obj.name}', 'info')
                        except Exception as leave_error:
                            logger.warning(f"Could not leave guild {guild_id}: {str(leave_error)}")
                                
                    except Exception as e:
                        flash(f'Error adding guild ban: {str(e)}', 'danger')
                        logger.error(f"Error adding guild ban: {str(e)}")
        
        elif action == 'remove':
            ban_id = request.form.get('ban_id')
            if ban_id and ban_type:
                try:
                    if ban_type == 'user':
                        # Get info before removing
                        ban_info = db.execute_query(
                            'SELECT user_id, username FROM banned_users WHERE id = ?',
                            (ban_id,),
                            fetch='one'
                        )
                        
                        db.remove_user_ban(ban_id=int(ban_id))
                        
                        if ban_info:
                            log_action(
                                action="USER_BAN_REMOVED",
                                details=f"Unbanned User: {ban_info.get('username') or ban_info['user_id']} (ID: {ban_info['user_id']})",
                                changes=""
                            )
                        
                        flash('User ban removed successfully', 'success')
                        
                    elif ban_type == 'guild':
                        # Get info before removing
                        ban_info = db.execute_query(
                            'SELECT guild_id, guild_name FROM banned_guilds WHERE id = ?',
                            (ban_id,),
                            fetch='one'
                        )
                        
                        db.remove_guild_ban(ban_id=int(ban_id))
                        
                        if ban_info:
                            log_action(
                                action="GUILD_BAN_REMOVED",
                                details=f"Unbanned Guild: {ban_info.get('guild_name') or ban_info['guild_id']} (ID: {ban_info['guild_id']})",
                                changes=""
                            )
                        
                        flash('Guild ban removed successfully', 'success')
                        
                except Exception as e:
                    flash(f'Error removing ban: {str(e)}', 'danger')
                    logger.error(f"Error removing ban: {str(e)}")
        
        return redirect(url_for('manage_user_guild_bans'))
    
    # GET request - display all bans
    try:
        # Deactivate expired bans
        db.deactivate_expired_user_bans()
        db.deactivate_expired_guild_bans()
        
        # Get all active bans
        user_bans = db.get_all_user_bans(include_expired=False)
        guild_bans = db.get_all_guild_bans(include_expired=False)
        
        # Get recently expired bans
        all_user_bans = db.get_all_user_bans(include_expired=True)
        all_guild_bans = db.get_all_guild_bans(include_expired=True)
        expired_user_bans = [b for b in all_user_bans if not b['is_active']][:10]
        expired_guild_bans = [b for b in all_guild_bans if not b['is_active']][:10]
        
        return render_template('manage_user_guild_bans.html',
                             user_bans=user_bans,
                             guild_bans=guild_bans,
                             expired_user_bans=expired_user_bans,
                             expired_guild_bans=expired_guild_bans)
    except Exception as e:
        logger.error(f"Error loading user/guild bans: {str(e)}")
        flash(f'Error loading bans: {str(e)}', 'danger')
        return render_template('manage_user_guild_bans.html',
                             user_bans=[], guild_bans=[],
                             expired_user_bans=[], expired_guild_bans=[])

@app.route('/admin/delete-bot-admin/<username>')
@head_admin_required
def delete_bot_admin(username):
    debug_print(f"Entering delete_bot_admin route with username: {username}", level="all")
    db.delete_bot_admin(username)
    
    log_action(
        action="BOT_ADMIN_DELETED",
        details=f"Deleted bot admin: {username}",
        changes=f"Bot Admin deleted with username: {username}"
    )
    
    flash('Bot admin deleted successfully', 'success')
    return redirect(url_for('manage_bot_admins'))

@app.route('/admin/api/<username>/update-privileges', methods=['POST'])
@head_admin_required
def update_privileges(username):
    debug_print(f"Entering update_privileges route with username: {username}", level="all")
    try:
        csrf.protect()
        privileges = {
            'manage_servers': 'manage_servers' in request.form,
            'edit_config': 'edit_config' in request.form,
            'remove_bot': 'remove_bot' in request.form,
            'send_announcements': 'send_announcements' in request.form,
            'manage_settings': 'manage_settings' in request.form,
            'ban_users_guilds': 'ban_users_guilds' in request.form
        }
        
        old_priv = db.get_admin_privileges(username) or {}
        db.update_admin_privileges(username, privileges)
        
        # Create human-readable changes
        changes = []
        for key in ['manage_servers', 'edit_config', 'remove_bot', 'send_announcements', 'manage_settings', 'ban_users_guilds']:
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

@app.route('/admin/api/guilds')
@admin_required
def admin_api_guilds():
    """API endpoint to get list of guilds for admin announcement interface"""
    debug_print("Entering admin_api_guilds route", level="all")
    try:
        # Check if admin can send announcements
        can_send = False
        if session.get('head_admin'):
            can_send = True
        else:
            admin_privileges = db.get_admin_privileges(session.get('admin_username', ''))
            can_send = admin_privileges and admin_privileges.get('can_send_announcements', False)
        
        if not can_send:
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        # Get all guilds from database
        guilds = db.get_all_guilds()
        guild_list = []
        
        for guild in guilds:
            # Check if guild has announcement channel configured
            config = db.get_announcement_config(guild['id'])
            if config and config.get('enabled', True):
                guild_list.append({
                    'id': guild['id'],
                    'name': guild['name'],
                    'has_announcement_channel': bool(config.get('channel_id'))
                })
        
        return jsonify(guild_list)
        
    except Exception as e:
        logger.error(f"Error in admin_api_guilds: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/api/guilds/<guild_id>/roles')
@admin_required
def admin_api_guild_roles(guild_id):
    """API endpoint to get roles for a specific guild"""
    debug_print(f"Entering admin_api_guild_roles route with guild_id: {guild_id}", level="all")
    try:
        # Check if admin can send announcements
        can_send = False
        if session.get('head_admin'):
            can_send = True
        else:
            admin_privileges = db.get_admin_privileges(session.get('admin_username', ''))
            can_send = admin_privileges and admin_privileges.get('can_send_announcements', False)
        
        if not can_send:
            return jsonify({'error': 'Insufficient permissions'}), 403
        
        # Get guild roles via bot API
        response = jwt_requests.get(f'{API_URL}/api/{guild_id}/roles')
        
        if response.status_code == 200:
            roles_data = response.json()
            # Filter out @everyone role and sort by position
            roles = [role for role in roles_data if role['name'] != '@everyone']
            roles.sort(key=lambda x: x.get('position', 0), reverse=True)
            return jsonify(roles)
        else:
            return jsonify({'error': 'Failed to fetch roles'}), response.status_code
        
    except Exception as e:
        logger.error(f"Error in admin_api_guild_roles: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/<guild_id>/roles')
@login_required
@guild_required
def get_guild_roles(guild_id):
    """API endpoint to get roles for a specific guild (for user settings)"""
    try:
        # Get guild roles via bot API
        response = jwt_requests.get(f'{API_URL}/api/{guild_id}/roles')
        
        if response.status_code == 200:
            roles_data = response.json()
            # Include @everyone for user settings and sort by position
            roles = roles_data.get('roles', roles_data) if isinstance(roles_data, dict) else roles_data
            # Sort roles by position (higher position = higher in hierarchy)
            if isinstance(roles, list):
                roles.sort(key=lambda x: x.get('position', 0), reverse=True)
            
            logger.info(f"Got {len(roles)} roles for guild {guild_id}")
            return jsonify({'roles': roles})
        else:
            logger.error(f"Failed to get roles for guild {guild_id}: {response.status_code}")
            return jsonify({'error': 'Failed to fetch roles'}), response.status_code
        
    except Exception as e:
        logger.error(f"Error getting roles for guild {guild_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/<guild_id>/channels')
@login_required
@guild_required
def get_guild_channels(guild_id):
    """API endpoint to get channels for a specific guild (for user settings)"""
    try:
        # Get guild channels from cache or API
        if guild_id in channel_cache:
            channels = channel_cache[guild_id]
        else:
            # Fetch from bot API
            response = jwt_requests.get(f'{API_URL}/api/{guild_id}/channels')
            if response.status_code == 200:
                channels_data = response.json()
                channels = channels_data.get('channels', channels_data) if isinstance(channels_data, dict) else channels_data
                # Cache the channels
                channel_cache[guild_id] = channels
            else:
                logger.error(f"Failed to get channels for guild {guild_id}: {response.status_code}")
                return jsonify({'error': 'Failed to fetch channels'}), response.status_code
        
        # Filter for text channels only (type 0) and sort by position
        text_channels = [ch for ch in channels if ch.get('type') == 0]
        text_channels.sort(key=lambda x: x.get('position', 0))
        
        logger.info(f"Got {len(text_channels)} text channels for guild {guild_id}")
        return jsonify({'channels': text_channels})
        
    except Exception as e:
        logger.error(f"Error getting channels for guild {guild_id}: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/api/send-announcement', methods=['POST'])
@admin_required
def admin_send_announcement():
    """API endpoint to send announcements"""
    debug_print("Entering admin_send_announcement route", level="all")
    try:
        # Check if admin can send announcements
        can_send = False
        admin_username = session.get('admin_username', 'unknown')
        if session.get('head_admin'):
            can_send = True
            admin_identity = f"HEAD-ADMIN:{admin_username}"
        else:
            admin_privileges = db.get_admin_privileges(admin_username)
            can_send = admin_privileges and admin_privileges.get('can_send_announcements', False)
            admin_identity = f"BOT-ADMIN:{admin_username}"
        
        if not can_send:
            return jsonify({'error': 'Insufficient permissions to send announcements'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        target_type = data.get('target_type')
        message = data.get('message', '').strip()
        guild_id = data.get('guild_id')
        
        if not target_type or not message:
            return jsonify({'error': 'Missing required fields'}), 400
        
        if len(message) > 2000:
            return jsonify({'error': 'Message too long (max 2000 characters)'}), 400
        
        # Helper function to format announcement message
        def format_announcement_message(message_text, role_id=None):
            if role_id:
                return f"📢 **Bot Announcement** <@&{role_id}>\n\n{message_text}"
            else:
                return f"📢 **Bot Announcement**\n\n{message_text}"
        
        # Send announcements based on target type
        success_count = 0
        error_count = 0
        errors = []
        
        if target_type == 'all':
            # Send to all servers with announcement channels
            guilds = db.get_all_guilds()
            for guild in guilds:
                try:
                    config = db.get_announcement_config(guild['id'])
                    if config and config.get('enabled', True) and config.get('channel_id'):
                        # Use configured role for this guild, or the specified role_id for specific announcements
                        announcement_role_id = config.get('role_id') if config.get('role_id') else None
                        announcement_content = format_announcement_message(message, announcement_role_id)
                        
                        # Send announcement via bot API
                        response = jwt_requests.post(
                            f'{API_URL}/api/{guild["id"]}/send-message',
                            json={
                                'channel_id': config['channel_id'],
                                'content': announcement_content
                            }
                        )
                        
                        if response.status_code == 200:
                            result = response.json()
                            db.log_announcement(
                                guild['id'], 
                                config['channel_id'], 
                                message, 
                                admin_identity,
                                result.get('message_id'),
                                True
                            )
                            success_count += 1
                        else:
                            error_msg = f"Failed to send to {guild['name']}: {response.status_code}"
                            errors.append(error_msg)
                            db.log_announcement(
                                guild['id'], 
                                config['channel_id'], 
                                message, 
                                admin_identity,
                                None,
                                False,
                                error_msg
                            )
                            error_count += 1
                            
                except Exception as e:
                    error_msg = f"Error sending to {guild['name']}: {str(e)}"
                    errors.append(error_msg)
                    error_count += 1
        
        elif target_type == 'specific':
            if not guild_id:
                return jsonify({'error': 'Guild ID required for specific announcements'}), 400
            
            try:
                # Verify guild exists and get config
                guild = db.get_guild(guild_id)
                if not guild:
                    return jsonify({'error': 'Guild not found'}), 404
                
                config = db.get_announcement_config(guild_id)
                if not config or not config.get('enabled', True):
                    return jsonify({'error': 'Announcements are disabled for this server'}), 400
                
                if not config.get('channel_id'):
                    return jsonify({'error': 'No announcement channel configured for this server'}), 400
                
                # Use guild's configured role for announcements
                announcement_role_id = config.get('role_id')
                announcement_content = format_announcement_message(message, announcement_role_id)
                
                # Send announcement
                response = jwt_requests.post(
                    f'{API_URL}/api/{guild_id}/send-message',
                    json={
                        'channel_id': config['channel_id'],
                        'content': announcement_content
                    }
                )
                
                if response.status_code == 200:
                    result = response.json()
                    db.log_announcement(
                        guild_id, 
                        config['channel_id'], 
                        message, 
                        admin_identity,
                        result.get('message_id'),
                        True
                    )
                    success_count = 1
                else:
                    error_msg = f"Failed to send announcement: {response.status_code}"
                    db.log_announcement(
                        guild_id, 
                        config['channel_id'], 
                        message, 
                        admin_identity,
                        None,
                        False,
                        error_msg
                    )
                    return jsonify({'error': error_msg}), 500
                    
            except Exception as e:
                logger.error(f"Error sending specific announcement: {str(e)}")
                return jsonify({'error': f'Error sending announcement: {str(e)}'}), 500
        
        else:
            return jsonify({'error': 'Invalid target type'}), 400
        
        # Log the action
        if target_type == 'all':
            log_action(
                action="ANNOUNCEMENT_SENT",
                details=f"Sent announcement to all servers (success: {success_count}, errors: {error_count})",
                changes=f"Message length: {len(message)} characters"
            )
            
            if error_count == 0:
                return jsonify({
                    'success': True,
                    'message': f'Announcement sent successfully to {success_count} server(s)'
                })
            else:
                return jsonify({
                    'success': True,
                    'message': f'Announcement sent to {success_count} server(s), {error_count} failed',
                    'errors': errors[:5]  # Limit error list
                })
        else:
            log_action(
                action="ANNOUNCEMENT_SENT",
                details=f"Sent announcement to {guild['name']}",
                changes=f"Message length: {len(message)} characters"
            )
            return jsonify({
                'success': True,
                'message': f'Announcement sent successfully to {guild["name"]}'
            })
        
    except Exception as e:
        logger.error(f"Error in admin_send_announcement: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin/api/users/<user_id>/mfa-status', methods=['GET'])
@admin_required
def admin_get_user_mfa_status(user_id):
    """Get MFA status for any user (Admins with Settings permission or Head Admin)"""
    debug_print(f"Entering admin_get_user_mfa_status for user_id: {user_id}", level="all")
    try:
        # Check permissions
        can_manage_settings = False
        if session.get('head_admin'):
            can_manage_settings = True
        else:
            admin_privileges = db.get_admin_privileges(session.get('admin_username', ''))
            can_manage_settings = admin_privileges and admin_privileges.get('can_manage_settings', False)
        
        if not can_manage_settings:
            return jsonify({'error': 'Insufficient permissions to manage settings'}), 403
            
        # Validate user_id format
        try:
            int(user_id)
        except ValueError:
            return jsonify({'error': 'Invalid user ID format'}), 400
            
        mfa_methods = db.get_mfa_methods(user_id)
        
        log_action(
            "MFA_STATUS_CHECKED",
            f"Checked MFA status for user {user_id}",
            f"TOTP: {'Enabled' if mfa_methods['totp_enabled'] else 'Disabled'}, Email: {'Enabled' if mfa_methods['email_enabled'] else 'Disabled'}"
        )
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'mfa_methods': mfa_methods
        })
        
    except Exception as e:
        logger.error(f"Error checking MFA status for user {user_id}: {str(e)}")
        return jsonify({'error': 'Failed to check MFA status'}), 500

@app.route('/admin/api/users/<user_id>/disable-mfa', methods=['POST'])
@admin_required
def admin_disable_user_mfa(user_id):
    """Disable all MFA for any user (Admins with Settings permission or Head Admin)"""
    debug_print(f"Entering admin_disable_user_mfa for user_id: {user_id}", level="all")
    try:
        # Check permissions
        can_manage_settings = False
        if session.get('head_admin'):
            can_manage_settings = True
        else:
            admin_privileges = db.get_admin_privileges(session.get('admin_username', ''))
            can_manage_settings = admin_privileges and admin_privileges.get('can_manage_settings', False)
        
        if not can_manage_settings:
            return jsonify({'error': 'Insufficient permissions to manage settings'}), 403
            
        # Validate user_id format
        try:
            int(user_id)
        except ValueError:
            return jsonify({'error': 'Invalid user ID format'}), 400
            
        # Get current MFA status before disabling
        current_mfa = db.get_mfa_methods(user_id)
        
        # Only proceed if user has MFA enabled
        if not current_mfa['any_enabled']:
            return jsonify({'error': 'User does not have MFA enabled'}), 400
            
        # Disable all MFA methods
        db.disable_all_mfa(user_id)
        
        # Log the admin action
        log_action(
            "ADMIN_DISABLED_USER_MFA",
            f"Disabled all MFA for user {user_id}",
            f"Previously enabled: TOTP: {'Yes' if current_mfa['totp_enabled'] else 'No'}, Email: {'Yes' if current_mfa['email_enabled'] else 'No'}"
        )
        
        return jsonify({
            'success': True,
            'message': f'Successfully disabled all MFA for user {user_id}',
            'user_id': user_id
        })
        
    except Exception as e:
        logger.error(f"Error disabling MFA for user {user_id}: {str(e)}")
        return jsonify({'error': 'Failed to disable MFA'}), 500

def log_action(action: str, details: str, changes: str = ""):
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
    debug_print(f"Entering guild_dashboard route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    return render_template('dashboard.html', guild=guild)

@app.route('/api/<guild_id>/remove-all-data', methods=['POST'])
@login_required
@guild_required
def remove_all_guild_data(guild_id):
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
        'give_xp_to_self': True,
        'cooldown_bypass_roles': [],
        'cooldown_bypass_users': []
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
            'give_xp_to_self': db_config.get('give_xp_to_self', default_config['give_xp_to_self']),
            'cooldown_bypass_roles': db_config.get('cooldown_bypass_roles', default_config['cooldown_bypass_roles']),
            'cooldown_bypass_users': db_config.get('cooldown_bypass_users', default_config['cooldown_bypass_users'])
        })
        
        # Ensure bypass lists are always lists, not strings
        if isinstance(merged_config['cooldown_bypass_roles'], str):
            try:
                merged_config['cooldown_bypass_roles'] = json.loads(merged_config['cooldown_bypass_roles'])
            except (json.JSONDecodeError, TypeError):
                merged_config['cooldown_bypass_roles'] = []
        
        if isinstance(merged_config['cooldown_bypass_users'], str):
            try:
                merged_config['cooldown_bypass_users'] = json.loads(merged_config['cooldown_bypass_users'])
            except (json.JSONDecodeError, TypeError):
                merged_config['cooldown_bypass_users'] = []
    
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
                'give_xp_to_self': bool(request.form.get('give_xp_to_self', False)),
                'cooldown_bypass_roles': request.form.get('cooldown_bypass_roles', '[]'),
                'cooldown_bypass_users': request.form.get('cooldown_bypass_users', '[]')
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

            # Validate cooldown bypass roles and users
            try:
                bypass_roles = json.loads(new_config['cooldown_bypass_roles'])
                if not isinstance(bypass_roles, list):
                    raise ValueError()
                # Validate role IDs exist
                valid_role_ids = [str(r['id']) for r in roles]
                new_config['cooldown_bypass_roles'] = [
                    r for r in bypass_roles if r in valid_role_ids
                ]
            except (json.JSONDecodeError, ValueError):
                flash('Invalid cooldown bypass roles format', 'danger')
                return redirect(url_for('level_config', guild_id=guild_id))

            try:
                bypass_users = json.loads(new_config['cooldown_bypass_users'])
                if not isinstance(bypass_users, list):
                    raise ValueError()
                # Basic validation that user IDs are strings/numbers
                new_config['cooldown_bypass_users'] = [
                    str(u) for u in bypass_users if str(u).isdigit()
                ]
            except (json.JSONDecodeError, ValueError):
                flash('Invalid cooldown bypass users format', 'danger')
                return redirect(url_for('level_config', guild_id=guild_id))

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
                "give_xp_to_self": new_config["give_xp_to_self"],
                # Convert bypass lists to JSON strings for storage
                "cooldown_bypass_roles": json.dumps(new_config["cooldown_bypass_roles"]),
                "cooldown_bypass_users": json.dumps(new_config["cooldown_bypass_users"])
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
                         roles=roles,
                         users=get_guild_users(guild_id))

# Auto Roles Management
@app.route('/dashboard/<guild_id>/auto-roles-config', methods=['GET', 'POST'])
@login_required
@guild_required
def auto_roles_config(guild_id):
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
        if not role_id:
            return ''
        for r in roles:
            if str(r['id']) == str(role_id):
                return f"<@&{r['id']}>"
        return ''
    def get_channel_name(channel_id):
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
        if not role_id:
            return ''
        for r in roles:
            if str(r['id']) == str(role_id):
                return f"<@&{r['id']}>"
        return ''
    def get_channel_name(channel_id):
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
    debug_print(f"Entering share_backup route with guild_id: {guild_id}, backup_id: {backup_id}", level="all")
    share_id = set_backup_share_id(backup_id, guild_id)
    flash(f'Share link created: {FRONTEND_URL}/backup/{share_id}', 'success')
    return redirect(url_for('guild_backups', guild_id=guild_id))

@app.route('/api/<guild_id>/backups/import', methods=['POST'])
@login_required
@guild_required
def import_backup(guild_id):
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
    debug_print(f"Entering public_backup_download route with share_id: {share_id}", level="all")
    backup = get_backup_by_share_id(share_id)
    if not backup or not os.path.exists(backup['file_path']):
        return "Backup not found or file missing.", 404
    return send_file(backup['file_path'], as_attachment=True)

@app.route('/dashboard/<guild_id>/backups/schedule', methods=['GET', 'POST'])
@login_required
@guild_required
def schedule_backup(guild_id):
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

# Restore Settings
@app.route('/dashboard/<guild_id>/restore-user-data', methods=['GET', 'POST'])
@login_required
@guild_required
def restore_user_data(guild_id):
    guild = get_guild_or_404(guild_id)
    settings = db.get_restore_settings(guild_id)
    
    # Fetch roles from Discord API
    roles = get_roles(guild_id)
    role_choices = [(r['id'], r['name']) for r in roles]

    if request.method == 'POST':
        restore_roles = bool(request.form.get('restore_roles'))
        restore_xp = bool(request.form.get('restore_xp'))
        restore_nickname = bool(request.form.get('restore_nickname'))
        excluded_roles = request.form.getlist('excluded_roles')
        db.update_restore_settings(guild_id, restore_roles, restore_xp, restore_nickname, excluded_roles)
        flash('Restore settings updated!', 'success')
        settings = db.get_restore_settings(guild_id)

    return render_template('restore_settings.html', guild=guild, settings=settings, role_choices=role_choices)

# Warnings Management
@app.route('/dashboard/<guild_id>/warnings')
@login_required
@guild_required
def warnings(guild_id):
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

# Birthday Management
@app.route('/dashboard/<guild_id>/birthdays')
@login_required
@birthday_calendar_access_required
def guild_birthdays(guild_id):
    debug_print(f"Entering guild_birthdays route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    
    try:
        # Get all birthdays for the guild
        birthdays = db.get_guild_birthdays(guild_id)
        
        # Get guild users for management purposes
        guild_users = get_guild_users(guild_id)
        
        return render_template('birthdays.html', 
                             guild=guild,
                             birthdays=birthdays,
                             guild_users=guild_users,
                             current_year=datetime.now().year)
    except Exception as e:
        debug_print(red(f"Error in guild_birthdays: {e}", level="all"))
        flash(f"Error loading birthdays: {str(e)}", "error")
        return redirect(url_for('guild_dashboard', guild_id=guild_id))

@app.route('/api/<guild_id>/birthdays', methods=['GET'])
@login_required
@birthday_calendar_access_required
def api_get_birthdays(guild_id):
    debug_print(f"Entering api_get_birthdays route with guild_id: {guild_id}", level="all")
    try:
        birthdays = db.get_guild_birthdays(guild_id)
        return jsonify({'success': True, 'birthdays': birthdays})
    except Exception as e:
        debug_print(red(f"Error in api_get_birthdays: {e}", level="all"))
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/<guild_id>/birthdays/<user_id>', methods=['PUT'])
@login_required
@guild_required
def api_update_birthday(guild_id, user_id):
    debug_print(f"Entering api_update_birthday route with guild_id: {guild_id}, user_id: {user_id}", level="all")
    try:
        data = request.get_json()
        username = data.get('username')
        month = data.get('month')
        day = data.get('day')
        year = data.get('year')  # Can be None
        
        # Check if birthday exists
        existing_birthday = db.get_user_birthday(guild_id, user_id)
        if not existing_birthday:
            return jsonify({'success': False, 'error': 'Birthday not found'}), 404
        
        # Validate date values if provided
        if month and not (1 <= int(month) <= 12):
            return jsonify({'success': False, 'error': 'Invalid month'}), 400
        
        if day and not (1 <= int(day) <= 31):
            return jsonify({'success': False, 'error': 'Invalid day'}), 400
        
        if year and year != '' and (int(year) < 1900 or int(year) > datetime.now().year):
            return jsonify({'success': False, 'error': 'Invalid year'}), 400
        
        # Handle year removal (empty string or 0)
        if year == '' or year == 0:
            year = None
        elif year:
            year = int(year)
        
        # Validate date combination if both month and day are provided
        if month and day:
            from datetime import date
            try:
                if year:
                    date(year, int(month), int(day))
                else:
                    date(2024, int(month), int(day))  # Use leap year for validation
            except ValueError:
                return jsonify({'success': False, 'error': 'Invalid date combination'}), 400
        
        # Update birthday
        db.update_user_birthday(guild_id, user_id, username, 
                              int(month) if month else None,
                              int(day) if day else None,
                              year)
        
        return jsonify({'success': True})
    except Exception as e:
        debug_print(red(f"Error in api_update_birthday: {e}", level="all"))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/<guild_id>/birthdays/<user_id>', methods=['DELETE'])
@login_required
@guild_required
def api_delete_birthday(guild_id, user_id):
    debug_print(f"Entering api_delete_birthday route with guild_id: {guild_id}, user_id: {user_id}", level="all")
    try:
        # Check if birthday exists
        existing_birthday = db.get_user_birthday(guild_id, user_id)
        if not existing_birthday:
            return jsonify({'success': False, 'error': 'Birthday not found'}), 404
        
        # Delete birthday
        db.remove_user_birthday(guild_id, user_id)
        
        return jsonify({'success': True})
    except Exception as e:
        debug_print(red(f"Error in api_delete_birthday: {e}", level="all"))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/<guild_id>/birthdays/upcoming')
@login_required
@birthday_calendar_access_required
def api_upcoming_birthdays(guild_id):
    debug_print(f"Entering api_upcoming_birthdays route with guild_id: {guild_id}", level="all")
    try:
        days_ahead = request.args.get('days', 7, type=int)
        if days_ahead < 1 or days_ahead > 365:
            return jsonify({'success': False, 'error': 'Days must be between 1 and 365'}), 400
        
        upcoming_birthdays = db.get_upcoming_birthdays(guild_id, days_ahead)
        
        return jsonify({'success': True, 'birthdays': upcoming_birthdays})
    except Exception as e:
        debug_print(red(f"Error in api_upcoming_birthdays: {e}", level="all"))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/<guild_id>/birthdays/month/<int:month>')
@login_required
@birthday_calendar_access_required
def api_birthdays_by_month(guild_id, month):
    debug_print(f"Entering api_birthdays_by_month route with guild_id: {guild_id}, month: {month}", level="all")
    try:
        if not (1 <= month <= 12):
            return jsonify({'success': False, 'error': 'Invalid month'}), 400
        
        month_birthdays = db.get_birthdays_by_month(guild_id, month)
        
        return jsonify({'success': True, 'birthdays': month_birthdays})
    except Exception as e:
        debug_print(red(f"Error in api_birthdays_by_month: {e}", level="all"))
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/dashboard/<guild_id>/birthday-config', methods=['GET', 'POST'])
@login_required
@guild_required
def birthday_configuration(guild_id):
    debug_print(f"Entering birthday_configuration route with guild_id: {guild_id}", level="all")
    guild = get_guild_or_404(guild_id)
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            # Update birthday configuration
            update_data = {}
            
            if 'birthday_message' in data:
                update_data['birthday_message'] = data['birthday_message']
            if 'birthday_channel_id' in data:
                update_data['birthday_channel_id'] = data['birthday_channel_id']
            if 'birthday_role_id' in data:
                update_data['birthday_role_id'] = data['birthday_role_id']
            if 'birthday_role_to_give_id' in data:
                update_data['birthday_role_to_give_id'] = data['birthday_role_to_give_id']
            if 'announce_birthdays' in data:
                update_data['announce_birthdays'] = bool(data['announce_birthdays'])
            if 'show_age' in data:
                update_data['show_age'] = bool(data['show_age'])
            if 'public_calendar' in data:
                update_data['public_calendar'] = bool(data['public_calendar'])
            if 'birthday_embed_enabled' in data:
                update_data['birthday_embed_enabled'] = bool(data['birthday_embed_enabled'])
            if 'birthday_embed_title' in data:
                update_data['birthday_embed_title'] = data['birthday_embed_title']
            if 'birthday_embed_color' in data:
                # Parse hex color to integer
                try:
                    color_hex = data['birthday_embed_color']
                    if color_hex.startswith('#'):
                        color_hex = color_hex[1:]
                    color_int = int(color_hex, 16)
                    update_data['birthday_embed_color'] = color_int
                except ValueError:
                    return jsonify({'success': False, 'error': 'Invalid color format'}), 400
            
            db.update_birthday_config(guild_id, **update_data)
            return jsonify({'success': True})
            
        except Exception as e:
            debug_print(red(f"Error updating birthday config: {e}", level="all"))
            return jsonify({'success': False, 'error': str(e)}), 500
    
    try:
        # Get current configuration
        config = db.get_birthday_config(guild_id)
        
        # Get guild channels and roles for dropdowns
        text_channels = get_text_channels(guild_id)
        roles = get_roles(guild_id)
        
        return render_template('birthday_config.html', 
                             guild=guild, 
                             config=config,
                             text_channels=text_channels,
                             roles=roles)
    except Exception as e:
        debug_print(red(f"Error in birthday_configuration: {e}", level="all"))
        flash(f"Error loading birthday configuration: {str(e)}", "error")
        return redirect(url_for('guild_dashboard', guild_id=guild_id))

# Crafty Controller & Cloudflare Routes
@app.route('/dashboard/<guild_id>/crafty-config', methods=['GET'])
@login_required
@guild_required
def crafty_config(guild_id):
    """Crafty Controller & Cloudflare configuration page"""
    debug_print(f"Entering crafty_config for guild: {guild_id}", level="all")
    
    try:
        guild = get_guild_or_404(guild_id)
        
        # Get Cloudflare configuration
        cloudflare_config = db.get_cloudflare_config(guild_id)
        
        # Get Crafty instances
        crafty_instances = db.get_crafty_instances(guild_id)
        
        # Get all Minecraft servers
        minecraft_servers = db.get_guild_crafty_servers(guild_id)
        
        # Get DNS records
        dns_records = db.get_minecraft_dns_records(guild_id)
        
        # Get server statuses
        server_statuses = {}
        if minecraft_servers:
            try:
                import asyncio
                from shared.crafty_api import CraftyManager
                crafty_manager = CraftyManager(db)
                server_statuses = asyncio.run(crafty_manager.get_servers_status(guild_id))
            except Exception as e:
                debug_print(red(f"Error getting server statuses: {str(e)}", level="all"))
                # If we can't get statuses, create empty dict so template doesn't break
                server_statuses = {server['id']: {'running': None, 'error': 'Status unavailable'} for server in minecraft_servers}
        
        # Get guild users and roles for permissions
        guild_users = get_guild_users(guild_id) or []
        guild_roles = get_roles(guild_id) or []
        
        # Sort users by name and roles by position
        guild_users.sort(key=lambda x: x.get('name', '').lower())
        if isinstance(guild_roles, list):
            # Filter out @everyone role and sort by position
            guild_roles = [role for role in guild_roles if role.get('name') != '@everyone']
            guild_roles.sort(key=lambda x: x.get('position', 0), reverse=True)
        
        return render_template('crafty_config.html',
                               guild=guild,
                               cloudflare_config=cloudflare_config,
                               crafty_instances=crafty_instances,
                               minecraft_servers=minecraft_servers,
                               dns_records=dns_records,
                               server_statuses=server_statuses,
                               guild_users=guild_users,
                               guild_roles=guild_roles)
                               
    except Exception as e:
        debug_print(red(f"Error in crafty_config: {str(e)}", level="all"))
        flash('Error loading Crafty configuration.', 'error')
        return redirect(url_for('guild_dashboard', guild_id=guild_id))

# Cloudflare API Routes
@app.route('/api/<guild_id>/crafty/cloudflare', methods=['POST'])
@login_required
@guild_required
def configure_cloudflare(guild_id):
    """Configure Cloudflare settings"""
    debug_print(f"Entering configure_cloudflare for guild: {guild_id}", level="all")
    
    try:
        api_token = request.form.get('api_token')
        zone_id = request.form.get('zone_id')
        domain = request.form.get('domain')
        enabled = bool(request.form.get('enabled'))
        
        if not api_token or not zone_id or not domain:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        # Test the configuration
        from shared.cloudflare_api import CloudflareAPIClient
        async def test_config():
            async with CloudflareAPIClient(api_token, zone_id) as client:
                return await client.test_connection()
        
        import asyncio
        if not asyncio.run(test_config()):
            return jsonify({'success': False, 'message': 'Failed to connect to Cloudflare with provided credentials'}), 400
        
        # Save configuration
        db.set_cloudflare_config(guild_id, api_token, zone_id, domain, enabled)
        
        log_action(
            action="CLOUDFLARE_CONFIG_UPDATED",
            details=f"Updated Cloudflare configuration for guild {guild_id}",
            changes=f"Domain: {domain}, Zone ID: {zone_id}, Enabled: {enabled}"
        )
        
        return jsonify({'success': True})
        
    except Exception as e:
        debug_print(red(f"Error in configure_cloudflare: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Configuration failed'}), 500

@app.route('/api/<guild_id>/crafty/cloudflare/test', methods=['POST'])
@login_required
@guild_required
def test_cloudflare_connection(guild_id):
    """Test Cloudflare connection"""
    debug_print(f"Entering test_cloudflare_connection for guild: {guild_id}", level="all")
    
    try:
        import asyncio
        success = asyncio.run(cloudflare_manager.test_guild_connection(guild_id))
        
        if success:
            return jsonify({'success': True, 'message': 'Connection successful'})
        else:
            return jsonify({'success': False, 'message': 'Connection failed'})
            
    except Exception as e:
        debug_print(red(f"Error testing Cloudflare connection: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Test failed'}), 500

@app.route('/api/<guild_id>/crafty/cloudflare/sync', methods=['POST'])
@login_required
@guild_required
def sync_cloudflare_records(guild_id):
    """Sync DNS records with Cloudflare"""
    debug_print(f"Entering sync_cloudflare_records for guild: {guild_id}", level="all")
    
    try:
        import asyncio
        success, message = asyncio.run(cloudflare_manager.sync_dns_records(guild_id))
        
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        debug_print(red(f"Error syncing DNS records: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Sync failed'}), 500

# Crafty Instance API Routes
@app.route('/api/<guild_id>/crafty/instances', methods=['POST'])
@login_required
@guild_required
def add_crafty_instance(guild_id):
    """Add a new Crafty instance"""
    debug_print(f"Entering add_crafty_instance for guild: {guild_id}", level="all")
    
    try:
        name = request.form.get('name')
        api_url = request.form.get('api_url')
        api_token = request.form.get('api_token')
        description = request.form.get('description', '')
        enabled = bool(request.form.get('enabled'))
        
        debug_print(f"Form data - name: {name}, api_url: {api_url}, description: {description}, enabled: {enabled}", level="all")
        
        if not name or not api_url or not api_token:
            debug_print(f"Missing required fields - name: {bool(name)}, api_url: {bool(api_url)}, api_token: {bool(api_token)}", level="all")
            return jsonify({'success': False, 'message': 'Name, API URL, and API token are required'}), 400
        
        # Test the connection
        from shared.crafty_api import CraftyAPIClient
        async def test_connection():
            async with CraftyAPIClient(api_url, api_token) as client:
                return await client.test_connection_detailed()
        
        import asyncio
        try:
            connection_success, connection_message = asyncio.run(test_connection())
            if not connection_success:
                debug_print(red(f"Connection test failed: {connection_message}", level="all"))
                return jsonify({'success': False, 'message': connection_message}), 400
            else:
                debug_print(f"Connection test successful: {connection_message}", level="all")
        except Exception as conn_e:
            debug_print(red(f"Connection test exception: {str(conn_e)}", level="all"))
            return jsonify({'success': False, 'message': f'Connection test failed: {str(conn_e)}'}), 400
        
        # Create the instance
        instance_id = db.create_crafty_instance(guild_id, name, api_url, api_token, description)
        db.update_crafty_instance(instance_id, enabled=enabled)
        
        log_action(
            action="CRAFTY_INSTANCE_ADDED",
            details=f"Added Crafty instance '{name}' for guild {guild_id}",
            changes=f"URL: {api_url}, Enabled: {enabled}, Description: {description or 'None'}"
        )
        
        return jsonify({'success': True})
        
    except Exception as e:
        debug_print(red(f"Error adding Crafty instance: {str(e)}"))
        return jsonify({'success': False, 'message': f'Failed to add instance: {str(e)}'}), 500

@app.route('/api/<guild_id>/crafty/instances/<int:instance_id>/test', methods=['POST'])
@login_required
@guild_required
def test_crafty_instance(guild_id, instance_id):
    """Test Crafty instance connection"""
    debug_print(f"Entering test_crafty_instance for guild: {guild_id}, instance: {instance_id}", level="all")
    
    try:
        import asyncio
        success, message = asyncio.run(crafty_manager.test_instance_connection_detailed(instance_id))
        
        return jsonify({'success': success, 'message': message})
            
    except Exception as e:
        debug_print(red(f"Error testing Crafty instance: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': f'Test failed: {str(e)}'}), 500
        return jsonify({'success': False, 'message': 'Test failed'}), 500

@app.route('/api/<guild_id>/crafty/instances/<int:instance_id>/sync', methods=['POST'])
@login_required
@guild_required
def sync_crafty_servers(guild_id, instance_id):
    """Sync servers from Crafty instance"""
    debug_print(f"Entering sync_crafty_servers for guild: {guild_id}, instance: {instance_id}", level="all")
    
    try:
        # Verify instance exists and belongs to guild
        instance = db.get_crafty_instance(instance_id)
        if not instance:
            return jsonify({'success': False, 'message': 'Crafty instance not found'}), 404
        
        if instance['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        import asyncio
        try:
            success, message = asyncio.run(crafty_manager.sync_servers_with_details(instance_id))
            
            if success:
                return jsonify({'success': True, 'message': message or 'Servers synced successfully'})
            else:
                return jsonify({'success': False, 'message': message or 'Failed to sync servers'})
        except Exception as sync_e:
            debug_print(red(f"Sync execution error: {str(sync_e)}", level="all"))
            return jsonify({'success': False, 'message': f'Sync failed: {str(sync_e)}'}), 500
            
    except Exception as e:
        debug_print(red(f"Error syncing Crafty servers: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': f'Sync failed: {str(e)}'}), 500

@app.route('/api/<guild_id>/crafty/instances/<int:instance_id>', methods=['DELETE'])
@login_required
@guild_required
def delete_crafty_instance(guild_id, instance_id):
    """Delete a Crafty instance"""
    debug_print(f"Entering delete_crafty_instance for guild: {guild_id}, instance: {instance_id}", level="all")
    
    try:
        # Get instance info for logging
        instance = db.get_crafty_instance(instance_id)
        if not instance:
            return jsonify({'success': False, 'message': 'Instance not found'}), 404
        
        if instance['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Access denied'}), 403
        
        # Delete the instance (cascades to servers and permissions)
        db.delete_crafty_instance(instance_id)
        
        log_action(
            action="CRAFTY_INSTANCE_DELETED",
            details=f"Deleted Crafty instance '{instance['name']}' from guild {guild_id}",
            changes=f"URL: {instance['api_url']}, Instance ID: {instance_id}"
        )
        
        return jsonify({'success': True})
        
    except Exception as e:
        debug_print(red(f"Error deleting Crafty instance: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to delete instance'}), 500

# Crafty Server API Routes
@app.route('/api/<guild_id>/crafty/servers/<int:server_id>/<action>', methods=['POST'])
@login_required
@guild_required
def crafty_server_action(guild_id, server_id, action):
    """Perform action on a Crafty server"""
    debug_print(f"Entering crafty_server_action for guild: {guild_id}, server: {server_id}, action: {action}", level="all")
    
    if action not in ['start', 'stop', 'restart']:
        return jsonify({'success': False, 'message': 'Invalid action'}), 400
    
    try:
        # Get server info
        server = db.get_crafty_server(server_id)
        if not server or server['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Server not found'}), 404
        
        # Check permissions
        user_id = session['user']['id']
        user_roles = []  # Get from Discord API in real implementation
        
        import asyncio
        success, message = asyncio.run(crafty_manager.perform_server_action(
            guild_id, server['server_name'], action, user_id, user_roles
        ))
        
        if success:
            log_action(
                action=f"CRAFTY_SERVER_{action.upper()}",
                details=f"{action.title()} server '{server['server_name']}' in guild {guild_id}",
                changes=f"User: {session['user']['username']}, Server ID: {server_id}"
            )
        
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        debug_print(red(f"Error performing server action: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Action failed'}), 500

@app.route('/api/<guild_id>/crafty/servers/<int:server_id>', methods=['DELETE'])
@login_required
@guild_required
def delete_crafty_server(guild_id, server_id):
    """Remove a Crafty server from the database"""
    debug_print(f"Entering delete_crafty_server for guild: {guild_id}, server: {server_id}", level="all")
    
    try:
        # Get server info for logging
        server = db.get_crafty_server(server_id)
        if not server or server['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Server not found'}), 404
        
        # Delete the server (cascades to permissions and DNS records)
        db.delete_crafty_server(server_id)
        
        log_action(
            action="CRAFTY_SERVER_DELETED",
            details=f"Removed Crafty server '{server['server_name']}' from guild {guild_id}",
            changes=f"Instance: {server['instance_name']}, Server ID: {server_id}"
        )
        
        return jsonify({'success': True})
        
    except Exception as e:
        debug_print(red(f"Error deleting Crafty server: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to remove server'}), 500

@app.route('/api/<guild_id>/crafty/servers/status', methods=['GET'])
@login_required
@guild_required
def get_crafty_servers_status(guild_id):
    """Get status for all Crafty servers in a guild"""
    debug_print(f"Entering get_crafty_servers_status for guild: {guild_id}", level="all")
    
    try:
        import asyncio
        from shared.crafty_api import CraftyManager
        crafty_manager = CraftyManager(db)
        server_statuses = asyncio.run(crafty_manager.get_servers_status(guild_id))
        
        return jsonify({'success': True, 'statuses': server_statuses})
        
    except Exception as e:
        debug_print(red(f"Error getting server statuses: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to get server statuses'}), 500

# DNS Record API Routes
@app.route('/api/<guild_id>/crafty/dns/<int:record_id>', methods=['GET', 'DELETE'])
@login_required
@guild_required
def delete_dns_record(guild_id, record_id):
    """Get or Delete a DNS record"""
    debug_print(f"Entering delete_dns_record for guild: {guild_id}, record: {record_id}, method: {request.method}", level="all")
    
    try:
        # Get record info
        record = db.get_minecraft_dns_record(record_id)
        debug_print(f"Retrieved DNS record: {record}", level="all")
        
        if not record:
            debug_print(f"DNS record {record_id} not found in database", level="all")
            return jsonify({'success': False, 'message': 'Record not found'}), 404
        
        if str(record.get('guild_id')) != str(guild_id):
            debug_print(f"Guild ID mismatch: record guild_id={record.get('guild_id')}, requested guild_id={guild_id}", level="all")
            return jsonify({'success': False, 'message': 'Record not found'}), 404
        
        # Handle GET request - return record details
        if request.method == 'GET':
            debug_print(f"Returning DNS record data for record {record_id}", level="all")
            return jsonify({
                'success': True,
                'record': {
                    'id': record.get('id'),
                    'hostname': record.get('hostname'),
                    'port': record.get('port'),
                    'priority': record.get('priority', 0),
                    'weight': record.get('weight', 5),
                    'crafty_server_id': record.get('crafty_server_id'),
                    'server_name': record.get('server_name', 'N/A'),
                    'instance_name': record.get('instance_name', 'N/A')
                }
            })
        
        # Handle DELETE request
        import asyncio
        success, message = asyncio.run(cloudflare_manager.delete_minecraft_srv_record(guild_id, record_id))
        
        if success:
            log_action(
                action="DNS_RECORD_DELETED",
                details=f"Deleted DNS record '{record['hostname']}' from guild {guild_id}",
                changes=f"Port: {record['port']}, Record ID: {record_id}"
            )
        
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        debug_print(red(f"Error with DNS record operation: {str(e)}", level="all"))
        import traceback
        debug_print(f"Traceback: {traceback.format_exc()}", level="all")
        return jsonify({'success': False, 'message': f'Failed to process record: {str(e)}'}), 500

# Instance Management API Routes
@app.route('/api/<guild_id>/crafty/instances/<int:instance_id>', methods=['PUT'])
@login_required
@guild_required
def update_crafty_instance(guild_id, instance_id):
    """Update Crafty instance details"""
    debug_print(f"Updating Crafty instance {instance_id} for guild: {guild_id}", level="all")
    
    try:
        name = request.form.get('name')
        api_url = request.form.get('api_url')
        api_token = request.form.get('api_token')
        description = request.form.get('description')
        enabled = request.form.get('enabled') == 'on'
        
        if not all([name, api_url, api_token]):
            return jsonify({'success': False, 'message': 'Name, API URL, and API token are required'}), 400
        
        # Update the instance
        db.update_crafty_instance(instance_id, name=name, api_url=api_url, 
                                  api_token=api_token, description=description, enabled=enabled)
        
        log_action(
            action="CRAFTY_INSTANCE_UPDATED",
            details=f"Updated Crafty instance {instance_id} for guild {guild_id}",
            changes=f"Name: {name}, URL: {api_url}, Enabled: {enabled}, Description: {description or 'None'}"
        )
        return jsonify({'success': True})
            
    except Exception as e:
        debug_print(red(f"Error updating Crafty instance: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to update instance'}), 500

@app.route('/api/<guild_id>/crafty/instances/<int:instance_id>/details', methods=['GET'])
@login_required
@guild_required
def get_crafty_instance_details(guild_id, instance_id):
    """Get instance details for editing"""
    debug_print(f"Getting Crafty instance {instance_id} details for guild: {guild_id}", level="all")
    
    try:
        instance = db.get_crafty_instance(instance_id)
        if not instance or instance['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Instance not found'}), 404
        
        return jsonify({
            'success': True,
            'instance': {
                'id': instance['id'],
                'name': instance['name'],
                'host': instance['host'],
                'port': instance['port'],
                'api_key': instance['api_key']
            }
        })
        
    except Exception as e:
        debug_print(red(f"Error getting instance details: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to get instance details'}), 500

# Permission Management API Routes
@app.route('/api/<guild_id>/crafty/permissions', methods=['POST'])
@login_required
@guild_required
def add_crafty_permission(guild_id):
    """Add permission for a server"""
    debug_print(f"Adding Crafty permission for guild: {guild_id}", level="all")
    
    try:
        server_id = request.form.get('server_id')
        permission_type = request.form.get('permission_type')
        user_id = request.form.get('user_id')
        role_id = request.form.get('role_id')
        can_start = bool(request.form.get('can_start'))
        can_stop = bool(request.form.get('can_stop'))
        can_restart = bool(request.form.get('can_restart'))
        can_manage = bool(request.form.get('can_manage'))
        
        if not server_id:
            return jsonify({'success': False, 'message': 'Server ID is required'}), 400
        
        if permission_type == 'user' and not user_id:
            return jsonify({'success': False, 'message': 'User ID is required for user permissions'}), 400
        elif permission_type == 'role' and not role_id:
            return jsonify({'success': False, 'message': 'Role ID is required for role permissions'}), 400
        
        # Check if permission already exists
        existing = db.get_crafty_permission_by_target(
            int(server_id), 
            user_id=int(user_id) if user_id else None,
            role_id=int(role_id) if role_id else None
        )
        
        if existing:
            return jsonify({'success': False, 'message': 'Permission already exists for this user/role'}), 400
        
        permission_id = db.add_crafty_permission(
            server_id=int(server_id),
            guild_id=guild_id,
            user_id=int(user_id) if user_id else None,
            role_id=int(role_id) if role_id else None,
            can_start=can_start,
            can_stop=can_stop,
            can_restart=can_restart,
            can_manage=can_manage
        )
        
        if permission_id:
            log_action(
                action="CRAFTY_PERMISSION_ADDED",
                details=f"Added Crafty permission for server {server_id} in guild {guild_id}",
                changes=f"Type: {permission_type}, User ID: {user_id or 'None'}, Role ID: {role_id or 'None'}, Permissions: start={can_start}, stop={can_stop}, restart={can_restart}, manage={can_manage}"
            )
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to add permission'}), 500
            
    except Exception as e:
        debug_print(red(f"Error adding Crafty permission: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to add permission'}), 500

@app.route('/api/<guild_id>/crafty/servers/<int:server_id>/permissions', methods=['GET'])
@login_required
@guild_required
def get_crafty_server_permissions(guild_id, server_id):
    """Get permissions for a server"""
    debug_print(f"Getting permissions for server {server_id} in guild: {guild_id}", level="all")
    
    try:
        permissions = db.get_crafty_permissions_for_server(server_id)
        
        # Enrich with username/role names if available
        for perm in permissions:
            if perm['user_id']:
                # Try to get username from bot
                try:
                    user = bot_instance.get_user(perm['user_id'])
                    if user:
                        perm['username'] = user.display_name
                except:
                    pass
            elif perm['role_id']:
                # Try to get role name from bot
                try:
                    guild = bot_instance.get_guild(int(guild_id))
                    if guild:
                        role = guild.get_role(perm['role_id'])
                        if role:
                            perm['role_name'] = role.name
                except:
                    pass
        
        return jsonify(permissions)
        
    except Exception as e:
        debug_print(red(f"Error getting server permissions: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to get permissions'}), 500

@app.route('/api/<guild_id>/crafty/permissions/<int:permission_id>', methods=['DELETE'])
@login_required
@guild_required
def delete_crafty_permission(guild_id, permission_id):
    """Delete a permission"""
    debug_print(f"Deleting Crafty permission {permission_id} for guild: {guild_id}", level="all")
    
    try:
        # Verify permission belongs to this guild
        permission = db.get_crafty_permission(permission_id)
        if not permission:
            return jsonify({'success': False, 'message': 'Permission not found'}), 404
        
        # Get server to verify guild ownership
        server = db.get_crafty_server(permission['server_id'])
        if not server or server['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Permission not found'}), 404
        
        success = db.delete_crafty_permission(permission_id)
        
        if success:
            log_action(
                action="CRAFTY_PERMISSION_DELETED",
                details=f"Deleted Crafty permission {permission_id} for guild {guild_id}",
                changes=f"Server ID: {permission['server_id']}, User ID: {permission.get('user_id', 'None')}, Role ID: {permission.get('role_id', 'None')}"
            )
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to delete permission'}), 500
            
    except Exception as e:
        debug_print(red(f"Error deleting Crafty permission: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to delete permission'}), 500

# Crafty Command Permissions API Routes
@app.route('/api/<guild_id>/crafty/command-permissions', methods=['GET'])
@login_required
@guild_required
def get_crafty_command_permissions(guild_id):
    """Get command permissions for Crafty Controller commands"""
    debug_print(f"Getting Crafty command permissions for guild: {guild_id}", level="all")
    
    try:
        commands = ['start_crafty_server', 'stop_crafty_server', 'restart_crafty_server', 'crafty_servers', 'crafty_status']
        permissions = {}
        
        for command in commands:
            permissions[command] = db.get_command_permissions(guild_id, command)
        
        return jsonify(permissions)
        
    except Exception as e:
        debug_print(red(f"Error getting Crafty command permissions: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to get command permissions'}), 500

@app.route('/api/<guild_id>/crafty/command-permissions', methods=['POST'])
@login_required
@guild_required
def add_crafty_command_permission(guild_id):
    """Add a command permission for Crafty Controller commands"""
    debug_print(f"Adding Crafty command permission for guild: {guild_id}", level="all")
    
    try:
        command_name = request.form.get('command_name')
        permission_type = request.form.get('permission_type')
        
        if not command_name or not permission_type:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Validate command name
        valid_commands = ['start_crafty_server', 'stop_crafty_server', 'restart_crafty_server', 'crafty_servers', 'crafty_status']
        if command_name not in valid_commands:
            return jsonify({'success': False, 'message': 'Invalid command name'}), 400
        
        # Get current permissions
        current_perms = db.get_command_permissions(guild_id, command_name)
        allow_roles = current_perms.get('allow_roles', [])
        allow_users = current_perms.get('allow_users', [])
        
        if permission_type == 'role':
            role_id = request.form.get('role_id')
            if not role_id:
                return jsonify({'success': False, 'message': 'Role ID required'}), 400
            
            # Check if role ID is already in the list
            if role_id not in allow_roles:
                allow_roles.append(role_id)
        
        elif permission_type == 'user':
            user_id = request.form.get('user_id')
            if not user_id:
                return jsonify({'success': False, 'message': 'User ID required'}), 400
            
            # Check if user ID is already in the list
            if user_id not in allow_users:
                allow_users.append(user_id)
        
        else:
            return jsonify({'success': False, 'message': 'Invalid permission type'}), 400
        
        # Update permissions
        db.set_command_permissions(guild_id, command_name, allow_roles, allow_users, is_custom=False)
        
        log_action(
            action="CRAFTY_COMMAND_PERMISSION_ADDED",
            details=f"Added {permission_type} permission for command '{command_name}' in guild {guild_id}",
            changes=f"Type: {permission_type}, Role ID: {role_id if permission_type == 'role' else 'N/A'}, User ID: {user_id if permission_type == 'user' else 'N/A'}, Command: {command_name}"
        )
        return jsonify({'success': True})
        
    except Exception as e:
        debug_print(red(f"Error adding Crafty command permission: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to add command permission'}), 500

@app.route('/api/<guild_id>/crafty/command-permissions/<command_name>', methods=['DELETE'])
@login_required
@guild_required
def remove_crafty_command_permission(guild_id, command_name):
    """Remove a command permission for Crafty Controller commands"""
    debug_print(f"Removing Crafty command permission for guild: {guild_id}, command: {command_name}", level="all")
    
    try:
        permission_type = request.form.get('permission_type')
        target_id = request.form.get('target_id')
        
        if not permission_type or not target_id:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Validate command name
        valid_commands = ['start_crafty_server', 'stop_crafty_server', 'restart_crafty_server', 'crafty_servers', 'crafty_status']
        if command_name not in valid_commands:
            return jsonify({'success': False, 'message': 'Invalid command name'}), 400
        
        # Get current permissions
        current_perms = db.get_command_permissions(guild_id, command_name)
        allow_roles = current_perms.get('allow_roles', [])
        allow_users = current_perms.get('allow_users', [])
        
        if permission_type == 'role':
            allow_roles = [role for role in allow_roles if role != target_id]
        elif permission_type == 'user':
            allow_users = [user for user in allow_users if user != target_id]
        else:
            return jsonify({'success': False, 'message': 'Invalid permission type'}), 400
        
        # Update permissions
        db.set_command_permissions(guild_id, command_name, allow_roles, allow_users, is_custom=False)
        
        log_action(
            action="CRAFTY_COMMAND_PERMISSION_REMOVED",
            details=f"Removed {permission_type} permission for command '{command_name}' in guild {guild_id}",
            changes=f"Type: {permission_type}, Target ID: {target_id}, Command: {command_name}"
        )
        return jsonify({'success': True})
        
    except Exception as e:
        debug_print(red(f"Error removing Crafty command permission: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to remove command permission'}), 500

# DNS Record Management API Routes
@app.route('/api/<guild_id>/crafty/dns', methods=['POST'])
@login_required
@guild_required
def create_dns_record(guild_id):
    """Create a new DNS record"""
    debug_print(f"Creating DNS record for guild: {guild_id}", level="all")
    
    try:
        server_id = request.form.get('server_id')
        hostname = request.form.get('hostname')
        port = request.form.get('port')
        priority = request.form.get('priority', 0)
        weight = request.form.get('weight', 5)
        
        if not all([server_id, hostname, port]):
            return jsonify({'success': False, 'message': 'Server, hostname, and port are required'}), 400
        
        # Verify server belongs to guild
        server = db.get_crafty_server(int(server_id))
        if not server or server['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Server not found'}), 404
        
        import asyncio
        success, message = asyncio.run(cloudflare_manager.create_minecraft_srv_record(
            guild_id=guild_id,
            crafty_server_id=int(server_id),
            hostname=hostname,
            port=int(port)
        ))
        
        debug_print(f"DNS creation result: success={success}, message={message}", level="all")
        
        if success:
            log_action(
                action="DNS_RECORD_CREATED",
                details=f"Created DNS record `{hostname}:{port}` for server {server_id} in guild {guild_id}",
                changes=f"Server: {server['server_name']}, Hostname: {hostname}, Port: {port}, Priority: {priority}, Weight: {weight}"
            )
        
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        debug_print(red(f"Error creating DNS record: {str(e)}", level="all"))
        import traceback
        debug_print(f"Traceback: {traceback.format_exc()}", level="all")
        return jsonify({'success': False, 'message': f'Failed to create DNS record: {str(e)}'}), 500

@app.route('/api/<guild_id>/crafty/dns/<int:record_id>', methods=['PUT'])
@login_required
@guild_required
def update_dns_record(guild_id, record_id):
    """Update a DNS record"""
    debug_print(f"Updating DNS record {record_id} for guild: {guild_id}", level="all")
    
    try:
        hostname = request.form.get('hostname')
        port = request.form.get('port')
        priority = request.form.get('priority')
        weight = request.form.get('weight')
        
        debug_print(f"Update DNS record params - hostname: {hostname}, port: {port}, priority: {priority}, weight: {weight}", level="all")
        
        if not all([hostname, port]):
            return jsonify({'success': False, 'message': 'Hostname and port are required'}), 400
        
        # Verify record belongs to guild
        record = db.get_minecraft_dns_record(record_id)
        if not record or str(record['guild_id']) != str(guild_id):
            return jsonify({'success': False, 'message': 'Record not found'}), 404
        
        import asyncio
        success, message = asyncio.run(cloudflare_manager.update_minecraft_srv_record(
            guild_id=guild_id,
            record_id=record_id,
            hostname=hostname,
            port=int(port),
            priority=int(priority) if priority else None,
            weight=int(weight) if weight else None
        ))
        
        if success:
            log_action("DNS_RECORD_UPDATED", f"Updated DNS record `{hostname}` for guild {guild_id}")
        
        return jsonify({'success': success, 'message': message})
        
    except Exception as e:
        debug_print(red(f"Error updating DNS record: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to update DNS record'}), 500

@app.route('/api/<guild_id>/crafty/dns/<int:record_id>/details', methods=['GET'])
@login_required
@guild_required
def get_dns_record_details(guild_id, record_id):
    """Get DNS record details for editing"""
    debug_print(f"Getting DNS record {record_id} details for guild: {guild_id}", level="all")
    
    try:
        record = db.get_minecraft_dns_record(record_id)
        if not record or record['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Record not found'}), 404
        
        return jsonify({
            'success': True,
            'record': {
                'id': record['id'],
                'hostname': record['hostname'],
                'port': record['port'],
                'priority': record['priority'],
                'weight': record['weight']
            }
        })
        
    except Exception as e:
        debug_print(red(f"Error getting DNS record details: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to get record details'}), 500

# Minecraft Server Scheduling API Routes
@app.route('/api/<guild_id>/crafty/schedules', methods=['GET'])
@login_required
@guild_required
def get_minecraft_schedules(guild_id):
    """Get all minecraft schedules for a guild"""
    debug_print(f"Getting minecraft schedules for guild: {guild_id}", level="all")
    
    try:
        schedules = db.get_minecraft_schedules(guild_id)
        import pytz
        
        for schedule in schedules:
            try:
                # Parse timezone and start time
                tz = pytz.timezone(schedule['timezone'])
                start_datetime = datetime.strptime(f"{schedule['start_date']} {schedule['start_time']}", "%Y-%m-%d %H:%M")
                start_datetime = tz.localize(start_datetime)
                
                # Calculate next occurrence
                now = datetime.now(tz)
                
                # Add frequency intervals until we find the next occurrence
                next_run = start_datetime
                if schedule['frequency_unit'] == 'minutes':
                    delta = timedelta(minutes=schedule['frequency_value'])
                elif schedule['frequency_unit'] == 'hours':
                    delta = timedelta(hours=schedule['frequency_value'])
                elif schedule['frequency_unit'] == 'days':
                    delta = timedelta(days=schedule['frequency_value'])
                elif schedule['frequency_unit'] == 'weeks':
                    delta = timedelta(weeks=schedule['frequency_value'])
                elif schedule['frequency_unit'] == 'months':
                    # Approximate monthly calculation
                    delta = timedelta(days=schedule['frequency_value'] * 30)
                elif schedule['frequency_unit'] == 'years':
                    # Approximate yearly calculation
                    delta = timedelta(days=schedule['frequency_value'] * 365)
                
                while next_run <= now:
                    next_run += delta
                
                schedule['next_run_utc'] = next_run.astimezone(pytz.UTC).strftime('%Y-%m-%d %H:%M:%S')
                schedule['next_run_local'] = next_run.strftime('%Y-%m-%d %H:%M:%S')
                schedule['seconds_until'] = int((next_run - now).total_seconds())
                
            except Exception as e:
                debug_print(red(f"Error calculating next run for schedule {schedule['id']}: {e}", level="all"))
                schedule['next_run_utc'] = 'Error'
                schedule['next_run_local'] = 'Error'
                schedule['seconds_until'] = 0
        
        return jsonify({'success': True, 'schedules': schedules})
        
    except Exception as e:
        debug_print(red(f"Error getting minecraft schedules: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to get schedules'}), 500

@app.route('/api/<guild_id>/crafty/schedules', methods=['POST'])
@login_required
@guild_required
def create_minecraft_schedule(guild_id):
    """Create a new minecraft server schedule"""
    debug_print(f"Creating minecraft schedule for guild: {guild_id}", level="all")
    
    try:
        crafty_server_id = request.form.get('crafty_server_id')
        action = request.form.get('action')
        start_date = request.form.get('start_date')
        start_time = request.form.get('start_time')
        frequency_value = request.form.get('frequency_value')
        frequency_unit = request.form.get('frequency_unit')
        timezone = request.form.get('timezone', 'UTC')
        enabled = request.form.get('enabled', 'true').lower() == 'true'
        # Use getlist to get all values and check if 'true' is present
        check_player_count_values = request.form.getlist('check_player_count')
        check_player_count = 'true' in [v.lower() for v in check_player_count_values]
        
        debug_print(f"Form check_player_count values: {check_player_count_values} -> boolean: {check_player_count}", level="all")
        min_idle_minutes = request.form.get('min_idle_minutes', '5')
        
        if not all([crafty_server_id, action, start_date, start_time, frequency_value, frequency_unit]):
            return jsonify({'success': False, 'message': 'All required fields must be provided'}), 400
        
        # Validate action
        if action not in ['start', 'stop', 'restart']:
            return jsonify({'success': False, 'message': 'Invalid action. Must be start, stop, or restart'}), 400
        
        # Validate frequency unit
        if frequency_unit not in ['minutes', 'hours', 'days', 'weeks', 'months', 'years']:
            return jsonify({'success': False, 'message': 'Invalid frequency unit'}), 400
        
        # Validate server belongs to guild
        server = db.get_crafty_server(int(crafty_server_id))
        if not server:
            return jsonify({'success': False, 'message': 'Server not found'}), 404
        
        # Get instance and verify it belongs to guild
        instance = db.get_crafty_instance(server['crafty_instance_id'])
        if not instance or instance['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Server does not belong to this guild'}), 403
        
        # Create schedule
        schedule_id = db.create_minecraft_schedule(
            guild_id=guild_id,
            crafty_server_id=int(crafty_server_id),
            action=action,
            start_date=start_date,
            start_time=start_time,
            frequency_value=int(frequency_value),
            frequency_unit=frequency_unit,
            timezone=timezone,
            enabled=enabled,
            check_player_count=check_player_count,
            min_idle_minutes=int(min_idle_minutes)
        )
        
        log_action("Created Minecraft schedule", f"Created {action} schedule for server {server['server_name']} in guild {guild_id}")
        
        # Reload schedules to update the scheduler
        try:
            from bot.bot import load_minecraft_schedules
            load_minecraft_schedules()
        except Exception as e:
            debug_print(red(f"Error reloading minecraft schedules after creation: {e}", level="all"))
        
        return jsonify({'success': True, 'message': 'Schedule created successfully', 'schedule_id': schedule_id})
        
    except Exception as e:
        debug_print(red(f"Error creating minecraft schedule: {str(e)}", level="all"))
        import traceback
        debug_print(f"Traceback: {traceback.format_exc()}", level="all")
        return jsonify({'success': False, 'message': f'Failed to create schedule: {str(e)}'}), 500

@app.route('/api/<guild_id>/crafty/schedules/<int:schedule_id>', methods=['DELETE'])
@login_required
@guild_required
def delete_minecraft_schedule(guild_id, schedule_id):
    """Delete a minecraft server schedule"""
    debug_print(f"Deleting minecraft schedule {schedule_id} for guild: {guild_id}", level="all")
    
    try:
        # Verify schedule belongs to guild
        schedule = db.get_minecraft_schedule(schedule_id)
        if not schedule or schedule['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Schedule not found'}), 404
        
        db.delete_minecraft_schedule(schedule_id)
        
        log_action("Deleted Minecraft schedule", f"Deleted {schedule['action']} schedule for server {schedule['server_name']} in guild {guild_id}")
        
        # Reload schedules to update the scheduler
        try:
            from bot.bot import load_minecraft_schedules
            load_minecraft_schedules()
        except Exception as e:
            debug_print(red(f"Error reloading minecraft schedules after deletion: {e}", level="all"))
        
        return jsonify({'success': True, 'message': 'Schedule deleted successfully'})
        
    except Exception as e:
        debug_print(red(f"Error deleting minecraft schedule: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to delete schedule'}), 500

@app.route('/api/<guild_id>/crafty/schedules/<int:schedule_id>/toggle', methods=['POST'])
@login_required
@guild_required
def toggle_minecraft_schedule(guild_id, schedule_id):
    """Toggle a minecraft server schedule enabled/disabled"""
    debug_print(f"Toggling minecraft schedule {schedule_id} for guild: {guild_id}", level="all")
    
    try:
        # Verify schedule belongs to guild
        schedule = db.get_minecraft_schedule(schedule_id)
        if not schedule or schedule['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Schedule not found'}), 404
        
        new_enabled = not schedule['enabled']
        db.update_minecraft_schedule(schedule_id, enabled=new_enabled)
        
        status = "enabled" if new_enabled else "disabled"
        log_action(f"{'Enabled' if new_enabled else 'Disabled'} Minecraft schedule", 
                  f"{status.title()} {schedule['action']} schedule for server {schedule['server_name']} in guild {guild_id}")
        
        return jsonify({'success': True, 'message': f'Schedule {status} successfully'})
        
    except Exception as e:
        debug_print(red(f"Error toggling minecraft schedule: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to toggle schedule'}), 500

@app.route('/api/<guild_id>/crafty/schedules/<int:schedule_id>/logs', methods=['GET'])
@login_required
@guild_required
def get_minecraft_schedule_logs(guild_id, schedule_id):
    """Get execution logs for a minecraft schedule"""
    debug_print(f"Getting logs for minecraft schedule {schedule_id} in guild: {guild_id}", level="all")
    
    try:
        # Verify schedule belongs to guild
        schedule = db.get_minecraft_schedule(schedule_id)
        if not schedule or schedule['guild_id'] != guild_id:
            return jsonify({'success': False, 'message': 'Schedule not found'}), 404
        
        logs = db.get_minecraft_schedule_logs(schedule_id)
        
        return jsonify({'success': True, 'logs': logs})
        
    except Exception as e:
        debug_print(red(f"Error getting minecraft schedule logs: {str(e)}", level="all"))
        return jsonify({'success': False, 'message': 'Failed to get logs'}), 500

# Custom Forms Routes
@app.route('/dashboard/<guild_id>/forms')
@login_required
@guild_required
def custom_forms_dashboard(guild_id):
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
    debug_print("Entering random_schedule_id", level="all")
    return ''.join(random.choices('0123456789', k=5))

# Get text channels from Discord API
def get_text_channels(guild_id):
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
        debug_print(red(f"Roles fetch HTTP error for {guild_id}: {e.response.status_code}"))
        return role_cache.get(guild_id, [])
    except Exception as e:
        debug_print(red(f"Roles fetch error for {guild_id}: {str(e)}"))
        return role_cache.get(guild_id, [])

# Get mutual guilds for a user
def get_mutual_guilds(user_id, user_access_token=None):
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
    debug_print(f"Entering get_username_filter with user_id: {user_id}", level="all")
    user = db.execute_query(
        'SELECT username FROM users WHERE user_id = ?',
        (user_id,),
        fetch='one'
    )
    return user['username'] if user else None
    
@app.template_filter('get_channel_name')
def get_channel_name_filter(channel_id, channels):
    debug_print(f"Entering get_channel_name_filter with channel_id: {channel_id}, channels: {channels}", level="all")
    for channel in channels:
        if str(channel['id']) == str(channel_id):
            return channel['name']
    return None

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
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
    debug_print(red(f"Entering handle_csrf_error with error: {e}"), level="all")
    flash('Security token expired. Please refresh the page and try again.', 'danger')
    return redirect(request.referrer or url_for('select_guild'))

@app.errorhandler(401)
def unauthorized(e):
    debug_print(red(f"Entering unauthorized error handler with error: {e}"), level="all")
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    debug_print(red(f"Entering forbidden error handler with error: {e}"), level="all")
    return render_template('error.html', 
                         error_message=str(e),
                         help_message="Contact your server administrator for access"), 403

@app.errorhandler(404)
def not_found(e):
    debug_print(red(f"Entering not_found error handler with error: {e}"), level="all")
    error_message = getattr(e, 'description', None) or "The page you requested does not exist."
    return render_template('error.html', 
                        error_message=error_message,
                        help_message="The page you requested does not exist."), 404

@app.errorhandler(500)
def internal_error(e):
    debug_print(red(f"Entering internal_error handler with error: {e}"), level="all")
    return render_template('error.html',
                        error_message="Internal Server Error",
                        help_message="Please try again later"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)