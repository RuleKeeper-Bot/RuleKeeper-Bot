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
    debug_print("Entering refresh_session", level="all")
    # Ensure all requests get a session cookie
    session.permanent = True
    if 'user' not in session and 'admin' not in session:
        if not session.get('_anon_session'):
            session['_anon_session'] = str(uuid.uuid4())
            session.modified = True
def log_real_ip():
    debug_print("Entering log_real_ip", level="all")
    real_ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    debug_print(f"Real IP: {real_ip} -> Path: {request.path}")

# Routes
@app.route('/')
def index():
    debug_print("Entering index route", level="all")
    return render_template('index.html')

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
        logging.error(f"Roles fetch HTTP error for {guild_id}: {e.response.status_code}")
        return role_cache.get(guild_id, [])
    except Exception as e:
        logging.error(f"Roles fetch error for {guild_id}: {str(e)}")
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
    debug_print(f"Entering handle_csrf_error with error: {e}", level="all")
    flash('Security token expired. Please refresh the page and try again.', 'danger')
    return redirect(request.referrer or url_for('select_guild'))

@app.errorhandler(401)
def unauthorized(e):
    debug_print(f"Entering unauthorized error handler with error: {e}", level="all")
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    debug_print(f"Entering forbidden error handler with error: {e}", level="all")
    return render_template('error.html', 
                         error_message=str(e),
                         help_message="Contact your server administrator for access"), 403

@app.errorhandler(404)
def not_found(e):
    debug_print(f"Entering not_found error handler with error: {e}", level="all")
    error_message = getattr(e, 'description', None) or "The page you requested does not exist."
    return render_template('error.html', 
                        error_message=error_message,
                        help_message="The page you requested does not exist."), 404

@app.errorhandler(500)
def internal_error(e):
    debug_print(f"Entering internal_error handler with error: {e}", level="all")
    return render_template('error.html',
                        error_message="Internal Server Error",
                        help_message="Please try again later"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)