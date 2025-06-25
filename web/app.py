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
from datetime import datetime
from functools import wraps

# Third-Party Libraries
import bcrypt
import requests
from authlib.integrations.flask_client import OAuth
from cachetools import TTLCache
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort, render_template_string
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
from bot.bot import bot_instance

# Runtime Config
load_dotenv()

# Initialize database
Config.verify_paths()
db = Database(str(Config.DATABASE_PATH))
db.initialize_db()
try:
    db.validate_schema()
    print(f"🌐 Web using database: {db.db_path}")
except RuntimeError as e:
    print(f"❌ Database schema validation failed: {str(e)}")
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
app.config['PERMANENT_SESSION_LIFETIME'] = 7200  # 2 hour expiration
app.config["DISCORD_SCOPE"] = ["identify", "guilds"]
app.config.update({
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'PERMANENT_SESSION_LIFETIME': 7200, # 2 hour expiration
    'WTF_CSRF_CHECK_DEFAULT': True,
    'WTF_CSRF_SSL_STRICT': False
})

# Initialize Discord OAuth
discord = DiscordOAuth2Session(app)

# Configuration
API_URL = os.getenv('API_URL', 'http://localhost:5003')
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:5000')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Caching
channel_cache = TTLCache(maxsize=100, ttl=600) # 10 minutes
role_cache = TTLCache(maxsize=100, ttl=600) # 10 minutes

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
        if not session.get('user') and not session.get('admin'):
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def guild_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        guild_id = kwargs.get('guild_id')
        if not guild_id:
            abort(400, "Missing guild ID")
            
        if session.get('admin'):
            return f(*args, **kwargs)
            
        user_guilds = get_user_guilds()
        
        # Properly handle guild lookup
        guild = next(
            (guild for guild in user_guilds if str(guild.id) == guild_id),
            None
        )
        
        # Check if guild exists and has permissions
        if not guild:
            abort(404, "Server not found in your accessible guilds")
            
        if not (guild.permissions.value & 0x20):
            abort(403, "You don't have manage server permissions")
            
        return f(*args, **kwargs)
    return wrapper

def get_user_guilds():
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

def get_bot_guild_ids():
    bot_guilds = db.get_all_guilds()
    return {g['id'] for g in bot_guilds}

def get_guild_or_404(guild_id):
    guild = db.get_guild(guild_id)
    if not guild:
        abort(404, "Guild not found in database")
    return guild
    
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            abort(403, description="Admin privileges required")
        return f(*args, **kwargs)
    return decorated_function

def head_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('head_admin'):
            abort(403, "Head admin privileges required")
        return f(*args, **kwargs)
    return decorated_function

@app.context_processor
def inject_admin_status():
    def check_head_admin():
        return session.get('head_admin', False)
    
    def check_bot_admin():
        return session.get('admin', False)
    
    return {
        'is_head_admin': check_head_admin,
        'is_bot_admin': check_bot_admin
    }

def resolve_youtube_handle(identifier: str) -> tuple:
    """Convert YouTube handle to channel ID with quota check"""
    API_KEY = os.getenv('YOUTUBE_API_KEY')
    if not API_KEY:
        return identifier, "API key not configured"
    
    try:
        # Handle @channel format
        if identifier.startswith('@'):
            handle = identifier[1:]
        else:
            handle = identifier
            
        # Resolve handle to channel ID
        url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&type=channel&q={handle}&key={API_KEY}"
        response = requests.get(url)
        data = response.json()
        
        # Check for quota errors
        if 'error' in data:
            if any(e.get('reason') == 'quotaExceeded' for e in data['error'].get('errors', [])):
                logger.error("YouTube API QUOTA EXCEEDED during handle resolution")
                return identifier, "YouTube API quota exceeded - try again later"
            
            error_msg = data['error'].get('message', 'Unknown YouTube API error')
            return identifier, f"YouTube API error: {error_msg}"
        
        if 'items' in data and len(data['items']) > 0:
            return data['items'][0]['snippet']['channelId'], None
            
        return identifier, "Channel not found"
    except Exception as e:
        logger.error(f"Error resolving YouTube handle: {str(e)}")
        return identifier, "Connection error"

# TEMPORARY ROUTE
# @app.route('/update-guild-icons')
# def update_guild_icons():
    # if not session.get('admin'):
        # abort(403)
        
    # try:
        # guilds = db.execute_query('SELECT guild_id FROM guilds', fetch='all')
        
        # updated = 0
        # for g in guilds:
            # # Use 'guild_id' instead of 'id'
            # guild_id = int(g['guild_id'])
            # guild = shared.bot.get_guild(guild_id)
            
            # if guild:
                # icon = str(guild.icon.url) if guild.icon else None
                # db.execute_query(
                    # 'UPDATE guilds SET icon = ? WHERE guild_id = ?',
                    # (icon, guild_id)
                # )
                # updated += 1
                
        # return f"Updated icons for {updated}/{len(guilds)} guilds"
        
    # except Exception as e:
        # logger.error(f"Error updating guild icons: {str(e)}")
        # return f"Error: {str(e)}", 500

# Before Requests
@app.before_request
def refresh_session():
    # Ensure all requests get a session cookie
    session.permanent = True
    if 'user' not in session and 'admin' not in session:
        if not session.get('_anon_session'):
            session['_anon_session'] = str(uuid.uuid4())
            session.modified = True
def log_real_ip():
    real_ip = request.headers.get("CF-Connecting-IP", request.remote_addr)
    print(f"Real IP: {real_ip} -> Path: {request.path}")

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy.html")

@app.route("/terms-of-service")
def terms_of_service():
    return render_template("terms.html")
    
@app.route("/end-user-license-agreement")
def end_user_license_agreement():
    return render_template("eula.html")

@app.route('/login')
def login():
    session.clear()
    session.permanent = True
    session.modified = True  # Force session save
    return discord.create_session(
        scope=["identify", "guilds"],
        prompt="none"
    )
    
@app.route('/admin/login', methods=['GET', 'POST'])
def login_admin():
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
    session.clear()
    flash('Successfully logged out', 'success')
    return redirect(url_for('login'))
    
@app.route('/logout-admin')
@login_required
def logout_admin():
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
        session.permanent = True
        
        return redirect(url_for("select_guild"))
        
    except Unauthorized as e:
        logger.error(f"Authorization failed: {str(e)}")
        session.clear()
        flash("Login failed. Please try again.", "danger")
        return redirect(url_for("login"))
    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        session.clear()
        flash("Login failed. Please try again.", "danger")
        return redirect(url_for("login"))

@app.route('/select-guild')
@login_required
def select_guild():
    user_guilds = get_user_guilds()
    
    # Prepare guild data for template
    common_guilds = [{
        'id': str(g.id),
        'name': g.name,
        'icon': g.icon_url or '',
        'permissions': g.permissions.value
    } for g in user_guilds]
    
    if session.get('admin'):
        # Get full guild data from DB
        common_guilds = db.execute_query(
            'SELECT guild_id as id, name, icon FROM guilds',
            fetch='all'
        )
        
    return render_template('select_guild.html', guilds=common_guilds)
    
@app.route('/admin/guilds')
@login_required
@admin_required
def admin_guilds():
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
    
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Get guild count
    guild_count_result = db.execute_query('SELECT COUNT(*) as count FROM guilds', fetch='one')
    guild_count = guild_count_result['count'] if guild_count_result else 0
    
    # Get admin count
    admin_count_result = db.execute_query('SELECT COUNT(*) as count FROM bot_admins', fetch='one')
    admin_count = admin_count_result['count'] if admin_count_result else 0
    
    # Get appeal count
    appeal_count_result = db.execute_query(
        'SELECT COUNT(*) as count FROM appeals WHERE status = "pending"',
        fetch='one'
    )
    appeal_count = appeal_count_result['count'] if appeal_count_result else 0
    
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
                         appeal_count=appeal_count,
                         recent_logs=recent_logs)

@app.route('/admin/bot-admins', methods=['GET', 'POST'])
@head_admin_required
def manage_bot_admins():
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

@app.route('/admin/guilds/<guild_id>/remove', methods=['POST'])
@admin_required
def remove_guild(guild_id):
    try:
        csrf.protect()  # Verify CSRF token
        
        # Remove guild from database
        db.execute_query('DELETE FROM guilds WHERE guild_id = ?', (guild_id,))
        
        flash(f'Successfully removed guild {guild_id}', 'success')
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
    guild = get_guild_or_404(guild_id)
    return render_template('guilds.html', guild=guild)

# Commands Management
@app.route('/dashboard/<guild_id>/commands', methods=['GET', 'POST'])
@login_required
@guild_required
def guild_commands(guild_id):
    guild = get_guild_or_404(guild_id)
    
    if request.method == 'POST':
        try:
            # Verify CSRF first
            csrf.protect()
            data = request.get_json()
            
            if not data:
                return jsonify({'success': False, 'error': 'No data provided'}), 400

            # Validate required fields
            required = ['command_name', 'description', 'content']
            if not all(key in data for key in required):
                return jsonify({
                    'success': False,
                    'error': 'Missing required fields'
                }), 400

            command_name = data['command_name'].lower().strip()
            description = data['description'].strip()
            content = data['content'].strip()
            ephemeral = data.get('ephemeral', True)

            # Validate command name
            if not re.fullmatch(r'^[a-z0-9\-]{1,32}$', command_name):
                return jsonify({
                    'success': False,
                    'error': 'Invalid command name (1-32 chars, lowercase, hyphens)'
                }), 400

            # Database operation
            try:
                db.add_command(
                    guild_id=guild_id,
                    command_name=command_name,
                    description=description,
                    content=content,
                    ephemeral=ephemeral
                )
                return jsonify({
                    'success': True,
                    'message': f'Command /{command_name} created!',
                    'redirect': url_for('guild_commands', guild_id=guild_id)
                })

            except sqlite3.IntegrityError:
                return jsonify({
                    'success': False,
                    'error': f'Command /{command_name} already exists'
                }), 409

        except Exception as e:
            logger.error(f"Command error: {str(e)}")
            return jsonify({
                'success': False,
                'error': 'Server error'
            }), 500

    # GET request
    try:
        # Convert SQLite Row objects to proper dictionaries
        commands = db.get_commands(guild_id)
        return render_template('commands.html',
                             commands=commands,
                             guild_id=guild_id,
                             guild=guild)
    except Exception as e:
        logger.error(f"Commands fetch error: {str(e)}")
        abort(500)
    
@app.route('/dashboard/<guild_id>/commands/<command_name>/edit', methods=['GET', 'POST'])
@login_required
@guild_required
def edit_command(guild_id, command_name):
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
            return redirect(url_for('edit_command', guild_id=guild_id))
        try:
            # Update command in database
            new_content = request.form['content']
            new_description = request.form['description']
            new_ephemeral = 'ephemeral' in request.form
            
            db.update_command(
                guild_id=guild_id,
                command_name=command_name,
                content=new_content,
                description=new_description,
                ephemeral=new_ephemeral
            )
            
            flash('Command updated successfully', 'success')
            return redirect(url_for('guild_commands', guild_id=guild_id))
            
        except Exception as e:
            logger.error(f"Error updating command: {str(e)}")
            flash('Error updating command', 'danger')
    
    # GET request - show edit form
    return render_template('edit.html',
        guild_id=guild_id,
        guild=guild,
        command_name=command_name,
        command=command
    )

@app.route('/dashboard/<guild_id>/commands/<command_name>/delete')
@login_required
@guild_required
def delete_command(guild_id, command_name):
    # Verify CSRF token first
    try:
        csrf.protect()
    except CSRFError:
        flash('Security token expired. Please submit the form again.', 'danger')
        return redirect(url_for('level_config', guild_id=guild_id))
    guild = get_guild_or_404(guild_id)
    db.remove_command(guild_id, command_name)
    flash('Command deleted successfully', 'success')
    return redirect(url_for('guild_commands', guild_id=guild_id))

# Log Configuration
@app.route('/dashboard/<guild_id>/log-config', methods=['GET', 'POST'])
@login_required
@guild_required
def log_config(guild_id):
    try:
        guild = get_guild_or_404(guild_id)
        config = db.get_log_config(guild_id)
        # Get channels from Discord API
        text_channels = get_text_channels(guild_id)
        if request.method == 'POST':
            # Verify CSRF token first
            try:
                csrf.protect()
            except CSRFError:
                flash('Security token expired. Please submit the form again.', 'danger')
                return redirect(url_for('log_config', guild_id=guild_id))
            
            update_data = {
                'log_channel_id': request.form.get('log_channel_id'),
                'log_config_update': 'log_config_update' in request.form,
                'message_delete': 'message_delete' in request.form,
                'bulk_message_delete': 'bulk_message_delete' in request.form,
                'message_edit': 'message_edit' in request.form,
                'invite_create': 'invite_create' in request.form,
                'invite_delete': 'invite_delete' in request.form,
                'member_role_add': 'member_role_add' in request.form,
                'member_role_remove': 'member_role_remove' in request.form,
                'member_timeout': 'member_timeout' in request.form,
                'member_warn': 'member_warn' in request.form,
                'member_unwarn': 'member_unwarn' in request.form,
                'member_ban': 'member_ban' in request.form,
                'member_unban': 'member_unban' in request.form,
                'role_create': 'role_create' in request.form,
                'role_delete': 'role_delete' in request.form,
                'role_update': 'role_update' in request.form,
                'channel_create': 'channel_create' in request.form,
                'channel_delete': 'channel_delete' in request.form,
                'channel_update': 'channel_update' in request.form,
                'emoji_create': 'emoji_create' in request.form,
                'emoji_name_change': 'emoji_name_change' in request.form,
                'emoji_delete': 'emoji_delete' in request.form
            }
            
            guild = get_guild_or_404(guild_id)
            db.update_log_config(guild_id, **update_data)
            flash('Log configuration updated', 'success')
            return redirect(url_for('log_config', guild_id=guild_id))
        
        return render_template('log_config.html', config=config, guild_id=guild_id, guild=guild, channels=text_channels)
        
    except Exception as e:
        logger.error(f"Error in log config: {str(e)}")
        abort(500)

# Welcome Message Config
@app.route('/dashboard/<guild_id>/welcome-config', methods=['GET', 'POST'])
@login_required
@guild_required
def welcome_config(guild_id):
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
    guild = get_guild_or_404(guild_id)
    
    users = db.execute_query('''
        SELECT * FROM user_levels 
        WHERE guild_id = ?
        ORDER BY level DESC, xp DESC
        LIMIT 100
    ''', (guild_id,), fetch='all')  # Add fetch='all' parameter
    
    return render_template('leaderboard.html',
                         users=users,
                         guild_id=guild_id,
                         guild=guild)

# Level System Configuration
@app.route('/dashboard/<guild_id>/leveling', methods=['GET', 'POST'])
@login_required
@guild_required
def level_config(guild_id):
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
        'embed_color': 0xFFD700
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
            'embed_color': db_config.get('embed_color', default_config['embed_color'])
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
                'embed_color': int(request.form.get('embed_color', 'ffd700').lstrip('#'), 16)
            }

            # Validate JSON fields
            try:
                boosts = json.loads(new_config['xp_boost_roles'])
                if not isinstance(boosts, dict):
                    raise ValueError()
                for k, v in boosts.items():
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

            db.update_level_config(guild_id, **new_config)
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

# Stream and Video Announcements page
@app.route('/dashboard/<guild_id>/stream-and-video', methods=['GET', 'POST'])
@login_required
@guild_required
def stream_announcements(guild_id):
    guild = get_guild_or_404(guild_id)
    channels = get_text_channels(guild_id)
    roles = get_roles(guild_id)

    # Default messages for stream and video announcements
    DEFAULT_STREAM_MESSAGE = "🔴 {streamer} is now live! Watch here: {url} {role}"
    DEFAULT_VIDEO_MESSAGE = "📺 New video from {channel}: {url} {role}"

    # Get existing announcements
    stream_announcements = db.execute_query(
        'SELECT * FROM stream_announcements WHERE guild_id = ?',
        (guild_id,),
        fetch='all'
    )
    
    video_announcements = db.execute_query(
        'SELECT * FROM video_announcements WHERE guild_id = ?',
        (guild_id,),
        fetch='all'
    )
    # Ensure both channel_id (YouTube) and announce_channel_id (Discord) are present in each dict
    for ann in video_announcements:
        if 'announce_channel_id' not in ann or ann['announce_channel_id'] is None:
            # fallback for legacy rows: try to use channel_id if it looks like a Discord channel
            ann['announce_channel_id'] = ann.get('announce_channel_id') or ann.get('channel_id')
        # channel_id is always YouTube channel
        ann['channel_id'] = ann.get('channel_id')

    # Helper: get role mention by id
    def get_role_mention(role_id):
        if not role_id:
            return ''
        for r in roles:
            if str(r['id']) == str(role_id):
                return f"<@&{r['id']}>"
        return ''
    
    # Helper: get channel name by id
    def get_channel_name(channel_id):
        for channel in channels:
            if str(channel['id']) == str(channel_id):
                return channel['name']
        return f"Unknown ({channel_id})"

    # Attach role mention to each announcement for preview
    for ann in stream_announcements:
        ann['role_mention'] = get_role_mention(ann.get('role_id'))
    for ann in video_announcements:
        ann['role_mention'] = get_role_mention(ann.get('role_id'))

    if request.method == 'POST':
        try:
            csrf.protect()
            action = request.form.get('action')
            
            if action == 'add_stream':
                platform = request.form['platform']
                streamer_id = request.form['streamer_id'].strip()
                channel_id = request.form['channel_id']
                message = request.form.get('message', '').strip() or DEFAULT_STREAM_MESSAGE
                role_id = request.form.get('role_id')
                db.execute_query(
                    '''INSERT INTO stream_announcements 
                    (guild_id, channel_id, platform, streamer_id, message, role_id)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (guild_id, channel_id, platform, streamer_id, message, role_id)
                )
                
            elif action == 'edit_stream':
                stream_id = request.form.get('stream_id')
                platform = request.form.get('platform')
                channel_id = request.form.get('channel_id')
                role_id = request.form.get('role_id') or None
                streamer_id = request.form.get('streamer_id')
                message = request.form.get('message')
                db.execute_query(
                    'UPDATE stream_announcements SET platform=?, channel_id=?, role_id=?, streamer_id=?, message=? WHERE id=? AND guild_id=?',
                    (platform, channel_id, role_id, streamer_id, message, stream_id, guild_id)
                )
                flash('Stream announcement updated!', 'success')
                return redirect(request.url)
            elif action == 'add_video':
                platform = request.form['platform']
                announce_channel_id = request.form['channel_id']  # Discord channel
                target_channel_id = request.form['target_channel_id']  # YouTube channel
                message = request.form.get('message', '').strip() or DEFAULT_VIDEO_MESSAGE
                role_id = request.form.get('role_id')
                db.execute_query(
                    '''INSERT INTO video_announcements 
                    (guild_id, channel_id, announce_channel_id, platform, message, role_id)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (guild_id, target_channel_id, announce_channel_id, platform, message, role_id)
                )
                
            elif action == 'edit_video':
                video_id = request.form.get('announcement_id') or request.form.get('video_id')
                platform = request.form.get('platform')
                announce_channel_id = request.form.get('channel_id')  # Discord channel
                target_channel_id = request.form.get('target_channel_id')  # YouTube channel
                message = request.form.get('message')
                role_id = request.form.get('role_id') or None
                db.execute_query(
                    'UPDATE video_announcements SET platform=?, channel_id=?, announce_channel_id=?, role_id=?, message=? WHERE id=? AND guild_id=?',
                    (platform, target_channel_id, announce_channel_id, role_id, message, video_id, guild_id)
                )
                flash('Video announcement updated!', 'success')
                return redirect(request.url)
            elif action == 'delete_stream':
                announcement_id = request.form['announcement_id']
                db.execute_query(
                    'DELETE FROM stream_announcements WHERE id = ? AND guild_id = ?',
                    (announcement_id, guild_id)
                )
                
            elif action == 'delete_video':
                announcement_id = request.form['announcement_id']
                db.execute_query(
                    'DELETE FROM video_announcements WHERE id = ? AND guild_id = ?',
                    (announcement_id, guild_id)
                )
                
            elif action == 'toggle_stream':
                announcement_id = request.form['announcement_id']
                enabled = request.form['enabled'] == 'true'
                db.execute_query(
                    'UPDATE stream_announcements SET enabled = ? WHERE id = ? AND guild_id = ?',
                    (int(enabled), announcement_id, guild_id)
                )
                
            elif action == 'toggle_video':
                announcement_id = request.form['announcement_id']
                enabled = request.form['enabled'] == 'true'
                db.execute_query(
                    'UPDATE video_announcements SET enabled = ? WHERE id = ? AND guild_id = ?',
                    (int(enabled), announcement_id, guild_id)
                )
                
            flash('Settings updated successfully', 'success')
            return redirect(url_for('stream_announcements', guild_id=guild_id))
            
        except Exception as e:
            logger.error(f"Stream config error: {str(e)}")
            flash('Error saving configuration', 'danger')
    
    return render_template('stream_and_video_announcements.html',
                         guild_id=guild_id,
                         guild=guild,
                         channels=channels,
                         roles=roles,
                         stream_announcements=stream_announcements,
                         video_announcements=video_announcements,
                         get_channel_name=get_channel_name,
                         DEFAULT_STREAM_MESSAGE=DEFAULT_STREAM_MESSAGE,
                         DEFAULT_VIDEO_MESSAGE=DEFAULT_VIDEO_MESSAGE)

# Warnings Management
@app.route('/dashboard/<guild_id>/warnings')
@login_required
@guild_required
def warnings(guild_id):
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

@app.route('/dashboard/<guild_id>/warnings/<user_id>/delete/<warning_id>')
@login_required
@guild_required
def delete_warning(guild_id, user_id, warning_id):
    guild = get_guild_or_404(guild_id)
    db.remove_warning(guild_id, user_id, warning_id)
    flash('Warning deleted successfully', 'success')
    return redirect(url_for('user_warnings', 
                          guild_id=guild_id, 
                          user_id=user_id))
     
# Spam Configuration
@app.route('/dashboard/<guild_id>/spam-config', methods=['GET', 'POST'])
@login_required
@guild_required
def spam_config(guild_id):
    guild = get_guild_or_404(guild_id)
    config = db.get_spam_config(guild_id)
    text_channels = get_text_channels(guild_id)
    roles = get_roles(guild_id)

    if request.method == 'POST':
        try:
            csrf.protect()
            new_config = {
                "spam_threshold": int(request.form.get("spam_threshold", 5)),
                "spam_time_window": int(request.form.get("spam_time_window", 10)),
                "mention_threshold": int(request.form.get("mention_threshold", 3)),
                "mention_time_window": int(request.form.get("mention_time_window", 30)),
                "excluded_channels": request.form.getlist("excluded_channels"),
                "excluded_roles": request.form.getlist("excluded_roles")
            }

            # Validate input
            if any(val < 1 for val in [
                new_config["spam_threshold"],
                new_config["spam_time_window"],
                new_config["mention_threshold"],
                new_config["mention_time_window"]
            ]):
                flash("All thresholds and windows must be at least 1", "danger")
                return redirect(url_for("spam_config", guild_id=guild_id))

            # Add default values for any missing keys
            complete_config = {
                "spam_threshold": 5,
                "spam_time_window": 10,
                "mention_threshold": 3,
                "mention_time_window": 30,
                "excluded_channels": [],
                "excluded_roles": [],
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
     
# Appeal System
@app.route('/dashboard/<guild_id>/ban-appeal-forms', methods=['GET', 'POST'])
@login_required
@guild_required
def ban_appeal_forms(guild_id):
    guild = get_guild_or_404(guild_id)
    forms = db.get_appeal_forms(guild_id) or {}
    text_channels = get_text_channels(guild_id)
    
    if request.method == 'POST':
        try:
            csrf.protect()
            # Get existing config first
            existing = db.get_appeal_forms(guild_id) or {}
            update_data = {
                'ban_enabled': 'ban_enabled' in request.form,
                'ban_channel_id': request.form.get('ban_channel_id'),
                'ban_form_url': request.form.get('ban_form_url'),
                'ban_form_fields': json.dumps(
                    [f.strip() for f in request.form.get('ban_form_fields', '').split('\n') if f.strip()]
                ),
                # Preserve other configs
                'kick_enabled': existing.get('kick_enabled', False),
                'kick_channel_id': existing.get('kick_channel_id'),
                'kick_form_fields': existing.get('kick_form_fields'),
                'timeout_enabled': existing.get('timeout_enabled', False),
                'timeout_channel_id': existing.get('timeout_channel_id'),
                'timeout_form_fields': existing.get('timeout_form_fields'),
                'base_url': FRONTEND_URL
            }
            
            db.update_appeal_forms(guild_id, **update_data)
            flash('Ban appeal settings updated', 'success')
            return redirect(url_for('ban_appeal_forms', guild_id=guild_id))
        
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('ban_appeal_forms', guild_id=guild_id))
    
    return render_template('ban_appeal_form.html',
                         forms=forms,
                         guild_id=guild_id,
                         guild=guild,
                         channels=text_channels,
                         FRONTEND_URL=FRONTEND_URL)

@app.route('/dashboard/<guild_id>/kick-appeal-forms', methods=['GET', 'POST'])
@login_required
@guild_required
def kick_appeal_forms(guild_id):
    guild = get_guild_or_404(guild_id)
    forms = db.get_appeal_forms(guild_id) or {}
    text_channels = get_text_channels(guild_id)
    
    if request.method == 'POST':
        try:
            csrf.protect()
            # Get existing config first
            existing = db.get_appeal_forms(guild_id) or {}
            update_data = {
                'kick_enabled': 'kick_enabled' in request.form,
                'kick_channel_id': request.form.get('kick_channel_id'),
                'kick_form_url': request.form.get('kick_form_url'),
                'kick_form_fields': json.dumps(
                    [f.strip() for f in request.form.get('kick_form_fields', '').split('\n') if f.strip()]
                ),
                # Preserve other configs
                'ban_enabled': existing.get('ban_enabled', False),
                'ban_channel_id': existing.get('ban_channel_id'),
                'ban_form_fields': existing.get('ban_form_fields'),
                'timeout_enabled': existing.get('timeout_enabled', False),
                'timeout_channel_id': existing.get('timeout_channel_id'),
                'timeout_form_fields': existing.get('timeout_form_fields'),
                'base_url': FRONTEND_URL
            }
            
            db.update_appeal_forms(guild_id, **update_data)
            flash('Kick appeal settings updated', 'success')
            return redirect(url_for('ban_appeal_forms', guild_id=guild_id))
        
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('kick_appeal_forms', guild_id=guild_id))
    
    return render_template('kick_appeal_form.html',
                         forms=forms,
                         guild_id=guild_id,
                         guild=guild,
                         channels=text_channels,
                         FRONTEND_URL=FRONTEND_URL)

@app.route('/dashboard/<guild_id>/timeout-appeal-forms', methods=['GET', 'POST'])
@login_required
@guild_required
def timeout_appeal_forms(guild_id):
    guild = get_guild_or_404(guild_id)
    forms = db.get_appeal_forms(guild_id) or {}
    text_channels = get_text_channels(guild_id)
    
    if request.method == 'POST':
        try:
            csrf.protect()
            # Get existing config first
            existing = db.get_appeal_forms(guild_id) or {}
            update_data = {
                'timeout_enabled': 'timeout_enabled' in request.form,
                'timeout_channel_id': request.form.get('timeout_channel_id'),
                'timeout_form_url': request.form.get('timeout_form_url'),
                'timeout_form_fields': json.dumps(
                    [f.strip() for f in request.form.get('timeout_form_fields', '').split('\n') if f.strip()]
                ),
                # Preserve other configs
                'kick_enabled': existing.get('kick_enabled', False),
                'kick_channel_id': existing.get('kick_channel_id'),
                'kick_form_fields': existing.get('kick_form_fields'),
                'ban_enabled': existing.get('ban_enabled', False),
                'ban_channel_id': existing.get('ban_channel_id'),
                'ban_form_fields': existing.get('ban_form_fields'),
                'base_url': FRONTEND_URL
            }
            
            db.update_appeal_forms(guild_id, **update_data)
            flash('Timeout appeal settings updated', 'success')
            return redirect(url_for('timeout_appeal_forms', guild_id=guild_id))
        
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('timeout_appeal_forms', guild_id=guild_id))
    
    return render_template('timeout_appeal_form.html',
                         forms=forms,
                         guild_id=guild_id,
                         guild=guild,
                         channels=text_channels,
                         FRONTEND_URL=FRONTEND_URL)
                         
@app.route('/dashboard/<guild_id>/ban-appeals')
@login_required
@guild_required
def ban_appeals(guild_id):
    try:
        # Get appeal form configuration
        form_config = db.execute_query(
            'SELECT ban_form_fields FROM appeal_forms WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        
        form_fields = []
        if form_config and form_config.get('ban_form_fields'):
            form_fields = [field.split('(')[0].strip() 
                         for field in json.loads(form_config['ban_form_fields'])]

        # Fetch appeals with review information
        appeals = db.execute_query('''
            SELECT 
                appeal_id as id,
                user_id,
                submitted_at,
                status,
                appeal_data,
                preview_text,
                reviewed_by,
                reviewed_at,
                moderator_notes
            FROM appeals 
            WHERE guild_id = ? AND type = 'ban'
            ORDER BY submitted_at DESC
        ''', (guild_id,), fetch='all')

        processed_appeals = []
        for appeal in appeals:
            try:
                appeal_data = json.loads(appeal['appeal_data']) if appeal['appeal_data'] else {}
            except json.JSONDecodeError:
                appeal_data = {}

            processed_appeals.append({
                'id': appeal['id'],
                'user_id': appeal['user_id'],
                'date': datetime.fromtimestamp(appeal['submitted_at']).strftime('%Y-%m-%d %H:%M'),
                'preview': appeal.get('preview_text', 'No preview'),
                'full_data': appeal_data,
                'status': appeal.get('status', 'under_review').lower(),
                'reviewed_by': appeal.get('reviewed_by'),
                'reviewed_at': datetime.fromtimestamp(appeal['reviewed_at']).strftime('%Y-%m-%d %H:%M') if appeal.get('reviewed_at') else None,
                'moderator_notes': appeal.get('moderator_notes'),
                'questions': form_fields
            })

        guild = get_guild_or_404(guild_id)
        return render_template('ban_appeals.html',
                            appeals=processed_appeals,
                            guild_id=guild_id,
                            guild=guild)

    except Exception as e:
        logger.error(f"Error in ban_appeals: {traceback.format_exc()}")
        abort(500, description="Failed to load ban appeals")

# Appeal forms (ban_form_url/kick_form_url/timeout_form_url in the database [appeal_forms table])
@app.route('/ban-appeal-form')
def ban_appeal_form():
    token = request.args.get('token')
    return handle_appeal_form(token, 'ban')
    
@app.route('/kick-appeal-form')
def kick_appeal_form():
    token = request.args.get('token')
    return handle_appeal_form(token, 'kick')

@app.route('/timeout-appeal-form')
def timeout_appeal_form():
    token = request.args.get('token')
    return handle_appeal_form(token, 'timeout')

def handle_appeal_form(token: str, appeal_type: str):
    if not token:
        return "Missing appeal token", 400

    # Validate appeal_type to prevent SQL injection
    valid_types = {'ban', 'kick', 'timeout'}
    if appeal_type not in valid_types:
        return "Invalid appeal type", 400
        
    # Initialize session for anonymous users
    session.permanent = True
    if not session.get('_anon_session'):
        session['_anon_session'] = str(uuid.uuid4())
        session.modified = True

    # Determine the correct columns based on appeal_type
    enabled_column = f"{appeal_type}_enabled"
    form_fields_column = f"{appeal_type}_form_fields"

    # Get appeal data with guild config
    appeal = db.execute_query(
        f'''
        SELECT a.*, af.{enabled_column}, af.{form_fields_column}, g.name as guild_name 
        FROM appeals a
        JOIN appeal_forms af ON a.guild_id = af.guild_id
        JOIN guilds g ON a.guild_id = g.guild_id
        WHERE a.appeal_token = ?
        AND a.type = ?
        AND a.status = 'pending'
        AND a.expires_at > ?
        ''',
        (token, appeal_type, int(time.time())),
        fetch='one'
    )

    if not appeal:
        return render_template('appeal_form.html',
                            form_config={'enabled': False},
                            guild_name="Unknown Server")

    # Build form config from database values
    form_config = {
        'enabled': bool(appeal[enabled_column]),
        'form_fields': json.loads(appeal[form_fields_column]),
        'guild_name': appeal['guild_name']
    }

    if not form_config['enabled']:
        return "Form Disabled", 403

    return render_template('appeal_form.html',
                         appeal_type=appeal_type,
                         form_config=form_config,
                         guild_name=appeal['guild_name'],
                         expires_at=appeal['expires_at'],
                         token=token)

@app.route('/submit-appeal', methods=['POST'])
def submit_appeal():
    """Handle appeal submissions with full validation and error handling"""
    try:
        # ===== [1] CSRF Validation =====
        csrf.protect()
        
        # ===== [2] Initial Data Validation =====
        required_fields = ['token', 'appeal_type']
        if any(field not in request.form for field in required_fields):
            return jsonify({
                "error": "Missing required fields",
                "required": required_fields
            }), 400

        token = request.form['token'].strip()
        appeal_type = request.form['appeal_type'].lower().strip()
        valid_types = {'ban', 'kick', 'timeout'}
        
        if appeal_type not in valid_types:
            return jsonify({
                "error": "Invalid appeal type",
                "valid_types": list(valid_types)
            }), 400

        # ===== [3] Appeal Validation =====
        appeal = db.get_appeal_by_token(token)
        if not appeal:
            return jsonify({"error": "Invalid or expired token"}), 400
            
        if appeal['status'] != 'pending':
            return jsonify({
                "error": "Appeal already processed",
                "current_status": appeal['status']
            }), 409

        # ===== [4] Form Configuration Check =====
        form_config = db.get_appeal_forms(appeal['guild_id']) or {}
        if not form_config.get(f"{appeal_type}_enabled", False):
            return jsonify({
                "error": "This appeal type is disabled",
                "type": appeal_type
            }), 403
            
        channel_id = form_config.get(f"{appeal_type}_channel_id")
        if not channel_id:
            return jsonify({
                "error": "No channel configured for this appeal type",
                "type": appeal_type
            }), 400

        # ===== [5] Response Data Collection =====
        form_fields = json.loads(form_config.get(f"{appeal_type}_form_fields", "[]"))
        response_data = {}
        
        for idx, field in enumerate(form_fields, 1):
            response_key = f"response_{idx}"
            response_data[response_key] = request.form.get(response_key, "").strip()[:2000]

        # ===== [6] Database Update =====
        db.update_appeal(
            appeal_id=appeal['appeal_id'],
            appeal_data=response_data,
            status='under_review',
            preview_text=" | ".join(
                f"{q[:20]}: {v[:30]}" 
                for q, v in zip(form_fields, response_data.values())
            )[:255]
        )

        # ===== [7] Send to Discord =====
        try:
            response = requests.post(
                f"{API_URL}/send_appeal_to_discord",
                json={
                    "appeal_id": appeal['appeal_id'],
                    "guild_id": appeal['guild_id']
                },
                timeout=10  # 10 second timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Bot API error: {response.status_code} {response.text}")
                return jsonify({
                    "error": "Failed to submit to Discord",
                    "details": response.text
                }), 502

        except requests.exceptions.RequestException as e:
            logger.error(f"Bot API connection failed: {str(e)}")
            return jsonify({
                "error": "Could not reach moderation service",
                "details": str(e)
            }), 503

        # ===== [8] Success Response =====
        return jsonify({
            "success": True,
            "appeal_id": appeal['appeal_id'],
            "guild_id": appeal['guild_id'],
            "status": "under_review"
        })

    except CSRFError as e:
        logger.warning(f"CSRF validation failed: {str(e)}")
        return jsonify({
            "error": "Security token expired. Please refresh and try again."
        }), 403
        
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        return jsonify({
            "error": "Failed to save appeal data"
        }), 500
        
    except Exception as e:
        logger.error(f"Unexpected error: {traceback.format_exc()}")
        return jsonify({
            "error": "Internal server error"
        }), 500

@app.route('/dashboard/<guild_id>/ban-appeals/<appeal_id>/approve', methods=['POST'])
@login_required
@guild_required
def approve_ban_appeal(guild_id, appeal_id):
    try:
        csrf.protect()
        moderator_id = session['user']['id']
        
        # Validate appeal exists
        appeal = db.execute_query(
            '''SELECT user_id, status, moderator_notes 
               FROM appeals 
               WHERE appeal_id = ? AND guild_id = ?''',
            (str(appeal_id), str(guild_id)),
            fetch='one'
        )

        if not appeal:
            return jsonify({'success': False, 'error': 'Appeal not found'}), 404

        if appeal['status'].lower() != 'under_review':
            return jsonify({
                'success': False,
                'error': f'Appeal cannot be approved from {appeal["status"]} state'
            }), 400

        # Update appeal status
        new_notes = f"{appeal['moderator_notes']}\nApproved by {moderator_id} at {int(time.time())}" if appeal['moderator_notes'] else f"Approved by {moderator_id} at {int(time.time())}"
        
        db.execute_query(
            '''UPDATE appeals 
               SET status = 'approved',
                   reviewed_at = ?,
                   reviewed_by = ?,
                   moderator_notes = ?
               WHERE appeal_id = ? AND guild_id = ?''',
            (
                int(time.time()), 
                moderator_id, 
                new_notes, 
                str(appeal_id),
                str(guild_id)
            )
        )

        # Direct REST API implementation
        def perform_unban():
            headers = {
                'Authorization': f'Bot {os.getenv("BOT_TOKEN")}',
                'Content-Type': 'application/json'
            }
            user_id = appeal['user_id']
            
            try:
                # Remove ban using Discord REST API
                response = requests.delete(
                    f'https://discord.com/api/v9/guilds/{guild_id}/bans/{user_id}',
                    headers=headers,
                    json={'reason': f'Ban appeal approved (ID: {appeal_id})'}
                )

                if response.status_code == 204:
                    logger.info(f"Successfully unbanned user {user_id}")
                elif response.status_code == 404:
                    logger.info(f"User {user_id} not banned in guild {guild_id}")
                else:
                    error_msg = f"Unban failed: {response.status_code} {response.text}"
                    logger.error(error_msg)
                    db.execute_query(
                        '''UPDATE appeals 
                           SET moderator_notes = moderator_notes || ?
                           WHERE appeal_id = ?''',
                        (f"\n{error_msg}", appeal_id)
                    )
                    
            except Exception as e:
                logger.error(f"Unban error: {str(e)}")
                db.execute_query(
                    '''UPDATE appeals 
                       SET moderator_notes = moderator_notes || ?
                       WHERE appeal_id = ?''',
                    (f"\nUnban failed: {str(e)}", appeal_id)
                )

        # Execute in a thread to avoid blocking
        threading.Thread(target=perform_unban, daemon=True).start()

        return jsonify({
            'success': True,
            'message': 'Appeal approved. Unban process initiated.'
        })

    except CSRFError as e:
        logger.warning(f"CSRF failure: {str(e)}")
        return jsonify({'success': False, 'error': 'Invalid security token'}), 403
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        return jsonify({'success': False, 'error': 'Database operation failed'}), 500
    except Exception as e:
        logger.error(f"Unexpected error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/dashboard/<guild_id>/ban-appeals/<appeal_id>/reject', methods=['POST'])
@login_required
@guild_required
def reject_ban_appeal(guild_id, appeal_id):
    try:
        csrf.protect()
        moderator_id = session['user']['id']
        reason = request.json.get('reason', 'No reason provided').strip()[:1000]
        
        if not reason:
            return jsonify({'success': False, 'error': 'Rejection reason required'}), 400

        # Verify appeal exists and is in correct state
        appeal = db.execute_query(
            '''SELECT status FROM appeals 
               WHERE appeal_id = ? AND guild_id = ?''',
            (str(appeal_id), str(guild_id)),  # Fixed parameter format
            fetch='one'
        )

        if not appeal:
            return jsonify({'success': False, 'error': 'Appeal not found'}), 404

        if appeal['status'].lower() != 'under_review':
            return jsonify({
                'success': False,
                'error': f'Appeal cannot be rejected from {appeal["status"]} state'
            }), 400

        # Update appeal with rejection details
        db.execute_query(
            '''UPDATE appeals 
               SET status = 'rejected',
                   reviewed_at = ?,
                   reviewed_by = ?,
                   moderator_notes = ?
               WHERE appeal_id = ? AND guild_id = ?''',
            (
                int(time.time()), 
                moderator_id, 
                reason, 
                str(appeal_id), 
                str(guild_id)
            )
        )

        return jsonify({
            'success': True,
            'message': 'Appeal rejected successfully'
        })

    except CSRFError as e:
        return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        return jsonify({'success': False, 'error': 'Database operation failed'}), 500
    except Exception as e:
        logger.error(f"Rejection error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

@app.route('/dashboard/<guild_id>/ban-appeals/<appeal_id>/delete', methods=['POST'])
@login_required
@guild_required
def delete_ban_appeal(guild_id, appeal_id):
    try:
        csrf.protect()
        
        # Verify appeal exists
        appeal = db.execute_query(
            'SELECT 1 FROM appeals WHERE appeal_id = ? AND guild_id = ?',
            (str(appeal_id), str(guild_id)),
            fetch='one'
        )
        
        if not appeal:
            return jsonify({'success': False, 'error': 'Appeal not found'}), 404

        # Delete appeal record
        db.execute_query(
            'DELETE FROM appeals WHERE appeal_id = ? AND guild_id = ?',
            (str(appeal_id), str(guild_id))
        )

        return jsonify({'success': True, 'message': 'Appeal permanently deleted'})

    except CSRFError:
        return jsonify({'success': False, 'error': 'CSRF validation failed'}), 403
    except sqlite3.Error as e:
        logger.error(f"Database error: {str(e)}")
        return jsonify({'success': False, 'error': 'Database operation failed'}), 500
    except Exception as e:
        logger.error(f"Deletion error: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Internal server error'}), 500

# Kick Appeals Routes
@app.route('/dashboard/<guild_id>/kick-appeals')
@login_required
@guild_required
def kick_appeals(guild_id):
    try:
        # Get appeal form configuration
        form_config = db.execute_query(
            'SELECT kick_form_fields FROM appeal_forms WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        
        form_fields = []
        if form_config and form_config.get('kick_form_fields'):
            form_fields = [field.split('(')[0].strip() 
                         for field in json.loads(form_config['kick_form_fields'])]

        # Fetch appeals with review information
        appeals = db.execute_query('''
            SELECT 
                appeal_id as id,
                user_id,
                submitted_at,
                status,
                appeal_data,
                preview_text,
                reviewed_by,
                reviewed_at,
                moderator_notes
            FROM appeals 
            WHERE guild_id = ? AND type = 'kick'
            ORDER BY submitted_at DESC
        ''', (guild_id,), fetch='all')

        processed_appeals = []
        for appeal in appeals:
            try:
                appeal_data = json.loads(appeal['appeal_data']) if appeal['appeal_data'] else {}
            except json.JSONDecodeError:
                appeal_data = {}

            processed_appeals.append({
                'id': appeal['id'],
                'user_id': appeal['user_id'],
                'date': datetime.fromtimestamp(appeal['submitted_at']).strftime('%Y-%m-%d %H:%M'),
                'preview': appeal.get('preview_text', 'No preview'),
                'full_data': appeal_data,
                'status': appeal.get('status', 'under_review').lower(),
                'reviewed_by': appeal.get('reviewed_by'),
                'reviewed_at': datetime.fromtimestamp(appeal['reviewed_at']).strftime('%Y-%m-%d %H:%M') if appeal.get('reviewed_at') else None,
                'moderator_notes': appeal.get('moderator_notes'),
                'questions': form_fields
            })

        guild = get_guild_or_404(guild_id)
        return render_template('kick_appeals.html',
                            appeals=processed_appeals,
                            guild_id=guild_id,
                            guild=guild)

    except Exception as e:
        logger.error(f"Error in kick_appeals: {traceback.format_exc()}")
        abort(500, description="Failed to load kick appeals")

@app.route('/dashboard/<guild_id>/kick-appeals/<appeal_id>/approve', methods=['POST'])
@login_required
@guild_required
def approve_kick_appeal(guild_id, appeal_id):
    return handle_appeal_action(guild_id, appeal_id, 'kick', 'approved')

@app.route('/dashboard/<guild_id>/kick-appeals/<appeal_id>/reject', methods=['POST'])
@login_required
@guild_required
def reject_kick_appeal(guild_id, appeal_id):
    return handle_appeal_action(guild_id, appeal_id, 'kick', 'rejected')

@app.route('/dashboard/<guild_id>/kick-appeals/<appeal_id>/delete', methods=['POST'])
@login_required
@guild_required
def delete_kick_appeal(guild_id, appeal_id):
    return handle_appeal_delete(guild_id, appeal_id, 'kick')

# Timeout Appeals Routes
@app.route('/dashboard/<guild_id>/timeout-appeals')
@login_required
@guild_required
def timeout_appeals(guild_id):
    try:
        # Get appeal form configuration
        form_config = db.execute_query(
            'SELECT timeout_form_fields FROM appeal_forms WHERE guild_id = ?',
            (guild_id,),
            fetch='one'
        )
        
        form_fields = []
        if form_config and form_config.get('timeout_form_fields'):
            form_fields = [field.split('(')[0].strip() 
                         for field in json.loads(form_config['timeout_form_fields'])]

        # Fetch appeals with review information
        appeals = db.execute_query('''
            SELECT 
                appeal_id as id,
                user_id,
                submitted_at,
                status,
                appeal_data,
                preview_text,
                reviewed_by,
                reviewed_at,
                moderator_notes
            FROM appeals 
            WHERE guild_id = ? AND type = 'timeout'
            ORDER BY submitted_at DESC
        ''', (guild_id,), fetch='all')

        processed_appeals = []
        for appeal in appeals:
            try:
                appeal_data = json.loads(appeal['appeal_data']) if appeal['appeal_data'] else {}
            except json.JSONDecodeError:
                appeal_data = {}

            processed_appeals.append({
                'id': appeal['id'],
                'user_id': appeal['user_id'],
                'date': datetime.fromtimestamp(appeal['submitted_at']).strftime('%Y-%m-%d %H:%M'),
                'preview': appeal.get('preview_text', 'No preview'),
                'full_data': appeal_data,
                'status': appeal.get('status', 'under_review').lower(),
                'reviewed_by': appeal.get('reviewed_by'),
                'reviewed_at': datetime.fromtimestamp(appeal['reviewed_at']).strftime('%Y-%m-%d %H:%M') if appeal.get('reviewed_at') else None,
                'moderator_notes': appeal.get('moderator_notes'),
                'questions': form_fields
            })

        guild = get_guild_or_404(guild_id)
        return render_template('timeout_appeals.html',
                            appeals=processed_appeals,
                            guild_id=guild_id,
                            guild=guild)

    except Exception as e:
        logger.error(f"Error in timeout_appeals: {traceback.format_exc()}")
        abort(500, description="Failed to load timeout appeals")

@app.route('/dashboard/<guild_id>/timeout-appeals/<appeal_id>/approve', methods=['POST'])
@login_required
@guild_required
def approve_timeout_appeal(guild_id, appeal_id):
    return handle_appeal_action(guild_id, appeal_id, 'timeout', 'approved')

@app.route('/dashboard/<guild_id>/timeout-appeals/<appeal_id>/reject', methods=['POST'])
@login_required
@guild_required
def reject_timeout_appeal(guild_id, appeal_id):
    return handle_appeal_action(guild_id, appeal_id, 'timeout', 'rejected')

@app.route('/dashboard/<guild_id>/timeout-appeals/<appeal_id>/delete', methods=['POST'])
@login_required
@guild_required
def delete_timeout_appeal(guild_id, appeal_id):
    return handle_appeal_delete(guild_id, appeal_id, 'timeout')

# Shared Appeal Handlers
def handle_appeals_page(guild_id, appeal_type, template_name):
    appeals = db.execute_query('''
        SELECT * FROM appeals 
        WHERE guild_id = ? AND appeal_type = ?
        ORDER BY timestamp DESC
    ''', (guild_id, appeal_type))
    
    processed_appeals = []
    for appeal in appeals:
        appeal_dict = process_appeal_data(appeal)
        processed_appeals.append(appeal_dict)
    
    guild = get_guild_or_404(guild_id)
    return render_template(template_name,
                         appeals=processed_appeals,
                         guild_id=guild_id,
                         guild=guild,
                         appeal_type=appeal_type)

def handle_appeal_action(guild_id, appeal_id, appeal_type, action):
    try:
        appeal = db.execute_query(
            'SELECT * FROM appeals WHERE appeal_id = ? AND guild_id = ? AND appeal_type = ?',
            (appeal_id, guild_id, appeal_type),
            fetch='one'
        )
        
        if not appeal:
            return jsonify({'success': False, 'error': 'Appeal not found'}), 404
            
        if action == 'rejected':
            rejection_reason = request.json.get('reason', 'No reason provided')
            db.execute_query(
                '''UPDATE appeals 
                   SET status = ?, 
                       moderator_notes = ?
                   WHERE appeal_id = ?''',
                (action, rejection_reason, appeal_id)
            )
        else:
            db.execute_query(
                'UPDATE appeals SET status = ? WHERE appeal_id = ?',
                (action, appeal_id)
            )
        
        # Add to audit log
        db.execute_query(
            'INSERT INTO audit_log (guild_id, user_id, action, details) VALUES (?, ?, ?, ?)',
            (guild_id, session['user']['id'], f'{appeal_type}_appeal_{action}', 
             f'{action} appeal {appeal_id} for user {appeal["user_id"]}')
        )
        
        return jsonify({'success': True, 'message': f'Appeal {action} successfully'})
        
    except Exception as e:
        logger.error(f"Error {action} {appeal_type} appeal {appeal_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

def handle_appeal_delete(guild_id, appeal_id, appeal_type):
    try:
        db.execute_query(
            'DELETE FROM appeals WHERE appeal_id = ? AND guild_id = ? AND appeal_type = ?',
            (appeal_id, guild_id, appeal_type)
        )
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting {appeal_type} appeal {appeal_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

def process_appeal_data(appeal):
    appeal_dict = dict(appeal)
    data = appeal_dict.get('data', '')
    
    if isinstance(data, str) and data:
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            data = {'answer': data}
    elif not data:
        data = {}
        
    if isinstance(data, dict):
        appeal_dict['data'] = [data]
    elif isinstance(data, list):
        appeal_dict['data'] = data
    else:
        appeal_dict['data'] = [{'answer': str(data)}]
        
    # Get username from Discord API
    user_id = appeal_dict['user_id']
    try:
        headers = {'Authorization': f'Bot {os.getenv("BOT_TOKEN")}'}
        user_data = requests.get(
            f'https://discord.com/api/v9/users/{user_id}',
            headers=headers
        ).json()
        appeal_dict['username'] = user_data.get('username', f'Unknown ({user_id})')
    except Exception as e:
        appeal_dict['username'] = f'Unknown ({user_id})'
        logger.error(f"Error fetching user {user_id}: {str(e)}")
    
    return appeal_dict

def get_appeal_config(guild_id: str, appeal_type: str):
    config = db.execute_query(
        'SELECT * FROM appeal_forms WHERE guild_id = ?',
        (guild_id,),
        fetch='one'
    )
    
    if not config:
        return {'enabled': False}

    type_map = {
        'ban': ('ban_enabled', 'ban_form_fields', 'ban_channel_id'),
        'kick': ('kick_enabled', 'kick_form_fields', 'kick_channel_id'),
        'timeout': ('timeout_enabled', 'timeout_form_fields', 'timeout_channel_id')
    }
    
    enabled_key, fields_key, channel_key = type_map[appeal_type]
    
    return {
        'enabled': bool(config.get(enabled_key, 0)),
        'channel_id': config.get(channel_key),
        'form_fields': json.loads(config.get(fields_key, '[]'))
    }

# Get text channels from Discord API
def get_text_channels(guild_id):
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
def get_roles(guild_id):
    """Fetch roles for a guild with caching"""
    try:
        # Check cache first
        if guild_id in role_cache:
            return role_cache[guild_id]
            
        headers = {'Authorization': f'Bot {os.getenv("BOT_TOKEN")}'}
        response = requests.get(
            f'https://discord.com/api/v9/guilds/{guild_id}/roles',
            headers=headers
        )
        response.raise_for_status()
        
        roles = response.json()
        # Filter out @everyone role and sort by position
        filtered_roles = sorted(
            [r for r in roles if r['id'] != str(guild_id)],
            key=lambda x: x['position'],
            reverse=True
        )
        
        # Cache the results
        role_cache[guild_id] = filtered_roles
        return filtered_roles
        
    except requests.exceptions.HTTPError as e:
        logging.error(f"Roles fetch HTTP error for {guild_id}: {e.response.status_code}")
        return role_cache.get(guild_id, [])
    except Exception as e:
        logging.error(f"Roles fetch error for {guild_id}: {str(e)}")
        return role_cache.get(guild_id, [])  # Return cached version if available

@app.template_filter('get_username')
def get_username_filter(user_id):
    user = db.execute_query(
        'SELECT username FROM users WHERE user_id = ?',
        (user_id,),
        fetch='one'
    )
    return user['username'] if user else None
    

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    return value.strftime(format)

# Error Handlers
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Security token expired. Please refresh the page and try again.', 'danger')
    return redirect(request.referrer or url_for('select_guild'))

@app.errorhandler(401)
def unauthorized(e):
    return redirect(url_for('login'))

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', 
                         error_message=str(e),
                         help_message="Contact your server administrator for access"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', 
                        error_message="404 - Page Not Found",
                        help_message="The page you requested does not exist."), 404
    
@app.errorhandler(500)
def internal_error(e):
    return render_template('error.html',
                        error_message="Internal Server Error",
                        help_message="Please try again later"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)