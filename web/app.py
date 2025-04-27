import sys
import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import uuid
import logging
import json
import requests
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort, render_template_string
from flask_discord import DiscordOAuth2Session, Unauthorized
from flask_wtf.csrf import CSRFProtect, CSRFError
from database import db
from database import Database
from config import Config
from shared_config import Config
from shared import shared
import re
import sqlite3
import time
from flask_discord.exceptions import RateLimited
from dotenv import load_dotenv

load_dotenv()

# Initialize Flask app
app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = os.getenv('SECRET_KEY')
app.config['DISCORD_CLIENT_ID'] = os.getenv('DISCORD_CLIENT_ID')
app.config['DISCORD_CLIENT_SECRET'] = os.getenv('DISCORD_CLIENT_SECRET')
app.config['DISCORD_REDIRECT_URI'] = os.getenv('FRONTEND_URL') + '/callback'
app.config.update({
    'WTF_CSRF_TIME_LIMIT': 3600 * 2,  # 2 hour expiration
    'WTF_CSRF_SSL_STRICT': False,
    'SESSION_COOKIE_SAMESITE': 'Lax'
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

# Initialize database connection
Config.verify_paths()
db = Database(str(Config.DATABASE_PATH))
print(f"🌐 Web using database: {db.db_path}")

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
    if request.args.get('admin') and request.args.get('password') == ADMIN_PASSWORD:
        session['admin'] = True
        session.permanent = True
        return redirect(url_for('select_guild'))
    return discord.create_session(scope=['identify', 'guilds'])
    
@app.route('/login-admin', methods=['GET', 'POST'])
def login_admin():
    if request.method == 'POST':
        # Verify CSRF token first
        try:
            csrf.protect()
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('login_admin', guild_id=guild_id))
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['admin'] = True
            session.permanent = True
            return redirect(url_for('select_guild'))
        else:
            error = "Invalid password"
    else:
        error = None

    return render_template_string('''
        <!doctype html>
        <title>Admin Login</title>
        <h2>Admin Login</h2>
        {% if error %}<p style="color: red;">{{ error }}</p>{% endif %}
        <form method="post">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input type="password" name="password" placeholder="Enter admin password" required>
            <input type="submit" value="Login">
        </form>
    ''', error=error)

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
            session.pop('admin', None)
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
        discord.callback()
        user = discord.fetch_user()
        session['user'] = {
            'id': str(user.id),
            'name': user.name,
            'avatar': user.avatar_url or ''
        }
        session.permanent = True
        return redirect(url_for('select_guild'))
    except Unauthorized:
        flash('Discord authentication failed', 'danger')
        return redirect(url_for('login'))

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
        
        return render_template('log_config.html', config=config, guild_id=guild_id, guild=guild)
        
    except Exception as e:
        logger.error(f"Error in log config: {str(e)}")
        abort(500)

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
    
    # Get existing config and convert to dict if needed
    db_config = db.get_level_config(guild_id)
    config = dict(db_config) if db_config else {}
    
    # Default configuration template
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
        'embed_color': 0xFFD700  # Default gold color
    }
    
    # Merge configurations
    merged_config = default_config.copy()
    merged_config.update(config)
    
    # Handle rewards
    rewards = db.get_level_rewards(guild_id)
    rewards_dict = {str(level): role_id for level, role_id in rewards.items()}

    # Handle form submission
    if request.method == 'POST':
        # Verify CSRF token first
        try:
            csrf.protect()
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('level_config', guild_id=guild_id))

        # Add reward handling
        if 'add_reward' in request.form:
            reward_level = request.form.get('reward_level', '').strip()
            reward_role_id = request.form.get('reward_role_id', '').strip()
            
            if not reward_level.isdigit() or not reward_role_id.isdigit():
                flash('Invalid reward parameters', 'danger')
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
                'excluded_channels': [
                    s.strip() for s in 
                    request.form.get('excluded_channels', '').split(',') 
                    if s.strip()
                ],
                'xp_boost_roles': request.form.get('xp_boost_roles', '{}'),
                'embed_title': request.form.get('embed_title', '🎉 Level Up!'),
                'embed_description': request.form.get(
                    'embed_description', 
                    '{user} has reached level **{level}**!'
                ),
                'embed_color': int(
                    request.form.get('embed_color', 'ffd700').lstrip('#'), 
                    16
                )
            }

            # Validate JSON fields
            try:
                json.loads(new_config['xp_boost_roles'])
            except json.JSONDecodeError:
                flash('Invalid XP boost roles format', 'danger')
                return redirect(url_for('level_config', guild_id=guild_id))

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
                         guild=guild)

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
                          
# Appeal System
@app.route('/dashboard/<guild_id>/appeal-forms', methods=['GET', 'POST'])
@login_required
@guild_required
def appeal_forms(guild_id):
    guild = get_guild_or_404(guild_id)
    forms = db.get_appeal_forms(guild_id) or {}
    
    if request.method == 'POST':
        # Verify CSRF token first
        try:
            csrf.protect()
        except CSRFError:
            flash('Security token expired. Please submit the form again.', 'danger')
            return redirect(url_for('appeal_forms', guild_id=guild_id))
        update_data = {
            'base_url': request.form.get('base_url'),
            'ban_enabled': 'ban_enabled' in request.form,
            'ban_channel_id': request.form.get('ban_channel_id'),
            'ban_form_url': request.form.get('ban_form_url'),
            'ban_form_fields': json.dumps(
                [f.strip() for f in request.form.get('ban_form_fields', '').split('\n') if f.strip()]
            ),
            'kick_enabled': 'kick_enabled' in request.form,
            'kick_channel_id': request.form.get('kick_channel_id'),
            'kick_form_url': request.form.get('kick_form_url'),
            'kick_form_fields': json.dumps(
                [f.strip() for f in request.form.get('kick_form_fields', '').split('\n') if f.strip()]
            ),
            'timeout_enabled': 'timeout_enabled' in request.form,
            'timeout_channel_id': request.form.get('timeout_channel_id'),
            'timeout_form_url': request.form.get('timeout_form_url'),
            'timeout_form_fields': json.dumps(
                [f.strip() for f in request.form.get('timeout_form_fields', '').split('\n') if f.strip()]
            )
        }
        
        guild = get_guild_or_404(guild_id)
        db.update_appeal_forms(guild_id, **update_data)
        flash('Appeal forms updated', 'success')
        return redirect(url_for('appeal_forms', guild_id=guild_id))
    
    return render_template('appeal_forms.html',
                         forms=forms,
                         guild_id=guild_id,
                         guild=guild)

@app.route('/dashboard/<guild_id>/ban-appeals')
@login_required
@guild_required
def ban_appeals(guild_id):
    appeals = db.execute_query('''
        SELECT * FROM appeals 
        WHERE guild_id = ?
        ORDER BY timestamp DESC
    ''', (guild_id,))
    
    processed_appeals = []
    for appeal in appeals:
        appeal_dict = dict(appeal)
        data = appeal_dict.get('data', '')
        
        # Handle data processing
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
            
            # Discord username format (without discriminator)
            if 'username' in user_data:
                appeal_dict['username'] = user_data['username']
            else:
                appeal_dict['username'] = f"Unknown ({user_id})"
                
        except Exception as e:
            appeal_dict['username'] = f"Unknown ({user_id})"
            logger.error(f"Error fetching user {user_id}: {str(e)}")
        
        processed_appeals.append(appeal_dict)
    
    guild = get_guild_or_404(guild_id)
    return render_template('ban_appeals.html',
                         appeals=processed_appeals,
                         guild_id=guild_id,
                         guild=guild)

@app.route('/dashboard/<guild_id>/ban-appeals/<appeal_id>/approve', methods=['POST'])
@login_required
@guild_required
def approve_ban_appeal(guild_id, appeal_id):
    try:
        csrf.protect()
    except CSRFError:
        return jsonify({'success': False, 'error': 'CSRF token expired'}), 403
    try:
        # Get appeal data first
        appeal = db.execute_query(
            'SELECT * FROM appeals WHERE appeal_id = ? AND guild_id = ?',
            (appeal_id, guild_id),
            fetch='one'
        )
        
        if not appeal:
            return jsonify({'success': False, 'error': 'Appeal not found'}), 404
            
        # Update appeal status
        db.execute_query(
            'UPDATE appeals SET status = ? WHERE appeal_id = ?',
            ('approved', appeal_id)
        )
        
        return jsonify({
            'success': True,
            'message': 'Appeal approved successfully'
        })
        
    except Exception as e:
        logger.error(f"Error approving appeal {appeal_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
        
@app.route('/dashboard/<guild_id>/ban-appeals/<appeal_id>/reject', methods=['POST'])
@login_required
@guild_required
def reject_ban_appeal(guild_id, appeal_id):
    try:
        csrf.protect()
    except CSRFError:
        return jsonify({'success': False, 'error': 'CSRF token expired'}), 403
    try:
        # Verify appeal exists
        appeal = db.execute_query(
            'SELECT * FROM appeals WHERE appeal_id = ? AND guild_id = ?',
            (appeal_id, guild_id),
            fetch='one'
        )
        
        if not appeal:
            return jsonify({'success': False, 'error': 'Appeal not found'}), 404
            
        # Update status and optionally store rejection reason
        rejection_reason = request.json.get('reason', 'No reason provided')
        
        db.execute_query(
            '''UPDATE appeals 
               SET status = ?, 
                   moderator_notes = ?
               WHERE appeal_id = ?''',
            ('rejected', rejection_reason, appeal_id)
        )
        
        return jsonify({
            'success': True,
            'message': 'Appeal rejected successfully'
        })
        
    except Exception as e:
        logger.error(f"Error rejecting appeal {appeal_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/dashboard/<guild_id>/ban-appeals/<appeal_id>/delete', methods=['POST'])
@login_required
@guild_required
def delete_ban_appeal(guild_id, appeal_id):
    try:
        csrf.protect()
    except CSRFError:
        return jsonify({'success': False, 'error': 'CSRF token expired'}), 403
    try:
        db.execute_query(
            'DELETE FROM appeals WHERE appeal_id = ? AND guild_id = ?',
            (appeal_id, guild_id)
        )
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error deleting appeal {appeal_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Kick Appeals Routes
@app.route('/dashboard/<guild_id>/kick-appeals')
@login_required
@guild_required
def kick_appeals(guild_id):
    return handle_appeals_page(guild_id, 'kick', 'kick_appeals.html')

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
    return handle_appeals_page(guild_id, 'timeout', 'timeout_appeals.html')

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


@app.template_filter('get_username')
def get_username_filter(user_id):
    user = db.execute_query(
        'SELECT username FROM users WHERE user_id = ?',
        (user_id,),
        fetch='one'
    )
    return user['username'] if user else None
    

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
    if "RuleKeeper bot is not" in str(e):
        return render_template('error.html', 
                            error_message=str(e),
                            help_message="Please add the bot to your server first"), 404
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
