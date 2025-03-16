from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, abort
import json
import requests
import sys
import os
import math
import uuid
from datetime import datetime
from markupsafe import Markup
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config
import logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.config.from_object(Config)

# -------------------- File Paths --------------------
COMMANDS_PATH = os.path.join('..', 'bot', 'commands.json')
LOG_CONFIG_PATH = os.path.join('..', 'bot', 'config', 'log_config.json')
LEVEL_CONFIG_PATH = os.path.join('..', 'bot', 'level_config.json')
LEVEL_REWARDS_PATH = os.path.join('..', 'bot', 'level_rewards.json')
LEVELS_PATH = os.path.join('..', 'bot', 'levels.json')
APPEAL_FORMS_PATH = os.path.join('..', 'bot', 'appeal_forms.json')
BAN_APPEALS_PATH = os.path.join('..', 'bot', 'ban_appeals.json')
WARNINGS_PATH = os.path.join('..', 'bot', 'warnings.json')
APPEALS_PATH = os.path.join('..', 'bot', 'appeals.json')

# -------------------- Admin Login System --------------------
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == app.config['ADMIN_PASSWORD']:
            session['logged_in'] = True
            flash("Logged in successfully!", "success")
            next_page = request.args.get('next') or url_for('index')
            return redirect(next_page)
        else:
            flash("Incorrect password.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

# -------------------- Main Routes --------------------
@app.route('/')
@login_required
def index():
    commands = get_commands()
    return render_template('index.html', commands=commands)

@app.route('/sync', methods=['POST'])
@login_required
def sync_commands():
    try:
        response = requests.post('http://localhost:5003/sync')
        return response.text, 200
    except Exception as e:
        return str(e), 500
        
@app.route('/sync_warnings', methods=['POST'])
def sync_warnings():
    try:
        # Force the bot to reload warnings from the file
        requests.post('http://localhost:5003/sync_warnings')
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/commands/create_command', methods=['POST'])
@login_required
def create_command():
    try:
        new_command = request.get_json()
        commands = get_commands()
        if new_command['command_name'] in commands:
            return jsonify({"success": False, "message": "Command already exists"}), 400
        commands[new_command['command_name']] = {
            "content": new_command['content'],
            "description": new_command['description'],
            "ephemeral": new_command['ephemeral']
        }
        save_commands(commands)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/commands/edit/<command_name>', methods=['GET', 'POST'])
@login_required
def edit_command(command_name):
    commands = get_commands()
    if request.method == 'POST':
        commands[command_name] = {
            "content": request.form['content'],
            "description": request.form['description'],
            "ephemeral": 'ephemeral' in request.form
        }
        save_commands(commands)
        return redirect('/')
    return render_template('edit.html', command=commands[command_name], command_name=command_name)

@app.route('/commands/delete/<command_name>')
@login_required
def delete_command(command_name):
    commands = get_commands()
    if command_name in commands:
        del commands[command_name]
        save_commands(commands)
    return redirect('/')

# -------------------- Utility Functions --------------------
def get_commands():
    try:
        with open(COMMANDS_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_commands(commands):
    with open(COMMANDS_PATH, 'w') as f:
        json.dump(commands, f, indent=4)

def load_log_config():
    try:
        with open(LOG_CONFIG_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        # Create default log config if it doesn't exist
        default_config = {
            "message_delete": True,
            "bulk_message_delete": True,
            "message_edit": True,
            "invite_create": True,
            "invite_delete": True,
            "member_role_add": True,
            "member_role_remove": True,
            "member_timeout": True,
            "member_warn": True,
            "member_unwarn": True,
            "member_ban": True,
            "member_unban": True,
            "role_create": True,
            "role_delete": True,
            "role_update": True,
            "channel_create": True,
            "channel_delete": True,
            "channel_update": True,
            "emoji_create": True,
            "emoji_name_change": True,
            "emoji_delete": True
        }
        with open(LOG_CONFIG_PATH, 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config

def save_log_config(config):
    with open(LOG_CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)

def load_level_config():
    default_config = {
        "cooldown": 60,
        "xp_range": [15, 25],
        "level_channel": None,
        "announce_level_up": True,
        "excluded_channels": [],
        "xp_boost_roles": {},
        "embed": {
            "title": "🎉 Level Up!",
            "description": "{user} has reached level **{level}**!",
            "color": 0xffd700
        }
    }
    try:
        with open(LEVEL_CONFIG_PATH, 'r') as f:  # Use LEVEL_CONFIG_PATH here
            config = json.load(f)
            return {**default_config, **config}
    except FileNotFoundError:
        with open(LEVEL_CONFIG_PATH, 'w') as f:  # Use LEVEL_CONFIG_PATH here
            json.dump(default_config, f, indent=4)
        return default_config

def save_level_config(config):
    with open(LEVEL_CONFIG_PATH, 'w') as f:  # Use LEVEL_CONFIG_PATH here
        json.dump(config, f, indent=4)
        
# Only these keys will be shown/edited on the dashboard.
ALLOWED_LOG_KEYS = [
    "message_delete", "bulk_message_delete", "message_edit",
    "invite_create", "invite_delete", "member_role_add",
    "member_role_remove", "member_timeout", "member_warn",
    "member_unwarn", "member_ban", "member_unban", "role_create",
    "role_delete", "role_update", "channel_create", "channel_delete",
    "channel_update", "emoji_create", "emoji_name_change", "emoji_delete",
    "log_config_update"
]

def load_warnings():
    try:
        with open(WARNINGS_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_warnings(warnings):
    with open(WARNINGS_PATH, 'w') as f:
        json.dump(warnings, f, indent=4)

def load_level_rewards():
    try:
        with open(LEVEL_REWARDS_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_level_rewards(rewards):
    with open(LEVEL_REWARDS_PATH, 'w') as f:
        json.dump(rewards, f, indent=4)
        
def load_user_levels():
    try:
        with open(USER_LEVELS_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

@app.route('/level_rewards', methods=['GET', 'POST'])
@login_required
def level_rewards():
    rewards = load_level_rewards()
    
    if request.method == 'POST':
        if 'delete' in request.form:
            # Handle deletion
            level = request.form['delete']
            if level in rewards:
                del rewards[level]
                save_level_rewards(rewards)
                flash('Reward deleted successfully!', 'success')
        else:
            # Handle add/edit
            level = str(request.form['level'])
            role_id = request.form['role_id'].strip()
            
            if not level.isdigit():
                flash('Level must be a number!', 'danger')
                return redirect('/level_rewards')
            
            if not role_id.isdigit():
                flash('Role ID must be a valid number!', 'danger')
                return redirect('/level_rewards')
            
            rewards[level] = role_id
            save_level_rewards(rewards)
            flash('Reward saved successfully!', 'success')
        
        return redirect('/level_rewards')
    
    return render_template('level_rewards.html', rewards=rewards)
    
@app.route('/leaderboard')
@login_required
def leaderboard():
    def load_levels():
        try:
            with open(LEVELS_PATH, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    users_data = load_levels()
    
    # Convert to list of tuples and sort by XP descending, then level descending
    sorted_users = sorted(users_data.items(),
                        key=lambda x: (-x[1]['xp'], -x[1]['level']))
    
    # Add this filter to format XP values
    app.jinja_env.filters['intxp'] = lambda x: int(x) if isinstance(x, float) and x.is_integer() else x
    
    return render_template('leaderboard.html', users=sorted_users)

@app.route('/commands')
@login_required
def commands_page():
    commands = get_commands()
    return render_template('commands.html', commands=commands)

# -------------------- Leveling Configuration Dashboard --------------------
@app.route('/level_config', methods=['GET', 'POST'])
@login_required
def level_config():
    config = load_level_config()
    all_channels = []  # Fetch actual channels from Discord API
    
    if request.method == 'POST':
        # Update main config
        config['cooldown'] = int(request.form['cooldown'])
        config['xp_range'] = [
            int(request.form['xp_min']),
            int(request.form['xp_max'])
        ]
        config['announce_level_up'] = 'announce_level_up' in request.form
        config['level_channel'] = request.form['level_channel'] or None
        
        # Process excluded channels
        excluded = request.form['excluded_channels'].split(',')
        config['excluded_channels'] = [int(c.strip()) for c in excluded if c.strip()]
        
        # Process XP boost roles
        try:
            xp_boost_roles = request.form['xp_boost_roles'].strip()
            config['xp_boost_roles'] = json.loads(xp_boost_roles) if xp_boost_roles else {}
        except json.JSONDecodeError:
            flash('Invalid XP boost roles format! Must be valid JSON', 'danger')
            return redirect('/level_config')
        
        # Update embed
        config['embed'] = {
            "title": request.form['embed_title'],
            "description": request.form['embed_description'],
            "color": int(request.form['embed_color'].lstrip('#'), 16)
        }
        
        save_level_config(config)
        flash('Leveling configuration updated!', 'success')
        return redirect('/level_config')

    # Convert color to hex string for input
    embed = config['embed']
    embed['color_hex'] = f"#{config['embed']['color']:06x}"
    
    return render_template('level_config.html', 
                         config=config,
                         embed=embed,
                         all_channels=all_channels)
                         
# -------------------- Logging Configuration Dashboard --------------------
@app.route('/log_config', methods=['GET', 'POST'])
@login_required
def log_config_dashboard():
    full_config = load_log_config()
    
    if request.method == 'POST':
        # Handle log channel ID input
        try:
            channel_id = int(request.form.get('log_channel_id', 0)) or None
            if channel_id:
                try:
                    full_config['log_channel_id'] = int(channel_id)
                except ValueError:
                    flash('Invalid channel ID format', 'danger')
            else:
                full_config['log_channel_id'] = None
        except ValueError:
            flash('Invalid channel ID format', 'danger')
        # Update only the allowed keys from the form
        for key in ALLOWED_LOG_KEYS:
            full_config[key] = (key in request.form)
        save_log_config(full_config)
        
        # Auto-reload bot configuration via its sync endpoint.
        try:
            requests.post('http://localhost:5003/sync')
        except Exception as e:
            print("Error reloading bot configuration:", e)
        
        return redirect('/log_config')
    else:
        visible_config = {key: full_config.get(key, True) for key in ALLOWED_LOG_KEYS}
        return render_template('log_config.html', config=visible_config)
        
# -------------------- Appeal Forms --------------------
def load_appeal_forms():
    default_forms = {
        "base_url": "",
        "ban": {
            "enabled": False,
            "channel_id": "",
            "form_fields": [],
            "form_url": "/ban-appeal-form"
        },
        "kick": {
            "enabled": False,
            "channel_id": "",
            "form_fields": [],
            "form_url": "/kick-appeal-form"
        },
        "timeout": {
            "enabled": False,
            "channel_id": "",
            "form_fields": [],
            "form_url": "/timeout-appeal-form"
        }
    }
    try:
        with open(APPEAL_FORMS_PATH, 'r') as f:
            loaded = json.load(f)
            # Properly merge all keys including base_url
            default_forms.update(loaded)
            # Ensure nested structures are preserved
            for appeal_type in ['ban', 'kick', 'timeout']:
                if appeal_type in loaded:
                    default_forms[appeal_type].update(loaded[appeal_type])
            return default_forms
    except (FileNotFoundError, json.JSONDecodeError):
        return default_forms

def save_appeal_forms(forms):
    # Ensure we're saving the complete structure
    with open(APPEAL_FORMS_PATH, 'w') as f:
        json.dump({
            "base_url": forms.get("base_url", ""),
            "ban": forms.get("ban", {}),
            "kick": forms.get("kick", {}),
            "timeout": forms.get("timeout", {})
        }, f, indent=4)
        
def load_appeals():
    try:
        with open(APPEALS_PATH, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_appeals(appeals):
    with open(APPEALS_PATH, 'w') as f:
        json.dump(appeals, f, indent=4)
    
    # Ensure proper structure
    required_keys = ['id', 'user_id', 'type', 'data', 'timestamp']
    if not all(key in appeal_data for key in required_keys):
        print("Invalid appeal data structure")
        return
    
    appeals.append(appeal_data)
    
    with open(APPEALS_PATH, 'w') as f:
        json.dump(appeals, f, indent=4)
    
@app.route('/ban-appeal-form', methods=['GET', 'POST'])
def ban_appeal_form():
    return handle_appeal_form("ban")

@app.route('/kick-appeal-form', methods=['GET', 'POST'])
def kick_appeal_form():
    return handle_appeal_form("kick")

@app.route('/timeout-appeal-form', methods=['GET', 'POST'])
def timeout_appeal_form():
    return handle_appeal_form("timeout")

# -------------------- Appeal Discord Notification --------------------

def handle_appeal_form(appeal_type):
    form_config = load_appeal_forms().get(appeal_type, {})
    
    if not form_config.get("enabled", False):
        return "This appeal form is not currently active.", 404

    if request.method == 'POST':
        appeal_id = str(uuid.uuid4())[:8]
        user_id = request.form.get('user_id', 'Unknown')  # Get from hidden field in form
        
        # Process form responses
        responses = []
        for field in form_config.get("form_fields", []):
            field_name = field.split('(')[0].strip()
            responses.append({
                "question": field_name,
                "answer": request.form.get(field_name, "")
            })

        # Prepare data for bot
        appeal_data = {
            "type": appeal_type,
            "user_id": user_id,
            "id": appeal_id,
            "data": responses,
            "channel_id": form_config["channel_id"]  # Pass the channel ID from config
        }

        # Send to bot's appeal handler
        try:
            requests.post('http://localhost:5003/appeal', json=appeal_data)
        except Exception as e:
            print(f"Error sending to bot: {e}")
            flash("Error submitting appeal. Please try again.", "danger")
            return redirect(url_for('index'))

        flash("Appeal submitted successfully! We'll review it shortly.", "success")
        return redirect(url_for('index'))

    return render_template('appeal_form.html',
                         form_config=form_config,
                         appeal_type=appeal_type)

@app.route('/submit-appeal', methods=['POST'])
def handle_appeal_submission():
    appeal_type = request.form['type']
    user_id = request.form['user_id']
    appeal_id = str(uuid.uuid4())[:8]
    
    # Process form data
    responses = []
    for key, value in request.form.items():
        if key not in ['type', 'user_id']:
            responses.append({'question': key, 'answer': value})
    
    appeal_data = {
        'type': appeal_type,
        'user_id': user_id,
        'id': appeal_id,
        'data': responses
    }
    
    # Send to bot
    try:
        requests.post('http://localhost:5003/appeal', json=appeal_data)
    except Exception as e:
        print(f"Error sending appeal to bot: {e}")
    
    flash("Appeal submitted successfully!", "success")
    return redirect(url_for('index'))

# -------------------- Warnings Management --------------------
@app.route('/warnings')
@login_required
def warnings_list():
    warnings = load_warnings()
    warned_users = []
    for user_id, data in warnings.items():
        warned_users.append({
            'id': user_id,
            'username': data.get('username', 'Unknown'),
            'count': len(data.get('warnings', []))
        })
    return render_template('warnings_list.html', users=warned_users)

@app.route('/warnings/<user_id>', methods=['GET', 'POST'])
@login_required
def view_warnings(user_id):
    warnings = load_warnings()
    user_data = warnings.get(user_id)
    if not user_data:
        flash('User not found', 'danger')
        return redirect('/warnings')
    
    if request.method == 'POST':
        new_warnings = []
        for key in request.form:
            if key.startswith('reason_'):
                index = int(key.split('_')[1])
                new_warnings.append({
                    'timestamp': user_data['warnings'][index]['timestamp'],
                    'reason': request.form[key]
                })
        warnings[user_id]['warnings'] = new_warnings
        save_warnings(warnings)
        flash('Warnings updated!', 'success')
        return redirect(f'/warnings/{user_id}')
    
    return render_template('user_warnings.html', 
                         user_data=user_data,
                         user_id=user_id)

# -------------------- Ban Appeals Management --------------------

def load_ban_appeals():
    try:
        with open(BAN_APPEALS_PATH, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_ban_appeals(appeals):
    with open(BAN_APPEALS_PATH, 'w') as f:
        json.dump(appeals, f, indent=4)

@app.route('/ban_appeals')
@login_required
def ban_appeals():
    appeals = load_appeals()
    ban_appeals = [a for a in appeals if a.get('type') == 'ban']
    return render_template('ban_appeals.html', appeals=ban_appeals)

@app.route('/ban_appeals/<appeal_id>/<action>')
@login_required
def handle_appeal(appeal_id, action):
    appeals = load_appeals()
    appeal = next((a for a in appeals if a['id'] == appeal_id and a['type'] == 'ban'), None)
    
    if not appeal:
        flash('Appeal not found', 'danger')
        return redirect('/ban_appeals')
    
    index = appeals.index(appeal)
    
    if action in ['approve', 'reject', 'delete']:
        if action == 'delete':
            del appeals[index]
        else:
            appeals[index]['status'] = action
        save_appeals(appeals)
        flash(f'Appeal {action}d!', 'success')
    
    return redirect('/ban_appeals')

# -------------------- Appeal Forms Backend --------------------
def generate_appeal_url(appeal_type, appeal_id):
    forms = load_appeal_forms()
    base_url = forms.get('base_url', '').rstrip('/')
    path = forms[appeal_type].get('form_url', '').format(id=appeal_id)
    
    if base_url:
        return f"{base_url}{path}"
    return path

@app.route('/appeal_forms', methods=['GET', 'POST'])
@login_required
def appeal_forms():
    # Load current configuration
    config_data = load_appeal_forms()
    
    if request.method == 'POST':
        try:
            # Update base URL
            config_data['base_url'] = request.form.get('base_url', '').strip()

            # Process each appeal type
            for appeal_type in ['ban', 'kick', 'timeout']:
                enabled = request.form.get(f'{appeal_type}_enabled', 'off') == 'on'
                channel_id = request.form.get(f'{appeal_type}_channel_id', '').strip()
                
                # Process form fields
                raw_fields = request.form.get(f'{appeal_type}_form_fields', '')
                form_fields = [
                    line.strip() 
                    for line in raw_fields.split('\n') 
                    if line.strip()
                ]
                
                # Update configuration
                config_data[appeal_type].update({
                    'enabled': enabled,
                    'channel_id': channel_id,
                    'form_fields': form_fields
                })

            # Save configuration
            save_appeal_forms(config_data)
            flash('Configuration successfully saved!', 'success')
            return redirect(url_for('appeal_forms'))
            
        except Exception as e:
            flash(f'Error saving configuration: {str(e)}', 'danger')
            return redirect(url_for('appeal_forms'))

    # Prepare template data with proper list->string conversion
    template_data = {
        'base_url': config_data.get('base_url', ''),
        'ban': {
            'enabled': config_data.get('ban', {}).get('enabled', False),
            'channel_id': config_data.get('ban', {}).get('channel_id', ''),
            'form_url': config_data.get('ban', {}).get('form_url', '/ban_appeals/{id}'),
            'form_fields': config_data.get('ban', {}).get('form_fields', [])  # Pass the list directly
        },
        'kick': {
            'enabled': config_data.get('kick', {}).get('enabled', False),
            'channel_id': config_data.get('kick', {}).get('channel_id', ''),
            'form_url': config_data.get('kick', {}).get('form_url', '/kick_appeals/{id}'),
            'form_fields': config_data.get('kick', {}).get('form_fields', [])
        },
        'timeout': {
            'enabled': config_data.get('timeout', {}).get('enabled', False),
            'channel_id': config_data.get('timeout', {}).get('channel_id', ''),
            'form_url': config_data.get('timeout', {}).get('form_url', '/timeout_appeals/{id}'),
            'form_fields': config_data.get('timeout', {}).get('form_fields', [])
        }
    }

    return render_template('appeal_forms.html',
                         config=template_data,
                         base_url=template_data['base_url'],
                         channel_types=['ban', 'kick', 'timeout'])

@app.route('/ban_appeals/<appeal_id>')
def view_ban_appeal(appeal_id):
    forms = load_appeal_forms()
    if not forms['ban']['enabled']:
        return "Ban appeals are not currently enabled", 404
        
    # Fetch actual appeal data
    appeals = load_appeals()
    appeal = next((a for a in appeals if a['id'] == appeal_id and a['type'] == 'ban'), None)
    
    if not appeal:
        return "Appeal not found", 404
    
    # Process form fields with question labels
    form_fields = forms['ban']['form_fields']
    processed_data = []
    for field in form_fields:
        if '(' in field and ')' in field:
            question = field.split('(')[0].strip()
        else:
            question = field
        processed_data.append({
            'question': question,
            'answer': appeal['data'].get(question, 'No response')
        })
    
    return render_template('view_appeal.html', 
                         appeal={
                             'id': appeal_id,
                             'status': appeal.get('status', 'pending'),
                             'data': processed_data,
                             'timestamp': appeal.get('timestamp'),
                             'type': 'ban'
                         },
                         appeal_type='ban')

@app.route('/kick_appeals/<appeal_id>')
def view_kick_appeal(appeal_id):
    forms = load_appeal_forms()
    if not forms['kick']['enabled']:
        return "Kick appeals are not currently enabled", 404
        
    # Fetch actual appeal data
    appeals = load_appeals()
    appeal = next((a for a in appeals if a['id'] == appeal_id and a['type'] == 'kick'), None)
    
    if not appeal:
        return "Appeal not found", 404
    
    # Process form fields with question labels
    form_fields = forms['kick']['form_fields']
    processed_data = []
    for field in form_fields:
        if '(' in field and ')' in field:
            question = field.split('(')[0].strip()
        else:
            question = field
        processed_data.append({
            'question': question,
            'answer': appeal['data'].get(question, 'No response')
        })
    
    return render_template('view_appeal.html', 
                         appeal={
                             'id': appeal_id,
                             'status': appeal.get('status', 'pending'),
                             'data': processed_data,
                             'timestamp': appeal.get('timestamp'),
                             'type': 'kick'
                         },
                         appeal_type='kick')

@app.route('/timeout_appeals/<appeal_id>')
def view_timeout_appeal(appeal_id):
    forms = load_appeal_forms()
    if not forms['timeout']['enabled']:
        return "Timeout appeals are not currently enabled", 404
        
    # Fetch actual appeal data
    appeals = load_appeals()
    appeal = next((a for a in appeals if a['id'] == appeal_id and a['type'] == 'timeout'), None)
    
    if not appeal:
        return "Appeal not found", 404
    
    # Process form fields with question labels
    form_fields = forms['timeout']['form_fields']
    processed_data = []
    for field in form_fields:
        if '(' in field and ')' in field:
            question = field.split('(')[0].strip()
        else:
            question = field
        processed_data.append({
            'question': question,
            'answer': appeal['data'].get(question, 'No response')
        })
    
    return render_template('view_appeal.html', 
                         appeal={
                             'id': appeal_id,
                             'status': appeal.get('status', 'pending'),
                             'data': processed_data,
                             'timestamp': appeal.get('timestamp'),
                             'type': 'timeout'
                         },
                         appeal_type='timeout')

@app.route('/appeal/<appeal_id>')
def view_appeal(appeal_id):
    appeals = load_appeals()
    appeal = next((a for a in appeals if a['id'] == appeal_id), None)
    
    if not appeal:
        abort(404)  # Return 404 if appeal not found
    
    return render_template('view_appeal.html', appeal=appeal)

# -------------------- Banned/Warned Users --------------------
@app.route('/banned_users')
@login_required
def banned_users():
    try:
        response = requests.get('http://localhost:5003/get_bans', timeout=10)
        if response.status_code == 200:
            return render_template('banned_users.html', bans=response.json())
        flash("Failed to fetch bans from bot", "danger")
    except requests.exceptions.RequestException as e:
        flash(f"Connection error: {str(e)}", "danger")
    return render_template('banned_users.html', bans=[])

@app.route('/warned_users')
@login_required
def warned_users():
    warnings = load_warnings()
    warned_users = [{
        'id': uid,
        'username': data.get('username', 'Unknown'),
        'count': len(data.get('warnings', []))
    } for uid, data in warnings.items()]
    return render_template('warned_users.html', users=warned_users)

@app.route('/warnings/<user_id>/delete/<int:warning_index>', methods=['GET'])
@login_required
def delete_warning(user_id, warning_index):
    warnings = load_warnings()
    if user_id in warnings:
        user_warnings = warnings[user_id]['warnings']
        if 0 <= warning_index < len(user_warnings):
            # Remove the warning
            del user_warnings[warning_index]
            
            # If no warnings are left, remove the user from the warnings dictionary
            if not user_warnings:
                del warnings[user_id]
            
            # Save the updated warnings to the file
            save_warnings(warnings)
            
            # Sync the bot's in-memory warnings
            try:
                requests.post('http://localhost:5003/sync_warnings')
            except Exception as e:
                print(f"Failed to sync warnings: {e}")
            
            flash('Warning deleted successfully!', 'success')
        else:
            flash('Invalid warning index', 'danger')
    else:
        flash('User not found', 'danger')
    return redirect(f'/warnings/{user_id}')

# -------------------- Blocked Words Configuration Dashboard --------------------
@app.template_filter('hex')
def hex_filter(value):
    # Assuming the value is an integer, convert it to a hex string
    if isinstance(value, int):
        return f'#{value:06x}'
    return value
    
@app.route('/blocked_words', methods=['GET', 'POST'])
@login_required
def blocked_words():
    # Load existing data
    try:
        with open(Config.BLOCKED_WORDS_FILE, 'r') as f:
            blocked_data = json.load(f)
            blocked_words = blocked_data.get('blocked_words', [])
    except (FileNotFoundError, json.JSONDecodeError):
        blocked_words = []

    try:
        with open(Config.BLOCKED_WORDS_EMBED_FILE, 'r') as f:
            embed_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        embed_data = {
            "title": "Blocked Word Detected!",
            "description": "You have used a word that is not allowed.",
            "color": 0xff0000
        }

    if request.method == 'POST':
        # Process form data
        new_words = [w.strip() for w in request.form.getlist('blocked_words') if w.strip()]
        embed_title = request.form['embed_title']
        embed_description = request.form['embed_description']
        embed_color = int(request.form['embed_color'].lstrip('#'), 16)

        # Save blocked words
        with open(Config.BLOCKED_WORDS_FILE, 'w') as f:
            json.dump({"blocked_words": new_words}, f, indent=4)

        # Save embed settings
        with open(Config.BLOCKED_WORDS_EMBED_FILE, 'w') as f:
            json.dump({
                "title": embed_title,
                "description": embed_description,
                "color": embed_color
            }, f, indent=4)

        flash('Settings saved successfully!', 'success')
        return redirect('/blocked_words')

    return render_template('blocked_words.html',
                         blocked_words=blocked_words,
                         embed=embed_data)

# -------------------- Main Entry --------------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)