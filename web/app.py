from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import json
import requests
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config  # config.py should define SECRET_KEY, ADMIN_PASSWORD, and COMMANDS_FILE

app = Flask(__name__)
app.config.from_object(Config)

# -------------------- File Paths --------------------
COMMANDS_PATH = os.path.join('..', 'bot', 'commands.json')
LOG_CONFIG_PATH = os.path.join('..', 'bot', 'config', 'log_config.json')

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

# Only these keys will be shown/edited on the dashboard.
ALLOWED_LOG_KEYS = [
    "message_delete", "bulk_message_delete", "message_edit",
    "invite_create", "invite_delete", "member_role_add",
    "member_role_remove", "member_timeout", "member_warn",
    "member_unwarn", "member_ban", "member_unban", "role_create",
    "role_delete", "role_update", "channel_create", "channel_delete",
    "channel_update", "emoji_create", "emoji_name_change", "emoji_delete"
]

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

@app.route('/create_command', methods=['POST'])
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

@app.route('/edit/<command_name>', methods=['GET', 'POST'])
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

@app.route('/delete/<command_name>')
@login_required
def delete_command(command_name):
    commands = get_commands()
    if command_name in commands:
        del commands[command_name]
        save_commands(commands)
    return redirect('/')

# -------------------- Logging Configuration Dashboard --------------------
@app.route('/log_config', methods=['GET', 'POST'])
@login_required
def log_config_dashboard():
    full_config = load_log_config()
    
    if request.method == 'POST':
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

# -------------------- Main Entry --------------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)