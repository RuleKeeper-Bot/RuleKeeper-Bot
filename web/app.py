from flask import Flask, render_template, request, jsonify, redirect
import json
import requests
import os

app = Flask(__name__)

# Path to commands and log config files (adjust if needed)
COMMANDS_PATH = os.path.join('..', 'bot', 'commands.json')
LOG_CONFIG_PATH = os.path.join('..', 'bot', 'config', 'log_config.json')

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
        # If not found, return default settings
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

@app.route('/')
def index():
    commands = get_commands()
    return render_template('index.html', commands=commands)

@app.route('/sync', methods=['POST'])
def sync_commands():
    try:
        response = requests.post('http://localhost:5003/sync')
        return response.text, 200
    except Exception as e:
        return str(e), 500

@app.route('/create_command', methods=['POST'])
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
def delete_command(command_name):
    commands = get_commands()
    if command_name in commands:
        del commands[command_name]
        save_commands(commands)
    return redirect('/')

# -------------------- Logging Config Dashboard --------------------
ALLOWED_LOG_KEYS = [
    "message_delete", "bulk_message_delete", "message_edit",
    "invite_create", "invite_delete", "member_role_add",
    "member_role_remove", "member_timeout", "member_warn",
    "member_unwarn", "member_ban", "member_unban", "role_create",
    "role_delete", "role_update", "channel_create", "channel_delete",
    "channel_update", "emoji_create", "emoji_name_change", "emoji_delete"
]

@app.route('/log_config', methods=['GET', 'POST'])
def log_config_dashboard():
    full_config = load_log_config()
    
    if request.method == 'POST':
        for key in ALLOWED_LOG_KEYS:
            full_config[key] = (key in request.form)
        save_log_config(full_config)
        
        # Auto reload the bot by calling its /sync endpoint
        try:
            requests.post('http://localhost:5003/sync')
        except Exception as e:
            print("Error reloading bot configuration:", e)
        
        return redirect('/log_config')
    else:
        visible_config = {key: full_config.get(key, True) for key in ALLOWED_LOG_KEYS}
        return render_template('log_config.html', config=visible_config)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)