from flask import Flask, render_template, request, redirect
import json
from pathlib import Path
from functools import cache
import requests

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this!

# Path to commands.json (adjust if needed)
COMMANDS_PATH = Path('../bot/commands.json').resolve()

@cache
def get_commands():
    with open(COMMANDS_PATH, 'r') as f:
        return json.load(f)

def save_commands(commands):
    with open(COMMANDS_PATH, 'w') as f:
        json.dump(commands, f, indent=4)

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

@app.route('/edit/<command_name>', methods=['GET', 'POST'])
def edit_command(command_name):
    commands = get_commands()
    
    if request.method == 'POST':
        # Update command data
        commands[command_name] = {
            "content": request.form['content'],
            "description": request.form['description'],
            "ephemeral": 'ephemeral' in request.form
        }
        save_commands(commands)
        get_commands.cache_clear()  # Clear cache
        return redirect('/')
    
    return render_template('edit.html', 
                         command=commands[command_name],
                         command_name=command_name)

@app.route('/delete/<command_name>')
def delete_command(command_name):
    commands = get_commands()
    if command_name in commands:
        del commands[command_name]
        save_commands(commands)
        get_commands.cache_clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)