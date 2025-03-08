from flask import Flask, render_template, request, jsonify, redirect  # Added redirect
import json
import requests

app = Flask(__name__)

def get_commands():
    try:
        with open('../bot/commands.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_commands(commands):  # New function to save commands
    with open('../bot/commands.json', 'w') as f:
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
        
        save_commands(commands)  # Use the new function here
        
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
        save_commands(commands)  # Now properly defined
        return redirect('/')  # Requires redirect import
    
    return render_template('edit.html', 
                         command=commands[command_name],
                         command_name=command_name)

@app.route('/delete/<command_name>')
def delete_command(command_name):
    commands = get_commands()
    if command_name in commands:
        del commands[command_name]
        save_commands(commands)  # Now properly defined
    return redirect('/')

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)