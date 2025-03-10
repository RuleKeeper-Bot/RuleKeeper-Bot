# RuleKeeper Discord Bot

A powerful Discord bot with a sleek dashboard for managing rules, custom commands, and moderation.

## Features

### Bot Features
- **Custom Commands:** Add, edit, and remove commands directly from Discord or through the dashboard.
- **Moderation:**
  - Warn users and track their warnings.
  - Remove warnings.
  - Automatically timeout or ban users who accumulate too many warnings.
- **Auto Moderation:**
  - Detects and mitigates spam (message and mention spam detection).
  - Blocks words that you can set and DM users when they say a blocked word.
- **Logging:** Tracks various server events.
- **Command Syncing:** Ensure commands are always up to date.

### Dashboard Features
- **Admin Login/Logout:** Secure the dashboard with an admin password.
- **Custom Commands:** Add, edit, and remove custom commands.
- **Command Syncing:** Update bot commands instantly.
- **Logging Control:** Enable or disable individual logging options.
- **Manage Blocked Words:**
  - Add, edit, and remove blocked words.
  - Edit the embed that gets sent to the user when they say a blocked word.

---

## Installation (FOR LINUX)

### Prerequisites
Ensure you have the following installed:
- **Git**
  - For Debian-based Linux distributions run: `sudo apt install git`
- **Python**
  - For Debian-based Linux distributions run: `sudo apt install python3 python3-pip python3-venv`

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Wesley-Playz/rulekeeperbot.git
   cd rulekeeperbot
   ```

2. **Create a Discord Bot:**
   - Go to [Discord Developer Portal](https://discord.com/developers/applications).
   - Create a new application and set up your bot.

3. **Set up environment variables:**
   - Create a `.env` file in the project root:
   ```plaintext
   SECRET_KEY=REPLACE_WITH_A_RANDOM_STRING
   ADMIN_PASSWORD=CHOOSE_A_SECURE_PASSWORD
   ```

---

## Running the Bot

1. **Start a screen session:**
   ```bash
   screen -S bot
   ```
2. **Make the virtual environment:**
   ```bash
   cd rulekeeperbot
   python3 -m venv env
   ```  
3. **Activate the virtual environment:**
   ```bash
   source venv/bin/activate
   ```
4. **Install dependencies:**
   ```bash
   cd bot
   pip install -r requirements.txt
   ```
5. **Add your bot token:**
   - Open `secrets.json` and replace the token with your bot's token.
6. **Add blocked words:**
   - Open `blocked_words.json` and add words in there that you want to block.
7. **Edit blocked word DM:**
   - Open `blocked_word_embed.json` and edit to send what you want the embed to send.
8. **Run the bot:**
   ```bash
   python3 bot.py
   ```
   
Alternatively, run the bot in the background without a screen session:
```bash
nohup python3 bot.py &
```

---

## Running the Dashboard (Optional but Recommended)

1. **Start a screen session:**
   ```bash
   screen -S dashboard
   ```
2. **Make the virtual environment:**
   ```bash
   cd rulekeeperbot
   python3 -m venv env
   ```  
3. **Activate the virtual environment:**
   ```bash
   source venv/bin/activate
   ```
4. **Install dependencies:**
   ```bash
   cd web
   pip install -r requirements.txt
   ```
5. **Run the dashboard:**
   ```bash
   python3 app.py
   ```
   
Alternatively, run it in the background without a screen session:
```bash
nohup python3 app.py &
```

Once running, access the dashboard:
- **Local access:** [http://localhost:5000](http://localhost:5000)  
- **Remote access:** http://OtherPCsIPAddress:5000

To detach from a screen session, press `Ctrl + A` then `Ctrl + D`.

---

## To-Do List

[- **Check the Trello board)**](https://trello.com/b/rVCkIgc5/rulekeeper-features)
