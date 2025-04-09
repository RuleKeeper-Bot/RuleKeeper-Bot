# RuleKeeper Discord Bot

A powerful Discord bot with a sleek dashboard for managing rules, custom commands, and moderation.

## Features

### Bot Features
- **Custom Commands:** Add, edit, and remove commands directly from Discord or through the dashboard.
- **Moderation:**
  - Ban, kick, deafen, timeout, and softban users.
  - Unban, undeafen, and untimeout users.
  - Warn users and track their warnings.
  - Remove warnings.
  - Automatically timeout or ban users who accumulate too many warnings.
  - Purge messages.
- **Auto Moderation:**
  - Detects and mitigates spam (message and mention spam detection).
  - Blocks words that you can set and DM users when they say a blocked word.
- **Logging:** Tracks various server events.
- **Leveling:**
  - Role rewards.
  - XP boosting for certain roles.
  - Custom XP ranges.
  - Custom cooldown.
- **Ban Appeals:**
  - Send ban appeals to a channel.
  - Approve and reject an appeal directly in the channel.

### Dashboard Features
- **Login Using Discord OAuth:** View all servers you have access to edit.
- **Admin Login/Logout:** Edit any server (that your version of the bot is in) using an admin password.
- **Custom Commands:** Add, edit, and remove custom commands.
- **Command Syncing:** Update bot commands instantly.
- **Logging Control:** Enable or disable individual logging options.
- **Manage Blocked Words:**
  - Add, edit, and remove blocked words.
  - Edit the embed that gets sent to the user when they say a blocked word.
- **Manage Leveling:** Customize XP ranges, boosts, and level embed.
- **Leaderboard:** View a server leaderboard.
- **Appeal Forms:** Make custom ban/kick/timeout appeal forms with a simple question builder.
- **Ban Appeals:** View, approve, and deny ban appeals.
- **Banned Users:**
  - View a list of banned users.
  - Unban users.
- **Warned Users:** View, edit, and delete warnings from a user.

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
   ADMIN_PASSWORD=CHOOSE_A_VERY_STRONG_PASSWORD
   FRONTEND_URL=http://localhost:5000
   API_URL=http://localhost:5003
   DISCORD_CLIENT_ID=GET_FROM_DISCORD_DEVELOPER_PORTAL
   DISCORD_CLIENT_SECRET=GET_FROM_DISCORD_DEVELOPER_PORTAL
   DISCORD_REDIRECT_URI=http://localhost:5000/callback
   DATABASE_PATH=bot/bot.db
   ENABLE_LEVELING=true
   ENABLE_MODERATION=true
   ENABLE_APPEALS=true
   ```

---

## Running the Bot

1. **Start a screen session:**
   ```bash
   screen -S rulekeeperbot
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
6. **Run the bot:**
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

[- **Check the Trello board**](https://trello.com/b/rVCkIgc5/rulekeeper-features)
