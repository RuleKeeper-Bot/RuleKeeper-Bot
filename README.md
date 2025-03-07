# RuleKeeper Discord Bot
My rule keeper discord bot and dashboard!


# Instructions (FOR LINUX)
Install git

Install python

Go to https://discord.com/developers/applications and make a new application (discord bot).

Run `git clone https://github.com/Wesley-Playz/rulekeeperbot.git`

## Bot
1. Open up a screen session
2. Run `cd path/to/where/you/ran/git-clone`
3. Run `cd rulekeeperbot` then `source venv/bin/activate`
4. Run `cd bot` then `pip install -r requirements.txt`
5. Replace bot token in secrets.json with your token
6. Run `python3 bot.py`

## Dashboard (optional)
1. Open up a screen session
2. Run `cd path/to/where/you/ran/git-clone`
3. Run `cd rulekeeperbot` then `source venv/bin/activate`
4. Run `cd web` then `pip install -r requirements.txt`
5. Run `python3 bot.py`


After both of these are running you can detach from the screen sessions and go to http://localhost:5000 (or http://OtherPCsIPAddress:5000 if running on another computer) to access the dashboard.

### What this bot allows you to do
- Make custom commands
- Remove custom commands
- Warn a user
- Get warnings from a user
- Remove a warning from a user
- Timeout and ban people if they get too many warnings
- Message and mention spam detection

### What the dashboard allows you to do
- Edit custom commands
- Remove custom commands

### Todo:
- Add more automod features (deletes certain blocked words and sends a dm when a user sends a blocked word)
- Integrate an add command button to the dashboard
