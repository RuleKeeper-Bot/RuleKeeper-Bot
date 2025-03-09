# RuleKeeper Discord Bot
My rule keeper discord bot and dashboard!


# Instructions (FOR LINUX)
Install git

Install python

Go to https://discord.com/developers/applications and make a new application (discord bot).

Run `git clone https://github.com/Wesley-Playz/rulekeeperbot.git` and run `cd rulekeeperbot`

Make a new file called `.env` and add these lines to it:
```
SECRET_KEY=REPLACE_WITH_A_RANDOM_STRING
ADMIN_PASSWORD=CHOOSE_A_SECURE_PASSWORD
```

## Bot
1. Open up a screen session
2. Run `cd path/to/where/you/ran/git-clone`
3. Run `cd rulekeeperbot` then `source venv/bin/activate`
4. Run `cd bot` then `pip install -r requirements.txt`
5. Replace bot token in secrets.json with your token
6. Run `python3 bot.py`

(You can also skip the screen session and just run the script with `nohup python bot. py &`)

## Dashboard (optional but recommended)
1. Open up a screen session
2. Run `cd path/to/where/you/ran/git-clone`
3. Run `cd rulekeeperbot` then `source venv/bin/activate`
4. Run `cd web` then `pip install -r requirements.txt`
5. Run `python3 app.py`

(You can also skip the screen session and just run the script with `nohup python app. py &`)


After both of these are running and the discord bot has been added to your server, you can detach from the screen sessions and go to http://localhost:5000 (or http://OtherPCsIPAddress:5000 if running on another computer) to access the dashboard.

### What this bot allows you to do
- Make custom commands
- Remove custom commands
- Warn a user
- Get warnings from a user
- Remove a warning from a user
- Timeout and ban people if they get too many warnings
- Sync commands to update them
- Message and mention spam detection
- Logs a lot of stuff

### What the dashboard allows you to do
- Login with an admin password
- Logout
- Add custom commands
- Edit custom commands
- Remove custom commands
- Sync commands to update then
- Enable and disable individual logging options

### Todo:
- Add more automod features (deletes certain blocked words and sends a dm when a user sends a blocked word)
