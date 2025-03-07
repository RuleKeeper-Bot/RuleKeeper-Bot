# rulekeeperbot
My rule keeper discord bot and dashboard


# Instructions (FOR LINUX)
Install git
Install python
Run `git clone https://github.com/Wesley-Playz/rulekeeperbot.git`

## Bot
1. Open up a screen session
2. Run `cd path/to/where/you/ran/git-clone`
3. Run `cd rulekeeperbot` then `source venv/bin/activate`
4. Run `cd bot` then `pip install -r requirements.txt`
5. Replace bot token in secrets.json with your token
6. Run `python3 bot.py`

## Dashboard
1. Open up a screen session
2. Run `cd path/to/where/you/ran/git-clone`
3. Run `cd rulekeeperbot` then `source venv/bin/activate`
4. Run `cd web` then `pip install -r requirements.txt`
5. Run `python3 bot.py`


After both of these are running you can detach from the screen sessions and go to http://localhost:5000 (or http://OtherPCsIPAddress:5000 if running on another computer) to access the dashboard.
