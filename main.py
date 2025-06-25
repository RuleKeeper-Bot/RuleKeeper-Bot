import os
from pathlib import Path
from dotenv import load_dotenv
from web.app import app
import multiprocessing
import sys


# For binaries, load .env from the executable's directory
if getattr(sys, 'frozen', False):
    base_dir = Path(sys.executable).parent
else:
    base_dir = Path(__file__).parent

dotenv_path = base_dir / '.env'
if dotenv_path.exists():
    load_dotenv(dotenv_path)


def run_bot():
    from shared import shared
    shared.bot.run(os.getenv("BOT_TOKEN"))


def run_flask():
    from web.app import app
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    multiprocessing.set_start_method("spawn")
    bot_process = multiprocessing.Process(target=run_bot)
    flask_process = multiprocessing.Process(target=run_flask)

    bot_process.start()
    flask_process.start()

    bot_process.join()
    flask_process.join()
