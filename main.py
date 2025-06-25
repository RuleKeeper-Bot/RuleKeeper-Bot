import os
import sys
import multiprocessing
from pathlib import Path
from dotenv import load_dotenv


def run_bot():
    from bot.bot import bot_instance, BOT_TOKEN
    bot_instance.run(BOT_TOKEN)

def run_flask():
    from web.app import app
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    print("Starting the bot and web server...")
    # Set the start method and start processes
    multiprocessing.set_start_method("spawn", force=True)

    # For binaries, load .env from the executable's directory
    if getattr(sys, 'frozen', False):
        base_dir = Path(sys.executable).parent
    else:
        base_dir = Path(__file__).parent

    dotenv_path = base_dir / '.env'
    if dotenv_path.exists():
        load_dotenv(dotenv_path)

    bot_process = multiprocessing.Process(target=run_bot)
    flask_process = multiprocessing.Process(target=run_flask)

    bot_process.start()
    flask_process.start()

    bot_process.join()
    flask_process.join()