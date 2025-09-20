import os
import sys
import multiprocessing

from pathlib import Path
from dotenv import load_dotenv
from bot.bot import bot_instance, BOT_TOKEN
try:
    from bot.bot import debug_print
except ImportError:
    def debug_print(*args, **kwargs):
        pass

def run_bot():
    debug_print("Entering run_bot", level="all")
    bot_instance.run(BOT_TOKEN)

def run_flask():
    debug_print("Entering run_flask", level="all")
    from web.app import app
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    debug_print("Starting main entry point")
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
        debug_print(f"Loading .env from {dotenv_path}")
        load_dotenv(dotenv_path)

    debug_print("Spawning bot and flask processes")
    bot_process = multiprocessing.Process(target=run_bot)
    flask_process = multiprocessing.Process(target=run_flask)

    bot_process.start()
    flask_process.start()

    debug_print("Waiting for bot and flask processes to finish")
    bot_process.join()
    flask_process.join()