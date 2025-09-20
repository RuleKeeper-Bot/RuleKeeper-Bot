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
        """
        Fallback debug printing function used when a real debug_print is not available.
        
        This no-op implementation accepts the same calling convention as built-in `print` (positional
        and keyword arguments) so callers can invoke it unconditionally. All arguments are ignored
        and the function returns None. Intended to provide a safe default when `bot.bot.debug_print`
        cannot be imported.
        """
        pass

def run_bot():
    """
    Start and run the configured bot instance.
    
    This launches the global `bot_instance` using the module-level `BOT_TOKEN` and blocks the current process while the bot runs. Intended to be used as the target for a separate process; it does not return until the bot stops or raises.
    """
    debug_print("Entering run_bot", level="all")
    bot_instance.run(BOT_TOKEN)

def run_flask():
    """
    Start the Flask web application by importing the app and running it on 0.0.0.0:5000.
    
    Performs a dynamic import of `web.app.app` and calls `app.run(host="0.0.0.0", port=5000)`. This blocks the current process while the server runs and binds to all network interfaces on port 5000.
    """
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