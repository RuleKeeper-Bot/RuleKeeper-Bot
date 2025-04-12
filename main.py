import os
from shared import shared
from web.app import app
import multiprocessing


def run_bot():
    shared.bot.run(os.getenv("BOT_TOKEN"))


def run_flask():
    app.run(host="0.0.0.0", port=5000)


if __name__ == "__main__":
    bot_process = multiprocessing.Process(target=run_bot)
    flask_process = multiprocessing.Process(target=run_flask)

    bot_process.start()
    flask_process.start()

    bot_process.join()
    flask_process.join()
