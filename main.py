from dotenv import load_dotenv

from infra_bot.telegram_app import run_bot


if __name__ == "__main__":
    load_dotenv()
    run_bot()
