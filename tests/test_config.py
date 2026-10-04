from infra_bot.config import Settings


def test_safe_defaults(monkeypatch):
    for key in [
        "TELEGRAM_BOT_TOKEN", "ADMIN_USER_IDS", "AUTHORIZED_USER_IDS", "SAFE_MODE",
        "ALLOW_CHAT_CREDENTIALS", "REDFISH_VERIFY_TLS",
    ]:
        monkeypatch.delenv(key, raising=False)
    settings = Settings.from_env()
    assert settings.safe_mode is True
    assert settings.allow_chat_credentials is False
    assert settings.redfish_verify_tls is True
    assert settings.bot_token == ""


def test_min_bandwidth():
    settings = Settings(total_bandwidth_gbps=10.0, max_parallel_sessions=20)
    assert settings.min_bandwidth_per_session_gbps == 0.5
