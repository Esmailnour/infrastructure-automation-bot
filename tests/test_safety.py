import pytest

from infra_bot.config import Settings


def test_mutations_blocked_by_default():
    settings = Settings()
    with pytest.raises(PermissionError):
        settings.require_mutations_enabled("test operation")


def test_chat_credentials_blocked_by_default():
    settings = Settings()
    with pytest.raises(PermissionError):
        settings.require_chat_credentials_enabled()
