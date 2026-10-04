import pytest

from infra_bot.network import normalize_subnet, validate_ip
from infra_bot.hostutils import parse_host_port


def test_subnet_normalization():
    assert str(normalize_subnet("192.0.2.0")) == "192.0.2.0/24"
    assert str(normalize_subnet("198.51.100.17/28")) == "198.51.100.16/28"


def test_large_subnet_rejected():
    with pytest.raises(ValueError):
        normalize_subnet("10.0.0.0/8")


def test_host_port_parser():
    assert parse_host_port("192.0.2.10") == ("192.0.2.10", 22)
    assert parse_host_port("example.internal:2222") == ("example.internal", 2222)


def test_bad_ip_rejected():
    with pytest.raises(ValueError):
        validate_ip("999.1.1.1")
