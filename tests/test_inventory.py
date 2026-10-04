from pathlib import Path

from infra_bot.inventory import InventoryStore, extract_ips


SAMPLE = Path(__file__).resolve().parents[1] / "sample_data" / "sample_inventory.xlsx"


def test_extract_ips_rejects_invalid_octets():
    assert extract_ips("192.0.2.10 / 999.1.1.1") == ["192.0.2.10"]


def test_static_lookup_pairs_management_and_server_rows():
    store = InventoryStore(SAMPLE)
    matches = store.search("198.18.24.141", mode="s")
    assert matches
    match = matches[0]
    assert match.static_context is not None
    assert match.static_context.tag == "LAB-1214"
    assert "198.18.12.61" in match.static_context.all_network_ips
    assert match.static_context.rack_unit == "bay 1"


def test_forward_fill_supports_server_row_search():
    store = InventoryStore(SAMPLE)
    matches = store.search("198.18.25.24", mode="s")
    assert matches
    assert matches[0].static_context is not None
    assert matches[0].static_context.tag == "LAB-1215"


def test_contains_anywhere_and_slash_position():
    store = InventoryStore(SAMPLE)
    assert store.contains_anywhere("198.18.23.131")
    between, endpoint = store.slash_position_flags("198.18.23.131")
    assert between is True
    assert endpoint is False
