from __future__ import annotations

import argparse

from .config import Settings
from .inventory import InventoryStore, format_matches


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only inventory demo for the infrastructure bot")
    parser.add_argument("mode", choices=["u", "s", "b"], help="u=asset fields, s=static IP, b=bandwidth")
    parser.add_argument("value", help="IP/value to search")
    parser.add_argument("--inventory", default=None, help="Override inventory workbook path")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    settings = Settings.from_env()
    path = args.inventory or str(settings.inventory_file)
    store = InventoryStore(path)
    matches = store.search(args.value, args.mode)
    print("\n\n".join(format_matches(matches)))


if __name__ == "__main__":
    main()
