#!/usr/bin/env python3
"""Sanitize the public demo XLSX in place without changing its visual layout."""

from __future__ import annotations

import ipaddress
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
ET.register_namespace("", NS)

SHEET_NAMES = [
    "SITE-A", "SITE-B", "SITE-C", "SITE-C-BLADES", "SITE-C-STORAGE",
    "SITE-C-NORTH", "SITE-D", "SITE-E", "CHANGE-LOG", "CUSTOMER-DEMO",
    "RACK-DEMO", "SERVER-GROUP", "DCIM-DEMO", "MGMT-MAP", "KVM-DEMO",
    "SWITCH-DEMO-01", "SWITCH-DEMO-02", "SWITCH-DEMO-03",
    "SWITCH-INVENTORY", "BACKUP-INVENTORY", "NOTES", "MISC",
]

SAFE_V4 = (
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
PREFIX_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}(?!\d)")
CELL_RE = re.compile(r"([A-Z]+)(\d+)")


def col_num(ref: str) -> int:
    m = CELL_RE.fullmatch(ref)
    if not m:
        return 0
    value = 0
    for ch in m.group(1):
        value = value * 26 + ord(ch) - 64
    return value


def row_num(ref: str) -> int:
    m = CELL_RE.fullmatch(ref)
    return int(m.group(2)) if m else 0


def header_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def cell_text(cell: ET.Element) -> str:
    return "".join((node.text or "") for node in cell.findall(f".//{{{NS}}}t"))


def set_cell_text(cell: ET.Element, value: str) -> None:
    nodes = cell.findall(f".//{{{NS}}}t")
    if not nodes:
        return
    nodes[0].text = value
    for node in nodes[1:]:
        node.text = ""


def map_ip(raw: str) -> str:
    ip = ipaddress.ip_address(raw)
    if any(ip in block for block in SAFE_V4):
        return str(ip)
    offset = int(ip) % 65534 + 1
    return str(ipaddress.IPv4Address(int(ipaddress.IPv4Address("198.19.0.0")) + offset))


def sanitize_ip_text(value: str) -> str:
    def repl(match: re.Match[str]) -> str:
        try:
            return map_ip(match.group(0))
        except ValueError:
            return match.group(0)

    value = IPV4_RE.sub(repl, value)

    def prefix_repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        try:
            probe = ipaddress.ip_address(raw + "1")
            if any(probe in block for block in SAFE_V4):
                return raw
        except ValueError:
            pass
        return "198.19.50."

    return PREFIX_RE.sub(prefix_repl, value)


def generic_note(row: int) -> str:
    labels = (
        "Demo workload", "Application host", "Backup target",
        "Maintenance spare", "Network test server",
        "Replication node", "Lab virtualization host", "QA storage node",
    )
    return labels[row % len(labels)]


def sanitize_sheet(data: bytes, sheet_index: int) -> bytes:
    root = ET.fromstring(data)
    headers: dict[int, str] = {}

    for cell in root.findall(f".//{{{NS}}}c"):
        ref = cell.get("r", "")
        if row_num(ref) == 1:
            text = cell_text(cell)
            if text:
                headers[col_num(ref)] = header_name(text)

    for cell in root.findall(f".//{{{NS}}}c"):
        ref = cell.get("r", "")
        row = row_num(ref)
        col = col_num(ref)
        if row <= 1:
            continue

        old = cell_text(cell)
        if not old:
            continue

        value = sanitize_ip_text(old)
        header = headers.get(col, "")

        if "in use or not" in header:
            low = value.lower()
            value = "no" if any(x in low for x in ("no", "unused", "cancel", "off")) else (
                "maintenance" if any(x in low for x in ("maintenance", "repair", "spare")) else "yes"
            )
        elif header.startswith("cust") or header in {"customer", "client"}:
            value = f"Demo Client {chr(65 + row % 4)}"
        elif header == "name" or header.endswith(" name"):
            value = f"demo-node-{row:03d}"
        elif any(x in header for x in ("more information", "more info", "notes", "note", "remarks", "description", "blade notes")):
            value = generic_note(row)
        elif "switch" in header and "port" in header:
            port = re.search(r"(?i)p/\s*[0-9-]+(?:/[0-9-]+)?", value)
            value = f"DEMO SWITCH {1 + row % 8} {port.group(0) if port else 'p/' + str(1 + row % 48)}"
        elif sheet_index in {8, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21}:
            # Auxiliary sheets are intentionally genericized more aggressively.
            if re.search(r"[A-Za-z]", value) and not re.fullmatch(
                r"(?i)(yes|no|ilo|idrac|kvm|management|\d+(?:\.\d+)?\s*(?:g|m|t)?bps)",
                value.strip(),
            ):
                if "http://" in value.lower() or "https://" in value.lower() or "user" in value.lower():
                    value = "https://198.18.27.15/ user:demo_admin credential:DEMO_ONLY"
                else:
                    value = "Demo"

        if value != old:
            set_cell_text(cell, value)

    return ET.tostring(root, encoding="utf-8")


def rename_workbook(data: bytes) -> bytes:
    root = ET.fromstring(data)
    sheets = root.find(f"{{{NS}}}sheets")
    if sheets is not None:
        for idx, sheet in enumerate(list(sheets)):
            if idx < len(SHEET_NAMES):
                sheet.set("name", SHEET_NAMES[idx])
    return ET.tostring(root, encoding="utf-8")


def sanitize(path: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / path.name
        with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(
            output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as target:
            for info in source.infolist():
                data = source.read(info.filename)
                if info.filename == "xl/workbook.xml":
                    data = rename_workbook(data)
                else:
                    match = re.fullmatch(r"xl/worksheets/sheet(\d+)\.xml", info.filename)
                    if match:
                        data = sanitize_sheet(data, int(match.group(1)) - 1)
                target.writestr(info, data)
        shutil.copy2(output, path)


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "sample_data/sample_inventory.xlsx")
    sanitize(target)
    print(f"Sanitized {target}")
