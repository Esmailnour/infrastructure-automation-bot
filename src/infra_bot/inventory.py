from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import pandas as pd


TAG_ALIASES = ["tag", "our tag", "dc tag", "asset tag", "rack tag"]
RACK_ALIASES = ["rack / unit", "rack / u #", "rack/u", "rack unit", "rack / slot", "rack / unit #"]
SWITCH_ALIASES = [
    "switch / port", "switch /port #", "switch / port #", "switch  / port",
    "switch /port", "switch / port#", "switch/port", "switch  /port #",
    "switch  / port", "switch  /port", "switch / port",
]
INFO_ALIASES = [
    "more information", "more info", "notes", "note", "remarks", "details",
    "description", "bay notes",
]
STATIC_ALIASES = ["static ip", "ip network", "static ips", "static ip "]
BANDWIDTH_ALIASES = ["bandwith", "bandwidth", "speed"]

UNUSED_SEARCH_COLUMNS = {
    "our tag", "rack / u #", "switch /port #", "tag", "dc tag",
    "in use or not ?", "switch  /port #", "more information",
    "server port 10 or 1 ?", "switch /port #", "switch / port", "bay",
    "bay notes", "notes", "rack / unit",
}
STATIC_SEARCH_COLUMNS = {"static ip", "ip network", "static ips"}
BANDWIDTH_SEARCH_COLUMNS = {"bandwidth", "bandwith", "speed"}


def normalize_value(value):
    if isinstance(value, str):
        value = value.strip()
        value = re.sub(r"\s+", " ", value)
        value = re.sub(r"\s*/\s*", "/", value)
        value = re.sub(r"\s*-\s*", "-", value)
        value = re.sub(r"\s*\+\s*", "+", value)
    return value


def normalize_header(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value).lower()).strip()


def safe_text(value: object) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except Exception:
        pass
    return normalize_value(str(value))


def find_column(df: pd.DataFrame, aliases: Iterable[str]) -> str | None:
    wanted = {normalize_header(a) for a in aliases}
    for col in df.columns:
        if normalize_header(col) in wanted:
            return str(col)
    return None


def extract_ips(text: object) -> list[str]:
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", safe_text(text))
    result: list[str] = []
    for candidate in candidates:
        try:
            ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if ip not in result:
            result.append(ip)
    return result


def extract_ref_tag(text: object) -> str:
    text = safe_text(text)
    for pattern in (r"i\s*lo\s*for\s*([A-Za-z0-9-]+)", r"idrac\s*for\s*([A-Za-z0-9-]+)"):
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1).strip()
    return ""


def clean_tag(text: object) -> str:
    value = safe_text(text)
    value = re.sub(r"^i\s*lo\s*for\s*", "", value, flags=re.I).strip()
    value = re.sub(r"^idrac\s*for\s*", "", value, flags=re.I).strip()
    return value


def contains_management_hint(text: object) -> bool:
    value = safe_text(text).lower()
    keywords = ("ilo", "i lo", "idrac", "management", "mgmt", "bmc")
    return bool(value) and any(k in value for k in keywords)


def looks_like_management_row(
    row: pd.Series,
    tag_col: str | None,
    switch_col: str | None,
    info_col: str | None,
    static_col: str | None,
    bandwidth_col: str | None,
) -> bool:
    direct = " | ".join(
        safe_text(row.get(col, ""))
        for col in (tag_col, switch_col, static_col, bandwidth_col)
        if col
    ).lower()
    if any(k in direct for k in ("ilo", "i lo", "idrac", "management", "mgmt", "bmc")):
        return True
    if tag_col and extract_ref_tag(row.get(tag_col, "")):
        return True
    if info_col and extract_ref_tag(row.get(info_col, "")):
        return True
    return False


@dataclass(slots=True)
class StaticContext:
    matched_is_management: bool
    related_management_ip: str | None
    network_switch: str
    network_ip: str
    all_network_ips: list[str]
    tag: str
    rack_unit: str
    note: str
    paired_index: int
    paired_relation: str


def resolve_static_ip_context(df: pd.DataFrame, matched_idx: int, searched_ip: str) -> StaticContext | None:
    tag_col = find_column(df, TAG_ALIASES)
    rack_col = find_column(df, RACK_ALIASES)
    switch_col = find_column(df, SWITCH_ALIASES)
    info_col = find_column(df, INFO_ALIASES)
    static_col = find_column(df, STATIC_ALIASES)
    bandwidth_col = find_column(df, BANDWIDTH_ALIASES)
    if static_col is None:
        return None

    row = df.loc[matched_idx]
    matched_tag = clean_tag(row.get(tag_col, "")) if tag_col else ""
    matched_rack = safe_text(row.get(rack_col, "")) if rack_col else ""
    matched_info = safe_text(row.get(info_col, "")) if info_col else ""
    matched_is_management = looks_like_management_row(
        row, tag_col, switch_col, info_col, static_col, bandwidth_col
    )

    ref_tag = ""
    if tag_col:
        ref_tag = extract_ref_tag(row.get(tag_col, "")) or matched_tag
    if not ref_tag and info_col:
        ref_tag = extract_ref_tag(matched_info)

    candidates: list[tuple[int, pd.Series]] = []
    if ref_tag and tag_col:
        mask = df[tag_col].fillna("").astype(str).map(lambda x: clean_tag(x).lower() == ref_tag.lower())
        candidates.extend((int(j), cand) for j, cand in df[mask].iterrows())
    for offset in (-1, 1, -2, 2, -3, 3, -4, 4, -5, 5):
        j = matched_idx + offset
        if j in df.index:
            candidates.append((int(j), df.loc[j]))

    dedup: list[tuple[int, pd.Series]] = []
    seen: set[int] = set()
    for j, cand in candidates:
        if j not in seen:
            seen.add(j)
            dedup.append((j, cand))
    candidates = dedup

    def cand_tag(cand: pd.Series) -> str:
        return clean_tag(cand.get(tag_col, "")) if tag_col else ""

    def cand_rack(cand: pd.Series) -> str:
        return safe_text(cand.get(rack_col, "")) if rack_col else ""

    def score_server(j: int, cand: pd.Series) -> int:
        score = 0
        ips = extract_ips(cand.get(static_col, ""))
        if [ip for ip in ips if ip != searched_ip]:
            score += 15
        switch = safe_text(cand.get(switch_col, "")) if switch_col else ""
        bandwidth = safe_text(cand.get(bandwidth_col, "")) if bandwidth_col else ""
        tag = cand_tag(cand)
        if switch and not contains_management_hint(switch):
            score += 30
        if switch and contains_management_hint(switch):
            score -= 40
        if bandwidth and "ilo" in bandwidth.lower():
            score -= 40
        elif bandwidth:
            score += 12
        if not looks_like_management_row(cand, tag_col, switch_col, info_col, static_col, bandwidth_col):
            score += 35
        if ref_tag and tag.lower() == ref_tag.lower():
            score += 60
        if matched_tag and tag.lower() == matched_tag.lower():
            score += 30
        if matched_rack and cand_rack(cand) == matched_rack:
            score += 35
        return score - abs(j - matched_idx)

    def score_management(j: int, cand: pd.Series) -> int:
        score = 0
        ips = extract_ips(cand.get(static_col, ""))
        if ips:
            score += 8
        if searched_ip in ips:
            score -= 25
        switch = safe_text(cand.get(switch_col, "")) if switch_col else ""
        bandwidth = safe_text(cand.get(bandwidth_col, "")) if bandwidth_col else ""
        tag_raw = safe_text(cand.get(tag_col, "")) if tag_col else ""
        info = safe_text(cand.get(info_col, "")) if info_col else ""
        if contains_management_hint(switch):
            score += 45
        if bandwidth and "ilo" in bandwidth.lower():
            score += 45
        if extract_ref_tag(tag_raw) or extract_ref_tag(info):
            score += 40
        if looks_like_management_row(cand, tag_col, switch_col, info_col, static_col, bandwidth_col):
            score += 45
        if ref_tag and cand_tag(cand).lower() == ref_tag.lower():
            score += 55
        if matched_tag and cand_tag(cand).lower() == matched_tag.lower():
            score += 25
        if matched_rack and cand_rack(cand) == matched_rack:
            score += 50
        return score - abs(j - matched_idx)

    paired_idx = matched_idx
    if candidates:
        if matched_is_management:
            paired_idx = max(candidates, key=lambda item: score_server(*item))[0]
            management_row = row
            server_row = df.loc[paired_idx]
        else:
            paired_idx = max(candidates, key=lambda item: score_management(*item))[0]
            management_row = df.loc[paired_idx]
            server_row = row
    else:
        management_row = row
        server_row = row

    management_ips = extract_ips(management_row.get(static_col, ""))
    server_ips = extract_ips(server_row.get(static_col, ""))

    related_management_ip = next((ip for ip in management_ips if ip != searched_ip), None)
    if related_management_ip is None and matched_is_management:
        related_management_ip = searched_ip

    all_network_ips = [ip for ip in server_ips if ip != related_management_ip]
    network_ip = searched_ip if not matched_is_management else (all_network_ips[0] if all_network_ips else "Not detected")

    network_switch = safe_text(server_row.get(switch_col, "")) if switch_col else ""
    if network_switch and contains_management_hint(network_switch):
        alt = safe_text(management_row.get(switch_col, "")) if switch_col else ""
        if alt and not contains_management_hint(alt):
            network_switch = alt

    tag = clean_tag(server_row.get(tag_col, "")) if tag_col else ""
    tag = tag or ref_tag or matched_tag
    rack = safe_text(server_row.get(rack_col, "")) if rack_col else ""
    if not rack and rack_col:
        rack = safe_text(management_row.get(rack_col, ""))
    note = safe_text(server_row.get(info_col, "")) if info_col else ""
    if not note and info_col:
        note = safe_text(management_row.get(info_col, ""))

    relation = "same"
    if paired_idx < matched_idx:
        relation = "previous"
    elif paired_idx > matched_idx:
        relation = "next"

    return StaticContext(
        matched_is_management=matched_is_management,
        related_management_ip=related_management_ip,
        network_switch=network_switch or "Switch/Port unknown",
        network_ip=network_ip,
        all_network_ips=all_network_ips,
        tag=tag or "Unknown tag",
        rack_unit=rack or "Unknown rack/unit",
        note=note,
        paired_index=paired_idx,
        paired_relation=relation,
    )


@dataclass(slots=True)
class SearchMatch:
    sheet_name: str
    searched_value: str
    row_index: int
    excel_row_number: int
    values: dict[str, str]
    static_context: StaticContext | None = None


class InventoryStore:
    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self._lock = threading.RLock()
        self._sheets: dict[str, pd.DataFrame] = {}
        self.reload()

    @property
    def sheets(self) -> dict[str, pd.DataFrame]:
        with self._lock:
            return {name: df.copy() for name, df in self._sheets.items()}

    def reload(self) -> None:
        if not self.file_path.is_file():
            raise FileNotFoundError(f"Inventory file not found: {self.file_path}")
        sheets = pd.read_excel(
            self.file_path,
            sheet_name=None,
            header=0,
            dtype=str,
            engine="openpyxl",
        )
        cleaned: dict[str, pd.DataFrame] = {}
        alias_families = (RACK_ALIASES, TAG_ALIASES, INFO_ALIASES)
        for name, frame in sheets.items():
            if frame is None or frame.empty:
                continue
            df = frame.copy()
            for aliases in alias_families:
                col = find_column(df, aliases)
                if col is not None:
                    series = df[col].replace(r"^\s*$", pd.NA, regex=True)
                    df[col] = series.ffill()
            cleaned[name] = df
        with self._lock:
            self._sheets = cleaned

    def _target_columns_for_mode(self, df: pd.DataFrame, mode: str) -> list[str]:
        normalized_mode = mode.lower().strip()
        if normalized_mode == "u":
            wanted = UNUSED_SEARCH_COLUMNS
        elif normalized_mode == "s":
            wanted = STATIC_SEARCH_COLUMNS
        elif normalized_mode == "b":
            wanted = BANDWIDTH_SEARCH_COLUMNS
        else:
            raise ValueError("mode must be one of: u, s, b")
        return [str(col) for col in df.columns if normalize_header(col) in {normalize_header(v) for v in wanted}]

    def contains_anywhere(self, value: str, exact_match: bool = True) -> bool:
        value = normalize_value(value)
        pattern = rf"\b{re.escape(str(value))}\b" if exact_match else re.escape(str(value))
        with self._lock:
            for df in self._sheets.values():
                for col in df.columns:
                    if df[col].astype(str).str.contains(pattern, na=False, case=False, regex=True).any():
                        return True
        return False

    def slash_position_flags(self, value: str) -> tuple[bool, bool]:
        found_between = False
        found_endpoint = False
        with self._lock:
            for df in self._sheets.values():
                for col in df.columns:
                    for cell in df[col].dropna().astype(str):
                        if value not in cell:
                            continue
                        parts = [part.strip() for part in cell.split("/") if part.strip()]
                        if value not in parts:
                            continue
                        pos = parts.index(value)
                        if len(parts) > 2 and pos not in (0, len(parts) - 1):
                            found_between = True
                        else:
                            found_endpoint = True
                        if found_endpoint:
                            return found_between, True
        return found_between, found_endpoint

    def search(self, value: str, mode: str, exact_match: bool = True) -> list[SearchMatch]:
        value = normalize_value(value)
        matches: list[SearchMatch] = []
        with self._lock:
            sheets = self._sheets
            for sheet_name, original_df in sheets.items():
                df = original_df.copy()
                target_cols = self._target_columns_for_mode(df, mode)
                if not target_cols:
                    continue

                for col in target_cols:
                    df[col] = df[col].map(normalize_value)

                if exact_match:
                    pattern = rf"\b{re.escape(str(value))}\b"
                else:
                    pattern = re.escape(str(value))

                row_mask = pd.Series(False, index=df.index)
                for col in target_cols:
                    row_mask |= df[col].astype(str).str.contains(pattern, na=False, case=False, regex=True)

                for idx in df[row_mask].index:
                    row = df.loc[idx]
                    values = {
                        str(col): safe_text(row.get(col, ""))
                        for col in target_cols
                        if safe_text(row.get(col, ""))
                    }
                    static_context = resolve_static_ip_context(df, int(idx), str(value)) if mode == "s" else None
                    excel_row = int(idx) + 2
                    matches.append(
                        SearchMatch(
                            sheet_name=sheet_name,
                            searched_value=str(value),
                            row_index=int(idx),
                            excel_row_number=excel_row,
                            values=values,
                            static_context=static_context,
                        )
                    )
        return matches


def format_matches(matches: list[SearchMatch]) -> list[str]:
    if not matches:
        return ["No matching rows found."]
    chunks: list[str] = []
    for match in matches:
        lines = [
            f"Sheet: {match.sheet_name}",
            f"Excel row: {match.excel_row_number}",
            f"Search: {match.searched_value}",
        ]
        for key, value in match.values.items():
            lines.append(f"{key}: {value}")
        if match.static_context:
            ctx = match.static_context
            if ctx.related_management_ip:
                lines.append(f"Management IP: {ctx.related_management_ip}")
            lines.extend([
                f"Detected tag: {ctx.tag}",
                f"Detected rack/unit: {ctx.rack_unit}",
                f"Detected network switch: {ctx.network_switch}",
            ])
            if ctx.all_network_ips:
                lines.append(f"Detected network IPs: {' / '.join(ctx.all_network_ips)}")
            elif ctx.network_ip:
                lines.append(f"Detected network IP: {ctx.network_ip}")
            if ctx.note:
                lines.append(f"More information: {ctx.note}")
        chunks.append("\n".join(lines))
    return chunks


class InventoryWatcher:
    def __init__(self, store: InventoryStore):
        self.store = store
        self._observer = None

    def start(self):
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        target = self.store.file_path.resolve()
        store = self.store

        class Handler(FileSystemEventHandler):
            def on_modified(self, event):
                try:
                    changed = Path(event.src_path).resolve()
                except OSError:
                    return
                if changed == target:
                    try:
                        store.reload()
                    except Exception:
                        pass

        observer = Observer()
        observer.schedule(Handler(), str(target.parent), recursive=False)
        observer.start()
        self._observer = observer
        return observer

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
