from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from typing import Any, Iterable

import requests

from .config import Settings


@dataclass(slots=True)
class RedfishCredentials:
    username: str
    password: str


@dataclass(slots=True)
class HardwareInfo:
    vendor: str
    model: str = "Unknown"
    serial_number: str = "Unknown"
    power_state: str = "Unknown"
    cpu_summary: str = "Unknown"
    memory_gib: float | None = None
    drives: list[str] = field(default_factory=list)

    def to_text(self) -> str:
        lines = [
            f"Vendor: {self.vendor}",
            f"Model: {self.model}",
            f"Serial: {self.serial_number}",
            f"Power: {self.power_state}",
            f"CPU: {self.cpu_summary}",
        ]
        if self.memory_gib is not None:
            lines.append(f"Memory: {self.memory_gib:g} GiB")
        if self.drives:
            lines.append("Drives:")
            lines.extend(f"- {drive}" for drive in self.drives)
        return "\n".join(lines)


class RedfishClient:
    def __init__(self, host: str, credentials: RedfishCredentials, settings: Settings):
        self.host = host.strip()
        self.credentials = credentials
        self.settings = settings
        self.base_url = f"https://{self.host}"
        self.session = requests.Session()
        self.session.auth = (credentials.username, credentials.password)
        self.session.verify = settings.redfish_verify_tls
        self.session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    def request(self, method: str, path: str, **kwargs) -> requests.Response:
        timeout = kwargs.pop("timeout", self.settings.redfish_timeout_seconds)
        return self.session.request(method, f"{self.base_url}{path}", timeout=timeout, **kwargs)

    def get_json(self, path: str, *, allow_404: bool = False) -> dict[str, Any] | None:
        response = self.request("GET", path)
        if allow_404 and response.status_code == 404:
            return None
        response.raise_for_status()
        value = response.json()
        return value if isinstance(value, dict) else {}

    def patch_json(self, path: str, payload: dict[str, Any]) -> requests.Response:
        self.settings.require_mutations_enabled("Redfish PATCH")
        response = self.request("PATCH", path, json=payload)
        response.raise_for_status()
        return response

    def post_json(self, path: str, payload: dict[str, Any]) -> requests.Response:
        self.settings.require_mutations_enabled("Redfish POST")
        response = self.request("POST", path, json=payload)
        response.raise_for_status()
        return response

    def delete(self, path: str) -> requests.Response:
        self.settings.require_mutations_enabled("Redfish DELETE")
        response = self.request("DELETE", path)
        if response.status_code not in (200, 202, 204, 404):
            response.raise_for_status()
        return response


def _first_system_path(client: RedfishClient) -> str:
    collection = client.get_json("/redfish/v1/Systems/") or {}
    members = collection.get("Members") or []
    for member in members:
        if isinstance(member, dict) and member.get("@odata.id"):
            return str(member["@odata.id"])
    for fallback in ("/redfish/v1/Systems/1/", "/redfish/v1/Systems/System.Embedded.1"):
        try:
            if client.get_json(fallback, allow_404=True) is not None:
                return fallback
        except requests.RequestException:
            continue
    raise RuntimeError("No Redfish system resource found")


def _member_json(client: RedfishClient, collection_path: str) -> list[dict[str, Any]]:
    try:
        collection = client.get_json(collection_path, allow_404=True)
    except requests.RequestException:
        return []
    if not collection:
        return []
    result: list[dict[str, Any]] = []
    for member in collection.get("Members") or []:
        href = member.get("@odata.id") if isinstance(member, dict) else None
        if not href:
            continue
        try:
            data = client.get_json(str(href), allow_404=True)
        except requests.RequestException:
            continue
        if data:
            result.append(data)
    return result


def _capacity_text(drive: dict[str, Any]) -> str:
    media = drive.get("MediaType") or drive.get("Protocol") or "Drive"
    capacity = drive.get("CapacityGB")
    if capacity is None:
        raw = drive.get("CapacityBytes")
        if isinstance(raw, (int, float)):
            capacity = round(float(raw) / (1024 ** 3), 1)
    model = drive.get("Model") or ""
    if capacity is None:
        return " ".join(part for part in (str(model), str(media)) if part).strip() or "Unknown drive"
    return " ".join(part for part in (str(capacity), "GB", str(media), str(model)) if part).strip()


def get_hardware_info(client: RedfishClient, vendor_hint: str = "Redfish") -> HardwareInfo:
    system_path = _first_system_path(client)
    system = client.get_json(system_path) or {}
    info = HardwareInfo(
        vendor=str(system.get("Manufacturer") or vendor_hint),
        model=str(system.get("Model") or "Unknown"),
        serial_number=str(system.get("SerialNumber") or "Unknown"),
        power_state=str(system.get("PowerState") or "Unknown"),
    )
    memory_mib = system.get("MemorySummary", {}).get("TotalSystemMemoryGiB") if isinstance(system.get("MemorySummary"), dict) else None
    if isinstance(memory_mib, (int, float)):
        info.memory_gib = float(memory_mib)
    else:
        memory_gib = system.get("MemorySummary", {}).get("TotalSystemMemoryGB") if isinstance(system.get("MemorySummary"), dict) else None
        if isinstance(memory_gib, (int, float)):
            info.memory_gib = float(memory_gib)

    proc_summary = system.get("ProcessorSummary") if isinstance(system.get("ProcessorSummary"), dict) else {}
    model = proc_summary.get("Model")
    count = proc_summary.get("Count")
    if model or count:
        info.cpu_summary = f"{count or '?'}x {model or 'processor'}"
    else:
        processors = _member_json(client, system_path.rstrip("/") + "/Processors/")
        models = [p.get("Model") for p in processors if p.get("Model")]
        total_threads = sum(int(p.get("TotalThreads") or 0) for p in processors)
        if processors:
            info.cpu_summary = f"{len(processors)}x {models[0] if models else 'processor'}"
            if total_threads:
                info.cpu_summary += f" ({total_threads} threads)"

    drives: list[str] = []
    storage_members = _member_json(client, system_path.rstrip("/") + "/Storage/")
    for storage in storage_members:
        for drive_ref in storage.get("Drives") or []:
            href = drive_ref.get("@odata.id") if isinstance(drive_ref, dict) else None
            if not href:
                continue
            try:
                drive = client.get_json(str(href), allow_404=True)
            except requests.RequestException:
                continue
            if drive:
                drives.append(_capacity_text(drive))
    if not drives:
        smart_root = system_path.rstrip("/") + "/SmartStorage/ArrayControllers/"
        controllers = _member_json(client, smart_root)
        for controller in controllers:
            href = controller.get("@odata.id")
            if not href:
                continue
            for drive in _member_json(client, str(href).rstrip("/") + "/DiskDrives/"):
                drives.append(_capacity_text(drive))
    info.drives = drives
    return info


def change_account_password(
    host: str,
    settings: Settings,
    username: str,
    old_passwords: Iterable[str],
    new_password: str,
    account_paths: Iterable[str],
) -> tuple[str, int]:
    settings.require_mutations_enabled("Redfish password change")
    if not new_password:
        raise ValueError("new_password must not be empty")
    last_status = 0
    for old_password in old_passwords:
        if not old_password:
            continue
        client = RedfishClient(host, RedfishCredentials(username, old_password), settings)
        for path in account_paths:
            try:
                response = client.request("PATCH", path, json={"Password": new_password})
            except requests.RequestException:
                continue
            last_status = response.status_code
            if response.status_code in (200, 202, 204):
                return old_password, response.status_code
    raise RuntimeError(f"Password change failed; last HTTP status: {last_status or 'n/a'}")


def random_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def ensure_account(
    host: str,
    settings: Settings,
    admin_credentials: RedfishCredentials,
    username: str,
    password: str,
    role_id: str = "Administrator",
) -> str:
    settings.require_mutations_enabled("Redfish account management")
    client = RedfishClient(host, admin_credentials, settings)
    collection_path = "/redfish/v1/AccountService/Accounts/"
    collection = client.get_json(collection_path) or {}
    for member in collection.get("Members") or []:
        href = member.get("@odata.id") if isinstance(member, dict) else None
        if not href:
            continue
        account = client.get_json(str(href), allow_404=True)
        if account and str(account.get("UserName", "")).lower() == username.lower():
            client.patch_json(str(href), {"Password": password, "RoleId": role_id, "Enabled": True})
            return str(href)
    response = client.post_json(
        collection_path,
        {"UserName": username, "Password": password, "RoleId": role_id, "Enabled": True},
    )
    return response.headers.get("Location", collection_path)
