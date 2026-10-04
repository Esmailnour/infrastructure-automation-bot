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


@dataclass(slots=True)
class AccountProvisionResult:
    username: str
    path: str
    action: str


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
            data = dict(data)
            data.setdefault("@odata.id", str(href))
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
    memory_summary = system.get("MemorySummary") if isinstance(system.get("MemorySummary"), dict) else {}
    memory = memory_summary.get("TotalSystemMemoryGiB")
    if memory is None:
        memory = memory_summary.get("TotalSystemMemoryGB")
    if isinstance(memory, (int, float)):
        info.memory_gib = float(memory)

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
        smart_roots = [
            system_path.rstrip("/") + "/SmartStorage/ArrayControllers/",
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/",
        ]
        for smart_root in smart_roots:
            controllers = _member_json(client, smart_root)
            for controller in controllers:
                href = controller.get("@odata.id")
                if not href:
                    continue
                for drive in _member_json(client, str(href).rstrip("/") + "/DiskDrives/"):
                    drives.append(_capacity_text(drive))
            if drives:
                break
    info.drives = drives
    return info


def _account_collection(client: RedfishClient) -> str:
    service = client.get_json("/redfish/v1/AccountService/", allow_404=True) or {}
    accounts = service.get("Accounts")
    if isinstance(accounts, dict) and accounts.get("@odata.id"):
        return str(accounts["@odata.id"])
    return "/redfish/v1/AccountService/Accounts/"


def _find_account(client: RedfishClient, username: str) -> tuple[str, dict[str, Any]] | None:
    collection = _account_collection(client)
    for account in _member_json(client, collection):
        if str(account.get("UserName", "")).strip().lower() == username.strip().lower():
            return str(account.get("@odata.id")), account
    return None


def change_named_account_password(
    host: str,
    settings: Settings,
    username: str,
    old_passwords: Iterable[str],
    new_password: str,
    fallback_paths: Iterable[str] = (),
) -> tuple[str, int, str]:
    settings.require_mutations_enabled("Redfish password change")
    if not new_password:
        raise ValueError("new_password must not be empty")
    last_status = 0
    for old_password in old_passwords:
        if not old_password:
            continue
        client = RedfishClient(host, RedfishCredentials(username, old_password), settings)
        paths: list[str] = []
        try:
            found = _find_account(client, username)
            if found:
                paths.append(found[0])
        except requests.RequestException:
            pass
        paths.extend(str(p) for p in fallback_paths if p not in paths)
        for path in paths:
            try:
                response = client.request("PATCH", path, json={"Password": new_password})
            except requests.RequestException:
                continue
            last_status = response.status_code
            if response.status_code in (200, 202, 204):
                return old_password, response.status_code, path
    raise RuntimeError(f"Password change failed; last HTTP status: {last_status or 'n/a'}")


def change_account_password(
    host: str,
    settings: Settings,
    username: str,
    old_passwords: Iterable[str],
    new_password: str,
    account_paths: Iterable[str],
) -> tuple[str, int]:
    old, status, _ = change_named_account_password(
        host,
        settings,
        username,
        old_passwords,
        new_password,
        account_paths,
    )
    return old, status


def random_password(length: int = 18) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def _hpe_payloads(username: str, password: str, role_id: str) -> list[dict[str, Any]]:
    full_privileges = {
        "LoginPriv": True,
        "RemoteConsolePriv": True,
        "VirtualPowerAndResetPriv": True,
        "VirtualMediaPriv": True,
    }
    return [
        {
            "UserName": username,
            "Password": password,
            "RoleId": role_id,
            "Enabled": True,
            "Oem": {"Hpe": {"LoginName": username}},
        },
        {
            "UserName": username,
            "Password": password,
            "Enabled": True,
            "Oem": {"Hp": {"LoginName": username, "Privileges": full_privileges}},
        },
    ]


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
    collection_path = _account_collection(client)
    found = _find_account(client, username)
    payloads = _hpe_payloads(username, password, role_id) + [
        {"UserName": username, "Password": password, "RoleId": role_id, "Enabled": True}
    ]

    last_error = ""
    if found:
        href = found[0]
        for payload in payloads:
            try:
                response = client.request("PATCH", href, json=payload)
                if response.status_code in (200, 202, 204):
                    return href
                last_error = f"HTTP {response.status_code}: {response.text[:300]}"
            except requests.RequestException as exc:
                last_error = str(exc)
        raise RuntimeError(f"Could not update Redfish account {username}: {last_error}")

    for payload in payloads:
        try:
            response = client.request("POST", collection_path, json=payload)
            if response.status_code in (200, 201, 202, 204):
                return response.headers.get("Location", collection_path)
            last_error = f"HTTP {response.status_code}: {response.text[:300]}"
        except requests.RequestException as exc:
            last_error = str(exc)
    raise RuntimeError(f"Could not create Redfish account {username}: {last_error}")


def ensure_hpe_support_workflow(
    host: str,
    settings: Settings,
    admin_credentials: RedfishCredentials,
    *,
    support_username: str,
    support_password: str,
    team_username: str = "",
    team_password: str = "",
) -> list[AccountProvisionResult]:
    settings.require_mutations_enabled("HPE account provisioning")
    results: list[AccountProvisionResult] = []
    if team_username and team_password:
        team_path = ensure_account(
            host,
            settings,
            admin_credentials,
            team_username,
            team_password,
            role_id="Administrator",
        )
        results.append(AccountProvisionResult(team_username, team_path, "created-or-updated"))

    support_path = ensure_account(
        host,
        settings,
        admin_credentials,
        support_username,
        support_password,
        role_id="Operator",
    )
    results.append(AccountProvisionResult(support_username, support_path, "created-or-updated"))
    return results
