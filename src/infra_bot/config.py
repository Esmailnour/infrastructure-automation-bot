from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _as_int(value: str | None, default: int) -> int:
    if value is None or not value.strip():
        return default
    return int(value)


def _as_float(value: str | None, default: float) -> float:
    if value is None or not value.strip():
        return default
    return float(value)


def _csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip() for part in value.split(",") if part.strip()}


def _csv_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


@dataclass(slots=True)
class Settings:
    """Runtime settings loaded exclusively from environment variables."""

    bot_token: str = ""
    admin_user_ids: set[str] = field(default_factory=set)
    authorized_user_ids: set[str] = field(default_factory=set)

    inventory_file: Path = Path("sample_data/sample_inventory.xlsx")
    log_file: Path = Path("runtime/bot.log")
    whitelist_file: Path = Path("runtime/whitelist.json")

    safe_mode: bool = True
    allow_chat_credentials: bool = False
    return_generated_secrets_in_chat: bool = False

    redfish_verify_tls: bool = True
    redfish_timeout_seconds: int = 12

    ssh_known_hosts: str | None = None
    ssh_connect_timeout_seconds: int = 30
    ssh_login_timeout_seconds: int = 30

    total_bandwidth_gbps: float = 10.0
    max_parallel_sessions: int = 20
    transfer_concurrency: int = 10
    parallel_split_threshold_gb: float = 1000.0
    screen_threshold_gb: float = 50.0
    transfer_split_max_depth: int = 8

    bootstrap_username: str = ""
    bootstrap_password: str = ""
    bootstrap_new_root_password: str = ""
    root_username: str = "root"
    centos_bootstrap_username: str = "root"
    centos_bootstrap_password: str = ""

    redfish_new_password: str = ""
    team_username: str = ""
    team_password: str = ""
    support_account_username: str = "support"
    support_account_password: str = ""
    redfish_password_candidates: list[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "Settings":
        known_hosts_raw = os.getenv("SSH_KNOWN_HOSTS", "").strip()
        ssh_known_hosts: str | None
        if not known_hosts_raw:
            ssh_known_hosts = None
        elif known_hosts_raw.lower() == "none":
            ssh_known_hosts = "__DISABLE__"
        else:
            ssh_known_hosts = known_hosts_raw

        return cls(
            bot_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
            admin_user_ids=_csv_set(os.getenv("ADMIN_USER_IDS")),
            authorized_user_ids=_csv_set(os.getenv("AUTHORIZED_USER_IDS")),
            inventory_file=Path(os.getenv("INVENTORY_FILE", "sample_data/sample_inventory.xlsx")),
            log_file=Path(os.getenv("LOG_FILE", "runtime/bot.log")),
            whitelist_file=Path(os.getenv("WHITELIST_FILE", "runtime/whitelist.json")),
            safe_mode=_as_bool(os.getenv("SAFE_MODE"), True),
            allow_chat_credentials=_as_bool(os.getenv("ALLOW_CHAT_CREDENTIALS"), False),
            return_generated_secrets_in_chat=_as_bool(os.getenv("RETURN_GENERATED_SECRETS_IN_CHAT"), False),
            redfish_verify_tls=_as_bool(os.getenv("REDFISH_VERIFY_TLS"), True),
            redfish_timeout_seconds=_as_int(os.getenv("REDFISH_TIMEOUT_SECONDS"), 12),
            ssh_known_hosts=ssh_known_hosts,
            ssh_connect_timeout_seconds=_as_int(os.getenv("SSH_CONNECT_TIMEOUT_SECONDS"), 30),
            ssh_login_timeout_seconds=_as_int(os.getenv("SSH_LOGIN_TIMEOUT_SECONDS"), 30),
            total_bandwidth_gbps=_as_float(os.getenv("TOTAL_BANDWIDTH_GBPS"), 10.0),
            max_parallel_sessions=_as_int(os.getenv("MAX_PARALLEL_SESSIONS"), 20),
            transfer_concurrency=_as_int(os.getenv("TRANSFER_CONCURRENCY"), 10),
            parallel_split_threshold_gb=_as_float(os.getenv("PARALLEL_SPLIT_THRESHOLD_GB"), 1000.0),
            screen_threshold_gb=_as_float(os.getenv("SCREEN_THRESHOLD_GB"), 50.0),
            transfer_split_max_depth=_as_int(os.getenv("TRANSFER_SPLIT_MAX_DEPTH"), 8),
            bootstrap_username=os.getenv("BOOTSTRAP_USERNAME", "").strip(),
            bootstrap_password=os.getenv("BOOTSTRAP_PASSWORD", ""),
            bootstrap_new_root_password=os.getenv("BOOTSTRAP_NEW_ROOT_PASSWORD", ""),
            root_username=os.getenv("ROOT_USERNAME", "root").strip() or "root",
            centos_bootstrap_username=os.getenv("CENTOS_BOOTSTRAP_USERNAME", "root").strip() or "root",
            centos_bootstrap_password=os.getenv("CENTOS_BOOTSTRAP_PASSWORD", ""),
            redfish_new_password=os.getenv("REDFISH_NEW_PASSWORD", ""),
            team_username=os.getenv("TEAM_USERNAME", "").strip(),
            team_password=os.getenv("TEAM_PASSWORD", ""),
            support_account_username=os.getenv("SUPPORT_ACCOUNT_USERNAME", "support").strip() or "support",
            support_account_password=os.getenv("SUPPORT_ACCOUNT_PASSWORD", ""),
            redfish_password_candidates=_csv_list(os.getenv("REDFISH_PASSWORD_CANDIDATES")),
        )

    @property
    def min_bandwidth_per_session_gbps(self) -> float:
        if self.max_parallel_sessions <= 0:
            return 0.0
        return self.total_bandwidth_gbps / self.max_parallel_sessions

    def ensure_runtime_dirs(self) -> None:
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)

    def require_bot_token(self) -> str:
        if not self.bot_token:
            raise RuntimeError(
                "TELEGRAM_BOT_TOKEN is not configured. Copy .env.example to .env "
                "and provide a token through the environment."
            )
        return self.bot_token

    def require_mutations_enabled(self, operation: str) -> None:
        if self.safe_mode:
            raise PermissionError(
                f"{operation} is disabled while SAFE_MODE=true. "
                "Set SAFE_MODE=false only in an authorized test/administration environment."
            )

    def require_chat_credentials_enabled(self) -> None:
        if not self.allow_chat_credentials:
            raise PermissionError(
                "Passing credentials in Telegram messages is disabled. "
                "Set ALLOW_CHAT_CREDENTIALS=true only if you accept that risk."
            )
