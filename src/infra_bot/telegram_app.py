from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass

from telegram import Update
from telegram.ext import Application, CallbackContext, CommandHandler, MessageHandler, filters

from .auth import AccessController
from .config import Settings
from .hostutils import parse_host_port
from .inventory import InventoryStore, InventoryWatcher, format_matches
from .linux_admin import LinuxAdmin
from .network import detect_ssh_ports, is_tcp_open, ping_subnet, validate_ip
from .redfish import (
    RedfishClient,
    RedfishCredentials,
    change_named_account_password,
    ensure_hpe_support_workflow,
    get_hardware_info,
    random_password,
)
from .ssh_client import SSHCredentials, SSHRunner
from .transfer import TransferEndpoint, TransferManager

LOGGER = logging.getLogger(__name__)
TELEGRAM_LIMIT = 4096


@dataclass
class BotServices:
    settings: Settings
    access: AccessController
    inventory: InventoryStore
    watcher: InventoryWatcher
    ssh: SSHRunner
    transfer: TransferManager
    linux: LinuxAdmin

    @classmethod
    def build(cls, settings: Settings) -> "BotServices":
        settings.ensure_runtime_dirs()
        access = AccessController(settings)
        inventory = InventoryStore(settings.inventory_file)
        watcher = InventoryWatcher(inventory)
        ssh = SSHRunner(settings)
        transfer = TransferManager(settings, ssh)
        linux = LinuxAdmin(settings, ssh)
        return cls(settings, access, inventory, watcher, ssh, transfer, linux)

    def resize_sessions(self, value: int) -> None:
        if not 1 <= value <= 50:
            raise ValueError("Session limit must be between 1 and 50")
        self.settings.max_parallel_sessions = value
        self.ssh = SSHRunner(self.settings)
        self.transfer = TransferManager(self.settings, self.ssh)
        self.linux = LinuxAdmin(self.settings, self.ssh)


async def _reply_chunks(update: Update, text: str) -> None:
    message = update.effective_message
    if not message:
        return
    text = str(text)
    for start in range(0, len(text), TELEGRAM_LIMIT):
        await message.reply_text(text[start:start + TELEGRAM_LIMIT])


def _user_id(update: Update) -> str:
    user = update.effective_user
    return str(user.id) if user else ""


async def _require_authorized(update: Update, services: BotServices) -> bool:
    if services.access.is_authorized(_user_id(update)):
        return True
    await _reply_chunks(update, "⚠️ You are not authorized to use this bot.")
    return False


async def _require_admin(update: Update, services: BotServices) -> bool:
    if services.access.is_admin(_user_id(update)):
        return True
    await _reply_chunks(update, "⛔ Admin only command")
    return False


def _redact_logs(text: str) -> str:
    text = re.sub(r"(?i)(password|passwd|token|authorization)(\s*[:=]\s*)\S+", r"\1\2<redacted>", text)
    text = re.sub(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b", "<telegram-token-redacted>", text)
    return text


def _endpoint(host_spec: str, username: str, password: str) -> TransferEndpoint:
    host, port = parse_host_port(host_spec)
    return TransferEndpoint(host, port, SSHCredentials(username, password))


def _credentials_from_args_or_env(services: BotServices, args: list[str]) -> RedfishCredentials:
    if len(args) >= 4:
        services.settings.require_chat_credentials_enabled()
        return RedfishCredentials(args[2], args[3])
    if services.settings.team_username and services.settings.team_password:
        return RedfishCredentials(services.settings.team_username, services.settings.team_password)
    raise ValueError(
        "No Redfish credentials configured. Set TEAM_USERNAME/TEAM_PASSWORD, or enable "
        "ALLOW_CHAT_CREDENTIALS=true and pass <USER> <PASS>."
    )


def _secret_for_operation(settings: Settings, configured: str, purpose: str) -> tuple[str, bool]:
    if configured:
        return configured, False
    if settings.return_generated_secrets_in_chat:
        return random_password(18), True
    raise ValueError(
        f"{purpose} needs a configured secret. Set the corresponding environment variable, or set "
        "RETURN_GENERATED_SECRETS_IN_CHAT=true only in an authorized environment."
    )


async def start(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_authorized(update, services):
        return
    mode = "SAFE" if services.settings.safe_mode else "ADMIN"
    await _reply_chunks(
        update,
        f"Infrastructure Automation Bot ({mode} mode)\n"
        "Use /help to view inventory, diagnostics, transfer, Linux and Redfish commands.",
    )


async def help_command(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_authorized(update, services):
        return
    text = """Infrastructure Automation & Server Management Bot

Inventory lookup
  u <IP>        Search asset/tag/rack/switch columns
  s <IP>        Search static IP and correlate server + management rows
  b <IP>        Search bandwidth columns

Diagnostics
  /subnet <CIDR-or-x.x.x.0> [...]   Ping subnets and report unreachable IPs absent from inventory
  /between <subnet> [...]           Admin: unreachable IPs found only inside slash-separated ranges, SSH closed
  /p <IP>                           Admin: scan open ports and identify SSH services
  /ping                             Bot health check

Server hardware / Redfish
  hp <iLO_IP> [USER PASS]           HPE/iLO hardware + inventory context
  di <iDRAC_IP> [USER PASS]         Dell/iDRAC hardware + inventory context
  li|le <Lenovo_IP> [USER PASS]     Lenovo Redfish hardware + inventory context
  p <iDRAC_IP>                      Admin: rotate configured Dell account password
  h <iLO_IP>                        Admin: rotate configured HPE account password
  l <Lenovo_IP> [OLD_PASS]          Admin: rotate configured Lenovo account password
  hr <iLO_IP> [ADMIN_USER PASS]     Admin: create/update Team + support accounts

Linux administration (Admin; disabled in SAFE_MODE)
  n <IP>                             Bootstrap a Linux host using env credentials
  nc <IP>                            Bootstrap a CentOS-style host using env credentials
  /centos <IP> <PASS> <NEW_IP>
  /centos_extra <IP> <PASS> <IP...>
  /centos_replace <IP> <PASS> <OLD_IP> <NEW_IP>
  /centos_repo <IP> <PASS>
  /centos9_repo <IP> <PASS>
  /ubuntu <IP> <PASS> <NEW_IP>
  /ubuntu_extra <IP> <PASS> <IP...>
  /ubuntu_replace <IP> <PASS> <OLD_IP> <NEW_IP>
  /ubuntu_remove <IP> <PASS> <IP>
  /prevent <IP> <PASS>

Data transfer (Admin; disabled in SAFE_MODE)
  /m <SRC[:PORT]> <USER> <PASS> <DST[:PORT]> <USER> <PASS>
     Recursively sync /home and split very large directories by child item
  /status <SRC[:PORT]> <USER> <PASS> <DST[:PORT]> <USER> <PASS>
  /progress <SRC[:PORT]> <USER> <PASS>
  /sessions <1-50>
  /bandwidth

Access / operations
  /add_user <TELEGRAM_USER_ID>
  /remove_user <TELEGRAM_USER_ID>
  /view_logs

Security defaults
  SAFE_MODE=true blocks server/password/network mutations.
  ALLOW_CHAT_CREDENTIALS=false blocks commands that pass passwords in Telegram messages.
  RETURN_GENERATED_SECRETS_IN_CHAT=false prevents generated passwords being echoed to chat.
"""
    await _reply_chunks(update, text)


async def inventory_text(update: Update, services: BotServices, mode: str, ip: str) -> None:
    ip = validate_ip(ip)
    matches = services.inventory.search(ip, mode=mode, exact_match=True)
    if not matches:
        await _reply_chunks(update, f"No matches found for {ip}.")
        return
    for formatted in format_matches(matches):
        await _reply_chunks(update, formatted)


async def handle_subnet(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_authorized(update, services):
        return
    if not context.args:
        await _reply_chunks(update, "Usage: /subnet <192.0.2.0/24> [additional subnets]")
        return
    report: list[str] = []
    for subnet in context.args:
        results = await ping_subnet(subnet)
        unreachable = [item.ip for item in results if not item.reachable]
        absent = [ip for ip in unreachable if not services.inventory.contains_anywhere(ip)]
        report.append(f"{subnet}: {len(unreachable)} unreachable; {len(absent)} absent from inventory")
        report.extend(absent)
    await _reply_chunks(update, "\n".join(report))


async def handle_between(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services):
        return
    if not context.args:
        await _reply_chunks(update, "Usage: /between <192.0.2.0/24> [additional subnets]")
        return
    report: list[str] = []
    for subnet in context.args:
        results = await ping_subnet(subnet)
        candidates: list[str] = []
        for item in results:
            if item.reachable:
                continue
            if await is_tcp_open(item.ip, 22):
                continue
            if not services.inventory.contains_anywhere(item.ip):
                continue
            found_between, found_endpoint = services.inventory.slash_position_flags(item.ip)
            if found_between and not found_endpoint:
                candidates.append(item.ip)
        if candidates:
            report.append(f"=== {subnet} ===")
            report.extend(candidates)
    await _reply_chunks(update, "\n".join(report) if report else "No strict in-between candidates found.")


async def handle_port_scan(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services):
        return
    if len(context.args) != 1:
        await _reply_chunks(update, "Usage: /p <IP>")
        return
    ports = await detect_ssh_ports(context.args[0])
    await _reply_chunks(update, f"SSH service ports: {', '.join(map(str, ports)) if ports else 'none detected'}")


async def handle_m(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services):
        return
    if len(context.args) != 6:
        await _reply_chunks(update, "Usage: /m <src[:port]> <user> <pass> <dst[:port]> <user> <pass>")
        return
    services.settings.require_chat_credentials_enabled()
    services.settings.require_mutations_enabled("Data transfer")
    source = _endpoint(context.args[0], context.args[1], context.args[2])
    destination = _endpoint(context.args[3], context.args[4], context.args[5])
    await _reply_chunks(update, f"Starting transfer {source.host}:{source.port} -> {destination.host}:{destination.port}")
    results = await services.transfer.transfer_home(source, destination)
    await _reply_chunks(update, "\n".join(results))


async def handle_progress(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services):
        return
    if len(context.args) != 3:
        await _reply_chunks(update, "Usage: /progress <src[:port]> <user> <pass>")
        return
    services.settings.require_chat_credentials_enabled()
    host, port = parse_host_port(context.args[0])
    creds = SSHCredentials(context.args[1], context.args[2])
    result = await services.ssh.run(
        host,
        port,
        creds,
        "printf 'Screen sessions:\n'; screen -ls 2>/dev/null || true; "
        "printf '\nRsync processes:\n'; pgrep -af rsync || true",
    )
    await _reply_chunks(update, result.stdout.strip() or "No active transfer sessions detected.")


async def handle_status(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services):
        return
    if len(context.args) != 6:
        await _reply_chunks(update, "Usage: /status <src[:port]> <user> <pass> <dst[:port]> <user> <pass>")
        return
    services.settings.require_chat_credentials_enabled()
    source = _endpoint(context.args[0], context.args[1], context.args[2])
    destination = _endpoint(context.args[3], context.args[4], context.args[5])
    status = await services.transfer.status(source, destination)
    await _reply_chunks(
        update,
        f"SOURCE {status.source_host}\n"
        f"Screen sessions: {status.screen_sessions}\n"
        f"Rsync processes: {status.rsync_processes}\n\n"
        f"DESTINATION {status.destination_host}\n"
        f"Disk: {status.destination_disk}\n{status.destination_home}",
    )


async def handle_bandwidth(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_authorized(update, services):
        return
    s = services.settings
    await _reply_chunks(
        update,
        f"Total modelled bandwidth: {s.total_bandwidth_gbps:g} Gbps\n"
        f"Max parallel sessions: {s.max_parallel_sessions}\n"
        f"Modelled bandwidth/session: {s.min_bandwidth_per_session_gbps:.2f} Gbps\n"
        f"Transfer workers: {s.transfer_concurrency}\n"
        f"Split threshold: {s.parallel_split_threshold_gb:g} GB",
    )


async def handle_sessions(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services):
        return
    if len(context.args) != 1:
        await _reply_chunks(update, "Usage: /sessions <1-50>")
        return
    services.resize_sessions(int(context.args[0]))
    await _reply_chunks(update, f"New commands will use up to {services.settings.max_parallel_sessions} SSH sessions.")


async def _linux_command_guard(update: Update, services: BotServices) -> bool:
    if not await _require_admin(update, services):
        return False
    services.settings.require_chat_credentials_enabled()
    services.settings.require_mutations_enabled("Linux administration")
    return True


async def handle_centos(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) != 3: return await _reply_chunks(update, "Usage: /centos <IP> <PASS> <NEW_IP>")
    msg = await services.linux.centos_change_primary(validate_ip(context.args[0]), context.args[1], context.args[2])
    await _reply_chunks(update, msg)


async def handle_centos_extra(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) < 3: return await _reply_chunks(update, "Usage: /centos_extra <IP> <PASS> <IP...>")
    msg = await services.linux.centos_add_ips(validate_ip(context.args[0]), context.args[1], context.args[2:])
    await _reply_chunks(update, msg)


async def handle_centos_replace(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) != 4: return await _reply_chunks(update, "Usage: /centos_replace <IP> <PASS> <OLD_IP> <NEW_IP>")
    msg = await services.linux.centos_replace_ip(validate_ip(context.args[0]), context.args[1], context.args[2], context.args[3])
    await _reply_chunks(update, msg)


async def handle_centos_repo(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) != 2: return await _reply_chunks(update, "Usage: /centos_repo <IP> <PASS>")
    msg = await services.linux.centos8_repo_to_vault(validate_ip(context.args[0]), context.args[1])
    await _reply_chunks(update, msg)


async def handle_centos9_repo(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) != 2: return await _reply_chunks(update, "Usage: /centos9_repo <IP> <PASS>")
    msg = await services.linux.centos9_repo_reset(validate_ip(context.args[0]), context.args[1])
    await _reply_chunks(update, msg)


async def handle_ubuntu(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) != 3: return await _reply_chunks(update, "Usage: /ubuntu <IP> <PASS> <NEW_IP>")
    msg = await services.linux.ubuntu_change_primary(validate_ip(context.args[0]), context.args[1], context.args[2])
    await _reply_chunks(update, msg)


async def handle_ubuntu_extra(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) < 3: return await _reply_chunks(update, "Usage: /ubuntu_extra <IP> <PASS> <IP...>")
    msg = await services.linux.ubuntu_add_ips(validate_ip(context.args[0]), context.args[1], context.args[2:])
    await _reply_chunks(update, msg)


async def handle_ubuntu_replace(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) != 4: return await _reply_chunks(update, "Usage: /ubuntu_replace <IP> <PASS> <OLD_IP> <NEW_IP>")
    msg = await services.linux.ubuntu_replace_ip(validate_ip(context.args[0]), context.args[1], context.args[2], context.args[3])
    await _reply_chunks(update, msg)


async def handle_ubuntu_remove(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) != 3: return await _reply_chunks(update, "Usage: /ubuntu_remove <IP> <PASS> <IP>")
    msg = await services.linux.ubuntu_remove_ip(validate_ip(context.args[0]), context.args[1], context.args[2])
    await _reply_chunks(update, msg)


async def handle_prevent(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _linux_command_guard(update, services): return
    if len(context.args) != 2: return await _reply_chunks(update, "Usage: /prevent <IP> <PASS>")
    msg = await services.linux.prevent_cloud_init_network(validate_ip(context.args[0]), context.args[1])
    await _reply_chunks(update, msg)


async def handle_add_user(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services): return
    if len(context.args) != 1 or not context.args[0].isdigit():
        return await _reply_chunks(update, "Usage: /add_user <TELEGRAM_USER_ID>")
    services.access.add_user(context.args[0])
    await _reply_chunks(update, f"Authorized user {context.args[0]}.")


async def handle_remove_user(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services): return
    if len(context.args) != 1 or not context.args[0].isdigit():
        return await _reply_chunks(update, "Usage: /remove_user <TELEGRAM_USER_ID>")
    services.access.remove_user(context.args[0])
    await _reply_chunks(update, f"Removed runtime authorization for {context.args[0]}.")


async def handle_view_logs(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_admin(update, services): return
    path = services.settings.log_file
    if not path.exists():
        return await _reply_chunks(update, "No log file exists yet.")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
    await _reply_chunks(update, _redact_logs("\n".join(lines)) or "Log file is empty.")


async def health_ping(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_authorized(update, services): return
    await _reply_chunks(update, "✅ Bot is running.")


async def handle_text(update: Update, context: CallbackContext, services: BotServices) -> None:
    if not await _require_authorized(update, services):
        return
    message = update.effective_message
    if not message or not message.text:
        return
    args = message.text.strip().split()
    if not args:
        return
    command = args[0].lower()

    if command in {"u", "s", "b"}:
        if len(args) != 2:
            return await _reply_chunks(update, f"Usage: {command} <IP>")
        return await inventory_text(update, services, command, args[1])

    if command in {"n", "nc"}:
        if not await _require_admin(update, services): return
        services.settings.require_mutations_enabled("Host bootstrap")
        if len(args) != 2: return await _reply_chunks(update, f"Usage: {command} <IP>")
        if command == "nc":
            bootstrap_user = services.settings.centos_bootstrap_username
            bootstrap_password = services.settings.centos_bootstrap_password
            missing_hint = "Configure CENTOS_BOOTSTRAP_USERNAME and CENTOS_BOOTSTRAP_PASSWORD first."
        else:
            bootstrap_user = services.settings.bootstrap_username
            bootstrap_password = services.settings.bootstrap_password
            missing_hint = "Configure BOOTSTRAP_USERNAME and BOOTSTRAP_PASSWORD first."
        if not bootstrap_user or not bootstrap_password:
            return await _reply_chunks(update, missing_hint)
        new_root_password, reveal = _secret_for_operation(
            services.settings,
            services.settings.bootstrap_new_root_password,
            "Host bootstrap",
        )
        msg = await services.linux.bootstrap_host(
            validate_ip(args[1]),
            bootstrap_user,
            bootstrap_password,
            new_root_password,
        )
        reply = f"{msg}\nRoot password rotated successfully."
        if reveal:
            reply += f"\nroot\n{new_root_password}"
        else:
            reply += "\nThe new root password came from BOOTSTRAP_NEW_ROOT_PASSWORD and was not echoed."
        await _reply_chunks(update, reply)
        return

    if command in {"p", "h", "l"}:
        if not await _require_admin(update, services): return
        services.settings.require_mutations_enabled("Redfish password rotation")
        if command == "l" and len(args) not in (2, 3):
            return await _reply_chunks(update, "Usage: l <Lenovo_IP> [OLD_PASSWORD]")
        if command != "l" and len(args) != 2:
            return await _reply_chunks(update, f"Usage: {command} <management_IP>")
        host = validate_ip(args[1])
        candidates = list(services.settings.redfish_password_candidates)
        if command == "l" and len(args) == 3:
            services.settings.require_chat_credentials_enabled()
            candidates.insert(0, args[2])
        new_password = services.settings.redfish_new_password
        if not candidates or not new_password:
            return await _reply_chunks(
                update,
                "Configure REDFISH_PASSWORD_CANDIDATES and REDFISH_NEW_PASSWORD in the environment first.",
            )
        if command == "p":
            username = "root"
            paths = ["/redfish/v1/Managers/iDRAC.Embedded.1/Accounts/2"]
        elif command == "h":
            username = "Administrator"
            paths = ["/redfish/v1/AccountService/Accounts/1"]
        else:
            username = "USERID"
            paths = ["/redfish/v1/AccountService/Accounts/1"]
        _, status, path = await asyncio.to_thread(
            change_named_account_password,
            host,
            services.settings,
            username,
            candidates,
            new_password,
            paths,
        )
        await _reply_chunks(update, f"Password rotation completed for {host} (HTTP {status}, account {path}).")
        return

    if command == "hr":
        if not await _require_admin(update, services): return
        services.settings.require_mutations_enabled("Redfish account management")
        if len(args) not in (2, 4):
            return await _reply_chunks(update, "Usage: hr <iLO_IP> [ADMIN_USER ADMIN_PASS]")
        host = validate_ip(args[1])
        if len(args) == 4:
            services.settings.require_chat_credentials_enabled()
            admin = RedfishCredentials(args[2], args[3])
        elif services.settings.team_username and services.settings.team_password:
            admin = RedfishCredentials(services.settings.team_username, services.settings.team_password)
        else:
            return await _reply_chunks(update, "Configure TEAM_USERNAME/TEAM_PASSWORD or supply admin credentials.")

        support_password, reveal = _secret_for_operation(
            services.settings,
            services.settings.support_account_password,
            "HPE support-account provisioning",
        )
        provisioned = await asyncio.to_thread(
            ensure_hpe_support_workflow,
            host,
            services.settings,
            admin,
            support_username=services.settings.support_account_username,
            support_password=support_password,
            team_username=services.settings.team_username,
            team_password=services.settings.team_password,
        )
        lines = [f"{item.username}: {item.action} ({item.path})" for item in provisioned]
        if reveal:
            lines.append(f"{services.settings.support_account_username}\n{support_password}")
        else:
            lines.append("Support password was sourced from SUPPORT_ACCOUNT_PASSWORD and was not echoed.")
        await _reply_chunks(update, "HPE account workflow complete:\n" + "\n".join(lines))
        return

    if command in {"hp", "di", "li", "le"}:
        if len(args) not in (2, 4):
            return await _reply_chunks(update, f"Usage: {command} <management_IP> [USER PASS]")
        host = validate_ip(args[1])
        try:
            credentials = _credentials_from_args_or_env(services, args)
            vendor = {"hp": "HPE", "di": "Dell", "li": "Lenovo", "le": "Lenovo"}[command]
            client = RedfishClient(host, credentials, services.settings)
            info = await asyncio.to_thread(get_hardware_info, client, vendor)
            reply = info.to_text()
            inventory_matches = services.inventory.search(host, mode="s", exact_match=True)
            if inventory_matches:
                reply += "\n\nInventory context:\n" + format_matches(inventory_matches[:1])[0]
            await _reply_chunks(update, reply)
        except Exception as exc:
            await _reply_chunks(update, f"Hardware lookup failed: {exc}")
        return

    await _reply_chunks(update, "Unknown command. Use /help.")


def create_application(settings: Settings | None = None) -> tuple[Application, BotServices]:
    settings = settings or Settings.from_env()
    services = BotServices.build(settings)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        handlers=[logging.FileHandler(settings.log_file, encoding="utf-8"), logging.StreamHandler()],
    )

    app = Application.builder().token(settings.require_bot_token()).build()

    def c(handler):
        async def wrapped(update: Update, context: CallbackContext):
            try:
                return await handler(update, context, services)
            except PermissionError as exc:
                await _reply_chunks(update, f"⛔ {exc}")
            except (ValueError, FileNotFoundError) as exc:
                await _reply_chunks(update, f"⚠️ {exc}")
            except Exception as exc:
                LOGGER.exception("Command failed")
                await _reply_chunks(update, f"❌ Operation failed: {exc}")
        return wrapped

    app.add_handler(CommandHandler("start", c(start)))
    app.add_handler(CommandHandler("help", c(help_command)))
    app.add_handler(CommandHandler("m", c(handle_m)))
    app.add_handler(CommandHandler("bandwidth", c(handle_bandwidth)))
    app.add_handler(CommandHandler("sessions", c(handle_sessions)))
    app.add_handler(CommandHandler("progress", c(handle_progress)))
    app.add_handler(CommandHandler("status", c(handle_status)))
    app.add_handler(CommandHandler("centos", c(handle_centos)))
    app.add_handler(CommandHandler("centos_extra", c(handle_centos_extra)))
    app.add_handler(CommandHandler("centos_repo", c(handle_centos_repo)))
    app.add_handler(CommandHandler("centos9_repo", c(handle_centos9_repo)))
    app.add_handler(CommandHandler("centos_replace", c(handle_centos_replace)))
    app.add_handler(CommandHandler("ubuntu", c(handle_ubuntu)))
    app.add_handler(CommandHandler("ubuntu_replace", c(handle_ubuntu_replace)))
    app.add_handler(CommandHandler("ubuntu_remove", c(handle_ubuntu_remove)))
    app.add_handler(CommandHandler("ubuntu_extra", c(handle_ubuntu_extra)))
    app.add_handler(CommandHandler("prevent", c(handle_prevent)))
    app.add_handler(CommandHandler("p", c(handle_port_scan)))
    app.add_handler(CommandHandler("add_user", c(handle_add_user)))
    app.add_handler(CommandHandler("remove_user", c(handle_remove_user)))
    app.add_handler(CommandHandler("view_logs", c(handle_view_logs)))
    app.add_handler(CommandHandler("subnet", c(handle_subnet)))
    app.add_handler(CommandHandler("between", c(handle_between)))
    app.add_handler(CommandHandler("ping", c(health_ping)))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, c(handle_text)))

    return app, services


def run_bot() -> None:
    app, services = create_application()
    services.watcher.start()
    try:
        LOGGER.info("Starting Telegram polling; SAFE_MODE=%s", services.settings.safe_mode)
        app.run_polling()
    finally:
        services.watcher.stop()
