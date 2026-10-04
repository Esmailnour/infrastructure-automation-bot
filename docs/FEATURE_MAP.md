# Feature map

This document maps the original operational bot capabilities to the public repository implementation so that sanitization does not silently remove project scope.

| Area | Original capability | Public implementation | Default safety |
|---|---|---|---|
| Inventory | Multi-sheet Excel loading | `InventoryStore.reload()` | Read-only |
| Inventory | Forward-fill merged Tag/Rack/Notes cells | `InventoryStore.reload()` | Read-only |
| Inventory | `u <IP>` asset/rack/switch lookup | `handle_text()` + `InventoryStore.search(mode="u")` | Read-only |
| Inventory | `s <IP>` static-IP lookup | `InventoryStore.search(mode="s")` | Read-only |
| Inventory | Server ↔ iLO/iDRAC pairing | `resolve_static_ip_context()` | Read-only |
| Inventory | `b <IP>` bandwidth lookup | `InventoryStore.search(mode="b")` | Read-only |
| Inventory | Automatic workbook reload | `InventoryWatcher` | Read-only |
| Diagnostics | Cross-platform ping | `network.ping_ip()` | Read-only |
| Diagnostics | Subnet sweep | `/subnet` | Read-only |
| Diagnostics | Strict in-between IP analysis | `/between` | Admin-only |
| Diagnostics | Check SSH port state | `is_tcp_open()` | Read-only |
| Diagnostics | Full TCP scan + SSH banner detection | `/p` + `detect_ssh_ports()` | Admin-only |
| Transfer | Configurable parallel sessions | `/sessions` | Admin-only |
| Transfer | Bandwidth model | `/bandwidth` | Read-only |
| Transfer | Source/destination status | `/status` | Admin + chat-credential opt-in |
| Transfer | Rsync transfer orchestration | `/m` | Admin + SAFE_MODE off |
| Transfer | Long transfer background sessions | `screen` in `TransferManager.transfer_path()` | SAFE_MODE off |
| Transfer | SSH retry logic | `SSHRunner.run()` | Internal |
| CentOS | Primary IP change | `/centos` | Admin + SAFE_MODE off |
| CentOS | Add secondary IPs | `/centos_extra` | Admin + SAFE_MODE off |
| CentOS | Replace secondary IP | `/centos_replace` | Admin + SAFE_MODE off |
| CentOS | CentOS 8 vault repository migration | `/centos_repo` | Admin + SAFE_MODE off |
| CentOS | CentOS Stream 9 repository refresh | `/centos9_repo` | Admin + SAFE_MODE off |
| Ubuntu | Primary IP change | `/ubuntu` | Admin + SAFE_MODE off |
| Ubuntu | Add secondary IPs | `/ubuntu_extra` | Admin + SAFE_MODE off |
| Ubuntu | Replace secondary IP | `/ubuntu_replace` | Admin + SAFE_MODE off |
| Ubuntu | Remove secondary IP | `/ubuntu_remove` | Admin + SAFE_MODE off |
| Ubuntu | Disable cloud-init network overwrite | `/prevent` | Admin + SAFE_MODE off |
| Bootstrap | Linux bootstrap/root rotation | `n` / `nc` → `LinuxAdmin.bootstrap_host()` | Admin + SAFE_MODE off |
| Redfish | Dell iDRAC password rotation | text `p` | Admin + SAFE_MODE off |
| Redfish | HPE iLO password rotation | text `h` | Admin + SAFE_MODE off |
| Redfish | Lenovo password rotation | text `l` | Admin + SAFE_MODE off |
| Redfish | HPE account creation | `hr` → `ensure_account()` | Admin + SAFE_MODE off |
| Redfish | HPE hardware information | `hp` | Authorized |
| Redfish | Dell hardware information | `di` | Authorized |
| Redfish | Lenovo hardware information | `li` | Authorized |
| Access | Admin IDs | `ADMIN_USER_IDS` | Environment-only |
| Access | Authorized users | `AUTHORIZED_USER_IDS` + runtime whitelist | Environment/runtime |
| Access | Add/remove user | `/add_user`, `/remove_user` | Admin-only |
| Operations | Bot status | `/ping` | Authorized |
| Operations | Log review | `/view_logs` | Admin + redaction |

## Intentional public-repository changes

The public version does **not** preserve unsafe implementation details merely for line-for-line similarity. The following were intentionally redesigned:

- Embedded Telegram token → `TELEGRAM_BOT_TOKEN`.
- Embedded Telegram admin ID → `ADMIN_USER_IDS`.
- Embedded server/iLO/iDRAC/Lenovo passwords → environment variables or caller-supplied credentials.
- Passwords printed in debug output → removed.
- `verify=False` as a global Redfish default → TLS verification enabled by default.
- `known_hosts=None` as a global SSH default → normal host-key verification by default.
- `create_subprocess_shell()` for nmap → validated `create_subprocess_exec()` arguments.
- Undefined in-memory whitelist → explicit `AccessController` and runtime JSON store.
- Duplicate CentOS repository handler → one implementation.
- One 1,600+ line text handler → separated inventory, network, SSH, transfer, Redfish and Linux modules.
- Destructive operations available immediately → `SAFE_MODE=true` default.
- Credentials in Telegram commands available immediately → `ALLOW_CHAT_CREDENTIALS=false` default.
- Bootstrap history deletion → removed from the public implementation.
