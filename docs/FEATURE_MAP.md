# Feature map

This document maps the original operational bot capabilities to the sanitized public implementation. The public repository preserves portfolio-relevant behavior while intentionally changing secret handling and unsafe defaults.

| Area | Operational capability | Public implementation | Default safety |
|---|---|---|---|
| Inventory | Multi-sheet Excel loading | `InventoryStore.reload()` | Read-only |
| Inventory | Forward-fill merged Tag/Rack/Notes cells | `InventoryStore.reload()` | Read-only |
| Inventory | `u <IP>` asset/rack/switch lookup | `handle_text()` + `InventoryStore.search(mode="u")` | Read-only |
| Inventory | `s <IP>` static-IP lookup | `InventoryStore.search(mode="s")` | Read-only |
| Inventory | Server ↔ iLO/iDRAC/BMC pairing | `resolve_static_ip_context()` | Read-only |
| Inventory | `b <IP>` bandwidth lookup | `InventoryStore.search(mode="b")` | Read-only |
| Inventory | Automatic workbook reload | `InventoryWatcher` | Read-only |
| Diagnostics | Cross-platform ping | `network.ping_ip()` | Read-only |
| Diagnostics | Subnet sweep | `/subnet` | Authorized |
| Diagnostics | Strict in-between slash-list analysis | `/between` | Admin-only |
| Diagnostics | Check SSH port state | `is_tcp_open()` | Read-only |
| Diagnostics | Full TCP scan + SSH banner detection | `/p` + `detect_ssh_ports()` | Admin-only |
| Transfer | Configurable parallel sessions | `/sessions` | Admin-only |
| Transfer | Bandwidth model / dynamic timeout | `/bandwidth` + `calculate_timeout()` | Read-only |
| Transfer | Source/destination status | `/status` | Admin + chat-credential opt-in |
| Transfer | Rsync `/home` orchestration | `/m` + `TransferManager.transfer_home()` | Admin + SAFE_MODE off |
| Transfer | Per-child recursive split for very large folders | `_transfer_entry()` + `remote_children()` | SAFE_MODE off |
| Transfer | Long-transfer background sessions | `screen` in `_launch_single_transfer()` | SAFE_MODE off |
| Transfer | SSH retry logic | `SSHRunner.run()` | Internal |
| CentOS | Primary IP change | `/centos` | Admin + SAFE_MODE off |
| CentOS | Add secondary IPs | `/centos_extra` | Admin + SAFE_MODE off |
| CentOS | Replace secondary IP | `/centos_replace` | Admin + SAFE_MODE off |
| CentOS | CentOS 8.5 vault migration | `centos8_repo_to_vault()` with BaseOS/AppStream/Extras/CentOSPlus | Admin + SAFE_MODE off |
| CentOS | CentOS Stream 9 repository reconstruction | `centos9_repo_reset()` with BaseOS/AppStream/CRB | Admin + SAFE_MODE off |
| Ubuntu | Primary IP change while preserving secondary IPs | `ubuntu_change_primary()` | Admin + SAFE_MODE off |
| Ubuntu | Add secondary IPs persistently | `ubuntu_add_ips()` | Admin + SAFE_MODE off |
| Ubuntu | Replace secondary IP persistently | `ubuntu_replace_ip()` | Admin + SAFE_MODE off |
| Ubuntu | Remove secondary IP persistently | `ubuntu_remove_ip()` | Admin + SAFE_MODE off |
| Ubuntu | Netplan YAML read/write + apply | `_read_netplan()` / `_write_netplan()` | SAFE_MODE off |
| Ubuntu | Disable cloud-init network overwrite | `/prevent` | Admin + SAFE_MODE off |
| Bootstrap | Linux bootstrap/root rotation | `n` / `nc` → `LinuxAdmin.bootstrap_host()` | Admin + SAFE_MODE off |
| Bootstrap | Generated root password response | Supported when `RETURN_GENERATED_SECRETS_IN_CHAT=true`; otherwise env-supplied secret | Explicit opt-in |
| Redfish | Dell iDRAC password rotation | text `p` + account discovery/fallback path | Admin + SAFE_MODE off |
| Redfish | HPE iLO password rotation | text `h` + account discovery/fallback path | Admin + SAFE_MODE off |
| Redfish | Lenovo password rotation | text `l`, optional old-password argument | Admin + SAFE_MODE off |
| Redfish | HPE Team/support account workflow | `hr` → `ensure_hpe_support_workflow()` | Admin + SAFE_MODE off |
| Redfish | HPE iLO4/iLO5 account payload fallback | HP/Hpe OEM payloads in `ensure_account()` | SAFE_MODE off |
| Redfish | HPE hardware information | `hp` + Redfish + inventory context | Authorized |
| Redfish | Dell hardware information | `di` + Redfish + inventory context | Authorized |
| Redfish | Lenovo hardware information | `li` / `le` + Redfish + inventory context | Authorized |
| Redfish | Standard + SmartStorage drive discovery | `get_hardware_info()` | Read-only |
| Access | Admin IDs | `ADMIN_USER_IDS` | Environment-only |
| Access | Authorized users | `AUTHORIZED_USER_IDS` + runtime whitelist | Environment/runtime |
| Access | Add/remove user | `/add_user`, `/remove_user` | Admin-only |
| Operations | Bot status | `/ping` | Authorized |
| Operations | Log review | `/view_logs` | Admin + redaction |

## Intentional public-repository changes

The public version does **not** preserve unsafe implementation details merely for line-for-line similarity:

- Embedded Telegram token → `TELEGRAM_BOT_TOKEN`.
- Embedded Telegram admin ID → `ADMIN_USER_IDS`.
- Embedded server/iLO/iDRAC/Lenovo passwords → environment variables or explicitly supplied credentials.
- Passwords printed in debug output → removed.
- Generated root/support passwords are not echoed unless `RETURN_GENERATED_SECRETS_IN_CHAT=true`.
- `verify=False` as a global Redfish default → TLS verification enabled by default.
- `known_hosts=None` as a global SSH default → normal host-key verification by default.
- Passwords are not embedded into rsync process command lines; source-to-destination key setup is used instead.
- `create_subprocess_shell()` for nmap → validated `create_subprocess_exec()` arguments.
- Undefined in-memory whitelist → explicit `AccessController` and runtime JSON store.
- Duplicate CentOS repository handler → one implementation per workflow.
- One 1,600+ line text handler → separated inventory, network, SSH, transfer, Redfish and Linux modules.
- Destructive operations available immediately → `SAFE_MODE=true` default.
- Credentials in Telegram commands available immediately → `ALLOW_CHAT_CREDENTIALS=false` default.
- Bootstrap history deletion → intentionally removed.

See [FEATURE_PARITY.md](FEATURE_PARITY.md) for the public parity statement.
