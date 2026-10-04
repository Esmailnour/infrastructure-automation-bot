# Public feature parity

This repository is a sanitized/refactored implementation of the operational bot, not a verbatim publication of the production source. The goal is behavioral parity for the portfolio-relevant workflows while deliberately removing secrets, company data and unsafe defaults.

## Preserved operational behavior

- Multi-sheet Excel inventory lookup using the original `u`, `s` and `b` command model.
- Server-to-management-controller correlation (server NIC ↔ iLO/iDRAC/BMC), including rack/switch context.
- Subnet ping sweeps, strict slash-list analysis and SSH-service detection after a full TCP port scan.
- Linux bootstrap/root-password rotation and SSH configuration changes.
- CentOS primary/secondary IP management and CentOS 8 vault migration.
- CentOS Stream 9 BaseOS/AppStream/CRB repository reconstruction.
- Ubuntu primary/secondary IP management persisted through Netplan, including replace/remove operations.
- Rsync `/home` synchronization with dynamic timeouts, long-transfer `screen` sessions and per-child recursive splitting for very large directories.
- Transfer progress/status reporting and adjustable parallel-session/bandwidth controls.
- Dell iDRAC, HPE iLO and Lenovo Redfish password rotation.
- HPE account provisioning with HPE/iLO5 and HP/iLO4 payload fallbacks.
- HPE/Dell/Lenovo hardware discovery (model, serial, power, CPU, memory and storage) with inventory context attached to the result.
- Telegram authorization, runtime whitelist management, log viewing and workbook hot reload.

## Intentional safety differences

These are not missing features; they are deliberate public-repository controls:

- Credentials and Telegram IDs come from environment variables instead of source code.
- `SAFE_MODE=true` blocks all mutating operations by default.
- `ALLOW_CHAT_CREDENTIALS=false` blocks passwords in Telegram commands by default.
- `RETURN_GENERATED_SECRETS_IN_CHAT=false` prevents generated root/support passwords from being echoed unless explicitly enabled in an authorized environment.
- SSH host-key and Redfish TLS verification are enabled by default.
- Nmap is executed without shell interpolation.
- Bootstrap history deletion from the operational script is intentionally not reproduced.
- Production inventory is replaced by the sanitized 22-sheet demo workbook.

## Verification

`docs/FEATURE_MAP.md` maps each command/capability to its public implementation. GitHub Actions compiles the package, runs tests, and executes a basic committed-secret guard on every push.
