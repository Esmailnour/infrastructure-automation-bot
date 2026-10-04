# Security refactor notes

The source used to build this portfolio repository came from an operational automation script. A public repository requires a different trust model.

## Risks removed before publication

1. **Hardcoded bot token**
   - Replaced by `TELEGRAM_BOT_TOKEN`.
   - The original token should be revoked/rotated before any public push.

2. **Hardcoded administrator identity**
   - Replaced by comma-separated `ADMIN_USER_IDS`.

3. **Hardcoded hardware-management credentials**
   - Removed.
   - Password candidates are accepted only through `REDFISH_PASSWORD_CANDIDATES`.
   - New account/root passwords are supplied through environment configuration or securely generated at runtime.

4. **Credentials printed to logs/debug output**
   - Password values are not logged by the refactored modules.
   - `/view_logs` performs additional redaction.

5. **Disabled TLS verification**
   - Redfish verifies TLS by default.
   - Labs with self-signed management interfaces can explicitly set `REDFISH_VERIFY_TLS=false`.

6. **Disabled SSH host-key checking**
   - AsyncSSH uses its normal host-key verification unless an operator explicitly opts out for an isolated lab.
   - Rsync uses `StrictHostKeyChecking=accept-new`, not `no`.

7. **Shell interpolation for port scans**
   - IP addresses are validated and supplied as separate process arguments.

8. **Unprotected handlers**
   - Read-only features require authorization.
   - Administrative features require admin authorization.
   - Mutations require `SAFE_MODE=false`.

9. **Sensitive production inventory**
   - Replaced with a sanitized 22-sheet `sample_inventory.xlsx` that preserves the workbook layout while replacing source-environment values with synthetic demo data and non-production documentation/benchmark addressing.

10. **Unsafe bootstrap cleanup**
    - The public implementation does not clear shell history.
    - Bootstrap-user deletion is optional and disabled by default.

## Remaining operational considerations

This repository is an engineering portfolio and administration framework, not a turnkey zero-trust management plane. For production use, consider:

- A secrets manager instead of `.env`.
- Short-lived credentials or certificates instead of password auth.
- Mutual TLS for Redfish where available.
- A job queue and durable task state for transfers.
- Structured audit logs sent to a central logging system.
- Role-based authorization rather than a single admin/user distinction.
- Network allowlists for management interfaces.
- Dedicated API/web UI instead of sending secrets through chat.
