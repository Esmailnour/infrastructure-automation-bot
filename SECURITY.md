# Security policy

## Do not commit secrets

Never commit:

- `.env`
- Telegram bot tokens
- server passwords
- Redfish/iLO/iDRAC credentials
- SSH private keys
- production inventory spreadsheets
- internal logs or generated result files

The repository `.gitignore` blocks the common local paths, but secret scanning and code review remain necessary.

## Default-safe behavior

`SAFE_MODE=true` is the repository default. Password changes, remote network mutations, bootstrap actions and data transfers require an explicit opt-in.

`ALLOW_CHAT_CREDENTIALS=false` is also the default because chat messages are not recommended as a secret-transport mechanism.

## Reporting

If this repository is published and a secret is accidentally committed:

1. Revoke/rotate the secret immediately.
2. Remove it from the current files.
3. Rewrite the Git history if the repository is public.
4. Re-run secret scanning before pushing again.
