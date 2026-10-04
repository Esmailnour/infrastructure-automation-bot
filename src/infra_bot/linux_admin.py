from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass

from .config import Settings
from .ssh_client import SSHCredentials, SSHRunner


def _ipv4(value: str) -> str:
    addr = ipaddress.ip_address(value.strip())
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 addresses are supported for this operation")
    return str(addr)


def _cidr(value: str, default_prefix: int = 24) -> str:
    value = value.strip()
    if "/" not in value:
        value = f"{_ipv4(value)}/{default_prefix}"
    iface = ipaddress.ip_interface(value)
    if not isinstance(iface, ipaddress.IPv4Interface):
        raise ValueError("Only IPv4 addresses are supported")
    return str(iface)


@dataclass(slots=True)
class LinuxAdmin:
    settings: Settings
    ssh: SSHRunner

    async def _run_root(self, host: str, password: str, command: str, port: int = 22):
        self.settings.require_mutations_enabled("Linux remote administration")
        if not password:
            raise ValueError("A root/administrative password is required")
        creds = SSHCredentials(self.settings.root_username, password)
        return await self.ssh.run(host, port, creds, command, check=True)

    async def prevent_cloud_init_network(self, host: str, password: str, port: int = 22) -> str:
        command = (
            "mkdir -p /etc/cloud/cloud.cfg.d && "
            "printf '%s\n' 'network:' '  config: disabled' > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg"
        )
        await self._run_root(host, password, command, port)
        return "cloud-init network reconfiguration disabled"

    async def centos8_repo_to_vault(self, host: str, password: str, port: int = 22) -> str:
        script = r'''set -euo pipefail
if ! grep -Eq '^VERSION_ID="?8' /etc/os-release; then
  echo "Not CentOS/RHEL-compatible version 8" >&2
  exit 2
fi
VER="8.5.2111"
VAULT="http://vault.centos.org/${VER}"
BACKUP_DIR="/etc/yum.repos.d/backup-$(date +%F-%H%M%S)"
mkdir -p "$BACKUP_DIR"
find /etc/yum.repos.d -maxdepth 1 -name '*.repo' -exec cp -a {} "$BACKUP_DIR"/ \;
cat > /etc/yum.repos.d/CentOS-Vault.repo <<EOF
[baseos]
name=CentOS-${VER} - BaseOS
baseurl=${VAULT}/BaseOS/x86_64/os/
gpgcheck=0
enabled=1

[appstream]
name=CentOS-${VER} - AppStream
baseurl=${VAULT}/AppStream/x86_64/os/
gpgcheck=0
enabled=1
EOF
yum clean all
yum makecache
'''
        await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        return "CentOS 8 repository configuration updated"

    async def centos9_repo_reset(self, host: str, password: str, port: int = 22) -> str:
        script = r'''set -euo pipefail
if ! grep -q 'VERSION_ID="9' /etc/os-release; then
  echo "Not version 9" >&2
  exit 2
fi
BACKUP_DIR="/etc/yum.repos.d/backup-$(date +%F-%H%M%S)"
mkdir -p "$BACKUP_DIR"
find /etc/yum.repos.d -maxdepth 1 -name '*.repo' -exec cp -a {} "$BACKUP_DIR"/ \;
if command -v dnf >/dev/null 2>&1; then
  dnf clean all
  dnf makecache
else
  yum clean all
  yum makecache
fi
'''
        await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        return "CentOS Stream 9 repositories refreshed"

    async def centos_add_ips(self, host: str, password: str, extra_ips: list[str], port: int = 22) -> str:
        addresses = [_cidr(ip) for ip in extra_ips]
        if not addresses:
            raise ValueError("At least one extra IP is required")
        addr_args = " ".join(shlex.quote(v) for v in addresses)
        script = f'''set -euo pipefail
CON=$(nmcli -t -f NAME connection show --active | grep -v '^lo$' | head -1)
[ -n "$CON" ]
for IP in {addr_args}; do
  nmcli con mod "$CON" +ipv4.addresses "$IP"
done
nmcli con up "$CON"
'''
        await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        return f"Added {len(addresses)} secondary IP address(es)"

    async def centos_replace_ip(self, host: str, password: str, old_ip: str, new_ip: str, port: int = 22) -> str:
        old_addr, new_addr = _cidr(old_ip), _cidr(new_ip)
        script = f'''set -euo pipefail
CON=$(nmcli -t -f NAME connection show --active | grep -v '^lo$' | head -1)
[ -n "$CON" ]
nmcli con mod "$CON" -ipv4.addresses {shlex.quote(old_addr)} || true
nmcli con mod "$CON" +ipv4.addresses {shlex.quote(new_addr)}
nmcli con up "$CON"
'''
        await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        return f"Replaced {old_addr} with {new_addr}"

    async def centos_change_primary(self, host: str, password: str, new_ip: str, port: int = 22) -> str:
        address = _cidr(new_ip)
        script = f'''set -euo pipefail
CON=$(nmcli -t -f NAME connection show --active | grep -v '^lo$' | head -1)
[ -n "$CON" ]
GW=$(ip route | awk '/default/ {{print $3; exit}}')
nmcli con mod "$CON" ipv4.method manual ipv4.addresses {shlex.quote(address)}
[ -z "$GW" ] || nmcli con mod "$CON" ipv4.gateway "$GW"
nmcli con up "$CON"
'''
        await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        return f"Primary address changed to {address}; verify connectivity on the new IP"

    async def _ubuntu_iface(self, host: str, password: str, port: int) -> str:
        creds = SSHCredentials(self.settings.root_username, password)
        result = await self.ssh.run(
            host, port, creds,
            "ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}'",
            check=True,
        )
        iface = result.stdout.strip()
        if not iface or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for ch in iface):
            raise RuntimeError("Could not determine a safe interface name")
        return iface

    async def ubuntu_change_primary(self, host: str, password: str, new_ip: str, port: int = 22) -> str:
        self.settings.require_mutations_enabled("Ubuntu network change")
        address = _cidr(new_ip)
        iface = await self._ubuntu_iface(host, password, port)
        script = f'''set -euo pipefail
FILE=/etc/netplan/99-infra-bot.yaml
cat > "$FILE" <<'EOF'
network:
  version: 2
  ethernets:
    {iface}:
      dhcp4: false
      addresses:
        - {address}
EOF
chmod 600 "$FILE"
netplan generate
netplan apply
'''
        await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        return f"Ubuntu primary address configured as {address} on {iface}"

    async def ubuntu_add_ips(self, host: str, password: str, extra_ips: list[str], port: int = 22) -> str:
        self.settings.require_mutations_enabled("Ubuntu network change")
        addresses = [_cidr(ip) for ip in extra_ips]
        iface = await self._ubuntu_iface(host, password, port)
        yaml_lines = "\n".join(f"        - {addr}" for addr in addresses)
        script = f'''set -euo pipefail
FILE=/etc/netplan/99-infra-bot-extra.yaml
cat > "$FILE" <<'EOF'
network:
  version: 2
  ethernets:
    {iface}:
      addresses:
{yaml_lines}
EOF
chmod 600 "$FILE"
netplan generate
netplan apply
'''
        await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        return f"Configured {len(addresses)} Ubuntu secondary address(es) on {iface}"

    async def ubuntu_replace_ip(self, host: str, password: str, old_ip: str, new_ip: str, port: int = 22) -> str:
        self.settings.require_mutations_enabled("Ubuntu network change")
        old_addr, new_addr = _ipv4(old_ip), _cidr(new_ip)
        iface = await self._ubuntu_iface(host, password, port)
        script = f'''set -euo pipefail
ip addr del {shlex.quote(old_addr)}/24 dev {shlex.quote(iface)} 2>/dev/null || true
ip addr add {shlex.quote(new_addr)} dev {shlex.quote(iface)}
'''
        await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        return f"Replaced Ubuntu address {old_addr} with {new_addr}; persist in your site netplan as required"

    async def ubuntu_remove_ip(self, host: str, password: str, remove_ip: str, port: int = 22) -> str:
        self.settings.require_mutations_enabled("Ubuntu network change")
        address = _ipv4(remove_ip)
        iface = await self._ubuntu_iface(host, password, port)
        script = f"ip addr del {shlex.quote(address)}/24 dev {shlex.quote(iface)}"
        await self._run_root(host, password, script, port)
        return f"Removed {address} from {iface}; persist the change in netplan if necessary"

    async def bootstrap_host(
        self,
        host: str,
        bootstrap_user: str,
        bootstrap_password: str,
        new_root_password: str,
        *,
        port: int = 22,
        remove_bootstrap_user: bool = False,
    ) -> str:
        self.settings.require_mutations_enabled("Host bootstrap")
        if not all((bootstrap_user, bootstrap_password, new_root_password)):
            raise ValueError("bootstrap username/password and new root password are required")
        creds = SSHCredentials(bootstrap_user, bootstrap_password)
        qpw = shlex.quote(new_root_password)
        quser = shlex.quote(bootstrap_user)
        cleanup = f"userdel -f {quser} || true;" if remove_bootstrap_user else ""
        script = (
            f"printf '%s\n%s\n' {qpw} {qpw} | passwd root; "
            "sed -i '/^PermitRootLogin[[:space:]]/d' /etc/ssh/sshd_config; "
            "printf '%s\n' 'PermitRootLogin yes' >> /etc/ssh/sshd_config; "
            "(systemctl restart sshd || systemctl restart ssh || service ssh restart); "
            + cleanup
        )
        sudo_script = f"sudo -S -p '' bash -lc {shlex.quote(script)}"
        await self.ssh.run(
            host,
            port,
            creds,
            sudo_script,
            check=True,
            input_data=bootstrap_password + "\n",
        )
        return "Bootstrap completed"
