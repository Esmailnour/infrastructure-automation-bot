from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass
from typing import Any

import yaml

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


def _address_ip(value: str) -> str:
    return str(ipaddress.ip_interface(value).ip)


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

    def _root_credentials(self, password: str) -> SSHCredentials:
        if not password:
            raise ValueError("A root/administrative password is required")
        return SSHCredentials(self.settings.root_username, password)

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
  echo "This server is not running CentOS 8" >&2
  exit 2
fi
VER="8.5.2111"
VAULT="http://vault.centos.org/${VER}"
BACKUP_DIR="/etc/yum.repos.d/backup-$(date +%F-%H%M%S)"
NEW_REPO="/etc/yum.repos.d/CentOS-Vault.repo"
mkdir -p "${BACKUP_DIR}"
mv /etc/yum.repos.d/CentOS-*.repo "${BACKUP_DIR}/" 2>/dev/null || true
cat > "${NEW_REPO}" <<EOF
[BaseOS]
name=CentOS-\$releasever - BaseOS
baseurl=${VAULT}/BaseOS/\$basearch/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial

[AppStream]
name=CentOS-\$releasever - AppStream
baseurl=${VAULT}/AppStream/\$basearch/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial

[Extras]
name=CentOS-\$releasever - Extras
baseurl=${VAULT}/extras/\$basearch/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial

[centosplus]
name=CentOS-\$releasever - CentOSPlus
baseurl=${VAULT}/centosplus/\$basearch/os/
gpgcheck=1
enabled=0
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial
EOF
yum clean all
yum makecache -y
yum repolist
'''
        result = await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        output = (result.stdout or result.stderr or "").strip()
        return "CentOS 8 vault migration complete" + (f"\n{output[:2500]}" if output else "")

    async def centos9_repo_reset(self, host: str, password: str, port: int = 22) -> str:
        script = r'''set -euo pipefail
if ! grep -q 'VERSION_ID="9"' /etc/os-release || ! grep -q 'CentOS Stream' /etc/os-release; then
  echo "This server is not running CentOS Stream 9" >&2
  exit 2
fi
BACKUP_DIR="/etc/yum.repos.d/backup-$(date +%F-%H%M%S)"
mkdir -p "$BACKUP_DIR"
if ls /etc/yum.repos.d/*.repo >/dev/null 2>&1; then
  mv /etc/yum.repos.d/*.repo "$BACKUP_DIR"/
fi
cat > /etc/yum.repos.d/centos-stream9.repo << 'REPOEOF'
[baseos]
name=CentOS Stream 9 - BaseOS
baseurl=https://mirror.stream.centos.org/9-stream/BaseOS/$basearch/os/
enabled=1
gpgcheck=1
gpgkey=https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official

[appstream]
name=CentOS Stream 9 - AppStream
baseurl=https://mirror.stream.centos.org/9-stream/AppStream/$basearch/os/
enabled=1
gpgcheck=1
gpgkey=https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official

[crb]
name=CentOS Stream 9 - CRB
baseurl=https://mirror.stream.centos.org/9-stream/CRB/$basearch/os/
enabled=1
gpgcheck=1
gpgkey=https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official

[extras-common]
name=CentOS Stream 9 - Extras Common
baseurl=https://mirror.stream.centos.org/9-stream/extras-common/$basearch/os/
enabled=0
gpgcheck=1
gpgkey=https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official
REPOEOF
dnf clean all -y || dnf clean all || true
rm -rf /var/cache/dnf/* || true
dnf makecache -y || dnf makecache || true
dnf repolist || true
'''
        result = await self._run_root(host, password, f"bash -lc {shlex.quote(script)}", port)
        output = (result.stdout or result.stderr or "").strip()
        return "CentOS Stream 9 repository configuration complete" + (f"\n{output[:2500]}" if output else "")

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

    async def _ubuntu_runtime(self, host: str, password: str, port: int) -> tuple[str, int, str]:
        creds = self._root_credentials(password)
        command = (
            "set -e; "
            "IFACE=$(ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}'); "
            "PREFIX=$(ip -o -f inet addr show \"$IFACE\" | head -n1 | cut -d/ -f2 | awk '{print $1}'); "
            "PRIMARY=$(ip -o -f inet addr show \"$IFACE\" | head -n1 | awk '{print $4}' | cut -d/ -f1); "
            "printf '%s\n%s\n%s\n' \"$IFACE\" \"$PREFIX\" \"$PRIMARY\""
        )
        result = await self.ssh.run(host, port, creds, command, check=True)
        lines = result.stdout.splitlines()
        if len(lines) < 3 or not lines[0].strip() or not lines[1].strip():
            raise RuntimeError("Could not determine Ubuntu interface/prefix")
        iface = lines[0].strip()
        if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for ch in iface):
            raise RuntimeError("Unsafe interface name returned by host")
        return iface, int(lines[1].strip()), lines[2].strip()

    async def _read_netplan(self, host: str, password: str, port: int) -> tuple[str, dict[str, Any]]:
        creds = self._root_credentials(password)
        result = await self.ssh.run(
            host,
            port,
            creds,
            "find /etc/netplan -maxdepth 1 -name '*.yaml' -print -quit",
            check=True,
        )
        path = result.stdout.strip()
        if not path:
            raise RuntimeError("No netplan YAML file found")
        content = await self.ssh.run(host, port, creds, f"cat {shlex.quote(path)}", check=True)
        config = yaml.safe_load(content.stdout) or {}
        if not isinstance(config, dict):
            raise RuntimeError("Netplan YAML did not contain a mapping")
        return path, config

    @staticmethod
    def _netplan_interface_config(config: dict[str, Any], iface: str) -> dict[str, Any]:
        network = config.setdefault("network", {})
        network.setdefault("version", 2)
        ethernets = network.setdefault("ethernets", {})
        if iface in ethernets and isinstance(ethernets[iface], dict):
            return ethernets[iface]
        for value in ethernets.values():
            if isinstance(value, dict) and value.get("set-name") == iface:
                return value
        ethernets[iface] = {}
        return ethernets[iface]

    async def _write_netplan(self, host: str, password: str, port: int, path: str, config: dict[str, Any]) -> None:
        creds = self._root_credentials(password)
        rendered = yaml.safe_dump(
            config,
            sort_keys=False,
            default_flow_style=False,
            width=1000,
            allow_unicode=True,
        )
        conn = await self.ssh.connect(host, port, creds)
        try:
            async with conn.start_sftp_client() as sftp:
                async with sftp.open(path, "w") as file_obj:
                    await file_obj.write(rendered)
            await conn.run(f"chmod 600 {shlex.quote(path)} && netplan generate && netplan apply", check=True)
        finally:
            conn.close()
            await conn.wait_closed()

    async def ubuntu_change_primary(self, host: str, password: str, new_ip: str, port: int = 22) -> str:
        self.settings.require_mutations_enabled("Ubuntu network change")
        iface, prefix, primary_ip = await self._ubuntu_runtime(host, password, port)
        new_address = _cidr(new_ip, prefix)
        path, config = await self._read_netplan(host, password, port)
        eth = self._netplan_interface_config(config, iface)
        current = [str(v) for v in eth.get("addresses", [])]
        secondary = [value for value in current if _address_ip(value) != primary_ip]
        eth["dhcp4"] = False
        eth["addresses"] = [new_address] + secondary
        new_ip_only = _address_ip(new_address)
        parts = new_ip_only.split(".")
        eth["gateway4"] = ".".join(parts[:3] + ["1"])
        eth["nameservers"] = {"addresses": ["8.8.8.8", "8.8.4.4"]}
        await self._write_netplan(host, password, port, path, config)
        return f"Ubuntu primary address persisted as {new_address} on {iface}"

    async def ubuntu_add_ips(self, host: str, password: str, extra_ips: list[str], port: int = 22) -> str:
        self.settings.require_mutations_enabled("Ubuntu network change")
        iface, prefix, _ = await self._ubuntu_runtime(host, password, port)
        addresses = [_cidr(ip, prefix) for ip in extra_ips]
        if not addresses:
            raise ValueError("At least one extra IP is required")
        path, config = await self._read_netplan(host, password, port)
        eth = self._netplan_interface_config(config, iface)
        current = [str(v) for v in eth.get("addresses", [])]
        existing_ips = {_address_ip(v) for v in current}
        for address in addresses:
            if _address_ip(address) not in existing_ips:
                current.append(address)
        eth["addresses"] = current
        await self._write_netplan(host, password, port, path, config)
        return f"Persisted {len(addresses)} Ubuntu secondary address(es) on {iface}"

    async def ubuntu_replace_ip(self, host: str, password: str, old_ip: str, new_ip: str, port: int = 22) -> str:
        self.settings.require_mutations_enabled("Ubuntu network change")
        old_ip_only = _ipv4(old_ip)
        iface, prefix, primary_ip = await self._ubuntu_runtime(host, password, port)
        if old_ip_only == primary_ip:
            raise ValueError(f"Cannot replace primary IP ({primary_ip}) with the secondary-IP command")
        new_address = _cidr(new_ip, prefix)
        path, config = await self._read_netplan(host, password, port)
        eth = self._netplan_interface_config(config, iface)
        current = [str(v) for v in eth.get("addresses", [])]
        replaced = [value for value in current if _address_ip(value) != old_ip_only]
        replaced.append(new_address)
        eth["addresses"] = replaced
        await self._write_netplan(host, password, port, path, config)
        return f"Persistently replaced {old_ip_only} with {new_address} on {iface}"

    async def ubuntu_remove_ip(self, host: str, password: str, remove_ip: str, port: int = 22) -> str:
        self.settings.require_mutations_enabled("Ubuntu network change")
        remove_ip_only = _ipv4(remove_ip)
        iface, _, primary_ip = await self._ubuntu_runtime(host, password, port)
        if remove_ip_only == primary_ip:
            raise ValueError(f"Cannot remove primary IP ({primary_ip}) with the secondary-IP command")
        path, config = await self._read_netplan(host, password, port)
        eth = self._netplan_interface_config(config, iface)
        current = [str(v) for v in eth.get("addresses", [])]
        eth["addresses"] = [value for value in current if _address_ip(value) != remove_ip_only]
        await self._write_netplan(host, password, port, path, config)
        return f"Persistently removed {remove_ip_only} from {iface}"

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
