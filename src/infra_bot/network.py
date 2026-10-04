from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
from dataclasses import dataclass


@dataclass(slots=True)
class PingResult:
    ip: str
    reachable: bool
    attempts: int


def validate_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def normalize_subnet(value: str) -> ipaddress.IPv4Network:
    raw = value.strip()
    if "/" not in raw:
        parts = raw.split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid IPv4 subnet: {value}")
        raw = ".".join(parts[:3] + ["0"]) + "/24"
    network = ipaddress.ip_network(raw, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 subnet scans are supported")
    if network.num_addresses > 1024:
        raise ValueError("Subnet too large for this utility; maximum supported size is /22")
    return network


async def ping_ip(ip: str, attempts: int = 2, timeout_seconds: float = 3.0) -> PingResult:
    ip = validate_ip(ip)
    system_name = platform.system().lower()
    if system_name == "windows":
        command = ["ping", "-n", "1", "-w", "2000", ip]
    elif system_name == "darwin":
        command = ["ping", "-c", "1", ip]
    else:
        command = ["ping", "-c", "1", "-W", "2", ip]

    negative = ("destination host unreachable", "100% packet loss", "timed out", "unreachable")
    for attempt in range(1, attempts + 1):
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
            output = stdout.decode("utf-8", errors="ignore").lower()
            positive = any(marker in output for marker in ("ttl=", "bytes from", "reply from"))
            if positive and not any(marker in output for marker in negative):
                return PingResult(ip=ip, reachable=True, attempts=attempt)
        except asyncio.TimeoutError:
            pass
    return PingResult(ip=ip, reachable=False, attempts=attempts)


async def ping_subnet(subnet: str, concurrency: int = 64) -> list[PingResult]:
    network = normalize_subnet(subnet)
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(host: ipaddress.IPv4Address) -> PingResult:
        async with semaphore:
            return await ping_ip(str(host))

    return await asyncio.gather(*(one(host) for host in network.hosts()))


async def is_tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    ip = validate_ip(ip)
    if not 1 <= int(port) <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, int(port)), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False


async def detect_ssh_ports(ip: str, timeout: float = 3.0) -> list[int]:
    ip = validate_ip(ip)
    proc = await asyncio.create_subprocess_exec(
        "nmap", "-p-", "--open", "-T4", "-n", ip,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(stderr.decode("utf-8", errors="ignore").strip() or "nmap failed")

    open_ports: list[int] = []
    for line in stdout.decode("utf-8", errors="ignore").splitlines():
        match = re.match(r"^(\d+)/tcp\s+open\b", line.strip())
        if match:
            open_ports.append(int(match.group(1)))

    async def has_ssh_banner(port: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            try:
                banner = await asyncio.wait_for(reader.readline(), timeout=2.0)
                return banner.startswith(b"SSH-")
            finally:
                writer.close()
                await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    result: list[int] = []
    for port in open_ports:
        if await has_ssh_banner(port):
            result.append(port)
    return result
