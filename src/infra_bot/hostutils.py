from __future__ import annotations

import ipaddress
import re

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def validate_host(host: str) -> str:
    host = host.strip()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if not host or not _HOST_RE.fullmatch(host) or ".." in host:
            raise ValueError(f"Invalid host: {host!r}")
        return host


def parse_host_port(host_spec: str, default_port: int = 22) -> tuple[str, int]:
    host_spec = host_spec.strip()
    if host_spec.startswith("[") and "]:" in host_spec:
        host, port_raw = host_spec[1:].rsplit("]:", 1)
    elif host_spec.count(":") == 1:
        host, port_raw = host_spec.rsplit(":", 1)
    else:
        return validate_host(host_spec.strip("[]")), default_port
    port = int(port_raw)
    if not 1 <= port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    return validate_host(host), port
