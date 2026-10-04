from __future__ import annotations

import asyncio
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import PurePosixPath

from .config import Settings
from .ssh_client import SSHCredentials, SSHRunner


def calculate_timeout(size_gb: float, min_bandwidth_per_session_gbps: float) -> int:
    if min_bandwidth_per_session_gbps <= 0:
        return 1800
    size_megabits = max(0.0, size_gb) * 8000
    minimum_seconds = size_megabits / (min_bandwidth_per_session_gbps * 1000)
    timeout = int(minimum_seconds * 2.5) + 1200
    return max(1800, min(timeout, 172800))


@dataclass(slots=True)
class TransferEndpoint:
    host: str
    port: int
    credentials: SSHCredentials


@dataclass(slots=True)
class TransferStatus:
    source_host: str
    destination_host: str
    rsync_processes: str
    screen_sessions: str
    destination_disk: str
    destination_home: str


class TransferManager:
    """Rsync/SSH transfer orchestration.

    The operational bot split very large directories into immediate children and
    processed those children concurrently. This implementation keeps that behavior
    while avoiding password embedding in the rsync process list.
    """

    def __init__(self, settings: Settings, ssh: SSHRunner):
        self.settings = settings
        self.ssh = ssh
        self._top_level_workers = asyncio.Semaphore(max(1, settings.transfer_concurrency))

    async def _ensure_key(self, source: TransferEndpoint, destination: TransferEndpoint) -> None:
        self.settings.require_mutations_enabled("SSH key setup for transfer")
        await self.ssh.run(
            source.host,
            source.port,
            source.credentials,
            "mkdir -p $HOME/.ssh && chmod 700 $HOME/.ssh && "
            "test -f $HOME/.ssh/id_ed25519 || "
            "ssh-keygen -q -t ed25519 -N '' -f $HOME/.ssh/id_ed25519",
            check=True,
        )
        pub = await self.ssh.run(
            source.host,
            source.port,
            source.credentials,
            "cat $HOME/.ssh/id_ed25519.pub",
            check=True,
        )
        public_key = pub.stdout.strip()
        if not public_key.startswith("ssh-"):
            raise RuntimeError("Source SSH public key could not be read")
        qkey = shlex.quote(public_key)
        install_cmd = (
            "mkdir -p $HOME/.ssh && chmod 700 $HOME/.ssh && touch $HOME/.ssh/authorized_keys && "
            f"grep -qxF {qkey} $HOME/.ssh/authorized_keys || printf '%s\n' {qkey} >> $HOME/.ssh/authorized_keys; "
            "chmod 600 $HOME/.ssh/authorized_keys"
        )
        await self.ssh.run(
            destination.host,
            destination.port,
            destination.credentials,
            install_cmd,
            check=True,
        )

    async def remote_is_dir(self, endpoint: TransferEndpoint, path: str) -> bool:
        result = await self.ssh.run(
            endpoint.host,
            endpoint.port,
            endpoint.credentials,
            f"test -d {shlex.quote(path)}",
        )
        return result.exit_status == 0

    async def remote_size_gb(self, endpoint: TransferEndpoint, path: str) -> float:
        result = await self.ssh.run(
            endpoint.host,
            endpoint.port,
            endpoint.credentials,
            f"du -s --block-size=1M {shlex.quote(path)} | awk '{{print $1}}'",
            check=True,
        )
        megabytes = float(result.stdout.strip() or 0)
        return megabytes / 1024.0

    async def remote_children(self, endpoint: TransferEndpoint, path: str) -> list[str]:
        result = await self.ssh.run(
            endpoint.host,
            endpoint.port,
            endpoint.credentials,
            f"find {shlex.quote(path)} -maxdepth 1 -mindepth 1 -print0",
            check=True,
        )
        return [item for item in result.stdout.split("\0") if item]

    async def ensure_destination_dir(self, endpoint: TransferEndpoint, path: str) -> None:
        await self.ssh.run(
            endpoint.host,
            endpoint.port,
            endpoint.credentials,
            f"mkdir -p {shlex.quote(path)}",
            check=True,
        )

    def _rsync_command(
        self,
        source_path: str,
        destination: TransferEndpoint,
        *,
        is_dir: bool,
        timeout_seconds: int,
    ) -> str:
        src = f"{source_path.rstrip('/')}/" if is_dir else source_path
        dest_dir = source_path.rstrip("/") if is_dir else str(PurePosixPath(source_path).parent)
        dst = f"{destination.credentials.username}@{destination.host}:{dest_dir.rstrip('/')}/"
        ssh_transport = (
            "ssh -i $HOME/.ssh/id_ed25519 "
            "-o BatchMode=yes -o StrictHostKeyChecking=accept-new "
            "-o TCPKeepAlive=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=10 "
            f"-p {destination.port}"
        )
        return (
            "rsync --ignore-existing -raz --partial --info=progress2 "
            f"--timeout={timeout_seconds} -e {shlex.quote(ssh_transport)} "
            f"{shlex.quote(src)} {shlex.quote(dst)}"
        )

    @staticmethod
    def _screen_label(path: str) -> str:
        base = PurePosixPath(path).name or "root"
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", base)[:50]

    async def _launch_single_transfer(
        self,
        source: TransferEndpoint,
        destination: TransferEndpoint,
        path: str,
        *,
        is_dir: bool,
        size_gb: float,
    ) -> str:
        timeout = calculate_timeout(size_gb, self.settings.min_bandwidth_per_session_gbps)
        command = self._rsync_command(path, destination, is_dir=is_dir, timeout_seconds=timeout)
        label = self._screen_label(path)

        if size_gb >= self.settings.screen_threshold_gb:
            screen_cmd = f"screen -dmS {shlex.quote('sync_' + label)} bash -lc {shlex.quote(command)}"
            await self.ssh.run(source.host, source.port, source.credentials, screen_cmd, check=True)
            return f"Started background transfer for {path} ({size_gb:.1f} GB)"

        start = time.monotonic()
        await self.ssh.run(
            source.host,
            source.port,
            source.credentials,
            command,
            check=True,
            timeout=timeout + 300,
        )
        duration = max(1.0, time.monotonic() - start)
        avg_gbps = size_gb * 8 / duration
        return f"Completed {path} ({size_gb:.1f} GB) in {duration:.0f}s, ~{avg_gbps:.2f} Gbps"

    async def _transfer_entry(
        self,
        source: TransferEndpoint,
        destination: TransferEndpoint,
        path: str,
        *,
        depth: int = 0,
    ) -> list[str]:
        is_dir = await self.remote_is_dir(source, path)
        size_gb = await self.remote_size_gb(source, path)

        if (
            is_dir
            and size_gb >= self.settings.parallel_split_threshold_gb
            and depth < self.settings.transfer_split_max_depth
        ):
            children = await self.remote_children(source, path)
            if children:
                await self.ensure_destination_dir(destination, path)
                child_workers = asyncio.Semaphore(max(1, self.settings.transfer_concurrency))

                async def one(child: str) -> list[str]:
                    async with child_workers:
                        return await self._transfer_entry(
                            source,
                            destination,
                            child,
                            depth=depth + 1,
                        )

                nested = await asyncio.gather(*(one(child) for child in children))
                flattened = [item for group in nested for item in group]
                return [
                    f"Split {path} ({size_gb:.1f} GB) into {len(children)} child item(s)"
                ] + flattened

        return [
            await self._launch_single_transfer(
                source,
                destination,
                path,
                is_dir=is_dir,
                size_gb=size_gb,
            )
        ]

    async def transfer_path(
        self,
        source: TransferEndpoint,
        destination: TransferEndpoint,
        path: str,
    ) -> list[str]:
        self.settings.require_mutations_enabled("Data transfer")
        async with self._top_level_workers:
            return await self._transfer_entry(source, destination, path)

    async def transfer_home(self, source: TransferEndpoint, destination: TransferEndpoint) -> list[str]:
        self.settings.require_mutations_enabled("Data transfer")
        await self._ensure_key(source, destination)
        listing = await self.ssh.run(
            source.host,
            source.port,
            source.credentials,
            "find /home -mindepth 1 -maxdepth 1 -print0",
            check=True,
        )
        paths = [p for p in listing.stdout.split("\0") if p]
        if not paths:
            return ["No entries found under /home."]
        groups = await asyncio.gather(*(self.transfer_path(source, destination, path) for path in paths))
        return [item for group in groups for item in group]

    async def status(self, source: TransferEndpoint, destination: TransferEndpoint) -> TransferStatus:
        src_screen = await self.ssh.run(
            source.host,
            source.port,
            source.credentials,
            "screen -ls 2>/dev/null | grep -c '\\.sync_' || true",
        )
        src_rsync = await self.ssh.run(
            source.host,
            source.port,
            source.credentials,
            "pgrep -fc rsync || true",
        )
        dst_disk = await self.ssh.run(
            destination.host,
            destination.port,
            destination.credentials,
            "df -h /home 2>/dev/null | tail -1 || df -h $HOME | tail -1",
        )
        dst_home = await self.ssh.run(
            destination.host,
            destination.port,
            destination.credentials,
            "du -sh /home/* 2>/dev/null || echo 'No /home data'",
        )
        return TransferStatus(
            source_host=f"{source.host}:{source.port}",
            destination_host=f"{destination.host}:{destination.port}",
            rsync_processes=src_rsync.stdout.strip(),
            screen_sessions=src_screen.stdout.strip(),
            destination_disk=dst_disk.stdout.strip(),
            destination_home=dst_home.stdout.strip(),
        )
