from __future__ import annotations

import asyncio
from dataclasses import dataclass

import asyncssh

from .config import Settings


@dataclass(slots=True)
class SSHCredentials:
    username: str
    password: str


class SSHRunner:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._semaphore = asyncio.Semaphore(max(1, settings.max_parallel_sessions))

    def _known_hosts(self):
        if self.settings.ssh_known_hosts == "__DISABLE__":
            return None
        if self.settings.ssh_known_hosts:
            return self.settings.ssh_known_hosts
        return ()

    async def connect(self, host: str, port: int, credentials: SSHCredentials):
        kwargs = dict(
            host=host,
            port=port,
            username=credentials.username,
            password=credentials.password,
            connect_timeout=self.settings.ssh_connect_timeout_seconds,
            login_timeout=self.settings.ssh_login_timeout_seconds,
        )
        known_hosts = self._known_hosts()
        if known_hosts != ():
            kwargs["known_hosts"] = known_hosts
        return await asyncssh.connect(**kwargs)

    async def run(
        self,
        host: str,
        port: int,
        credentials: SSHCredentials,
        command: str,
        *,
        check: bool = False,
        timeout: float | None = None,
        retries: int = 3,
        input_data: str | None = None,
    ) -> asyncssh.SSHCompletedProcess:
        last_error: Exception | None = None
        for attempt in range(max(1, retries)):
            try:
                async with self._semaphore:
                    conn = await self.connect(host, port, credentials)
                    try:
                        return await conn.run(command, check=check, timeout=timeout, input=input_data)
                    finally:
                        conn.close()
                        await conn.wait_closed()
            except (asyncssh.DisconnectError, asyncssh.ConnectionLost, OSError, asyncio.TimeoutError) as exc:
                last_error = exc
                if attempt + 1 < retries:
                    await asyncio.sleep(2.0)
                    continue
                break
        raise ConnectionError(f"SSH command failed after {retries} attempts: {last_error}")
