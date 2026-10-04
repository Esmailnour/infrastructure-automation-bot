import pytest

from infra_bot.config import Settings
from infra_bot.linux_admin import LinuxAdmin
from infra_bot.ssh_client import SSHCredentials
from infra_bot.transfer import TransferEndpoint, TransferManager


class Result:
    def __init__(self, stdout="", stderr="", exit_status=0):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status


class FakeSSH:
    def __init__(self):
        self.commands = []

    async def run(self, host, port, credentials, command, **kwargs):
        self.commands.append(command)
        return Result(stdout="repo output")


@pytest.mark.asyncio
async def test_large_transfer_splits_into_child_items(monkeypatch):
    settings = Settings(
        safe_mode=False,
        parallel_split_threshold_gb=1000,
        screen_threshold_gb=50,
        transfer_concurrency=3,
        transfer_split_max_depth=4,
    )
    manager = TransferManager(settings, FakeSSH())
    source = TransferEndpoint("192.0.2.10", 22, SSHCredentials("src", "pw"))
    dest = TransferEndpoint("192.0.2.20", 22, SSHCredentials("dst", "pw"))

    async def is_dir(endpoint, path):
        return path == "/home/big"

    async def size(endpoint, path):
        return 1500.0 if path == "/home/big" else 10.0

    async def children(endpoint, path):
        return ["/home/big/a", "/home/big/b"]

    async def mkdir(endpoint, path):
        return None

    async def launch(source, destination, path, *, is_dir, size_gb):
        return f"done:{path}"

    monkeypatch.setattr(manager, "remote_is_dir", is_dir)
    monkeypatch.setattr(manager, "remote_size_gb", size)
    monkeypatch.setattr(manager, "remote_children", children)
    monkeypatch.setattr(manager, "ensure_destination_dir", mkdir)
    monkeypatch.setattr(manager, "_launch_single_transfer", launch)

    result = await manager._transfer_entry(source, dest, "/home/big")
    assert result[0].startswith("Split /home/big")
    assert "done:/home/big/a" in result
    assert "done:/home/big/b" in result


@pytest.mark.asyncio
async def test_centos8_repo_contains_original_vault_sections():
    ssh = FakeSSH()
    admin = LinuxAdmin(Settings(safe_mode=False), ssh)
    await admin.centos8_repo_to_vault("192.0.2.10", "pw")
    command = ssh.commands[-1]
    for section in ("[BaseOS]", "[AppStream]", "[Extras]", "[centosplus]"):
        assert section in command
    assert "vault.centos.org" in command


@pytest.mark.asyncio
async def test_centos9_repo_contains_stream_sections():
    ssh = FakeSSH()
    admin = LinuxAdmin(Settings(safe_mode=False), ssh)
    await admin.centos9_repo_reset("192.0.2.10", "pw")
    command = ssh.commands[-1]
    for section in ("[baseos]", "[appstream]", "[crb]", "[extras-common]"):
        assert section in command
    assert "mirror.stream.centos.org/9-stream" in command


def test_netplan_interface_selection_preserves_existing_mapping():
    config = {"network": {"version": 2, "ethernets": {"ens18": {"addresses": ["192.0.2.10/24"]}}}}
    eth = LinuxAdmin._netplan_interface_config(config, "ens18")
    eth["addresses"].append("192.0.2.11/24")
    assert config["network"]["ethernets"]["ens18"]["addresses"] == ["192.0.2.10/24", "192.0.2.11/24"]


def test_public_secret_defaults_are_safe():
    settings = Settings()
    assert settings.return_generated_secrets_in_chat is False
    assert settings.transfer_split_max_depth == 8
