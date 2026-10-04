from __future__ import annotations

import json
import threading

from .config import Settings


class AccessController:
    """Admin/authorization state with a small persistent runtime whitelist.

    Static IDs live in environment variables.  IDs added at runtime are stored in
    runtime/whitelist.json, which is ignored by git.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.RLock()
        self._runtime_users: set[str] = set()
        self._load()

    def _load(self) -> None:
        path = self.settings.whitelist_file
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            users = data.get("authorized_user_ids", []) if isinstance(data, dict) else []
            self._runtime_users = {str(v) for v in users}
        except (OSError, ValueError, TypeError):
            self._runtime_users = set()

    def _save(self) -> None:
        self.settings.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"authorized_user_ids": sorted(self._runtime_users)}
        tmp = self.settings.whitelist_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self.settings.whitelist_file)

    def is_admin(self, user_id: int | str) -> bool:
        return str(user_id) in self.settings.admin_user_ids

    def is_authorized(self, user_id: int | str) -> bool:
        uid = str(user_id)
        return (
            uid in self.settings.admin_user_ids
            or uid in self.settings.authorized_user_ids
            or uid in self._runtime_users
        )

    def add_user(self, user_id: int | str) -> None:
        with self._lock:
            self._runtime_users.add(str(user_id))
            self._save()

    def remove_user(self, user_id: int | str) -> None:
        with self._lock:
            self._runtime_users.discard(str(user_id))
            self._save()

    def runtime_users(self) -> set[str]:
        with self._lock:
            return set(self._runtime_users)
