# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Local team roster: names and roles for one checked-out project.

This is NOT a company account system. It is a plain file (.chrono/team.json)
inside the project, so anyone with write access to the folder can edit it;
its real value is attribution (who approved / ran what in the audit log) and
policy role checks on this one machine. Central accounts need a server.
"""
import getpass
import json
import os
import re
import time
from pathlib import Path

ROLES = ("viewer", "developer", "admin")
RANK = {role: i for i, role in enumerate(ROLES)}
NAME = re.compile(r"[A-Za-z0-9_.@-]{1,64}\Z")
FILE = "team.json"


def current_user():
    return (os.environ.get("CHRONO_USER") or _os_user())


def _os_user():
    try:
        name = getpass.getuser()
    except Exception:
        name = ""
    return name or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


class Team:
    def __init__(self, root="."):
        self.dir = Path(root).resolve() / ".chrono"
        self.path = self.dir / FILE

    def _read(self):
        if not self.path.is_file():
            return {"users": {}}
        if self.path.is_symlink():
            raise RuntimeError("Unsafe symlink in team storage")
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
                raise ValueError("bad shape")
            for name, info in data["users"].items():
                if not NAME.fullmatch(name) or info.get("role") not in ROLES:
                    raise ValueError("bad entry")
            return data
        except (ValueError, TypeError) as e:
            raise RuntimeError("Corrupt team file: " + str(self.path)) from e

    def _write(self, data):
        from .snapshot import _atomic
        _atomic(self.path, json.dumps(data, indent=2).encode("utf-8"))

    def list(self):
        return self._read()["users"]

    def add(self, name, role):
        if not NAME.fullmatch(name):
            raise RuntimeError("User name: 1-64 letters, digits, dot, dash, underscore or @")
        if role not in ROLES:
            raise RuntimeError("Role must be one of: " + ", ".join(ROLES))
        data = self._read()
        is_new = name not in data["users"]
        if is_new and not data["users"] and role != "admin":
            raise RuntimeError("The first team member must be an admin")
        data["users"][name] = {"role": role, "added": time.time()}
        self._write(data)
        return is_new

    def remove(self, name):
        data = self._read()
        if name not in data["users"]:
            raise RuntimeError("No such team member: " + name)
        if data["users"][name]["role"] == "admin" and \
                sum(1 for u in data["users"].values() if u["role"] == "admin") == 1:
            raise RuntimeError("Cannot remove the last admin")
        del data["users"][name]
        self._write(data)

    def role_of(self, name):
        info = self._read()["users"].get(name)
        return info["role"] if info else None

    def require(self, action, policy):
        """Enforce policy.roles[action] for the current user, if configured."""
        needed = (policy or {}).get("roles", {}).get(action)
        if not needed:
            return current_user(), None
        user = current_user()
        have = self.role_of(user)
        if have is None or RANK[have] < RANK[needed]:
            raise RuntimeError(
                "Action %r needs role %s; %s has %s. Set CHRONO_USER or add the user: chrono team add"
                % (action, needed, user, have or "no role"))
        return user, have
