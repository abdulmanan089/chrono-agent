# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Database snapshot/restore, stored next to the file snapshots.

Engines:
  sqlite   — fully supported here: a consistent copy via SQLite's backup API,
             restored atomically and checked with PRAGMA integrity_check.
  postgres — uses the pg_dump / psql command-line tools (must be installed);
             not exercised by the test-suite because no server ships with it.
  mysql    — uses mysqldump / mysql; same testing limitation.

A database dump is only a point-in-time copy of that database. Restoring it
does not roll back other databases, queues, or files outside the project.
"""
import json
import shutil
import subprocess
import time
from pathlib import Path

from .snapshot import _atomic

ENGINES = ("sqlite", "postgres", "mysql")
CONFIG = "db.json"


def _config(root):
    path = Path(root).resolve() / ".chrono" / CONFIG
    if not path.is_file():
        return {"databases": {}}
    if path.is_symlink():
        raise RuntimeError("Unsafe symlink in database config")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("databases"), dict):
            raise ValueError("bad shape")
        return data
    except (ValueError, TypeError) as e:
        raise RuntimeError("Corrupt database config: " + str(path)) from e


def _write_config(root, data):
    _atomic(Path(root).resolve() / ".chrono" / CONFIG,
            json.dumps(data, indent=2).encode("utf-8"))


def add(root, name, engine, path=None, url=None):
    if not name.isidentifier() or len(name) > 40:
        raise RuntimeError("Database name: a simple identifier, e.g. appdb")
    if engine not in ENGINES:
        raise RuntimeError("Engine must be one of: " + ", ".join(ENGINES))
    entry = {"engine": engine, "added": time.time()}
    if engine == "sqlite":
        if not path:
            raise RuntimeError("sqlite needs --path, e.g. chrono db add appdb --engine sqlite --path app.db")
        p = (Path(root).resolve() / path).resolve()
        if not str(p).startswith(str(Path(root).resolve())):
            raise RuntimeError("sqlite path must be inside the project")
        entry["path"] = str(p)
    else:
        if not url:
            raise RuntimeError(engine + " needs --url, e.g. postgresql://user:pass@host/db")
        if not url.startswith(("postgresql://", "postgres://", "mysql://")):
            raise RuntimeError("Connection URL must start with postgresql:// or mysql://")
        entry["url"] = url
    data = _config(root)
    data["databases"][name] = entry
    _write_config(root, data)


def remove(root, name):
    data = _config(root)
    if name not in data["databases"]:
        raise RuntimeError("No database registered as " + name)
    del data["databases"][name]
    _write_config(root, data)


def list_dbs(root):
    return _config(root)["databases"]


def _dump_path(root, name):
    return Path(root).resolve() / ".chrono" / "db" / (name + ".dump")


def _run(cmd, **kw):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300, **kw)
    except FileNotFoundError as e:
        raise RuntimeError("Tool not found: %s — install the %s client tools" % (cmd[0], cmd[0])) from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError("Database tool timed out") from e
    if out.returncode != 0:
        raise RuntimeError("%s failed: %s" % (cmd[0], (out.stderr or "").strip()[:300]))
    return out


def snapshot(root, name):
    dbs = _config(root)["databases"]
    if name not in dbs:
        raise RuntimeError("No database registered as %s. Run: chrono db add %s --engine ..." % (name, name))
    entry = dbs[name]
    dest = _dump_path(root, name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    engine = entry["engine"]
    if engine == "sqlite":
        src = Path(entry["path"])
        if not src.is_file():
            raise RuntimeError("sqlite file not found: " + str(src))
        import sqlite3
        tmp = dest.with_suffix(".tmp")
        if tmp.exists():
            tmp.unlink()
        source = sqlite3.connect(str(src))
        try:
            target = sqlite3.connect(str(tmp))
            try:
                source.backup(target)
            finally:
                target.close()
        finally:
            source.close()
        _atomic(dest, tmp.read_bytes())
        tmp.unlink(missing_ok=True)
    elif engine == "postgres":
        _run(["pg_dump", "--format=plain", "--file", str(dest), entry["url"]])
    else:
        out = _run(["mysqldump", "--result-file", str(dest), entry["url"]])
    size = dest.stat().st_size
    return {"name": name, "engine": engine, "bytes": size, "dump": str(dest)}


def restore(root, name):
    dbs = _config(root)["databases"]
    if name not in dbs:
        raise RuntimeError("No database registered as " + name)
    dest = _dump_path(root, name)
    if not dest.is_file():
        raise RuntimeError("No dump for %s. Run: chrono db snapshot %s" % (name, name))
    entry = dbs[name]
    engine = entry["engine"]
    if engine == "sqlite":
        src = Path(entry["path"])
        import sqlite3
        check = sqlite3.connect(str(dest))
        try:
            row = check.execute("PRAGMA integrity_check").fetchone()
            if not row or row[0] != "ok":
                raise RuntimeError("Dump failed integrity_check; not restored")
        finally:
            check.close()
        _atomic(src, dest.read_bytes())
    elif engine == "postgres":
        _run(["psql", entry["url"], "--file", str(dest)])
    else:
        with open(dest, "rb") as f:
            _run(["mysql", entry["url"]], stdin=f)
    return {"name": name, "engine": engine, "bytes": dest.stat().st_size}
