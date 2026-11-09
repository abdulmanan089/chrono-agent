# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Append-only, hash-chained audit log of every Chrono action.

Every record stores the digest of the record before it, so editing, deleting or
reordering an entry breaks the chain (verify() reports where).

Since 0.5.0 the log is **signed by default**. Each digest is an HMAC-SHA256 made
with a key that lives outside every project, in the user's Chrono home
(``~/.chrono-agent/keys``, or ``$CHRONO_HOME/keys``). An agent or a person who can
only write the project folder can no longer rebuild a valid-looking chain after
editing it. After every record Chrono also updates an external *witness* (the
newest sequence number and digest, kept in the same home folder). Deleting the
newest records, or replacing the whole log, is therefore detected too.

Where the signing key comes from, in this order:

* ``CHRONO_AUDIT_KEY``: a secret you manage yourself (vault, CI secret).
* ``CHRONO_AUDIT_UNSIGNED=1``: explicit opt-out, plain SHA-256 digests (0.4 behaviour).
* ``<chrono home>/keys``: created automatically on first use (32 random bytes).

``CHRONO_AUDIT_REQUIRE_KEY=1`` turns on strict mode: unsigned records fail
verification and unsigned writing is refused.

Limits: this is still a local file. Anyone who can read the key file (the same OS
account, an administrator) can forge records, and anyone who can write the
Chrono home can move the witness. Push the chain to a store you do not control
(``chrono audit --push``) when that matters.
"""
import contextlib
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import tempfile
import time
from pathlib import Path

GENESIS = "GENESIS"
KEY_ENV = "CHRONO_AUDIT_KEY"
UNSIGNED_ENV = "CHRONO_AUDIT_UNSIGNED"
REQUIRE_ENV = "CHRONO_AUDIT_REQUIRE_KEY"
HOME_ENV = "CHRONO_HOME"
ALG = "hmac-sha256"
FIELDS = ("seq", "ts", "t", "actor", "host", "root", "action", "outcome", "kind",
          "detail", "command", "snapshot", "model", "agent", "risk_score",
          "risk_level", "files", "alert", "alg", "kid", "prev", "hash")
KID = re.compile(r"[a-f0-9]{16}\Z")


# Secrets must not be copied into a log that is exported, shared and kept for years.
_REDACTIONS = [
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)[^\s'\"]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(sk-ant-|sk-|pk-|rk-)[A-Za-z0-9_-]{16,}"), "[REDACTED-KEY]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_\w{20,}|\bxox[abprs]-[\w-]{10,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{30,}"), "[REDACTED-KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "[REDACTED-JWT]"),
    (re.compile(r"(://[^/\s:@]+:)[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(?i)(--?(?:password|passwd|pass|token|secret|api-?key|access-?key)(?:=|\s+))(?:\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;&|]+)"), r"\1[REDACTED]"),
    (re.compile(r"\b([A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z0-9_]*=)(?:\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
]


def redact(text):
    """Mask common secret shapes (tokens, passwords, URL credentials) in a string."""
    if not isinstance(text, str):
        return text
    for rx, repl in _REDACTIONS:
        text = rx.sub(repl, text)
    return text


def _csv_safe(value):
    """Neutralise spreadsheet formula injection (cells starting with = + - @)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _actor():
    try:
        name = getpass.getuser()
    except Exception:
        name = ""
    return (name or os.environ.get("USER") or os.environ.get("USERNAME")
            or os.environ.get("LOGNAME") or "unknown")


def _host():
    raw = os.environ.get("CHRONO_HOST")
    if raw:
        return raw
    try:
        return socket.gethostname() or "unknown"
    except Exception:
        return "unknown"


def _truthy(name):
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _key():
    """The key from CHRONO_AUDIT_KEY, or None (kept for callers of the 0.4 API)."""
    raw = os.environ.get(KEY_ENV)
    return raw.encode("utf-8") if raw else None


def _digest(payload, key):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")
    return (hmac.new(key, body, hashlib.sha256) if key
            else hashlib.sha256(body)).hexdigest()


# ------------------------------------------------------------- chrono home
def chrono_home():
    """Per-user Chrono folder for keys, witnesses and policy pins. It is never
    inside a project, so whoever can only write a project cannot reach it."""
    raw = os.environ.get(HOME_ENV)
    return Path(raw).expanduser().resolve() if raw else Path.home() / ".chrono-agent"


def project_id(root):
    """Stable id of a project folder, used to name its witness and policy pin."""
    return hashlib.sha256(os.path.normcase(str(Path(root).resolve())).encode("utf-8")).hexdigest()[:32]


def _private_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError("Unsafe symlink in Chrono home: " + str(path))
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path


def _replace(src, dst, attempts=8):
    delay = 0.02
    for i in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:      # Windows: a reader or a virus scanner holds the file briefly
            if i == attempts - 1:
                raise
            time.sleep(delay)
            delay *= 2


def write_private(path, data, exclusive=False):
    """Write a small file that only this OS user can read. exclusive=True never
    replaces an existing file (raises FileExistsError instead)."""
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError("Unsafe symlink in Chrono home: " + str(path))
    if exclusive:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(str(path), flags, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        return
    fd, temp = tempfile.mkstemp(prefix=".chrono-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _replace(temp, str(path))
    finally:
        if os.path.exists(temp):
            try:
                os.unlink(temp)
            except OSError:
                pass


# ------------------------------------------------------------- signing keys
def key_id(key):
    """Short public id of a key. It names the key and reveals nothing about it."""
    return hashlib.sha256(b"chrono-audit-key-id\0" + key).hexdigest()[:16]


class KeyRing:
    """Audit signing keys in <chrono home>/keys, outside every project.

    Keys are never deleted. Rotation adds a key and makes it active, so records
    signed with an older key still verify. Back this folder up: a log whose key
    is lost can no longer be verified."""

    def __init__(self, home=None):
        self.dir = (Path(home) if home else chrono_home()) / "keys"

    @staticmethod
    def env_key():
        return _key()

    def _load(self, kid):
        if not isinstance(kid, str) or not KID.fullmatch(kid):
            return None
        p = self.dir / (kid + ".key")
        try:
            if p.is_symlink() or not p.is_file():
                return None
            key = bytes.fromhex(p.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return None
        return key if key and key_id(key) == kid else None

    def get(self, kid):
        """The key with this id (from CHRONO_AUDIT_KEY or the key store), or None."""
        env = self.env_key()
        if env is not None and key_id(env) == kid:
            return env
        return self._load(kid)

    def _active_kid(self, wait=False):
        p = self.dir / "active"
        for _ in range(100 if wait else 1):
            try:
                if p.is_symlink():
                    raise RuntimeError("Unsafe symlink in audit key store: " + str(p))
                text = p.read_text(encoding="ascii").strip()
            except FileNotFoundError:
                return None
            except OSError as e:
                raise RuntimeError("Cannot read the audit key store %s: %s" % (self.dir, e)) from e
            if KID.fullmatch(text):
                return text
            if wait:                      # another process is still writing the marker
                time.sleep(0.02)
        raise RuntimeError("Corrupt active-key marker in " + str(self.dir))

    def active(self, create=True):
        """(kid, key) for new records, or (None, None) when signing is switched off."""
        env = self.env_key()
        if env is not None:
            return key_id(env), env
        if _truthy(UNSIGNED_ENV):
            if _truthy(REQUIRE_ENV):
                raise RuntimeError("%s=1 conflicts with %s=1" % (UNSIGNED_ENV, REQUIRE_ENV))
            return None, None
        kid = self._active_kid()
        if kid:
            key = self._load(kid)
            if key is None:
                raise RuntimeError("Audit signing key %s is missing or damaged in %s. Restore it from "
                                   "your backup, or set %s." % (kid, self.dir, KEY_ENV))
            return kid, key
        if not create:
            return None, None
        return self._create(first=True)

    def _create(self, first):
        _private_dir(self.dir)
        key = secrets.token_bytes(32)
        kid = key_id(key)
        key_file = self.dir / (kid + ".key")
        write_private(key_file, key.hex().encode("ascii"), exclusive=True)
        marker = self.dir / "active"
        if not first:
            write_private(marker, kid.encode("ascii"))
            return kid, key
        try:
            write_private(marker, kid.encode("ascii"), exclusive=True)
        except FileExistsError:           # another process created the store first: use its key
            try:
                key_file.unlink()
            except OSError:
                pass
            other = self._active_kid(wait=True)
            other_key = self._load(other)
            if other_key is None:
                raise RuntimeError("Audit key store in %s is incomplete; retry" % self.dir)
            return other, other_key
        return kid, key

    def rotate(self):
        """Make a fresh key active. Older keys stay, so older records still verify."""
        if self.env_key() is not None:
            raise RuntimeError("The signing key comes from %s; rotate it in your secret manager instead" % KEY_ENV)
        if _truthy(UNSIGNED_ENV):
            raise RuntimeError("Signing is switched off by %s" % UNSIGNED_ENV)
        if self._active_kid() is None:
            return self._create(first=True)[0]
        return self._create(first=False)[0]

    def kids(self):
        try:
            return sorted(p.stem for p in self.dir.glob("*.key") if KID.fullmatch(p.stem))
        except OSError:
            return []


def _witness_body(data):
    return json.dumps({"root": data.get("root"), "seq": data.get("seq"), "hash": data.get("hash")},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


# ------------------------------------------------------------- the log
class AuditLog:
    """One append-only log per project, stored at .chrono/audit.jsonl."""

    def __init__(self, root="."):
        self.dir = Path(root).resolve() / ".chrono"
        self.path = self.dir / "audit.jsonl"

    @property
    def enabled(self):
        return self.dir.is_dir() and not self.path.is_symlink()

    @property
    def witness_path(self):
        return chrono_home() / "witness" / (project_id(self.dir.parent) + ".json")

    def _raw_lines(self):
        if not self.path.is_file():
            return []
        with open(self.path, "rb") as f:
            return f.read().decode("utf-8", errors="replace").splitlines()

    def read(self):
        """Parsed records; unreadable lines come back marked, never dropped."""
        out = []
        for n, line in enumerate(self._raw_lines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError("not an object")
            except (ValueError, TypeError):
                rec = {"seq": None, "action": "CORRUPT", "outcome": "unreadable",
                       "detail": "line " + str(n)}
            out.append(rec)
        return out

    def record(self, action, outcome="ok", **fields):
        """Append one event. Returns None when the project is not initialised."""
        return self._record(action, outcome, fields, force_witness=False)

    def _record(self, action, outcome, fields, force_witness):
        if not self.enabled:
            return None
        if self.path.is_symlink():
            raise RuntimeError("Unsafe symlink in audit storage: " + str(self.path))
        kid, key = KeyRing().active()
        fields.setdefault("model", os.environ.get("CHRONO_MODEL"))
        fields.setdefault("agent", os.environ.get("CHRONO_AGENT"))
        for name in ("command", "detail"):
            if isinstance(fields.get(name), str):
                fields[name] = redact(fields[name])
        with self._append_lock():
            return self._append(action, outcome, fields, kid, key, force_witness)

    def _tail_state(self):
        """(seq, hash) of the newest record read from the end of the file, or None."""
        try:
            size = self.path.stat().st_size
        except OSError:
            return (0, GENESIS)
        if size == 0:
            return (0, GENESIS)
        chunk = 65536
        with open(self.path, "rb") as f:
            while True:
                start = max(0, size - chunk)
                f.seek(start)
                lines = [x for x in f.read().split(b"\n") if x.strip()]
                if len(lines) >= 2 or start == 0:
                    break
                chunk *= 4
        try:
            last = json.loads(lines[-1].decode("utf-8"))
        except (ValueError, IndexError, UnicodeDecodeError):
            return None
        if isinstance(last, dict) and isinstance(last.get("hash"), str) and isinstance(last.get("seq"), int):
            return (last["seq"], last["hash"])
        return None

    @contextlib.contextmanager
    def _append_lock(self):
        """Serialise writers so two processes can never fork the hash chain."""
        lock = self.dir / "audit.lock"
        if lock.is_symlink():
            raise RuntimeError("Unsafe symlink in audit storage: " + str(lock))
        f = open(lock, "a+b")
        try:
            deadline = time.time() + 15
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt
                        f.seek(0, 2)
                        if f.tell() == 0:
                            f.write(b"0"); f.flush()
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.time() > deadline:
                        raise RuntimeError("Audit log busy: could not get the write lock")
                    time.sleep(0.01)
            yield
        finally:
            f.close()

    def _append(self, action, outcome, fields, kid=None, key=None, force_witness=False):
        tail = self._tail_state()
        if tail is not None:
            seq_prev, prev = tail
        else:                                   # unusual tail: fall back to a full scan
            lines = self._raw_lines()
            prev = GENESIS
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    last = json.loads(line)
                except ValueError:
                    last = None
                if isinstance(last, dict) and isinstance(last.get("hash"), str):
                    prev = last["hash"]
                break
            seq_prev = len([x for x in lines if x.strip()])
        rec = {"seq": seq_prev + 1,
               "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "t": time.time(),
               "actor": _actor(),
               "host": _host(),
               "root": str(self.dir.parent),
               "action": action,
               "outcome": outcome}
        for name in ("detail", "command", "snapshot", "model", "agent", "kind",
                     "risk_score", "risk_level", "files"):
            value = fields.get(name)
            if value is not None:
                rec[name] = value
        # A log whose newest records were cut off must not be "repaired" by the
        # next write: in that case the witness stays frozen at what it last saw,
        # so verify() keeps failing until a person resets it.
        conflict = self._witness_conflict(seq_prev, prev)
        if conflict:
            rec["alert"] = "audit log does not match its external witness: " + conflict
        if key is not None:
            rec["alg"] = ALG
            rec["kid"] = kid
        rec["prev"] = prev
        rec["hash"] = _digest({k: v for k, v in rec.items() if k != "hash"}, key)
        body = (json.dumps(rec, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
        with open(self.path, "ab") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        if force_witness or not conflict:
            self._update_witness(rec["seq"], rec["hash"], kid, key)   # only after the record is on disk
        return rec

    # ---- external witness -------------------------------------------------
    def _witness_conflict(self, seq_prev, prev):
        """None when the newest record matches the external witness, else why not."""
        w = self.read_witness()
        if w is None:
            return None
        if "_error" in w:
            return "external witness is " + w["_error"]
        wseq, whash = w.get("seq"), w.get("hash")
        if isinstance(wseq, bool) or not isinstance(wseq, int) or not isinstance(whash, str):
            return "external witness is malformed"
        if wseq > seq_prev:
            return "the log ends at #%d but the witness expects #%d" % (seq_prev, wseq)
        if wseq == seq_prev:
            return None if whash == prev else "record #%d differs from the witness" % wseq
        for rec in self.read():            # witness is behind (an earlier witness write failed)
            if rec.get("seq") == wseq:
                return None if rec.get("hash") == whash else "record #%d differs from the witness" % wseq
        return "record #%d named by the witness is missing" % wseq

    def archive_stale_witness(self):
        """Called when a brand-new project is created where an older one lived.
        The old witness is kept in witness/archive (never silently deleted) and
        its summary is returned so the new log can record it."""
        w = self.read_witness()
        if w is None:
            return None
        target_dir = _private_dir(self.witness_path.parent / "archive")
        target = target_dir / ("%s-%d.json" % (self.witness_path.stem, int(time.time() * 1000)))
        _replace(str(self.witness_path), str(target))
        return {"seq": w.get("seq"), "hash": w.get("hash"), "archived_as": str(target)}

    def _update_witness(self, seq, digest, kid, key):
        data = {"root": str(self.dir.parent), "seq": seq, "hash": digest, "t": time.time()}
        if key is not None:
            data["kid"] = kid
            data["mac"] = hmac.new(key, _witness_body(data), hashlib.sha256).hexdigest()
        try:
            _private_dir(self.witness_path.parent)
            write_private(self.witness_path, json.dumps(data, sort_keys=True).encode("utf-8"))
        except (OSError, RuntimeError):
            if _truthy(REQUIRE_ENV):
                raise
            # Without a writable Chrono home the chain is still verified; only
            # truncation detection is lost, and verify() reports the stale witness.

    def read_witness(self):
        p = self.witness_path
        try:
            if p.is_symlink():
                return {"_error": "symlink"}
            data = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return {"_error": "unreadable"}
        return data if isinstance(data, dict) else {"_error": "unreadable"}

    def reset_witness(self, detail="external witness re-anchored by a person"):
        """Deliberately accept the current log as the new reference point, for
        example after restoring .chrono from a backup. The reset is recorded,
        including what the old witness expected."""
        return self._record("audit.witness_reset", "ok", {"detail": detail}, force_witness=True)

    def head(self):
        """(seq, hash) of the newest record; (0, GENESIS) when the log is empty."""
        for line in reversed(self._raw_lines()):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                return (None, None)
            if isinstance(rec, dict) and isinstance(rec.get("hash"), str):
                return (rec.get("seq"), rec["hash"])
            return (None, None)
        return (0, GENESIS)

    def verify(self):
        """Walk the chain, check every signature, then compare the newest record
        with the external witness. Reports the first thing that does not add up."""
        witness = self.read_witness()      # read BEFORE the log: the log only grows after this
        lines = [x for x in self._raw_lines() if x.strip()]
        ring = KeyRing()
        env_key = ring.env_key()
        strict = _truthy(REQUIRE_ENV)
        info = {"ok": True, "records": len(lines), "broken_at": None, "reason": "",
                "signed": 0, "legacy_unsigned": 0, "legacy_signed": 0, "keys": [],
                "witness": "none"}

        def fail(n, why):
            info.update(ok=False, broken_at=n, reason=why)
            return info

        prev = GENESIS
        signed_seen = False
        by_seq = {}
        for n, line in enumerate(lines, 1):
            try:
                rec = json.loads(line)
            except ValueError:
                return fail(n, "record is not valid JSON")
            if not isinstance(rec, dict):
                return fail(n, "record is not an object")
            stored = rec.get("hash")
            if not isinstance(stored, str):
                return fail(n, "record has no digest")
            if rec.get("prev") != prev:
                return fail(n, "previous link does not match (record deleted or reordered)")
            body = {k: v for k, v in rec.items() if k != "hash"}
            alg = rec.get("alg")
            if alg is None:
                if signed_seen:
                    return fail(n, "unsigned record after signed records (downgraded or forged)")
                if strict:
                    return fail(n, "unsigned record, but %s requires a signed log" % REQUIRE_ENV)
                if hmac.compare_digest(_digest(body, None), stored):
                    info["legacy_unsigned"] += 1
                elif env_key is not None and hmac.compare_digest(_digest(body, env_key), stored):
                    info["legacy_signed"] += 1
                else:
                    why = "content does not match its digest (record edited)"
                    if env_key is None:
                        why += "; if this log is HMAC-signed, set " + KEY_ENV
                    return fail(n, why)
            elif alg == ALG:
                kid = rec.get("kid")
                key = ring.get(kid)
                if key is None:
                    return fail(n, "record is signed with key %s, which is not available here; set %s "
                                   "to that key or restore %s" % (kid, KEY_ENV, ring.dir))
                if not hmac.compare_digest(_digest(body, key), stored):
                    return fail(n, "content does not match its signature (record edited or forged)")
                info["signed"] += 1
                signed_seen = True
                if kid not in info["keys"]:
                    info["keys"].append(kid)
            else:
                return fail(n, "unknown digest algorithm %r" % (alg,))
            if isinstance(rec.get("seq"), int):
                by_seq[rec["seq"]] = stored
            prev = stored

        if witness is not None:
            if "_error" in witness:
                return fail(len(lines) + 1, "external witness is %s" % witness["_error"])
            wseq, whash = witness.get("seq"), witness.get("hash")
            if isinstance(wseq, bool) or not isinstance(wseq, int) or wseq < 0 or not isinstance(whash, str):
                return fail(len(lines) + 1, "external witness is malformed")
            if witness.get("mac") is not None:
                wkey = ring.get(witness.get("kid"))
                if wkey is not None and not hmac.compare_digest(
                        hmac.new(wkey, _witness_body(witness), hashlib.sha256).hexdigest(), str(witness["mac"])):
                    return fail(len(lines) + 1, "external witness was edited")
            if wseq > 0 and by_seq.get(wseq) != whash:
                return fail(min(wseq, len(lines) + 1),
                            "the newest records were removed or the log was replaced: the external witness "
                            "expects record #%d (%s...)" % (wseq, whash[:12]))
            info["witness"] = "ok"

        if not lines:
            info["reason"] = "no audit records"
            return info
        if info["signed"] and not (info["legacy_unsigned"] or info["legacy_signed"]):
            kind = "HMAC-signed"
        elif info["signed"]:
            kind = "%d signed, %d older records in the 0.4 format" % (
                info["signed"], info["legacy_unsigned"] + info["legacy_signed"])
        elif info["legacy_signed"]:
            kind = "HMAC-signed, 0.4 format"
        else:
            kind = "unsigned"
        tail = "external witness matches" if info["witness"] == "ok" else "no external witness yet"
        info["reason"] = "chain intact (%s); %s" % (kind, tail)
        return info

    def rows(self, limit=None, action=None):
        recs = self.read()
        if action:
            recs = [r for r in recs if r.get("action") == action]
        return recs[-limit:] if limit else recs

    def to_csv(self, records):
        head = ["seq", "ts", "actor", "host", "action", "outcome", "snapshot",
                "model", "agent", "risk_score", "risk_level", "files", "detail",
                "command", "hash"]
        import csv, io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=head, extrasaction="ignore",
                                lineterminator="\n")
        writer.writeheader()
        for rec in records:
            row = {k: _csv_safe(rec.get(k, "")) for k in head}
            if isinstance(row.get("files"), dict):
                row["files"] = _csv_safe(" ".join("%s=%s" % kv for kv in sorted(row["files"].items())))
            writer.writerow(row)
        return buf.getvalue()
