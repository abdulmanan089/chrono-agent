"""Append-only, hash-chained audit log of every Chrono action.

Every record stores the digest of the record before it, so editing, deleting or
reordering an entry breaks the chain (verify() reports where). With
CHRONO_AUDIT_KEY set the digests are HMACs, so a writer who does not hold the
key cannot forge a valid chain.

This is still a local file: it proves a record was not quietly altered in place,
but it is not a legal-grade ledger, a remote write-once store, or proof of what a
program did outside the tracked files.
"""
import getpass
import hashlib
import hmac
import json
import os
import socket
import time
from pathlib import Path

GENESIS = "GENESIS"
KEY_ENV = "CHRONO_AUDIT_KEY"
FIELDS = ("seq", "ts", "t", "actor", "host", "root", "action", "outcome", "kind",
          "detail", "command", "snapshot", "model", "agent", "risk_score",
          "risk_level", "files", "prev", "hash")


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


def _key():
    raw = os.environ.get(KEY_ENV)
    return raw.encode("utf-8") if raw else None


def _digest(payload, key):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")
    return (hmac.new(key, body, hashlib.sha256) if key
            else hashlib.sha256(body)).hexdigest()


class AuditLog:
    """One append-only log per project, stored at .chrono/audit.jsonl."""

    def __init__(self, root="."):
        self.dir = Path(root).resolve() / ".chrono"
        self.path = self.dir / "audit.jsonl"

    @property
    def enabled(self):
        return self.dir.is_dir() and not self.path.is_symlink()

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
        if not self.enabled:
            return None
        if self.path.is_symlink():
            raise RuntimeError("Unsafe symlink in audit storage: " + str(self.path))
        key = _key()
        fields.setdefault("model", os.environ.get("CHRONO_MODEL"))
        fields.setdefault("agent", os.environ.get("CHRONO_AGENT"))
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
        rec = {"seq": len([x for x in lines if x.strip()]) + 1,
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
        rec["prev"] = prev
        rec["hash"] = _digest({k: v for k, v in rec.items() if k != "hash"}, key)
        body = (json.dumps(rec, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
        with open(self.path, "ab") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        return rec

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
        """Walk the chain and report the first record that does not add up."""
        key = _key()
        lines = [x for x in self._raw_lines() if x.strip()]
        if not lines:
            return {"ok": True, "records": 0, "broken_at": None, "reason": "no audit records"}
        if key is None and os.environ.get("CHRONO_AUDIT_REQUIRE_KEY"):
            return {"ok": False, "records": len(lines), "broken_at": None,
                    "reason": "signed log but " + KEY_ENV + " is not set"}
        prev = GENESIS
        for n, line in enumerate(lines, 1):
            try:
                rec = json.loads(line)
            except ValueError:
                return {"ok": False, "records": len(lines), "broken_at": n,
                        "reason": "record is not valid JSON"}
            if not isinstance(rec, dict):
                return {"ok": False, "records": len(lines), "broken_at": n,
                        "reason": "record is not an object"}
            stored = rec.get("hash")
            if not isinstance(stored, str):
                return {"ok": False, "records": len(lines), "broken_at": n,
                        "reason": "record has no digest"}
            if rec.get("prev") != prev:
                return {"ok": False, "records": len(lines), "broken_at": n,
                        "reason": "previous link does not match (record deleted or reordered)"}
            if _digest({k: v for k, v in rec.items() if k != "hash"}, key) != stored:
                why = "content does not match its digest (record edited)"
                if key is None:
                    why += "; if this log is HMAC-signed, set " + KEY_ENV
                return {"ok": False, "records": len(lines), "broken_at": n,
                        "reason": why}
            prev = stored
        return {"ok": True, "records": len(lines), "broken_at": None,
                "reason": "chain intact" + (" (HMAC-signed)" if key else "")}

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
            row = {k: rec.get(k, "") for k in head}
            if isinstance(row.get("files"), dict):
                row["files"] = " ".join("%s=%s" % kv for kv in sorted(row["files"].items()))
            writer.writerow(row)
        return buf.getvalue()
