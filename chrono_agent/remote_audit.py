# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Push the local audit chain to a remote append-only store over HTTP(S).

The local log alone cannot prove that its newest records were not deleted —
whoever controls the folder can truncate it. Pushing each record to a store
the project owner does not control closes that gap: the remote keeps its own
copy, and `chrono audit push --verify-remote` compares chain heads.

The remote service itself is not part of this package; the contract is:
  POST <url>   body {"records": [...], "chain_head": "...", "chain_seq": N}
               -> HTTP 2xx with JSON {"accepted": <count>} (extra fields ok)
  GET  <url>   -> JSON {"chain_head": "...", "chain_seq": N}  (for --verify-remote)
"""
import json
import urllib.request
from pathlib import Path

from .audit import AuditLog
from .snapshot import _atomic

STATE = "remote.json"


def _state_path(root):
    return Path(root).resolve() / ".chrono" / STATE


def _read_state(root):
    p = _state_path(root)
    if not p.is_file():
        return {}
    if p.is_symlink():
        raise RuntimeError("Unsafe symlink in remote-audit state")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def _check_url(url):
    if not isinstance(url, str) or not url.startswith(("http://", "https://")) or len(url) > 500:
        raise RuntimeError("Remote URL must start with http:// or https://")
    return url


def push(root, url, verify_remote=False, timeout=20):
    url = _check_url(url)
    log = AuditLog(root)
    state = _read_state(root)
    last_sent = state.get("last_seq", 0) if state.get("url") == url else 0
    if not isinstance(last_sent, int) or last_sent < 0:
        last_sent = 0
    records = [r for r in log.read() if isinstance(r.get("seq"), int)]
    new = [r for r in records if r["seq"] > last_sent]
    seq, head = log.head()
    result = {"sent": 0, "url": url}
    if new:
        body = json.dumps({"records": new, "chain_head": head, "chain_seq": seq},
                          ensure_ascii=True).encode("utf-8")
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status >= 300:
                    raise RuntimeError("Remote store answered HTTP %d" % resp.status)
                reply = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError("Could not reach the remote audit store: " + str(e)) from e
        accepted = reply.get("accepted", len(new)) if isinstance(reply, dict) else len(new)
        if accepted != len(new):
            raise RuntimeError("Remote accepted %d of %d records; push not recorded locally"
                               % (accepted, len(new)))
        result["sent"] = len(new)
    _atomic(_state_path(root), json.dumps({"url": url, "last_seq": seq, "head": head},
                                          indent=2).encode("utf-8"))
    result["last_seq"] = seq
    if verify_remote:
        req = urllib.request.Request(url, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                remote = json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
        except Exception as e:
            raise RuntimeError("Could not verify the remote store: " + str(e)) from e
        remote_head = remote.get("chain_head") if isinstance(remote, dict) else None
        result["remote_head"] = remote_head
        result["remote_match"] = (remote_head == head)
    return result
