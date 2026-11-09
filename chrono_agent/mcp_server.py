# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""MCP connector: expose Chrono to AI clients (Claude Desktop, Cursor, etc.)
as a Model Context Protocol server over stdio — newline-delimited JSON-RPC 2.0.

Config snippet for an MCP client:
    { "mcpServers": { "chrono": { "command": "chrono", "args": ["mcp"] } } }

The server acts on the project in the client's working directory. Rollback needs
{"confirm": true}, enforces the same policy roles as the CLI, always saves a rescue
savepoint first (returned as 'redo'), and can require a named human approval via
the policy 'gates' section. Everything the tools do
is recorded in the project's audit log with agent/model attribution when the
client sets CHRONO_AGENT / CHRONO_MODEL.
"""
import json
import os
import sys

from . import __version__
from .interceptor import is_read_only
from .policy import load as load_policy, gate, note_policy_change, PolicyError
from .snapshot import SnapshotStore
from .team import Team

PROTOCOL_VERSION = "2024-11-05"

# What a savepoint and a rollback can and cannot undo. Returned with every run and
# rollback so neither an agent nor a person mistakes the time machine for a
# whole-system restore.
COVERS = ("Savepoints and rollback cover the tracked files in this project folder only. They do NOT undo "
          "system changes (registry, services, scheduled tasks, shadow copies, boot settings, installed "
          "software), files outside this folder or in ignored folders (.git, node_modules, .venv ...), "
          "network calls, or databases not registered with 'chrono db'.")

TOOLS = [
    {"name": "chrono_scan",
     "description": "Advisory risk check of a shell command before running it: the command text plus the scripts, package scripts and make targets it would run in the project folder. Returns score 0-100, level, reasons, and action (allow/approve/block). It does not stop other tools from running the command, and an 'allow' is not proof of safety.",
     "inputSchema": {"type": "object",
                     "properties": {"command": {"type": "string"}},
                     "required": ["command"]}},
    {"name": "chrono_run",
     "description": "ENFORCED execution: scans the command and what it runs (scripts, npm scripts, make targets), physically refuses HIGH/CRITICAL or approval-required commands (nothing runs), otherwise takes a savepoint (skipped for read-only commands such as dir, ls, git status) and runs it in the project folder (timeout, captured output). Use this instead of a raw shell tool so blocks are real, not advisory. Rollback covers project files only, not system changes.",
     "inputSchema": {"type": "object",
                     "properties": {"command": {"type": "string"},
                                    "timeout": {"type": "integer", "minimum": 1, "maximum": 600}},
                     "required": ["command"]}},
    {"name": "chrono_snapshot",
     "description": "Create a savepoint of all tracked project files. Returns the savepoint id.",
     "inputSchema": {"type": "object",
                     "properties": {"message": {"type": "string"}}}},
    {"name": "chrono_status",
     "description": "List files added, deleted or modified since the last savepoint.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "chrono_log",
     "description": "List recent savepoints (id, time, branch, message).",
     "inputSchema": {"type": "object",
                     "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}}}},
    {"name": "chrono_rollback",
     "description": "Restore tracked files to a savepoint. Requires confirm=true. Unsaved changes are first saved to a rescue savepoint, returned as 'redo' (roll back to that id to undo). If the project policy sets gates: mcp.rollback: approve, a named human must first approve the request (chrono approvals approve ID --by NAME) and the call is repeated.",
     "inputSchema": {"type": "object",
                     "properties": {"id": {"type": "string"},
                                    "confirm": {"type": "boolean"}},
                     "required": ["confirm"]}},
    {"name": "chrono_audit_verify",
     "description": "Verify the tamper-evident audit chain (hash links and snapshot anchors).",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _text(payload, is_error=False):
    out = {"content": [{"type": "text", "text": json.dumps(payload, indent=2, ensure_ascii=False)}]}
    if is_error:
        out["isError"] = True
    return out


def _store():
    s = SnapshotStore(".")
    if not s.initialized:
        raise RuntimeError("Not a chrono project in the current directory; run 'chrono init' there first.")
    return s


def apply_retention(store, policy=None):
    """Prune old automatic savepoints when chrono-policy.yaml has a retention section.
    Returns the prune result, or None when no retention is configured."""
    if policy is None:
        policy = load_policy(store.root)
    keep = (policy or {}).get("retention") or {}
    if not keep:
        return None
    return store.prune(keep_auto=keep.get("keep_auto"), older_than_days=keep.get("older_than_days"))


def _savepoints_always():
    return os.environ.get("CHRONO_SAVEPOINTS", "").strip().lower() == "always"


def _run(args):
    import subprocess
    cmd = args.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        raise RuntimeError("chrono_run needs a 'command' string")
    timeout = args.get("timeout", 120)
    timeout = min(max(int(timeout), 1), 600) if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) else 120
    s = _store()
    try:
        note_policy_change(".")
    except OSError:
        pass
    r = gate(cmd, ".")
    base = {"command": cmd, "score": r["score"], "level": r["level"], "reasons": r["reasons"],
            "engine_version": __version__}
    if r["blocked"] or r["action"] != "allow":
        s.audit.record("run.blocked", outcome="blocked", command=cmd, risk_score=r["score"],
                       risk_level=r["level"], detail="via MCP; " + "; ".join(r["reasons"]))
        return {**base, "executed": False, "status": "BLOCKED" if r["blocked"] else "APPROVAL_REQUIRED",
                "directive": "Execution denied by Chrono. Nothing ran. Do not retry with another tool."}
    read_only = is_read_only(cmd, cwd=s.root) and not _savepoints_always()
    sp = None if read_only else s.snapshot("before: " + cmd[:200], kind="auto")
    s.audit.record("run.begin", command=cmd, snapshot=sp["id"] if sp else None, risk_score=r["score"],
                   risk_level=r["level"], detail="via MCP" + ("; read-only, no savepoint needed" if read_only else ""))
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        rc, out, err = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, out, err = -1, e.stdout if isinstance(e.stdout, str) else "", "timed out after %ss" % timeout
    s.audit.record("run.end", outcome="ok" if rc == 0 else "failed", command=cmd,
                   snapshot=sp["id"] if sp else None, detail="exit %s" % rc)
    result = {**base, "executed": True, "exit_code": rc, "stdout": (out or "")[-20000:],
              "stderr": (err or "")[-20000:], "savepoint": sp["id"] if sp else None, "covers": COVERS}
    if sp:
        result["undo"] = "call chrono_rollback with id=%s confirm=true" % sp["id"]
        try:
            pruned = apply_retention(s)
            if pruned and pruned["deleted"]:
                result["retention"] = "pruned %d old automatic savepoint(s)" % len(pruned["deleted"])
        except (RuntimeError, OSError, PolicyError) as e:
            result["retention"] = "not applied: %s" % e
    else:
        result["savepoint_skipped"] = "read-only command: it cannot change files, so no savepoint was needed"
    return result


def call_tool(name, args):
    args = args or {}
    if name == "chrono_scan":
        cmd = args.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            raise RuntimeError("chrono_scan needs a 'command' string")
        load_policy(".")                     # a broken policy file is reported as an error, as before
        result = gate(cmd, ".")
        try:
            note_policy_change(".")
            _store().audit.record("scan", outcome="blocked" if result["blocked"] else "ok",
                                  command=cmd, risk_score=result["score"],
                                  risk_level=result["level"],
                                  detail="; ".join(result["reasons"]))
        except (RuntimeError, OSError):
            pass  # scanning must work even outside an initialised project
        result["engine_version"] = __version__
        if result["blocked"]:
            result["directive"] = ("STRICT ENFORCEMENT: this command is BLOCKED. Do not execute it with "
                                   "any tool. Refuse, or ask a human to review.")
        elif result["action"] == "approve":
            result["directive"] = "Needs a named human approval before running; do not run it automatically."
        return result
    if name == "chrono_run":
        return _run(args)
    s = _store()
    if name == "chrono_snapshot":
        meta = s.snapshot(args.get("message") or "snapshot via MCP", kind="mcp")
        return {"id": meta["id"], "files": len(meta["files"]), "message": meta["message"]}
    if name == "chrono_status":
        st = s.state()
        return {"branch": st["branch"], "head": st["branches"].get(st["branch"]),
                **s.diff(None)}
    if name == "chrono_log":
        limit = args.get("limit", 10)
        limit = min(max(int(limit), 1), 100) if isinstance(limit, int) else 10
        snaps = s.list()[-limit:]
        return [{"id": m["id"], "time": m["time"], "branch": m["branch"],
                 "kind": m["kind"], "message": m["message"],
                 "files": len(m["files"])} for m in reversed(snaps)]
    if name == "chrono_rollback":
        if args.get("confirm") is not True:
            raise RuntimeError("Refused: pass confirm=true to roll back. Unsaved changes will be lost.")
        policy = load_policy(".")
        team = Team(".")
        team.require("rollback", policy)       # same role rule as the CLI
        team.require("mcp.rollback", policy)   # optional stricter rule for AI clients
        target = s.get(args.get("id") or None)
        if (policy or {}).get("gates", {}).get("mcp.rollback") == "approve":
            from .fleet import Fleet
            g = Fleet(".").gate("mcp", {"tool": "chrono_rollback", "snapshot": target["id"]},
                                "MCP rollback to %s (%s)" % (target["id"], target["message"]))
            if g["action"] != "allow":
                s.audit.record("rollback", outcome="pending", detail="awaiting human approval",
                               snapshot=target["id"])
                return {"status": "approval_required", "approval_id": g["approval_id"],
                        "snapshot": target["id"],
                        "next": "A human must run: chrono approvals approve %s --by NAME "
                                "(valid 10 minutes, single use). Then call chrono_rollback again "
                                "with the same id and confirm=true." % g["approval_id"]}
        meta, redo = s.rollback_with_rescue(target["id"])
        s.audit.record("rollback", detail="via MCP client", snapshot=meta["id"], redo=redo)
        return {"restored": meta["id"], "message": meta["message"], "files": len(meta["files"]),
                "redo": redo, "covers": COVERS}
    if name == "chrono_audit_verify":
        v = s.audit.verify()
        bad = s.verify_audit() if v["ok"] else []
        return {"ok": v["ok"] and not bad, "records": v["records"],
                "reason": v["reason"] if not bad else "snapshot anchors do not match the log",
                "broken_at": v["broken_at"],
                "signed_records": v.get("signed", 0),
                "legacy_records": v.get("legacy_unsigned", 0) + v.get("legacy_signed", 0),
                "signing_keys": v.get("keys", []),
                "external_witness": v.get("witness"),
                "snapshot_anchor_problems": [sid for sid, _ in bad[:10]]}
    raise RuntimeError("Unknown tool: " + str(name))


def handle(msg):
    """One JSON-RPC message dict -> response dict, or None for notifications."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32600, "message": "Invalid request"}}
    method = msg.get("method")
    mid = msg.get("id")
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"protocolVersion": PROTOCOL_VERSION,
                           "capabilities": {"tools": {}},
                           "serverInfo": {"name": "chrono-agent", "version": __version__}}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        try:
            result = call_tool(params.get("name"), params.get("arguments"))
            return {"jsonrpc": "2.0", "id": mid, "result": _text(result)}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": mid, "result": _text({"error": str(e)}, is_error=True)}
    if mid is None:
        return None
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": -32601, "message": "Method not found: " + str(method)}}


def serve(stdin=None, stdout=None):
    """Read newline-delimited JSON-RPC from stdin, write replies to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.lstrip("﻿").strip()     # some Windows shells prepend a byte-order mark
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": "Parse error"}}
        else:
            reply = handle(msg)
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            stdout.flush()
