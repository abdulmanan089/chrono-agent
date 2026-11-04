"""MCP connector: expose Chrono to AI clients (Claude Desktop, Cursor, etc.)
as a Model Context Protocol server over stdio — newline-delimited JSON-RPC 2.0.

Config snippet for an MCP client:
    { "mcpServers": { "chrono": { "command": "chrono", "args": ["mcp"] } } }

The server acts on the project in the client's working directory. Destructive
tools (rollback) need an explicit {"confirm": true}. Everything the tools do
is recorded in the project's audit log with agent/model attribution when the
client sets CHRONO_AGENT / CHRONO_MODEL.
"""
import json
import sys

from . import __version__
from .interceptor import assess
from .policy import load as load_policy, evaluate
from .snapshot import SnapshotStore

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {"name": "chrono_scan",
     "description": "Blast-radius risk check for a shell command before running it. Returns score 0-100, level, reasons, and action (allow/approve/block).",
     "inputSchema": {"type": "object",
                     "properties": {"command": {"type": "string"}},
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
     "description": "Restore tracked files to a savepoint. DESTRUCTIVE to unsaved changes: requires confirm=true and ideally a prior chrono_snapshot.",
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


def call_tool(name, args):
    args = args or {}
    if name == "chrono_scan":
        cmd = args.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            raise RuntimeError("chrono_scan needs a 'command' string")
        result = evaluate(cmd, load_policy("."))
        try:
            _store().audit.record("scan", outcome="blocked" if result["blocked"] else "ok",
                                  command=cmd, risk_score=result["score"],
                                  risk_level=result["level"],
                                  detail="; ".join(result["reasons"]))
        except RuntimeError:
            pass  # scanning must work even outside an initialised project
        return result
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
        target = args.get("id")
        meta = s.restore(target or None)
        s.audit.record("rollback", detail="via MCP client", snapshot=meta["id"])
        return {"restored": meta["id"], "message": meta["message"], "files": len(meta["files"])}
    if name == "chrono_audit_verify":
        v = s.audit.verify()
        bad = s.verify_audit() if v["ok"] else []
        return {"ok": v["ok"] and not bad, "records": v["records"],
                "reason": v["reason"] if v["ok"] else v["reason"],
                "broken_at": v["broken_at"],
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
        line = line.strip()
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
