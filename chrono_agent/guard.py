# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Chrono guard: a PreToolUse hook for Claude Code and compatible AI clients.

MCP ``chrono_run`` only protects the commands an agent chooses to send to it.
An agent that also has its client's own shell tool (Bash, PowerShell) could run
anything around Chrono. The guard closes that gap. The client calls
``python -m chrono_agent guard hook`` before every shell command and file edit,
passing the tool call as JSON on stdin, and Chrono decides with the same rules
as ``chrono_run`` (command text, the scripts it runs, the policy and its pin):

* block   - exit code 2: the client refuses the tool call and shows the reason
            to the agent. Nothing runs.
* approve - ``permissionDecision: ask``: the person at the keyboard must confirm.
* allow   - in a Chrono project a savepoint is taken first (not for read-only
            commands), then the client's normal permission rules apply. The
            guard never auto-approves anything.

File-editing tools (Write, Edit, MultiEdit, NotebookEdit) are refused when they
target Chrono's own control files: the ``.chrono`` folder, ``chrono-policy.yaml``,
the client's ``.claude/settings*.json`` and the Chrono home with its keys.

Any error inside the guard blocks the call (fail closed). One case cannot be
handled here: if Python or the chrono_agent package is removed, the client
cannot start the hook at all. Run ``chrono guard status`` after upgrades.
"""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

from .audit import chrono_home
from .interceptor import is_read_only
from .policy import gate, note_policy_change, PolicyError
from .snapshot import SnapshotStore

SHELL_TOOLS = ("Bash", "PowerShell")
EDIT_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
MATCHER = "|".join(SHELL_TOOLS + EDIT_TOOLS)
MARKER = "chrono_agent guard hook"
MAX_INPUT = 4 * 1024 * 1024
PROTECTED_NAMES = {"chrono-policy.yaml"}


def _project(start):
    """The nearest folder at or above `start` that is a Chrono project, or None."""
    p = Path(start).resolve()
    for candidate in [p] + list(p.parents)[:30]:
        if (candidate / ".chrono" / "state.json").is_file():
            return candidate
    return None


def _protected(path, cwd):
    """Why `path` is one of Chrono's control files, or None."""
    p = Path(path)
    if not p.is_absolute():
        p = Path(cwd) / p
    try:
        p = p.resolve()
    except OSError:
        return "path could not be resolved"
    parts = [x.lower() for x in p.parts] if os.name == "nt" else list(p.parts)
    if ".chrono" in parts:
        return "the .chrono folder holds Chrono's savepoints and audit log"
    if (p.name.lower() if os.name == "nt" else p.name) in PROTECTED_NAMES:
        return "chrono-policy.yaml holds the rules that govern this agent"
    if len(parts) >= 2 and parts[-2] == ".claude" and parts[-1] in ("settings.json", "settings.local.json"):
        return "the client settings hold the Chrono guard itself"
    home = chrono_home()
    try:
        p.relative_to(home.resolve())
        return "the Chrono home holds the audit signing keys and witnesses"
    except ValueError:
        pass
    return None


def _agent():
    return os.environ.get("CHRONO_AGENT") or "claude-code"


def decide(event):
    """(exit_code, stdout_text, stderr_text) for one hook event."""
    if not isinstance(event, dict):
        raise ValueError("hook input must be a JSON object")
    tool = str(event.get("tool_name") or "")
    tool_input = event.get("tool_input") if isinstance(event.get("tool_input"), dict) else {}
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) and event.get("cwd") else os.getcwd()
    if not Path(cwd).is_dir():
        raise ValueError("working folder does not exist: %s" % cwd)
    root = _project(cwd)
    store = SnapshotStore(root) if root else None

    if tool in EDIT_TOOLS:
        target = tool_input.get("file_path") or tool_input.get("notebook_path") or tool_input.get("path")
        if not isinstance(target, str) or not target:
            return 0, "", ""
        why = _protected(target, cwd)
        if why is None:
            return 0, "", ""
        if store:
            store.audit.record("guard.blocked", outcome="blocked", command="%s %s" % (tool, target),
                               risk_score=95, risk_level="CRITICAL", agent=_agent(),
                               detail="edit of a Chrono control file refused: " + why)
        return 2, "", ("Chrono guard refused this %s: %s, and an agent may not change it. "
                       "Ask the person to make this change themselves." % (tool, why))

    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return 0, "", ""                      # not a shell command: nothing to judge
    policy_root = root or Path(cwd)
    if store:
        try:
            note_policy_change(root)
        except OSError:
            pass
    r = gate(command, str(policy_root))
    if r["action"] == "allow" and str(Path(cwd).resolve()) != str(Path(policy_root).resolve()):
        nested = gate(command, cwd)           # scripts are resolved where the command really runs
        if nested["blocked"] or nested["action"] != "allow":
            r = nested
    reasons = "; ".join(r["reasons"])
    if r["blocked"] or r["action"] == "block":
        if store:
            store.audit.record("guard.blocked", outcome="blocked", command=command, risk_score=r["score"],
                               risk_level=r["level"], agent=_agent(), detail="%s tool; %s" % (tool, reasons))
        return 2, "", ("Chrono blocked this command (risk %d/100, %s): %s. Nothing ran. Do not retry it "
                       "another way; explain to the person what you wanted to do." % (r["score"], r["level"], reasons))
    if r["action"] == "approve":
        if store:
            store.audit.record("guard.ask", outcome="approval requested", command=command, risk_score=r["score"],
                               risk_level=r["level"], agent=_agent(), detail="%s tool; %s" % (tool, reasons))
        out = {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "ask",
            "permissionDecisionReason": "Chrono: a person must approve this command (risk %d/100): %s"
                                        % (r["score"], reasons)}}
        return 0, json.dumps(out), ""
    sp = None
    if store and not (is_read_only(command, cwd=cwd) and os.environ.get("CHRONO_SAVEPOINTS", "") != "always"):
        sp = store.snapshot("before %s: %s" % (tool, command[:180]), kind="auto")
        try:
            from .mcp_server import apply_retention
            apply_retention(store)
        except (RuntimeError, OSError, PolicyError):
            pass
    if store:
        store.audit.record("guard.allowed", command=command, risk_score=r["score"], risk_level=r["level"],
                           snapshot=sp["id"] if sp else None, agent=_agent(),
                           detail="%s tool%s" % (tool, "" if sp else "; read-only, no savepoint needed"))
    return 0, "", ""


def hook_main(stdin=None, stdout=None, stderr=None):
    """Entry point for `chrono guard hook`. Returns the process exit code."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        source = getattr(stdin, "buffer", None)
        if source is not None:                   # the client sends UTF-8 whatever the console code page is
            raw = source.read(MAX_INPUT + 1).decode("utf-8", errors="replace")
        else:
            raw = stdin.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError("hook input larger than 4 MB")
        code, out, err = decide(json.loads(raw))
    except Exception as e:                       # fail closed: an error never lets a command through
        code, out, err = 2, "", "Chrono guard could not check this call, so it was blocked: %s" % e
    if out:
        stdout.write(out)
        stdout.flush()
    if err:
        stderr.write(err + "\n")
        stderr.flush()
    return code


# ------------------------------------------------------------- install
def settings_path(root=".", scope="project"):
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    if scope == "project":
        return Path(root).resolve() / ".claude" / "settings.json"
    raise RuntimeError("scope must be project or user")


def hook_command(python=None):
    exe = python or sys.executable
    quoted = '"%s"' % exe if os.name == "nt" else shlex.quote(exe)
    return "%s -m chrono_agent guard hook" % quoted


def _read_settings(path):
    if not path.is_file():
        return {}
    if path.is_symlink():
        raise RuntimeError("Refusing to edit a symlinked settings file: %s" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except ValueError as e:
        raise RuntimeError("%s is not valid JSON; fix it first (nothing was changed): %s" % (path, e))
    if not isinstance(data, dict):
        raise RuntimeError("%s must hold a JSON object" % path)
    return data


def _write_settings(path, data):
    from .snapshot import _atomic
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic(path, (json.dumps(data, indent=2) + "\n").encode("utf-8"))


def _ours(entry):
    return isinstance(entry, dict) and any(
        isinstance(h, dict) and MARKER in str(h.get("command", "")) for h in entry.get("hooks", []) or [])


def install(root=".", scope="project", deny_raw_shell=False, python=None):
    """Add (or refresh) the guard hook in the client settings. Returns
    (settings_path, created). Existing settings and hooks are kept."""
    path = settings_path(root, scope)
    data = _read_settings(path)
    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise RuntimeError("'hooks' in %s is not an object; nothing was changed" % path)
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        raise RuntimeError("'hooks.PreToolUse' in %s is not a list; nothing was changed" % path)
    entry = {"matcher": MATCHER,
             "hooks": [{"type": "command", "command": hook_command(python), "timeout": 120}]}
    created = not any(_ours(e) for e in pre)
    pre[:] = [e for e in pre if not _ours(e)] + [entry]
    if deny_raw_shell:
        perms = data.setdefault("permissions", {})
        if not isinstance(perms, dict):
            raise RuntimeError("'permissions' in %s is not an object; nothing was changed" % path)
        deny = perms.setdefault("deny", [])
        for tool in SHELL_TOOLS:
            if tool not in deny:
                deny.append(tool)
    _write_settings(path, data)
    return path, created


def uninstall(root=".", scope="project"):
    """Remove only the hook entries Chrono added. Permission rules stay."""
    path = settings_path(root, scope)
    data = _read_settings(path)
    pre = (data.get("hooks") or {}).get("PreToolUse")
    if not isinstance(pre, list) or not any(_ours(e) for e in pre):
        return path, False
    pre[:] = [e for e in pre if not _ours(e)]
    if not pre:
        del data["hooks"]["PreToolUse"]
        if not data["hooks"]:
            del data["hooks"]
    _write_settings(path, data)
    return path, True


def self_test(root=".", python=None):
    """Run the installed hook command on a harmless and a dangerous sample.
    Returns (ok, detail). Uses a temporary folder, never the project."""
    import tempfile
    cmd = hook_command(python)
    with tempfile.TemporaryDirectory() as tmp:
        def run(command):
            event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": tmp,
                                "tool_input": {"command": command}})
            p = subprocess.run(cmd, shell=True, input=event, capture_output=True, text=True, timeout=60, cwd=tmp)
            return p.returncode, (p.stderr or "").strip()
        safe = run("echo chrono-guard-self-test")
        danger = run("rm -rf /")
    ok = safe[0] == 0 and danger[0] == 2
    detail = "harmless sample -> exit %d, dangerous sample -> exit %d" % (safe[0], danger[0])
    if not ok:
        detail += " (%s)" % (danger[1] or safe[1])[:300]
    return ok, detail


def status(root=".", scope="project"):
    path = settings_path(root, scope)
    try:
        data = _read_settings(path)
    except RuntimeError as e:
        return {"path": str(path), "installed": False, "error": str(e)}
    pre = (data.get("hooks") or {}).get("PreToolUse") or []
    ours = [e for e in pre if _ours(e)] if isinstance(pre, list) else []
    deny = ((data.get("permissions") or {}).get("deny") or []) if isinstance(data.get("permissions"), dict) else []
    return {"path": str(path), "installed": bool(ours),
            "matcher": ours[0].get("matcher") if ours else None,
            "command": ours[0]["hooks"][0].get("command") if ours else None,
            "raw_shell_denied": all(t in deny for t in SHELL_TOOLS)}
