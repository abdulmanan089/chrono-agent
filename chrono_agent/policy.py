# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Project policy file: custom command rules, risk thresholds, approvers and
role requirements, declared in chrono-policy.yaml at the project root.

The parser intentionally supports only the small YAML subset shown below so the
package stays dependency-free; anything else raises PolicyError. A file written
as JSON also loads (JSON is a YAML subset, but here it goes through the same
mini-parser only if it follows the line format — so prefer the YAML form).

    thresholds:
      block: 70
      approve: 40
    gates:
      mcp.rollback: approve   # a named human must approve MCP rollbacks
    allow:                    # exact commands that skip the built-in scan
      - rm -rf node_modules
      - rm -rf dist/*         # * never matches a slash, space or shell operator
      - reg add HKCU\\Software\\MyCompany\\MyApp /v * /d * /f
    approvers:
      - manan
      - sara
    roles:
      rollback: admin
      run.force: admin
    retention:                # automatic savepoints (kind auto/rescue) to keep
      keep_auto: 500
      older_than_days: 30
    rules:
      - name: no-force-push
        pattern: "git push.*--force"
        score: 85
        action: block
        reason: "force push rewrites shared history"
      - name: migrate-prod
        pattern: "alembic upgrade"
        score: 50
        action: approve
        reason: "schema change needs a named human"

Since 0.5.0 a person can *pin* the policy (``chrono policy pin``). Chrono then
stores the file's fingerprint in the user's Chrono home, outside the project.
If the file is edited afterwards, every enforcing path (MCP ``chrono_run``, the
guard hook, ``chrono run``) blocks all commands until a person reviews the
change and pins it again. Every change Chrono notices is also written to the
audit log as ``policy.changed``.
"""
import hashlib
import hmac
import json
import re
import time
from pathlib import Path

from .audit import KeyRing, chrono_home, project_id, write_private, _private_dir
from .interceptor import assess as _builtin_assess, level_for

FILE_NAME = "chrono-policy.yaml"
RULE_ACTIONS = ("block", "approve", "allow")
RULE_KEYS = ("name", "pattern", "score", "action", "reason")
THRESHOLD_KEYS = ("block", "approve")
RETENTION_KEYS = ("keep_auto", "older_than_days")
SECTIONS = ("thresholds", "approvers", "roles", "rules", "gates", "allow", "retention")
DEFAULT_BLOCK = 70
DEFAULT_APPROVE = 10**9  # approval off unless a policy lowers the band
NO_PATTERN = "No dangerous pattern detected; program behavior is not inspected"


class PolicyError(RuntimeError):
    pass


def _scalar(text, lineno):
    text = text.strip()
    if not text:
        raise PolicyError("line %d: empty value" % lineno)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if text in ("true", "false"):
        return text == "true"
    if any(ch in text for ch in "#{}[]"):
        raise PolicyError("line %d: quote this value" % lineno)
    return text


def load(root="."):
    """Parsed policy dict, or None when the project has no policy file."""
    path = Path(root).resolve() / FILE_NAME
    if not path.is_file():
        return None
    if path.is_symlink():
        raise PolicyError("Policy file must not be a symlink")
    policy = {"thresholds": {"block": DEFAULT_BLOCK, "approve": DEFAULT_APPROVE},
              "approvers": [], "roles": {}, "rules": [], "gates": {}, "allow": [], "retention": {}}
    section = None
    current_rule = None
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split(" #", 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if indent == 0:
            section = body[:-1] if body.endswith(":") else None
            if section not in SECTIONS:
                raise PolicyError("line %d: unknown section %r" % (lineno, body))
            current_rule = None
            continue
        if section == "rules" and body.startswith("- "):
            current_rule = {}
            policy["rules"].append(current_rule)
            body = body[2:].strip()
            if not body:
                continue
        if section == "allow":
            if not body.startswith("- "):
                raise PolicyError("line %d: allow is a simple list" % lineno)
            entry = _scalar(body[2:], lineno)
            if (not isinstance(entry, str) or not 1 <= len(entry) <= 200 or "**" in entry
                    or re.search(r"[;&|<>`$()\n\r]", entry) or entry.endswith("\\")):
                raise PolicyError("line %d: allow entries are one plain command (no ; & | < > ` $ ( ) "
                                  "and no trailing backslash)" % lineno)
            policy["allow"].append(entry)
            continue
        if section == "approvers":
            if not body.startswith("- "):
                raise PolicyError("line %d: approvers are a simple list" % lineno)
            name = _scalar(body[2:], lineno)
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", name):
                raise PolicyError("line %d: bad approver name" % lineno)
            policy["approvers"].append(name)
            continue
        if ":" not in body:
            raise PolicyError("line %d: expected 'key: value'" % lineno)
        key, _, value = body.partition(":")
        key = key.strip()
        value = _scalar(value, lineno)
        if section == "thresholds":
            if key not in THRESHOLD_KEYS or not isinstance(value, int) or not 0 <= value <= 100:
                raise PolicyError("line %d: thresholds are block/approve, 0-100" % lineno)
            policy["thresholds"][key] = value
        elif section == "retention":
            if key not in RETENTION_KEYS or isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PolicyError("line %d: retention keys are keep_auto / older_than_days, 0 or more" % lineno)
            policy["retention"][key] = value
        elif section == "roles":
            if not isinstance(value, str) or value not in ("viewer", "developer", "admin"):
                raise PolicyError("line %d: role must be viewer, developer or admin" % lineno)
            if not re.fullmatch(r"[a-z][a-z0-9._-]{0,39}", key):
                raise PolicyError("line %d: bad action name" % lineno)
            policy["roles"][key] = value
        elif section == "gates":
            if value not in ("approve", "allow") or not re.fullmatch(r"[a-z][a-z0-9._-]{0,39}", key):
                raise PolicyError("line %d: gates are 'name: approve' or 'name: allow'" % lineno)
            policy["gates"][key] = value
        elif section == "rules":
            if current_rule is None:
                raise PolicyError("line %d: rule entries start with '- name: ...'" % lineno)
            if key not in RULE_KEYS:
                raise PolicyError("line %d: unknown rule key %r" % (lineno, key))
            current_rule[key] = value
        else:
            raise PolicyError("line %d: value outside a section" % lineno)
    for i, rule in enumerate(policy["rules"], 1):
        missing = [k for k in ("name", "pattern", "score") if k not in rule]
        if missing:
            raise PolicyError("rule %d: missing %s" % (i, ", ".join(missing)))
        if not isinstance(rule["score"], int) or not 0 <= rule["score"] <= 100:
            raise PolicyError("rule %r: score must be 0-100" % rule["name"])
        try:
            re.compile(str(rule["pattern"]))
        except re.error as e:
            raise PolicyError("rule %r: bad pattern: %s" % (rule["name"], e))
        rule.setdefault("action", "block" if rule["score"] >= policy["thresholds"]["block"] else "approve")
        if rule["action"] not in RULE_ACTIONS:
            raise PolicyError("rule %r: action must be block, approve or allow" % rule["name"])
        rule.setdefault("reason", str(rule["name"]))
    if (policy["thresholds"]["approve"] != DEFAULT_APPROVE
            and policy["thresholds"]["approve"] > policy["thresholds"]["block"]):
        raise PolicyError("approve threshold must not exceed block threshold")
    return policy


def _allowed(cmd, policy):
    """The allow-list entry that matches the WHOLE command, or None. '*' matches
    letters, digits and . _ - @ % + = : , only: never a space, slash, backslash or
    operator, so 'rm -rf node_modules; rm -rf /' and 'rm -rf node_modules/../..'
    do not match."""
    text = cmd.strip()
    for entry in policy.get("allow", []):
        rx = "".join(r"[\w.@%+=:,-]*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", entry))
        if re.fullmatch(rx, text):
            return entry
    return None


def evaluate(cmd, policy=None, root=None):
    """Built-in scan plus policy rules. Adds 'action': allow | approve | block.
    With `root`, the scan also reads the scripts the command will run there."""
    allowed = _allowed(cmd, policy) if policy else None
    if allowed:
        result = {"score": 5, "level": "LOW", "blocked": False,
                  "reasons": ["Allow-listed by policy: " + allowed]}
    else:
        result = _builtin_assess(cmd, cwd=root)
    reasons = list(result["reasons"])
    score = result["score"]
    action = None
    block_at, approve_at = DEFAULT_BLOCK, DEFAULT_APPROVE
    if policy:
        block_at = policy["thresholds"]["block"]
        approve_at = policy["thresholds"]["approve"]
        for rule in policy["rules"]:
            if re.search(str(rule["pattern"]), cmd, re.I):
                score = max(score, rule["score"])
                reasons.append("%s (policy: %s)" % (rule["reason"], rule["name"]))
                if rule["action"] == "block":
                    action = "block"
                elif rule["action"] == "approve" and action != "block":
                    action = "approve"
    if len(reasons) > 1 and NO_PATTERN in reasons:
        reasons.remove(NO_PATTERN)
    if action is None:
        action = "block" if score >= block_at else "approve" if score >= approve_at else "allow"
    out = {"score": score, "level": level_for(score), "reasons": reasons,
           "blocked": action == "block", "action": action,
           "policy": policy is not None}
    if allowed:
        out["allowlisted"] = allowed
    return out


# ------------------------------------------------------------- fingerprint and pin
def fingerprint(root="."):
    """SHA-256 of chrono-policy.yaml, or 'none' when the project has no policy."""
    path = Path(root).resolve() / FILE_NAME
    if path.is_symlink():
        raise PolicyError("Policy file must not be a symlink")
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return "none"


def _pin_path(root):
    return chrono_home() / "pins" / (project_id(root) + ".json")


def _pin_body(root, fp):
    return json.dumps({"root": str(Path(root).resolve()), "fingerprint": fp},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def pin(root="."):
    """Record the current policy as reviewed by a person. Returns its fingerprint."""
    load(root)                                    # never pin a file that does not parse
    fp = fingerprint(root)
    kid, key = KeyRing().active()
    data = {"root": str(Path(root).resolve()), "fingerprint": fp, "t": time.time()}
    if key is not None:
        data["kid"] = kid
        data["mac"] = hmac.new(key, _pin_body(root, fp), hashlib.sha256).hexdigest()
    path = _pin_path(root)
    _private_dir(path.parent)
    write_private(path, json.dumps(data, indent=2, sort_keys=True).encode("utf-8"))
    return fp


def unpin(root="."):
    path = _pin_path(root)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def pin_state(root="."):
    """None (not pinned), 'ok' (unchanged since the pin) or 'changed'."""
    path = _pin_path(root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return "changed"                          # an unreadable pin fails closed
    if not isinstance(data, dict):
        return "changed"
    try:
        fp = fingerprint(root)
    except PolicyError:
        return "changed"
    if data.get("mac") is not None:
        key = KeyRing().get(data.get("kid"))
        expected = hmac.new(key, _pin_body(root, data.get("fingerprint")), hashlib.sha256).hexdigest() if key else None
        if expected is None or not hmac.compare_digest(expected, str(data["mac"])):
            return "changed"
    return "ok" if fp == data.get("fingerprint") else "changed"


def gate(cmd, root="."):
    """The decision for paths that really execute commands (MCP chrono_run, the
    guard hook, chrono run): built-in scan including what the command will run,
    the policy, and the policy pin. A broken or unpinned-after-change policy
    blocks everything (fail closed)."""
    try:
        policy = load(root)
    except PolicyError as e:
        return {"score": 100, "level": "CRITICAL", "blocked": True, "action": "block", "policy": True,
                "reasons": ["%s is invalid, so nothing may run until it is fixed: %s" % (FILE_NAME, e)],
                "pin": None}
    r = evaluate(cmd, policy, root=root)
    state = pin_state(root)
    r["pin"] = state
    if state == "changed":
        r["reasons"] = ["%s changed since a person pinned it; review the change, then run: chrono policy pin"
                        % FILE_NAME] + [x for x in r["reasons"] if x != NO_PATTERN]
        r["score"] = max(r["score"], 90)
        r["level"] = level_for(r["score"])
        r["blocked"], r["action"] = True, "block"
    return r


def note_policy_change(root="."):
    """Write a policy.changed audit record when chrono-policy.yaml differs from
    the version Chrono last saw in this project. Returns the new fingerprint, or
    None when nothing changed (or the project is not initialised)."""
    from .audit import AuditLog
    log = AuditLog(root)
    if not log.enabled:
        return None
    try:
        fp = fingerprint(root)
    except PolicyError:
        fp = "unreadable"
    seen = log.dir / "policy.seen"
    try:
        old = seen.read_text(encoding="ascii").strip() or None
    except (OSError, UnicodeDecodeError):
        old = None
    if old == fp:
        return None
    if old is not None or fp != "none":
        log.record("policy.changed", outcome="changed" if old else "first-seen",
                   detail="%s fingerprint %s -> %s" % (FILE_NAME, (old or "unknown")[:16], fp[:16]))
    write_private(seen, fp.encode("ascii"))
    return fp
