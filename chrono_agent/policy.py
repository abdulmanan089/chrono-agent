"""Project policy file: custom command rules, risk thresholds, approvers and
role requirements, declared in chrono-policy.yaml at the project root.

The parser intentionally supports only the small YAML subset shown below so the
package stays dependency-free; anything else raises PolicyError. A file written
as JSON also loads (JSON is a YAML subset, but here it goes through the same
mini-parser only if it follows the line format — so prefer the YAML form).

    thresholds:
      block: 70
      approve: 40
    approvers:
      - manan
      - sara
    roles:
      rollback: admin
      run.force: admin
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
"""
import re
from pathlib import Path

from .interceptor import assess as _builtin_assess

FILE_NAME = "chrono-policy.yaml"
RULE_ACTIONS = ("block", "approve", "allow")
RULE_KEYS = ("name", "pattern", "score", "action", "reason")
THRESHOLD_KEYS = ("block", "approve")
DEFAULT_BLOCK = 70
DEFAULT_APPROVE = 10**9  # approval off unless a policy lowers the band


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
              "approvers": [], "roles": {}, "rules": []}
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
            if section not in ("thresholds", "approvers", "roles", "rules"):
                raise PolicyError("line %d: unknown section %r" % (lineno, body))
            current_rule = None
            continue
        if section == "rules" and body.startswith("- "):
            current_rule = {}
            policy["rules"].append(current_rule)
            body = body[2:].strip()
            if not body:
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
        elif section == "roles":
            if not isinstance(value, str) or value not in ("viewer", "developer", "admin"):
                raise PolicyError("line %d: role must be viewer, developer or admin" % lineno)
            if not re.fullmatch(r"[a-z][a-z0-9._-]{0,39}", key):
                raise PolicyError("line %d: bad action name" % lineno)
            policy["roles"][key] = value
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


def evaluate(cmd, policy=None):
    """Built-in scan plus policy rules. Adds 'action': allow | approve | block."""
    result = _builtin_assess(cmd)
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
    if action is None:
        action = "block" if score >= block_at else "approve" if score >= approve_at else "allow"
    return {"score": score, "level": result["level"], "reasons": reasons,
            "blocked": action == "block", "action": action,
            "policy": policy is not None}
