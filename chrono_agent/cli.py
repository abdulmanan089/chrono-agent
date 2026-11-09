# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
import argparse, difflib, json, os, shlex, subprocess, sys, tempfile, time
from datetime import datetime
from pathlib import Path
from .snapshot import SnapshotStore
from .audit import AuditLog, KeyRing, chrono_home
from .interceptor import assess
from .policy import (load as load_policy, evaluate, gate, note_policy_change, pin as pin_policy,
                     unpin as unpin_policy, pin_state, PolicyError, FILE_NAME as POLICY_FILE)
from .team import Team
from . import gitlink, db as dbmod, remote_audit, dashboard as dashmod
from . import __version__

for _s in (sys.stdout, sys.stderr):
    try: _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception: pass
if os.name == "nt":
    os.system("")  # enable ANSI colours in Windows CMD
NOCOL = not sys.stdout.isatty() or os.environ.get("NO_COLOR")
def c(t, code): return t if NOCOL else f"\033[{code}m{t}\033[0m"
G = lambda t: c(t, "32"); R = lambda t: c(t, "31"); Y = lambda t: c(t, "33"); B = lambda t: c(t, "36"); D = lambda t: c(t, "2")

def ask(prompt, choices, eof=None):
    while True:
        try:
            a = input(prompt).strip().lower()
        except EOFError:
            return eof if eof is not None else choices[-1]
        if a in choices:
            return a
        print(Y(f"  choose one of: {', '.join(choices)}"))

def store():
    s = SnapshotStore(".")
    if not s.initialized:
        print(R("✗ Not a chrono project here.") + " Run " + B("chrono init") + " first.")
        sys.exit(1)
    return s

def show_diff(s, sid):
    d = s.diff(sid)
    if not any(d.values()):
        print(D("  (no changes)")); return
    for f in d["added"]: print(G(f"  + {f}"))
    for f in d["deleted"]: print(R(f"  - {f}"))
    for f in d["modified"]:
        print(Y(f"  ~ {f}"))
        try:
            old = s.read_old(sid, f).splitlines(); new = s._path(f).read_text(encoding="utf-8", errors="replace").splitlines()
            for line in list(difflib.unified_diff(old, new, lineterm="", n=1))[2:40]:
                print("    " + (G(line) if line.startswith("+") else R(line) if line.startswith("-") else D(line)))
        except Exception:
            print(D("    (binary file)"))

# ---------------- commands ----------------
def cmd_init(a):
    s = SnapshotStore(".")
    if s.initialized:
        print("Already initialized; no new snapshot created"); return
    s.init(); m = s.snapshot("initial snapshot", kind="init")
    s.audit.record("init", detail=str(s.root), files=len(m["files"]))
    print(G("✓ chrono initialised") + f" in {s.root}"); print(f"  {B(m['id'])}  {len(m['files'])} files  ({m['ms']} ms)")

def cmd_snapshot(a):
    s = store()
    m = s.snapshot(a.message or "manual snapshot")
    print(G("✓ SAVEPOINT ") + B(m["id"]) + f"  {len(m['files'])} files  ({m['ms']} ms)  \"{m['message']}\"")
    skipped = getattr(s, "skipped", [])
    if skipped:
        shown = ", ".join(skipped[:3]) + (" ..." if len(skipped) > 3 else "")
        print(Y(f"  ! {len(skipped)} item(s) not tracked (symlinks/special files are never followed or restored): {shown}"))

def cmd_log(a):
    s = store(); head = s.state()["branches"].get(s.state()["branch"])
    for m in reversed(s.list()):
        t = datetime.fromtimestamp(m["time"]).strftime("%Y-%m-%d %H:%M:%S")
        mark = G(" ← HEAD") if m["id"] == head else ""
        print(f"{B(m['id'])}  {D(t)}  [{m['branch']}]  {m['message']}{mark}")

def cmd_status(a):
    s = store(); st = s.state()
    print(f"branch: {G(st['branch'])}   head: {B(str(st['branches'].get(st['branch'])))}")
    show_diff(s, None)

def cmd_diff(a):
    show_diff(store(), a.id)

def cmd_rollback(a):
    s = store()
    Team(".").require("rollback", load_policy("."))
    target = a.id or s.state()["branches"].get(s.state()["branch"])
    if not a.yes and ask(Y(f"Restore working tree to {target}? Unsaved changes are saved to a rescue savepoint first. [y/n] "), ["y", "n"]) != "y":
        s.audit.record("rollback", outcome="aborted", detail="user declined", snapshot=str(target))
        print("aborted"); return
    m, redo = s.rollback_with_rescue(target)
    s.audit.record("rollback", detail="confirmed by user", snapshot=m["id"], redo=redo)
    print(G("✓ ROLLBACK TO ") + B(m["id"]) + f"  \"{m['message']}\"")
    if redo and redo != m["id"]:
        print(f"  undo this rollback: chrono rollback {redo}")

def cmd_scan(a):
    try:
        policy = load_policy(".")
    except PolicyError as e:
        raise RuntimeError(f"{POLICY_FILE}: {e}") from e
    try:
        note_policy_change(".")
    except OSError:
        pass
    r = gate(a.command, ".")          # text + the scripts it runs + policy + policy pin
    col = R if r["action"] == "block" else Y if r["action"] == "approve" or r["score"] >= 30 else G
    bar = "█" * (r["score"] // 5) + "░" * (20 - r["score"] // 5)
    print(f"Blast radius: {col(bar)} {col(str(r['score']) + '/100 ' + r['level'])}  action: {col(r['action'])}")
    for why in r["reasons"]: print(f"  • {why}")
    if policy: print(D(f"  (policy: {POLICY_FILE}" + (", pinned" if r.get("pin") == "ok" else "") + ")"))
    AuditLog(".").record("scan", outcome=r["action"], command=a.command,
                         risk_score=r["score"], risk_level=r["level"],
                         detail="; ".join(r["reasons"]))
    return r

def command_args(a):
    args = list(a.command)
    if args and args[0] == "--":
        args.pop(0)
    if not args:
        raise RuntimeError("Provide a program: chrono run python agent.py")
    if a.shell:
        if len(args) != 1:
            raise RuntimeError("Shell mode requires one quoted command string")
        return args[0], args[0]
    if os.name == "nt" and Path(args[0]).suffix.lower() in (".bat", ".cmd"):
        raise RuntimeError("Batch files require explicit --shell mode")
    display = subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)
    return args, display


def cmd_run(a):
    command, display = command_args(a)
    s = store()
    r = cmd_scan(argparse.Namespace(command=display))
    print(D("Advisory scan only: this is NOT a sandbox; use trusted programs in a test folder."))
    if a.force:
        Team(".").require("run.force", load_policy("."))
    if r["blocked"] and not a.force:
        s.audit.record("run.blocked", outcome="blocked", command=display,
                       risk_score=r["score"], risk_level=r["level"],
                       detail="; ".join(r["reasons"]))
        print(R("✗ BLOCKED by interceptor. Nothing executed."))
        raise SystemExit(2)
    if r["action"] == "approve":
        approver, reason = a.approver, a.approval_reason
        if approver is None:
            print(Y("Policy requires a named human approval for this command."))
            try:
                approver = input("  approver name > ").strip()
                reason = reason or input("  reason > ").strip()
            except EOFError:
                approver = ""
        known = (load_policy(".") or {}).get("approvers", [])
        if not approver or (known and approver not in known):
            s.audit.record("run.approval", outcome="denied", command=display,
                           detail="unknown or missing approver: %r" % (approver or ""))
            print(R("✗ Approval denied: approver is empty or not listed in " + POLICY_FILE))
            raise SystemExit(3)
        s.audit.record("run.approved", outcome="approved", command=display,
                       detail="approved by %s: %s" % (approver, reason or "no reason given"),
                       risk_score=r["score"], risk_level=r["level"])
        print(G("✓ approved by " + approver))
    with s.locked():
        sp = s.snapshot("before: " + display, kind="auto")
        s.audit.record("run.begin", command=display, snapshot=sp["id"],
                       risk_score=r["score"], risk_level=r["level"])
        print(D(f"BEGIN; SAVEPOINT {sp['id']}  ({sp['ms']} ms)"))
        while True:
            try:
                rc = subprocess.call(command, shell=a.shell)
            except KeyboardInterrupt:
                s.restore(sp["id"])
                s.audit.record("run.interrupted", outcome="rolled back", command=display,
                               snapshot=sp["id"])
                print(Y("Interrupted; tracked files rolled back. Verify any external child effects separately."))
                raise SystemExit(130)
            except OSError as error:
                s.restore(sp["id"])
                s.audit.record("run.start_failed", outcome="rolled back", command=display,
                               snapshot=sp["id"], detail=str(error))
                raise RuntimeError("Program could not start; tracked files restored: " + str(error)) from error
            if rc == 0:
                try:
                    committed = s.snapshot("COMMIT: " + display, kind="commit")
                except Exception as error:
                    s.restore(sp["id"])
                    s.audit.record("run.commit_failed", outcome="rolled back", command=display,
                                   snapshot=sp["id"], detail=str(error))
                    raise RuntimeError("Commit failed; tracked files rolled back: " + str(error)) from error
                s.audit.record("run.commit", command=display, snapshot=committed["id"],
                               files=len(committed["files"]))
                print(G("✓ COMMIT " + committed["id"] + " (exit 0)"))
                return
            print(R(f"✗ command failed (exit {rc})"))
            while True:
                changes = s.diff(sp["id"])
                n = sum(len(v) for v in changes.values())
                print(Y(f"Savepoint Rescue — {n} file(s) changed since {sp['id']}"))
                ch = ask("  [r]ollback  [d]iff  [t]ry again  [k]eep changes > ", ["r", "d", "t", "k"], eof="r")
                if ch == "d":
                    show_diff(s, sp["id"])
                    continue
                if ch == "t":
                    s.audit.record("run.retry", detail=display, snapshot=sp["id"])
                    break
                if ch == "r":
                    s.restore(sp["id"])
                    s.audit.record("run.rollback", detail=display, snapshot=sp["id"])
                    print(G("✓ ROLLBACK — working tree restored"))
                else:
                    s.audit.record("run.keep", outcome="uncommitted", detail=display,
                                   snapshot=sp["id"])
                    print(Y("kept changes (not committed)"))
                raise SystemExit(rc if rc > 0 else 128 - rc)


def cmd_branch(a):
    s = store()
    if a.name is None:
        st = s.state()
        for b, h in st["branches"].items():
            print(("* " + G(b) if b == st["branch"] else "  " + b) + D(f"  {h}"))
        return
    s.create_branch(a.name)
    s.audit.record("branch", detail=a.name, snapshot=s.state()["branches"].get(a.name))
    print(G("✓ created and switched to branch " + a.name))


def cmd_checkout(a):
    s = store()
    s.checkout(a.name)
    s.audit.record("checkout", detail=a.name)
    print(G("✓ switched to " + a.name))


def cmd_merge(a):
    s = store()
    Team(".").require("merge", load_policy("."))
    m = s.merge(a.name)
    s.audit.record("merge", detail=a.name, snapshot=m["id"])
    print(G("✓ merged " + a.name + "  ") + B(m["id"]))

def cmd_audit(a):
    s = store(); log = s.audit
    if a.keys:
        ring = KeyRing()
        env = ring.env_key()
        if env is not None:
            from .audit import key_id
            print(f"signing key: {B(key_id(env))}  (from CHRONO_AUDIT_KEY)")
        else:
            kid, _ = ring.active(create=True)
            print(f"signing key: {B(str(kid))}  " + D(f"(key store: {ring.dir})") if kid else Y("signing is switched off (CHRONO_AUDIT_UNSIGNED)"))
        for k in ring.kids():
            print(D(f"  known key {k}"))
        print(D(f"  witness: {log.witness_path}"))
        print(D("  Back up the key store: a log whose key is lost can no longer be verified."))
        return
    if a.rotate_key:
        new = KeyRing().rotate()
        log.record("audit.key_rotated", detail="new signing key " + new)
        print(G("✓ new signing key ") + B(new) + D("  — older records keep verifying with their own key"))
        return
    if a.reset_witness:
        before = log.verify()
        log.reset_witness(detail="re-anchored by a person; before reset: " + before["reason"])
        print(G("✓ external witness re-anchored to the current log") +
              D(f"  (before: {before['reason']})"))
        return
    if a.push:
        r = remote_audit.push(".", a.push, verify_remote=a.verify_remote)
        log.record("audit.push", detail=f"{r['sent']} record(s) to {r['url']}", files=r["sent"])
        print(G("✓ pushed ") + f"{r['sent']} new record(s) to {r['url']}" + D(f"  (chain head seq {r['last_seq']})"))
        if a.verify_remote:
            if r.get("remote_match"):
                print(G("✓ remote chain head matches the local log"))
            else:
                print(R("✗ remote chain head DIFFERS — records may be missing remotely"))
                raise SystemExit(1)
        return
    if a.verify:
        v = log.verify()
        bad = s.verify_audit() if v["ok"] else []
        ok = v["ok"] and not bad
        reason = (v["reason"] if not v["ok"] else
                  "snapshot anchors do not match the log" if bad else v["reason"])
        log.record("audit.verify", outcome="ok" if ok else "failed", detail=reason,
                   files=v["records"])
        print((G("✓ ") if ok else R("✗ ")) + "audit chain: " + reason +
              D(f"  ({v['records']} records)"))
        if v.get("keys"):
            print(D(f"  signed with key(s) {', '.join(v['keys'])}  (key store: {KeyRing().dir})"))
        if not v["ok"]:
            print(R(f"  first bad record: #{v['broken_at']}") +
                  D("  — the log was edited, truncated, reordered or re-signed"))
            if "witness" in v["reason"]:
                print(D("  If you restored .chrono from a backup on purpose: chrono audit --reset-witness"))
            raise SystemExit(1)
        for sid, why in bad[:5]:
            print(R("  " + sid + ": " + why))
        if bad:
            raise SystemExit(1)
        return
    recs = log.rows(limit=a.limit, action=a.action)
    if a.json:
        text = json.dumps(recs, indent=2, ensure_ascii=False)
    elif a.csv:
        text = log.to_csv(recs).rstrip("\n")
    else:
        lines = []
        for r in recs:
            t = str(r.get("ts", ""))[11:19]
            det = str(r.get("detail") or r.get("command") or "")
            lines.append(f"  {D('#' + str(r.get('seq')))}  {D(t)}  {B(str(r.get('action'))):<18} "
                         f"{str(r.get('outcome')):<10} {D(det[:58])}")
        text = "\n".join(lines)
    if not text:
        print(D("no audit records yet")); return
    if a.out:
        out = Path(a.out)
        if out.parent != Path(""):
            out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print(G("✓ wrote ") + str(out) + D(f"  ({len(recs)} records)"))
    else:
        print(text)


# ---------------- policy / team / git / db / dashboard / mcp ----------------
def cmd_policy(a):
    action = getattr(a, "action", None) or "show"
    if action == "pin":
        fp = pin_policy(".")
        AuditLog(".").record("policy.pin", detail=f"{POLICY_FILE} pinned at fingerprint {fp[:16]}")
        print(G("✓ policy pinned") + D(f"  fingerprint {fp[:16]} — any later edit blocks every command "
                                       "run through Chrono until you review it and pin again"))
        return
    if action == "unpin":
        removed = unpin_policy(".")
        if removed:
            AuditLog(".").record("policy.unpin", detail=f"{POLICY_FILE} pin removed")
        print(G("✓ pin removed") if removed else D("the policy was not pinned"))
        return
    policy = load_policy(".")
    state = pin_state(".")
    if state == "changed":
        print(R(f"✗ {POLICY_FILE} changed since it was pinned — every command is blocked until you run: chrono policy pin"))
    elif state == "ok":
        print(G("✓ pinned") + D(" (unchanged since a person pinned it)"))
    if policy is None:
        print(D(f"No {POLICY_FILE} here — built-in rules only.")); return
    t = policy["thresholds"]
    print(f"{B(POLICY_FILE)}  block ≥ {t['block']}" +
          (f", approve ≥ {t['approve']}" if t["approve"] <= 100 else "") +
          (f"  approvers: {', '.join(policy['approvers'])}" if policy["approvers"] else ""))
    for action, role in sorted(policy["roles"].items()):
        print(f"  role gate: {action} needs {role}")
    for rule in policy["rules"]:
        print(f"  rule {B(str(rule['name']))}: {rule['action']} (score {rule['score']}) — {rule['reason']}")
    if policy.get("allow"):
        print(f"  allow-listed: {len(policy['allow'])} exact command(s)")
    if policy.get("retention"):
        print("  retention: " + ", ".join(f"{k} {v}" for k, v in sorted(policy["retention"].items())))
    print(G("✓ policy file is valid"))


def cmd_guard(a):
    from . import guard as guardmod
    if a.guard_cmd == "hook":
        raise SystemExit(guardmod.hook_main())
    if a.guard_cmd == "status":
        st = guardmod.status(".", a.scope)
        if st.get("error"):
            raise RuntimeError(st["error"])
        print(f"settings: {B(st['path'])}")
        print((G("✓ guard installed") + D(f"  matcher {st['matcher']}")) if st["installed"] else Y("✗ guard not installed"))
        if st["installed"]:
            print(D(f"  hook: {st['command']}"))
            ok, detail = guardmod.self_test()
            print((G("✓ self-test: ") if ok else R("✗ self-test: ")) + detail)
        print(D("  raw Bash/PowerShell tools: ") + ("denied (only chrono_run can run commands)" if st["raw_shell_denied"] else "allowed, checked by the guard"))
        return
    if a.guard_cmd == "uninstall":
        path, removed = guardmod.uninstall(".", a.scope)
        AuditLog(".").record("guard.uninstall", detail=f"{a.scope}: {path}")
        print(G("✓ guard removed from ") + str(path) if removed else D(f"no Chrono guard in {path}"))
        return
    path, created = guardmod.install(".", a.scope, deny_raw_shell=a.deny_raw_shell)
    AuditLog(".").record("guard.install", detail=f"{a.scope}: {path}" + ("; raw shell denied" if a.deny_raw_shell else ""))
    print(G("✓ guard installed" if created else "✓ guard refreshed") + f" in {path}")
    ok, detail = guardmod.self_test()
    print((G("✓ self-test: ") if ok else R("✗ self-test: ")) + detail)
    if not ok:
        print(Y("  The client could not run the hook with this Python. Install chrono-agent for it:"))
        print(Y(f'  "{sys.executable}" -m pip install --upgrade chrono-agent-{__version__}.zip'))
        raise SystemExit(1)
    print(D("  Restart your AI client so it loads the new settings. Edits to Chrono's own files by the agent are refused too."))


def cmd_prune(a):
    s = store()
    keep, days = a.keep_auto, a.older_than
    if keep is None and days is None:
        retention = (load_policy(".") or {}).get("retention") or {}
        keep, days = retention.get("keep_auto"), retention.get("older_than_days")
    r = s.prune(keep_auto=keep, older_than_days=days, dry_run=a.dry_run)
    verb = "would delete" if a.dry_run else "deleted"
    print(G(f"✓ {verb} {len(r['deleted'])} automatic savepoint(s)") +
          D(f", {r['objects_removed']} unused file version(s), {r['bytes_freed']} bytes; {r['kept']} savepoint(s) kept"))
    if a.dry_run:
        for sid in r["deleted"][:20]:
            print(D("  " + sid))

def cmd_team(a):
    s = store(); team = Team(".")
    if a.team_cmd == "list":
        users = team.list()
        if not users:
            print(D("no team members; add one: chrono team add <name> --role admin")); return
        for name, info in sorted(users.items()):
            print(f"  {B(name):<20} {info['role']}")
        return
    if a.team_cmd == "add":
        is_new = team.add(a.name, a.role)
        s.audit.record("team.add", detail=f"{a.name} as {a.role}" + ("" if is_new else " (updated)"))
        print(G("✓ ") + f"{a.name} is now {a.role}" + ("" if is_new else D(" (was already a member)")))
        return
    if a.team_cmd == "remove":
        team.remove(a.name)
        s.audit.record("team.remove", detail=a.name)
        print(G("✓ removed ") + a.name)

def cmd_git(a):
    s = store()
    if a.git_cmd == "install-hook":
        created = gitlink.install_hook(".")
        s.audit.record("git.hook", outcome="installed" if created else "already present")
        print(G("✓ post-commit hook installed" if created else "hook already installed") +
              D(" — every git commit now also creates a chrono savepoint"))
        return
    if a.git_cmd == "uninstall-hook":
        removed = gitlink.uninstall_hook(".")
        s.audit.record("git.hook", outcome="removed" if removed else "none present")
        print(G("✓ hook removed") if removed else D("no chrono hook installed"))
        return
    info = gitlink.status(".", s)
    if not info["repo"]:
        print(D("not a git repository")); return
    print(f"git HEAD:       {B(str(info['head']))}")
    print(f"savepoint HEAD: {B(str(info['snapshot_head']))}")
    print(f"hook:           {'installed' if info['hook'] else 'not installed'}")
    if info["in_sync"] is True: print(G("✓ in sync — last savepoint matches this commit"))
    elif info["in_sync"] is False: print(Y("✗ out of sync — commit or snapshot to realign"))

def cmd_db(a):
    s = store()
    if a.db_cmd == "add":
        dbmod.add(".", a.name, a.engine, path=a.path, url=a.url)
        s.audit.record("db.add", detail=f"{a.name} ({a.engine})")
        print(G("✓ registered database ") + B(a.name))
        return
    if a.db_cmd == "remove":
        dbmod.remove(".", a.name)
        s.audit.record("db.remove", detail=a.name)
        print(G("✓ removed ") + a.name); return
    if a.db_cmd == "list":
        dbs = dbmod.list_dbs(".")
        if not dbs:
            print(D("no databases registered; add one: chrono db add <name> --engine sqlite --path app.db")); return
        for name, e in sorted(dbs.items()):
            print(f"  {B(name):<16} {e['engine']:<10} {D(e.get('path') or e.get('url') or '')}")
        return
    if a.db_cmd == "snapshot":
        r = dbmod.snapshot(".", a.name)
        s.audit.record("db.snapshot", detail=f"{a.name} ({r['engine']})", files=r["bytes"])
        print(G(f"✓ DB SAVEPOINT {a.name}") + f"  {r['bytes']} bytes")
        return
    if a.db_cmd == "restore":
        if not a.yes and ask(Y(f"Restore database {a.name} from its dump? Current data is overwritten. [y/n] "), ["y", "n"]) != "y":
            s.audit.record("db.restore", outcome="aborted", detail=a.name); print("aborted"); return
        r = dbmod.restore(".", a.name)
        s.audit.record("db.restore", detail=f"{a.name} ({r['engine']})", files=r["bytes"])
        print(G(f"✓ DB RESTORED {a.name}") + f"  {r['bytes']} bytes")

def cmd_dashboard(a):
    s = store()
    out = Path(a.out or "chrono-report.html")
    dashmod.write_report(s, out)
    s.audit.record("dashboard", detail=str(out))
    print(G("✓ wrote ") + str(out) + D("  — open it in any browser"))

def cmd_mcp(a):
    from .mcp_server import serve
    print(D("chrono MCP server on stdio — point your AI client's MCP config at: chrono mcp"), file=sys.stderr)
    serve()

# ---------------- demo ----------------
def step(t):
    sys.stdout.write("  " + t + " "); sys.stdout.flush()
    for _ in range(3): time.sleep(0.25); sys.stdout.write("."); sys.stdout.flush()

def cmd_demo(a):
    task = " ".join(a.task) or "fix login page and update database"
    tmp = Path(tempfile.mkdtemp(prefix="chrono_demo_")); os.chdir(tmp)
    (tmp / "models").mkdir(); (tmp / "migrations").mkdir(); (tmp / "web").mkdir(); (tmp / "tests").mkdir()
    (tmp / "web/login.py").write_text("def login(user, pw):\n    return check_password(user, pw)\n")
    s = SnapshotStore(tmp); s.init(); s.snapshot("pre-task", kind="begin")
    s.audit.record("demo.begin", detail=task)
    print(B(f'chrono "{task}"') + D(f"   (sandbox: {tmp})"))
    print(D("SCRIPTED DEMO — not an AI agent; BEGIN local file transaction"))
    plan = [("models/user.py", "class User:\n    email: str\n    password_hash: str\n", True),
            ("migrations/004_add_email.sql", "ALTER TABLE users ADD COLUMN email TEXT;\n", True),
            ("tests/test_login.py", "def test_login():\n    assert True\n", True),
            ("web/login.py", "def login(user, pw):\n    return authenticate_magic(user, pw)  # hallucinated API\n", False)]
    sps = []
    for i, (f, body, ok) in enumerate(plan, 1):
        sp = s.snapshot(f"before step {i}", kind="savepoint"); sps.append(sp["id"])
        step(f"[{i}/4] writing {f}"); (tmp / f).write_text(body)
        if ok: print(G(" ok") + D(f"  SAVEPOINT sp_{i}")); continue
        print(R(" FAILED")); print(R("  NameError: name 'authenticate_magic' is not defined"))
        while True:
            print(Y("\nSavepoint Rescue — steps 1-3 are safe, step 4 broke the build"))
            ch = ask("  [u]ndo step 4 only  [d]iff  [r]etry with error feedback  [f]ull rollback > ", ["u", "d", "r", "f"], eof="f")
            if ch == "d": show_diff(s, sps[-1]); continue
            if ch == "u":
                s.restore(sps[-1]); s.audit.record("demo.undo", snapshot=sps[-1], detail="step 4 undone")
                print(G("✓ ROLLBACK TO sp_3 — step 4 undone, steps 1-3 kept")); break
            if ch == "f":
                s.restore(s.list()[0]["id"]); s.audit.record("demo.full_rollback", snapshot=s.list()[0]["id"])
                print(G("✓ FULL ROLLBACK — tracked files restored to pre-task snapshot")); return
            s.audit.record("demo.retry", detail="retried step 4 with error feedback")
            step("[4/4] retrying with feedback: 'authenticate_magic does not exist, use check_password'")
            (tmp / f).write_text("def login(user, pw):\n    return check_password(user, pw)\n"); print(G(" ok"))
            break
    m = s.snapshot("COMMIT", kind="commit"); s.audit.record("demo.commit", snapshot=m["id"])
    print(G(f"COMMIT {m['id']}") + "  — tracked file changes saved")
    print(D(f"Inspect: cd {tmp}  then  chrono log"))

def main(argv=None):
    p = argparse.ArgumentParser(prog="chrono", description="Local file snapshots, savepoints and recovery for trusted coding programs")
    p.add_argument("--version", action="version", version=f"chrono-agent {__version__}")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("init", help="start tracking this folder").set_defaults(f=cmd_init)
    x = sub.add_parser("snapshot", help="create a savepoint"); x.add_argument("-m", "--message"); x.set_defaults(f=cmd_snapshot)
    sub.add_parser("log", help="list savepoints").set_defaults(f=cmd_log)
    sub.add_parser("status", help="changes since last savepoint").set_defaults(f=cmd_status)
    x = sub.add_parser("diff", help="diff vs a savepoint"); x.add_argument("id", nargs="?"); x.set_defaults(f=cmd_diff)
    x = sub.add_parser("rollback", help="restore a savepoint"); x.add_argument("id", nargs="?"); x.add_argument("-y", "--yes", action="store_true"); x.set_defaults(f=cmd_rollback)
    x = sub.add_parser("scan", help="blast-radius check for a command"); x.add_argument("command"); x.set_defaults(f=cmd_scan)
    x = sub.add_parser("run", help="run a command inside a transaction"); x.add_argument("--force", action="store_true"); x.add_argument("--shell", action="store_true", help="explicit shell execution; pass one quoted command string"); x.add_argument("--approver", help="name of the human approving a policy-gated command"); x.add_argument("--approval-reason", help="why the approver allowed it"); x.add_argument("command", nargs=argparse.REMAINDER); x.set_defaults(f=cmd_run)
    x = sub.add_parser("policy", help="show and validate chrono-policy.yaml; pin it after review")
    x.add_argument("action", nargs="?", choices=["show", "pin", "unpin"], default="show",
                   help="pin: any later edit blocks every command until a person pins again")
    x.set_defaults(f=cmd_policy)
    x = sub.add_parser("guard", help="guard an AI client's own shell and edit tools (Claude Code hook)")
    gs = x.add_subparsers(dest="guard_cmd", required=True)
    for name, text in (("install", "add the PreToolUse hook to the client settings"),
                       ("uninstall", "remove the hook Chrono added"),
                       ("status", "show the hook and run a self-test")):
        t = gs.add_parser(name, help=text)
        t.add_argument("--scope", choices=["project", "user"], default="project",
                       help="project: .claude/settings.json here (default); user: ~/.claude/settings.json")
        if name == "install":
            t.add_argument("--deny-raw-shell", action="store_true",
                           help="also deny the client's Bash/PowerShell tools, so only MCP chrono_run can run commands")
        t.set_defaults(f=cmd_guard)
    gs.add_parser("hook", help="(called by the AI client) read one tool call as JSON on stdin").set_defaults(f=cmd_guard)
    x = sub.add_parser("prune", help="delete old automatic savepoints and unused file versions")
    x.add_argument("--keep-auto", type=int, help="keep the newest N automatic savepoints")
    x.add_argument("--older-than", type=float, help="delete automatic savepoints older than N days")
    x.add_argument("--dry-run", action="store_true", help="only show what would be deleted")
    x.set_defaults(f=cmd_prune)
    x = sub.add_parser("team", help="local team roster and roles")
    ts = x.add_subparsers(dest="team_cmd", required=True)
    ts.add_parser("list").set_defaults(f=cmd_team)
    t = ts.add_parser("add"); t.add_argument("name"); t.add_argument("--role", required=True, choices=["viewer", "developer", "admin"]); t.set_defaults(f=cmd_team)
    t = ts.add_parser("remove"); t.add_argument("name"); t.set_defaults(f=cmd_team)
    x = sub.add_parser("git", help="git integration: hooks and sync status")
    gs = x.add_subparsers(dest="git_cmd", required=True)
    gs.add_parser("status").set_defaults(f=cmd_git)
    gs.add_parser("install-hook").set_defaults(f=cmd_git)
    gs.add_parser("uninstall-hook").set_defaults(f=cmd_git)
    x = sub.add_parser("db", help="database snapshot and restore")
    ds = x.add_subparsers(dest="db_cmd", required=True)
    ds.add_parser("list").set_defaults(f=cmd_db)
    t = ds.add_parser("add"); t.add_argument("name"); t.add_argument("--engine", required=True, choices=["sqlite", "postgres", "mysql"]); t.add_argument("--path"); t.add_argument("--url"); t.set_defaults(f=cmd_db)
    t = ds.add_parser("remove"); t.add_argument("name"); t.set_defaults(f=cmd_db)
    t = ds.add_parser("snapshot"); t.add_argument("name"); t.set_defaults(f=cmd_db)
    t = ds.add_parser("restore"); t.add_argument("name"); t.add_argument("-y", "--yes", action="store_true"); t.set_defaults(f=cmd_db)
    x = sub.add_parser("dashboard", help="render a local HTML report of this project"); x.add_argument("--out", help="output file (default chrono-report.html)"); x.set_defaults(f=cmd_dashboard)
    sub.add_parser("mcp", help="serve Chrono tools to AI clients over MCP (stdio)").set_defaults(f=cmd_mcp)
    x = sub.add_parser("branch", help="list or create branches"); x.add_argument("name", nargs="?"); x.set_defaults(f=cmd_branch)
    x = sub.add_parser("checkout", help="switch branch"); x.add_argument("name"); x.set_defaults(f=cmd_checkout)
    x = sub.add_parser("merge", help="merge branch into current"); x.add_argument("name"); x.set_defaults(f=cmd_merge)
    x = sub.add_parser("audit", help="show or verify the tamper-evident action log")
    x.add_argument("-n", "--limit", type=int, default=25, help="newest N records (0 = all)")
    x.add_argument("--action", help="only this action, e.g. run.commit")
    x.add_argument("--json", action="store_true", dest="json", help="full records as JSON")
    x.add_argument("--csv", action="store_true", help="export as CSV")
    x.add_argument("--out", help="write the report to a file instead of the screen")
    x.add_argument("--verify", action="store_true", help="check the hash chain for tampering")
    x.add_argument("--push", metavar="URL", help="push new records to a remote append-only audit store")
    x.add_argument("--verify-remote", action="store_true", help="with --push: also compare the remote chain head")
    x.add_argument("--keys", action="store_true", help="show the signing key id and where keys are stored (never the key)")
    x.add_argument("--rotate-key", action="store_true", help="start signing with a fresh key (old records still verify)")
    x.add_argument("--reset-witness", action="store_true",
                   help="accept the current log as the reference point (after restoring .chrono from a backup)")
    x.set_defaults(f=cmd_audit)
    x = sub.add_parser("demo", help="replay the agent-blunder scenario"); x.add_argument("task", nargs="*"); x.set_defaults(f=cmd_demo)
    from .fleet_cli import install
    install(sub)
    known = {"gateway","fleet","approvals","init","snapshot","log","status","diff","rollback","scan","run","branch","checkout","merge","demo","audit","policy","team","git","db","dashboard","mcp","guard","prune","-h","--help","--version"}
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] not in known and not argv[0].startswith("-") and " " in argv[0]:  # compatibility: quoted task -> demo
        argv = ["demo"] + argv
    a = p.parse_args(argv)
    if not getattr(a, "f", None):
        p.print_help(); return
    try:
        a.f(a)
    except (RuntimeError, OSError, ValueError) as e:
        print(R(f"✗ {e}")); sys.exit(1)
    except KeyboardInterrupt:
        print(Y("\ninterrupted")); sys.exit(130)

if __name__ == "__main__":
    main()
