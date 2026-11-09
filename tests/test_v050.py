"""Tests for 0.5.0: the fixes for the independent audit of 0.4.1rc2.

H1  signed audit log by default, external witness against truncation/replacement
H2  guard hook for the AI client's own shell and edit tools
H3  scanning what a command runs (scripts, package scripts, make targets)
H4  every run and rollback states what a rollback covers
H5  no savepoint for read-only commands; prune and retention
H6  registry autostart rule, backslash allow entries, example policy
+   policy pin, policy-change audit records, Chrono control-file protection
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _home  # noqa: F401  (temporary Chrono home for keys and witnesses)

from chrono_agent import guard, mcp_server, policy as policymod
from chrono_agent.audit import (AuditLog, GENESIS, KEY_ENV, REQUIRE_ENV, UNSIGNED_ENV, _digest,
                                chrono_home)
from chrono_agent.cli import main as cli_main
from chrono_agent.interceptor import TOO_MANY, assess, is_read_only
from chrono_agent.snapshot import SnapshotStore

ROOT = str(Path(__file__).resolve().parent.parent)
ENV_VARS = (KEY_ENV, UNSIGNED_ENV, REQUIRE_ENV, "CHRONO_SAVEPOINTS", "CHRONO_AGENT", "CHRONO_MODEL", "CHRONO_USER")


class Base(unittest.TestCase):
    def setUp(self):
        self.saved = {k: os.environ.get(k) for k in ENV_VARS}
        for k in ENV_VARS:
            os.environ.pop(k, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.old = os.getcwd()
        os.chdir(self.root)
        self.store = SnapshotStore(self.root)
        self.store.init()
        (self.root / "app.py").write_text("print('v1')\n")
        self.v1 = self.store.snapshot("v1")["id"]

    def tearDown(self):
        os.chdir(self.old)
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def lines(self):
        return [x for x in self.store.audit.path.read_text(encoding="utf-8").splitlines() if x.strip()]

    def write_lines(self, rows):
        self.store.audit.path.write_text("".join(r + "\n" for r in rows), encoding="utf-8")

    def call(self, name, **args):
        r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name, "arguments": args}})
        return json.loads(r["result"]["content"][0]["text"]), r["result"].get("isError", False)

    def cli(self, args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch("builtins.input", side_effect=EOFError):
            try:
                cli_main(args)
                code = 0
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()


# ============================================================ H1
class SignedAuditTests(Base):
    def test_records_are_signed_with_a_key_outside_the_project(self):
        recs = self.store.audit.read()
        self.assertTrue(recs)
        self.assertTrue(all(r.get("alg") == "hmac-sha256" for r in recs))
        key_file = chrono_home() / "keys" / (recs[-1]["kid"] + ".key")
        self.assertTrue(key_file.is_file())
        self.assertFalse(str(key_file.resolve()).startswith(str(self.root)))
        v = self.store.audit.verify()
        self.assertTrue(v["ok"], v)
        self.assertIn("HMAC-signed", v["reason"])
        self.assertEqual(v["witness"], "ok")

    def test_unkeyed_rechain_of_a_signed_log_is_caught(self):
        self.store.snapshot("second")
        forged, prev = [], GENESIS
        for line in self.lines():
            rec = json.loads(line)
            if rec["seq"] == 1:
                rec["detail"] = "innocent"
            rec["prev"] = prev
            rec["hash"] = _digest({k: v for k, v in rec.items() if k != "hash"}, None)
            prev = rec["hash"]
            forged.append(json.dumps(rec, sort_keys=True))
        self.write_lines(forged)
        v = self.store.audit.verify()
        self.assertFalse(v["ok"])
        self.assertEqual(v["broken_at"], 1)
        self.assertIn("signature", v["reason"])

    def test_full_downgrade_to_unsigned_is_caught_by_the_witness(self):
        forged, prev = [], GENESIS
        for line in self.lines():
            rec = json.loads(line)
            rec.pop("alg")
            rec.pop("kid")
            rec["prev"] = prev
            rec["hash"] = _digest({k: v for k, v in rec.items() if k != "hash"}, None)
            prev = rec["hash"]
            forged.append(json.dumps(rec, sort_keys=True))
        self.write_lines(forged)
        v = self.store.audit.verify()
        self.assertFalse(v["ok"])
        self.assertIn("witness", v["reason"])

    def test_unsigned_record_after_signed_ones_is_caught(self):
        rows = self.lines()
        last = json.loads(rows[-1])
        rec = {"seq": last["seq"] + 1, "action": "scan", "outcome": "ok", "prev": last["hash"]}
        rec["hash"] = _digest(rec, None)
        rows.append(json.dumps(rec, sort_keys=True))
        self.write_lines(rows)
        v = self.store.audit.verify()
        self.assertFalse(v["ok"])
        self.assertIn("unsigned record after signed", v["reason"])

    def test_deleting_the_newest_records_is_caught(self):
        for i in range(3):
            self.store.snapshot("s%d" % i)
        self.write_lines(self.lines()[:-2])
        v = self.store.audit.verify()
        self.assertFalse(v["ok"])
        self.assertIn("newest records were removed", v["reason"])

    def test_the_next_write_does_not_hide_a_truncation(self):
        for i in range(3):
            self.store.snapshot("s%d" % i)
        self.write_lines(self.lines()[:-2])
        self.store.snapshot("written after the cut")
        self.assertFalse(self.store.audit.verify()["ok"])
        self.assertIn("alert", self.store.audit.read()[-1])

    def test_deleting_the_whole_log_is_caught(self):
        self.store.audit.path.unlink()
        v = self.store.audit.verify()
        self.assertFalse(v["ok"])
        self.assertIn("witness", v["reason"])

    def test_edited_witness_is_caught(self):
        self.store.snapshot("second")
        self.store.snapshot("third")
        w = self.store.audit.witness_path
        data = json.loads(w.read_text(encoding="utf-8"))
        data["seq"], data["hash"] = 1, json.loads(self.lines()[0])["hash"]
        w.write_text(json.dumps(data), encoding="utf-8")
        v = self.store.audit.verify()
        self.assertFalse(v["ok"])
        self.assertIn("witness was edited", v["reason"])

    def test_reset_witness_is_a_recorded_human_action(self):
        self.write_lines(self.lines()[:-1])
        self.assertFalse(self.store.audit.verify()["ok"])
        code, out = self.cli(["audit", "--reset-witness"])
        self.assertEqual(code, 0, out)
        self.assertTrue(self.store.audit.verify()["ok"])
        last = self.store.audit.read()[-1]
        self.assertEqual(last["action"], "audit.witness_reset")
        self.assertIn("before reset", last["detail"])

    def test_key_rotation_keeps_older_records_verifiable(self):
        old_kid = self.store.audit.read()[-1]["kid"]
        code, out = self.cli(["audit", "--rotate-key"])
        self.assertEqual(code, 0, out)
        self.store.snapshot("after rotation")
        kids = {r.get("kid") for r in self.store.audit.read()}
        self.assertIn(old_kid, kids)
        self.assertEqual(len(kids), 2)
        self.assertTrue(self.store.audit.verify()["ok"])
        code, out = self.cli(["audit", "--keys"])
        self.assertEqual(code, 0)
        self.assertIn(old_kid, out)
        self.assertNotIn(".key\n", out.split("known key")[0])

    def test_key_from_the_environment_must_be_present_to_verify(self):
        os.environ[KEY_ENV] = "team-secret-from-the-vault"
        self.store.snapshot("signed with the team key")
        self.assertTrue(self.store.audit.verify()["ok"])
        os.environ.pop(KEY_ENV)
        v = self.store.audit.verify()
        self.assertFalse(v["ok"])
        self.assertIn(KEY_ENV, v["reason"])
        os.environ[KEY_ENV] = "team-secret-from-the-vault"
        self.assertTrue(self.store.audit.verify()["ok"])

    def test_a_04_log_still_verifies_and_new_records_are_signed(self):
        project = self.root / "legacy"
        project.mkdir()
        os.environ[UNSIGNED_ENV] = "1"
        s = SnapshotStore(project)
        s.init()
        (project / "a.txt").write_text("x")
        s.snapshot("old format")
        AuditLog(project).witness_path.unlink()          # 0.4 never wrote a witness
        os.environ.pop(UNSIGNED_ENV)
        v = AuditLog(project).verify()
        self.assertTrue(v["ok"], v)
        self.assertGreater(v["legacy_unsigned"], 0)
        self.assertEqual(v["witness"], "none")
        s.snapshot("new format")
        v = AuditLog(project).verify()
        self.assertTrue(v["ok"], v)
        self.assertGreater(v["signed"], 0)
        self.assertIn("0.4 format", v["reason"])

    def test_strict_mode_rejects_unsigned_records_and_unsigned_writing(self):
        project = self.root / "strict"
        project.mkdir()
        os.environ[UNSIGNED_ENV] = "1"
        s = SnapshotStore(project)
        s.init()
        (project / "a.txt").write_text("x")
        s.snapshot("unsigned")
        os.environ.pop(UNSIGNED_ENV)
        os.environ[REQUIRE_ENV] = "1"
        v = AuditLog(project).verify()
        self.assertFalse(v["ok"])
        self.assertIn(REQUIRE_ENV, v["reason"])
        os.environ[UNSIGNED_ENV] = "1"
        with self.assertRaises(RuntimeError):
            AuditLog(project).record("scan", command="x")

    def test_many_processes_keep_chain_and_witness_consistent(self):
        code = "from chrono_agent.audit import AuditLog\na = AuditLog('.')\nfor i in range(20): a.record('scan', command='c%d' % i)"
        env = {**os.environ, "PYTHONPATH": ROOT}
        before = len(self.lines())
        procs = [subprocess.Popen([sys.executable, "-c", code], cwd=self.root, env=env) for _ in range(6)]
        for p in procs:
            self.assertEqual(p.wait(timeout=240), 0)
        v = self.store.audit.verify()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["records"], before + 120)
        self.assertEqual(v["witness"], "ok")

    def test_first_use_key_creation_is_race_free(self):
        home = tempfile.mkdtemp(prefix="chrono-race-home-")
        try:
            project = self.root / "race"
            project.mkdir()
            (project / ".chrono").mkdir()
            code = "from chrono_agent.audit import AuditLog\na = AuditLog('.')\nfor i in range(5): a.record('scan', command='c%d' % i)"
            env = {**os.environ, "PYTHONPATH": ROOT, "CHRONO_HOME": home}
            procs = [subprocess.Popen([sys.executable, "-c", code], cwd=project, env=env) for _ in range(8)]
            for p in procs:
                self.assertEqual(p.wait(timeout=240), 0)
            self.assertEqual(len(list((Path(home) / "keys").glob("*.key"))), 1)
            with mock.patch.dict(os.environ, {"CHRONO_HOME": home}):
                v = AuditLog(project).verify()
            self.assertTrue(v["ok"], v)
            self.assertEqual(v["records"], 40)
        finally:
            shutil.rmtree(home, ignore_errors=True)

    def test_new_project_where_an_old_one_lived_keeps_the_evidence(self):
        project = self.root / "reborn"
        project.mkdir()
        s = SnapshotStore(project)
        s.init()
        (project / "a.txt").write_text("x")
        s.snapshot("first life")
        shutil.rmtree(project / ".chrono")
        s2 = SnapshotStore(project)
        s2.init()
        recs = s2.audit.read()
        self.assertEqual(recs[0]["action"], "audit.witness_archived")
        self.assertIn("previous Chrono log", recs[0]["detail"])
        self.assertTrue(s2.audit.verify()["ok"])
        self.assertTrue(list((s2.audit.witness_path.parent / "archive").glob("*.json")))

    def test_mcp_verify_reports_signing_and_witness(self):
        out, err = self.call("chrono_audit_verify")
        self.assertFalse(err)
        self.assertTrue(out["ok"])
        self.assertGreater(out["signed_records"], 0)
        self.assertEqual(out["external_witness"], "ok")
        self.assertTrue(out["signing_keys"])


# ============================================================ H2
class GuardTests(Base):
    def hook(self, event):
        out, err = io.StringIO(), io.StringIO()
        code = guard.hook_main(stdin=io.StringIO(json.dumps(event)), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()

    def shell(self, command, cwd=None, tool="Bash"):
        return self.hook({"hook_event_name": "PreToolUse", "tool_name": tool,
                          "cwd": str(cwd or self.root), "tool_input": {"command": command}})

    def test_dangerous_command_is_refused_with_exit_2(self):
        code, out, err = self.shell("rm -rf /")
        self.assertEqual(code, 2)
        self.assertIn("Chrono blocked", err)
        self.assertEqual(out, "")
        self.assertEqual(self.store.audit.read()[-1]["action"], "guard.blocked")

    def test_powershell_tool_is_guarded_too(self):
        self.assertEqual(self.shell("Remove-Item C:\\ -Recurse -Force", tool="PowerShell")[0], 2)

    def test_allowed_command_gets_a_savepoint_and_is_never_auto_approved(self):
        before = len(self.store.list())
        self.assertEqual(self.shell("python app.py"), (0, "", ""))
        self.assertEqual(len(self.store.list()), before + 1)
        self.assertEqual(self.store.list()[-1]["kind"], "auto")
        rec = self.store.audit.read()[-1]
        self.assertEqual((rec["action"], rec["agent"]), ("guard.allowed", "claude-code"))

    def test_read_only_command_needs_no_savepoint(self):
        before = len(self.store.list())
        self.assertEqual(self.shell("git status")[0], 0)
        self.assertEqual(len(self.store.list()), before)

    def test_what_a_command_runs_is_checked(self):
        (self.root / "cleanup.py").write_text("import shutil\nshutil.rmtree('src')\n")
        code, _, err = self.shell("python cleanup.py")
        self.assertEqual(code, 2)
        self.assertIn("cleanup.py", err)

    def test_approval_band_asks_the_person(self):
        (self.root / "chrono-policy.yaml").write_text("thresholds:\n  block: 70\n  approve: 40\n")
        code, out, _ = self.shell("sudo echo hi")
        self.assertEqual(code, 0)
        decision = json.loads(out)["hookSpecificOutput"]
        self.assertEqual((decision["hookEventName"], decision["permissionDecision"]), ("PreToolUse", "ask"))

    def test_agent_edits_to_chrono_control_files_are_refused(self):
        targets = ["chrono-policy.yaml", ".chrono/audit.jsonl", ".claude/settings.json",
                   ".claude/settings.local.json", str(chrono_home() / "keys" / "x.key")]
        for target in targets:
            with self.subTest(target=target):
                code, _, err = self.hook({"tool_name": "Write", "cwd": str(self.root),
                                          "tool_input": {"file_path": target, "content": "x"}})
                self.assertEqual(code, 2)
                self.assertIn("refused", err)
        self.assertEqual(self.hook({"tool_name": "Edit", "cwd": str(self.root),
                                    "tool_input": {"file_path": "app.py"}})[0], 0)

    def test_errors_fail_closed(self):
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(guard.hook_main(stdin=io.StringIO("{not json"), stdout=out, stderr=err), 2)
        self.assertIn("blocked", err.getvalue())
        self.assertEqual(self.shell("ls", cwd=self.root / "missing")[0], 2)
        with mock.patch.object(guard, "gate", side_effect=RuntimeError("boom")):
            self.assertEqual(self.shell("echo hi")[0], 2)

    def test_outside_a_chrono_project_it_still_blocks(self):
        plain = Path(tempfile.mkdtemp())
        try:
            self.assertEqual(self.shell("rm -rf /", cwd=plain)[0], 2)
            self.assertEqual(self.shell("echo hi", cwd=plain)[0], 0)
            self.assertFalse((plain / ".chrono").exists())
        finally:
            shutil.rmtree(plain, ignore_errors=True)

    def test_a_subfolder_uses_the_project_above_it(self):
        sub = self.root / "src"
        sub.mkdir()
        before = len(self.store.list())
        self.assertEqual(self.shell('python -c "print(1)"', cwd=sub)[0], 0)
        self.assertEqual(len(self.store.list()), before + 1)

    def test_install_merges_settings_and_uninstall_removes_only_ours(self):
        settings = self.root / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool"}]}]}}))
        path, created = guard.install(self.root, "project", deny_raw_shell=True)
        data = json.loads(settings.read_text())
        self.assertTrue(created)
        self.assertEqual(data["model"], "x")
        commands = [h["command"] for e in data["hooks"]["PreToolUse"] for h in e["hooks"]]
        self.assertIn("other-tool", commands)
        self.assertEqual(sum(guard.MARKER in c for c in commands), 1)
        self.assertEqual(data["permissions"]["deny"], ["Bash", "PowerShell"])
        self.assertFalse(guard.install(self.root, "project")[1])          # idempotent
        data = json.loads(settings.read_text())
        self.assertEqual(sum(guard.MARKER in h["command"] for e in data["hooks"]["PreToolUse"] for h in e["hooks"]), 1)
        self.assertTrue(guard.status(self.root)["installed"])
        self.assertTrue(guard.uninstall(self.root, "project")[1])
        data = json.loads(settings.read_text())
        self.assertEqual([h["command"] for e in data["hooks"]["PreToolUse"] for h in e["hooks"]], ["other-tool"])
        self.assertFalse(guard.status(self.root)["installed"])

    def test_install_never_clobbers_broken_settings(self):
        settings = self.root / ".claude" / "settings.json"
        settings.parent.mkdir()
        settings.write_text("{oops")
        with self.assertRaises(RuntimeError):
            guard.install(self.root)
        self.assertEqual(settings.read_text(), "{oops")

    def test_guard_settings_survive_a_rollback(self):
        guard.install(self.root)
        self.store.restore(self.v1)
        self.assertTrue((self.root / ".claude" / "settings.json").is_file())
        self.assertNotIn(".claude/settings.json", self.store.snapshot("after")["files"])

    def test_the_exact_command_the_client_runs(self):
        env = {**os.environ, "PYTHONPATH": ROOT}
        cmd = [sys.executable, "-m", "chrono_agent", "guard", "hook"]

        def event(c):
            return json.dumps({"tool_name": "Bash", "cwd": str(self.root), "tool_input": {"command": c}})
        bad = subprocess.run(cmd, input=event("rm -rf /"), capture_output=True, text=True, env=env,
                             cwd=self.root, timeout=120)
        good = subprocess.run(cmd, input=event("echo hi"), capture_output=True, text=True, env=env,
                              cwd=self.root, timeout=120)
        self.assertEqual(bad.returncode, 2, bad.stderr)
        self.assertIn("Chrono blocked", bad.stderr)
        self.assertEqual(good.returncode, 0, good.stderr)

    def test_self_test_runs_the_installed_command(self):
        with mock.patch.dict(os.environ, {"PYTHONPATH": ROOT}):
            ok, detail = guard.self_test()
        self.assertTrue(ok, detail)

    def test_cli_install_and_status(self):
        with mock.patch.dict(os.environ, {"PYTHONPATH": ROOT}):
            code, out = self.cli(["guard", "install"])
            self.assertEqual(code, 0, out)
            self.assertIn("self-test", out)
            code, out = self.cli(["guard", "status"])
        self.assertEqual(code, 0, out)
        self.assertIn("guard installed", out)
        self.assertIn("guard.install", [r["action"] for r in self.store.audit.read()])


# ============================================================ H3
class InspectionTests(Base):
    def ev(self, cmd):
        return policymod.evaluate(cmd, None, root=str(self.root))

    def test_python_script_that_deletes_recursively(self):
        (self.root / "cleanup.py").write_text("import shutil\nshutil.rmtree('build')\n")
        r = self.ev("python cleanup.py")
        self.assertTrue(r["blocked"])
        self.assertIn("In cleanup.py: Recursive delete (Python)", r["reasons"])
        self.assertEqual(assess("python cleanup.py")["score"], 5)        # without a folder nothing is read

    def test_benign_scripts_and_comments_are_left_alone(self):
        (self.root / "ok.py").write_text("# never run rm -rf / here\nprint(sum(range(10)))\n")
        for cmd in ("python ok.py", "py -3 ok.py", "python -u ok.py", "python -m ok", "python app.py"):
            with self.subTest(cmd=cmd):
                self.assertFalse(self.ev(cmd)["blocked"], self.ev(cmd))

    def test_batch_files_and_the_scripts_they_start(self):
        (self.root / "clean.py").write_text("import shutil\nshutil.rmtree('x')\n")
        (self.root / "wipe.bat").write_text("@echo off\nrd /s /q C:\\data\n")
        (self.root / "run.cmd").write_text("@echo off\npython clean.py\n")
        self.assertTrue(self.ev("wipe.bat")["blocked"])
        self.assertTrue(self.ev("cmd /c run.cmd")["blocked"])
        self.assertIn("In clean.py: Recursive delete (Python)", self.ev("cmd /c run.cmd")["reasons"])

    def test_powershell_and_shell_scripts(self):
        (self.root / "x.ps1").write_text("Remove-Item -Path C:\\data -Recurse -Force\n")
        (self.root / "x.sh").write_text("#!/bin/sh\nrm -rf ~/projects\n")
        self.assertTrue(self.ev("powershell -ExecutionPolicy Bypass -File x.ps1")["blocked"])
        self.assertTrue(self.ev("bash x.sh")["blocked"])
        self.assertTrue(self.ev("./x.sh")["blocked"])

    def test_npm_scripts_with_pre_and_post_hooks(self):
        (self.root / "package.json").write_text(json.dumps({"scripts": {
            "pretest": "rd /s /q dist", "test": "echo ok", "build": "node build.js",
            "postinstall": "node setup.js"}}))
        (self.root / "build.js").write_text("console.log('build')\n")
        (self.root / "setup.js").write_text("require('fs').rmSync('src', {recursive: true})\n")
        r = self.ev("npm test")
        self.assertTrue(r["blocked"])
        self.assertTrue(any('npm script "pretest"' in x for x in r["reasons"]))
        self.assertFalse(self.ev("npm run build")["blocked"])
        self.assertTrue(self.ev("npm install")["blocked"])                  # runs the project's postinstall
        self.assertFalse(self.ev("npm install react")["blocked"])           # third-party code is not readable here
        self.assertTrue(self.ev("yarn install")["blocked"])

    def test_make_targets_and_their_dependencies(self):
        (self.root / "Makefile").write_text("all: build\n\nbuild: clean\n\tpython app.py\n\nclean:\n\t@rm -rf build\n")
        self.assertTrue(self.ev("make")["blocked"])                         # all -> build -> clean
        self.assertTrue(self.ev("make clean")["blocked"])
        (self.root / "Makefile").write_text("all:\n\tpython app.py\n")
        self.assertFalse(self.ev("make")["blocked"])

    def test_large_scripts_too_many_scripts_and_loops_fail_closed(self):
        (self.root / "big.py").write_text("x = 1\n" * 300000)             # about 1.8 MB
        r = self.ev("python big.py")
        self.assertTrue(r["blocked"])
        self.assertTrue(any("larger than 1 MB" in x for x in r["reasons"]))
        names = ["s%d.py" % i for i in range(20)]
        for n in names:
            (self.root / n).write_text("print(1)\n")
        (self.root / "all.bat").write_text("\n".join("python " + n for n in names))
        self.assertIn(TOO_MANY, self.ev("all.bat")["reasons"])
        (self.root / "a.bat").write_text("call b.bat\n")
        (self.root / "b.bat").write_text("call a.bat\n")
        self.assertFalse(self.ev("a.bat")["blocked"])                       # ends, and nothing dangerous

    def test_commands_wrapped_in_chrono_run_are_inspected(self):
        (self.root / "evil.py").write_text("import shutil\nshutil.rmtree('src')\n")
        self.assertTrue(self.ev("chrono run python evil.py")["blocked"])
        self.assertTrue(self.ev("chrono run -- python evil.py")["blocked"])
        self.assertTrue(self.ev('chrono run --shell "python evil.py"')["blocked"])
        self.assertTrue(self.ev("python -m chrono_agent run python evil.py")["blocked"])
        self.assertFalse(self.ev("chrono run python app.py")["blocked"])
        self.assertTrue(assess("chrono run --force python app.py")["blocked"])     # agents may not skip the scan

    def test_mcp_scan_and_run_read_what_runs(self):
        (self.root / "cleanup.py").write_text("import shutil\nshutil.rmtree('.')\n")
        out, _ = self.call("chrono_scan", command="python cleanup.py")
        self.assertTrue(out["blocked"])
        out, _ = self.call("chrono_run", command="python cleanup.py")
        self.assertFalse(out["executed"])
        self.assertTrue((self.root / "app.py").exists())


# ============================================================ H4 + H5
class SavepointTests(Base):
    def test_read_only_detection(self):
        for cmd in ("dir", "cd && dir /a", "git status", "git log --oneline -5", "python --version",
                    "python -m pip list", "type a.txt | findstr x", "Get-ChildItem", "chrono status",
                    "chrono audit --verify", "echo hello"):
            with self.subTest(cmd=cmd):
                self.assertTrue(is_read_only(cmd, cwd=self.root))
        for cmd in ("echo hi > f.txt", "git branch -D x", "git -c core.pager=x log", "npm test", "python app.py",
                    "find . -delete", "chrono policy pin", "chrono audit --push http://x", "C:\\tools\\dir.exe",
                    "echo (x)", "npm version patch", "dir & del x", "type x | python -", ""):
            with self.subTest(cmd=cmd):
                self.assertFalse(is_read_only(cmd, cwd=self.root))

    @unittest.skipUnless(os.name == "nt", "Windows runs programs from the current folder first")
    def test_a_program_in_the_project_folder_is_not_trusted(self):
        (self.root / "where.bat").write_text("@echo off\nrd /s /q .\n")
        self.assertFalse(is_read_only("where python", cwd=self.root))

    def test_mcp_run_skips_the_savepoint_only_for_read_only_commands(self):
        before = len(self.store.list())
        out, _ = self.call("chrono_run", command="dir" if os.name == "nt" else "ls")
        self.assertTrue(out["executed"])
        self.assertIsNone(out["savepoint"])
        self.assertIn("savepoint_skipped", out)
        self.assertEqual(len(self.store.list()), before)
        out, _ = self.call("chrono_run", command='"%s" -c "print(1)"' % sys.executable)
        self.assertTrue(out["savepoint"])
        self.assertIn("undo", out)
        os.environ["CHRONO_SAVEPOINTS"] = "always"
        out, _ = self.call("chrono_run", command="dir" if os.name == "nt" else "ls")
        self.assertTrue(out["savepoint"])

    def test_run_and_rollback_say_what_a_rollback_covers(self):
        out, _ = self.call("chrono_run", command='"%s" -c "print(1)"' % sys.executable)
        self.assertIn("project folder only", out["covers"])
        self.assertIn("registry", out["covers"])
        out, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertIn("project folder only", out["covers"])

    def auto_savepoints(self, n):
        for i in range(n):
            (self.root / "app.py").write_text("print(%d)\n" % i)
            self.store.snapshot("auto %d" % i, kind="auto")

    def test_prune_keeps_the_newest_automatic_savepoints_and_every_head(self):
        self.auto_savepoints(6)
        head = self.store.get()["id"]
        manual = self.store.get(self.v1)["id"]
        r = self.store.prune(keep_auto=2)
        ids = [m["id"] for m in self.store.list()]
        self.assertEqual(len(r["deleted"]), 3)            # 5 candidates (the head is never one), keep 2
        self.assertIn(head, ids)
        self.assertIn(manual, ids)
        self.assertGreater(r["objects_removed"], 0)
        self.store.restore(head)                           # what is left still restores
        self.assertEqual((self.root / "app.py").read_text(), "print(5)\n")
        self.assertEqual(self.store.audit.read()[-2]["action"], "prune")
        self.assertTrue(self.store.audit.verify()["ok"])

    def test_large_snapshot_stores_files_in_parallel_safely(self):
        for i in range(120):
            (self.root / ("same%03d.txt" % i)).write_text("identical content\n")   # one shared stored version
            (self.root / ("uniq%03d.txt" % i)).write_text("unique %d\n" % i)
        meta = self.store.snapshot("parallel")
        self.assertEqual(len(meta["files"]), 241)
        self.assertEqual(len(set(meta["files"].values())), 122)
        for i in range(120):
            (self.root / ("uniq%03d.txt" % i)).write_text("changed")
        self.store.restore(meta["id"])
        self.assertEqual((self.root / "uniq007.txt").read_text(), "unique 7\n")
        self.assertFalse(any(self.store.diff().values()))

    def test_dry_run_changes_nothing(self):
        self.auto_savepoints(4)
        before = [m["id"] for m in self.store.list()]
        r = self.store.prune(keep_auto=0, dry_run=True)
        self.assertEqual(len(r["deleted"]), 3)
        self.assertEqual([m["id"] for m in self.store.list()], before)

    def test_history_is_relinked_and_merge_still_works(self):
        self.auto_savepoints(3)
        self.store.snapshot("manual on main")
        self.store.create_branch("feature")
        (self.root / "feature.txt").write_text("f")
        self.store.snapshot("feature work")
        self.store.checkout("main")
        (self.root / "main.txt").write_text("m")
        self.store.snapshot("main work")
        self.store.prune(keep_auto=0)
        for m in self.store.list():
            for key in ("parent", "merge_parent"):
                if m.get(key):
                    self.store.get(m[key])                 # no dangling links
        merged = self.store.merge("feature")
        self.assertTrue((self.root / "feature.txt").exists())
        self.assertEqual(merged["kind"], "merge")

    def test_retention_policy_prunes_after_chrono_run(self):
        (self.root / "chrono-policy.yaml").write_text("retention:\n  keep_auto: 2\n")
        for i in range(5):
            out, _ = self.call("chrono_run", command='"%s" -c "print(%d)"' % (sys.executable, i))
            self.assertTrue(out["executed"])
        autos = [m for m in self.store.list() if m["kind"] == "auto"]
        self.assertLessEqual(len(autos), 3)                # 2 kept + the current head

    def test_cli_prune(self):
        self.auto_savepoints(4)
        code, out = self.cli(["prune", "--keep-auto", "1", "--dry-run"])
        self.assertEqual(code, 0, out)
        self.assertIn("would delete 2", out)
        code, out = self.cli(["prune", "--keep-auto", "1"])
        self.assertIn("deleted 2", out)
        self.assertEqual(self.cli(["prune"])[0], 1)          # says what to keep


# ============================================================ H6 + policy
class PolicyTests(Base):
    def write(self, text):
        (self.root / "chrono-policy.yaml").write_text(text)

    def test_allow_entries_may_contain_backslashes(self):
        self.write("allow:\n  - reg add HKCU\\Software\\MyCompany\\MyApp /v * /d * /f\n")
        p = policymod.load(".")
        ok = policymod.evaluate(r"reg add HKCU\Software\MyCompany\MyApp /v Theme /d dark /f", p)
        self.assertEqual(ok["action"], "allow")
        other = policymod.evaluate(r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d y /f", p)
        self.assertEqual(other["action"], "block")
        self.write("allow:\n  - \"rm -rf build\\\\\"\n")
        with self.assertRaises(policymod.PolicyError):
            policymod.load(".")

    def test_retention_section(self):
        self.write("retention:\n  keep_auto: 100\n  older_than_days: 14\n")
        self.assertEqual(policymod.load(".")["retention"], {"keep_auto": 100, "older_than_days": 14})
        for bad in ("retention:\n  keep_auto: -1\n", "retention:\n  forever: 1\n"):
            self.write(bad)
            with self.assertRaises(policymod.PolicyError):
                policymod.load(".")

    def test_example_policy_in_the_package_is_valid(self):
        example = Path(ROOT) / "examples" / "chrono-policy.yaml"
        shutil.copy(example, self.root / "chrono-policy.yaml")
        p = policymod.load(".")
        self.assertTrue(p["allow"])
        self.assertEqual(p["gates"].get("mcp.rollback"), "approve")

    def test_policy_rule_hides_the_no_pattern_reason(self):
        self.write('rules:\n  - name: prod\n    pattern: "deploy prod"\n    score: 50\n    action: approve\n')
        r = policymod.evaluate("deploy prod", policymod.load("."))
        self.assertNotIn(policymod.NO_PATTERN, r["reasons"])

    def test_pin_blocks_everything_after_an_edit_until_a_person_pins_again(self):
        self.write("thresholds:\n  block: 70\n")
        code, out = self.cli(["policy", "pin"])
        self.assertEqual(code, 0, out)
        self.assertTrue(self.call("chrono_run", command="echo hi")[0]["executed"])
        self.write("thresholds:\n  block: 100\n")              # an agent tries to loosen the rules
        out, _ = self.call("chrono_run", command="echo hi")
        self.assertFalse(out["executed"])
        self.assertTrue(any("pinned" in x for x in out["reasons"]))
        code, out = self.cli(["policy"])
        self.assertIn("changed since it was pinned", out)
        self.cli(["policy", "pin"])
        self.assertTrue(self.call("chrono_run", command="echo hi")[0]["executed"])
        self.cli(["policy", "unpin"])
        self.assertIsNone(policymod.pin_state("."))

    def test_a_forged_pin_does_not_count(self):
        self.write("thresholds:\n  block: 70\n")
        policymod.pin(".")
        pin_file = chrono_home() / "pins" / (__import__("chrono_agent.audit", fromlist=["project_id"]).project_id(".") + ".json")
        self.write("thresholds:\n  block: 100\n")
        data = json.loads(pin_file.read_text())
        data["fingerprint"] = policymod.fingerprint(".")       # rewritten without the key
        pin_file.write_text(json.dumps(data))
        self.assertEqual(policymod.pin_state("."), "changed")

    def test_policy_changes_are_recorded(self):
        self.call("chrono_run", command="echo one")
        self.write("thresholds:\n  block: 80\n")
        self.call("chrono_run", command="echo two")
        self.write("thresholds:\n  block: 90\n")
        self.call("chrono_scan", command="echo three")
        changes = [r for r in self.store.audit.read() if r["action"] == "policy.changed"]
        self.assertEqual(len(changes), 2)                     # none -> v1, then v1 -> v2
        self.assertEqual([c["outcome"] for c in changes], ["changed", "changed"])
        self.assertIn("-> ", changes[0]["detail"])
        self.assertIn("none", changes[0]["detail"])

    def test_a_policy_seen_for_the_first_time_is_recorded(self):
        self.write("thresholds:\n  block: 70\n")
        self.call("chrono_scan", command="echo hi")
        changes = [r for r in self.store.audit.read() if r["action"] == "policy.changed"]
        self.assertEqual([c["outcome"] for c in changes], ["first-seen"])


class ControlPlaneRuleTests(unittest.TestCase):
    def test_agents_cannot_change_chrono_itself(self):
        for cmd in ("chrono approvals approve 1234 --by sara", "python -m chrono_agent approvals approve x --by s",
                    "chrono policy pin", "chrono team add me --role admin", "chrono guard uninstall",
                    "chrono prune --keep-auto 0", "chrono audit --reset-witness", "del .chrono\\audit.jsonl",
                    "copy forged.jsonl .chrono\\audit.jsonl", "echo x > chrono-policy.yaml",
                    "Remove-Item chrono-policy.yaml", "echo {} > .claude/settings.json",
                    r"del %USERPROFILE%\.chrono-agent\keys\abc.key"):
            with self.subTest(cmd=cmd):
                self.assertTrue(assess(cmd)["blocked"], assess(cmd))

    def test_reading_chrono_files_is_fine(self):
        for cmd in ("chrono status", "chrono audit --verify", "type .chrono\\audit.jsonl", "cat chrono-policy.yaml",
                    "cp -r .chrono /backup", "git status > .chrono-report.txt", "chrono scan \"rm -rf /\""):
            with self.subTest(cmd=cmd):
                r = assess(cmd)
                if cmd.startswith("chrono scan"):
                    self.assertNotIn("Changes Chrono's own safety controls", " ".join(r["reasons"]))
                else:
                    self.assertFalse(r["blocked"], r)


if __name__ == "__main__":
    unittest.main()
