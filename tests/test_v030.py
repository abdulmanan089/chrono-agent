"""Tests for 0.3.0 features: policy file, approval flow, team roles, git
integration, sqlite database rollback, MCP server, remote audit push,
dashboard report."""
import io
import json
import os
import sqlite3
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tempfile
from chrono_agent.snapshot import SnapshotStore
from chrono_agent import policy as policymod, team as teammod, gitlink
from chrono_agent import db as dbmod, remote_audit, mcp_server
from chrono_agent.dashboard import render
from chrono_agent.cli import main as cli_main


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old = os.getcwd()
        os.chdir(self.root)
        self.store = SnapshotStore(self.root)
        self.store.init()

    def tearDown(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def write_policy(self, text):
        (self.root / "chrono-policy.yaml").write_text(text)


class PolicyTest(Base):
    def test_custom_rule_blocks(self):
        self.write_policy('rules:\n  - name: no-prod\n    pattern: "prod-db"\n    score: 90\n    action: block\n    reason: "touches prod"\n')
        p = policymod.load(".")
        r = policymod.evaluate("backup prod-db now", p)
        self.assertEqual(r["action"], "block")
        self.assertEqual(r["score"], 90)
        self.assertIn("touches prod", "; ".join(r["reasons"]))

    def test_custom_rule_approve_and_thresholds(self):
        self.write_policy('thresholds:\n  block: 80\n  approve: 40\nrules:\n  - name: migrate\n    pattern: "alembic"\n    score: 50\n    action: approve\n')
        p = policymod.load(".")
        self.assertEqual(policymod.evaluate("alembic upgrade head", p)["action"], "approve")
        self.assertEqual(policymod.evaluate("echo hello", p)["action"], "allow")

    def test_no_policy_still_blocks_builtin(self):
        self.assertIsNone(policymod.load("."))
        self.assertTrue(policymod.evaluate("rm -rf /", None)["blocked"])

    def test_bad_policy_rejected(self):
        self.write_policy("nonsense: true\n")
        with self.assertRaises(policymod.PolicyError):
            policymod.load(".")

    def test_bad_regex_rejected(self):
        self.write_policy('rules:\n  - name: x\n    pattern: "(["\n    score: 10\n')
        with self.assertRaises(policymod.PolicyError):
            policymod.load(".")


class TeamTest(Base):
    def test_first_member_must_be_admin(self):
        t = teammod.Team(".")
        with self.assertRaises(RuntimeError):
            t.add("junior", "viewer")
        t.add("boss", "admin")
        t.add("junior", "viewer")
        self.assertEqual(t.role_of("junior"), "viewer")

    def test_last_admin_protected(self):
        t = teammod.Team(".")
        t.add("boss", "admin")
        with self.assertRaises(RuntimeError):
            t.remove("boss")

    def test_role_gate(self):
        t = teammod.Team(".")
        t.add("boss", "admin")
        t.add("junior", "viewer")
        policy = {"roles": {"rollback": "admin"}}
        os.environ["CHRONO_USER"] = "junior"
        try:
            with self.assertRaises(RuntimeError):
                t.require("rollback", policy)
            os.environ["CHRONO_USER"] = "boss"
            t.require("rollback", policy)
        finally:
            os.environ.pop("CHRONO_USER", None)

    def test_no_policy_means_no_gate(self):
        teammod.Team(".").require("rollback", None)  # must not raise


class ApprovalFlowTest(Base):
    def test_run_approve_requires_named_approver(self):
        self.write_policy('approvers:\n  - manan\nrules:\n  - name: migrate\n    pattern: "touch"\n    score: 50\n    action: approve\n')
        # Unknown approver -> exit 3, nothing executed
        with self.assertRaises(SystemExit) as cm:
            cli_main(["run", "--approver", "stranger", "--", "touch", "x.txt"])
        self.assertEqual(cm.exception.code, 3)
        self.assertFalse((self.root / "x.txt").exists())
        # Named approver -> executes and is recorded
        cli_main(["run", "--approver", "manan", "--approval-reason", "needed for release",
                  "--", "touch", "x.txt"])
        self.assertTrue((self.root / "x.txt").exists())
        actions = [r["action"] for r in self.store.audit.read()]
        self.assertIn("run.approved", actions)
        rec = [r for r in self.store.audit.read() if r["action"] == "run.approved"][0]
        self.assertIn("manan", rec["detail"])

    def test_policy_block_cannot_be_forced_past(self):
        self.write_policy('rules:\n  - name: hard-no\n    pattern: "forbidden-cmd"\n    score: 99\n    action: block\n')
        with self.assertRaises(SystemExit) as cm:
            cli_main(["run", "--", "forbidden-cmd --now"])
        self.assertEqual(cm.exception.code, 2)


class GitTest(Base):
    def _git(self, *args):
        subprocess.run(["git", "-C", str(self.root)] + list(args), check=True,
                       capture_output=True)

    def test_hook_and_head_tracking(self):
        try:
            self._git("init", "-q")
        except subprocess.CalledProcessError:
            self.skipTest("git init unavailable in this environment")
        self._git("config", "user.email", "t@t.t")
        self._git("config", "user.name", "t")
        (self.root / "a.txt").write_text("one")
        self._git("add", ".")
        self._git("commit", "-qm", "first")
        self.assertTrue(gitlink.is_repo(self.root))
        head = gitlink.head(self.root)
        self.assertTrue(head)
        # snapshot records the git head
        meta = self.store.snapshot("with git")
        self.assertEqual(meta["git_head"], head)
        info = gitlink.status(self.root, self.store)
        self.assertTrue(info["in_sync"])
        # install hook, commit again -> auto snapshot created
        self.assertTrue(gitlink.install_hook(self.root))
        (self.root / "a.txt").write_text("two")
        self._git("add", ".")
        self._git("commit", "-qm", "second")
        messages = [m["message"] for m in self.store.list()]
        self.assertTrue(any("git commit" in m for m in messages))
        info = gitlink.status(self.root, self.store)
        self.assertTrue(info["in_sync"])
        # uninstall only removes our own hook
        self.assertTrue(gitlink.uninstall_hook(self.root))
        self.assertFalse(gitlink.hook_installed(self.root))

    def test_not_a_repo(self):
        self.assertFalse(gitlink.is_repo(self.root))
        self.assertIsNone(gitlink.head(self.root))
        with self.assertRaises(RuntimeError):
            gitlink.install_hook(self.root)


class DbTest(Base):
    def test_sqlite_snapshot_and_restore(self):
        dbpath = self.root / "app.db"
        con = sqlite3.connect(str(dbpath))
        con.execute("CREATE TABLE users (name TEXT)")
        con.execute("INSERT INTO users VALUES ('ada')")
        con.commit(); con.close()
        dbmod.add(".", "appdb", "sqlite", path="app.db")
        info = dbmod.snapshot(".", "appdb")
        self.assertGreater(info["bytes"], 0)
        # damage the database, then restore
        con = sqlite3.connect(str(dbpath))
        con.execute("DELETE FROM users"); con.commit(); con.close()
        dbmod.restore(".", "appdb")
        con = sqlite3.connect(str(dbpath))
        names = [r[0] for r in con.execute("SELECT name FROM users")]
        con.close()
        self.assertEqual(names, ["ada"])
        actions = [r["action"] for r in self.store.audit.read()]  # via CLI only; direct calls audit nothing
        self.assertTrue((self.root / ".chrono" / "db" / "appdb.dump").is_file())

    def test_unknown_engine_and_missing_db(self):
        with self.assertRaises(RuntimeError):
            dbmod.add(".", "x", "oracle")
        with self.assertRaises(RuntimeError):
            dbmod.snapshot(".", "ghost")


class McpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old = os.getcwd()
        os.chdir(self.root)
        self.store = SnapshotStore(self.root); self.store.init()
        (self.root / "f.txt").write_text("v1")

    def tearDown(self):
        os.chdir(self.old); self.tmp.cleanup()

    def rpc(self, method, params=None, mid=1):
        return mcp_server.handle({"jsonrpc": "2.0", "id": mid, "method": method,
                                  "params": params or {}})

    def test_initialize_and_tools(self):
        r = self.rpc("initialize")
        self.assertEqual(r["result"]["serverInfo"]["name"], "chrono-agent")
        names = [t["name"] for t in self.rpc("tools/list")["result"]["tools"]]
        self.assertEqual(sorted(names), ["chrono_audit_verify", "chrono_log",
                                         "chrono_rollback", "chrono_scan",
                                         "chrono_snapshot", "chrono_status"])

    def test_scan_snapshot_status_rollback_flow(self):
        r = self.rpc("tools/call", {"name": "chrono_scan",
                                    "arguments": {"command": "rm -rf /"}})
        payload = json.loads(r["result"]["content"][0]["text"])
        self.assertTrue(payload["blocked"])
        r = self.rpc("tools/call", {"name": "chrono_snapshot",
                                    "arguments": {"message": "before edit"}})
        sid = json.loads(r["result"]["content"][0]["text"])["id"]
        (self.root / "f.txt").write_text("v2")
        r = self.rpc("tools/call", {"name": "chrono_status", "arguments": {}})
        self.assertEqual(json.loads(r["result"]["content"][0]["text"])["modified"], ["f.txt"])
        # rollback without confirm is refused; file untouched
        r = self.rpc("tools/call", {"name": "chrono_rollback", "arguments": {}})
        self.assertTrue(r["result"].get("isError"))
        self.assertEqual((self.root / "f.txt").read_text(), "v2")
        # with confirm -> restored
        r = self.rpc("tools/call", {"name": "chrono_rollback",
                                    "arguments": {"id": sid, "confirm": True}})
        self.assertFalse(r["result"].get("isError", False))
        self.assertEqual((self.root / "f.txt").read_text(), "v1")
        r = self.rpc("tools/call", {"name": "chrono_audit_verify", "arguments": {}})
        self.assertTrue(json.loads(r["result"]["content"][0]["text"])["ok"])

    def test_notifications_and_unknown_method(self):
        self.assertIsNone(mcp_server.handle({"jsonrpc": "2.0",
                                             "method": "notifications/initialized"}))
        r = self.rpc("bogus/method")
        self.assertEqual(r["error"]["code"], -32601)

    def test_serve_over_stdio(self):
        inp = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}) + "\n")
        out = io.StringIO()
        mcp_server.serve(stdin=inp, stdout=out)
        reply = json.loads(out.getvalue())
        self.assertEqual(reply["id"], 7)


class _AuditSink(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        data = json.loads(body)
        _AuditSink.received.extend(data["records"])
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"accepted": len(data["records"]),
                                     "chain_head": data["chain_head"]}).encode())

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"chain_head": _AuditSink.received[-1]["hash"]
                                     if _AuditSink.received else None}).encode())

    def log_message(self, *a):
        pass


class RemoteAuditTest(Base):
    def test_push_and_verify_remote(self):
        server = HTTPServer(("127.0.0.1", 0), _AuditSink)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = "http://127.0.0.1:%d/audit" % server.server_port
        try:
            _AuditSink.received.clear()
            self.store.snapshot("one")
            self.store.snapshot("two")
            r = remote_audit.push(".", url, verify_remote=True)
            self.assertGreater(r["sent"], 0)
            self.assertTrue(r["remote_match"])
            # second push sends only new records
            self.store.snapshot("three")
            r2 = remote_audit.push(".", url)
            self.assertEqual(r2["sent"], 1)
            total = len(_AuditSink.received)
            r3 = remote_audit.push(".", url)
            self.assertEqual(r3["sent"], 0)
            self.assertEqual(len(_AuditSink.received), total)
        finally:
            server.shutdown()

    def test_bad_url_rejected(self):
        with self.assertRaises(RuntimeError):
            remote_audit.push(".", "file:///etc/passwd")


class DashboardTest(Base):
    def test_report_contains_audit_and_snapshots(self):
        self.store.snapshot("checkpoint one")
        self.store.audit.record("scan", command="rm -rf /", risk_score=98,
                                risk_level="CRITICAL", outcome="blocked")
        html = render(self.store)
        self.assertIn("checkpoint one", html)
        self.assertIn("rm -rf /", html)
        self.assertIn("CHAIN INTACT", html)
        self.assertIn("CRITICAL", html)
        out = self.root / "report.html"
        from chrono_agent.dashboard import write_report
        write_report(self.store, out)
        self.assertTrue(out.is_file())


if __name__ == "__main__":
    unittest.main()
