"""Tests for rescue/redo rollback, the MCP approval gate and role checks."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _home  # noqa: F401  (temporary Chrono home for keys and witnesses)

from chrono_agent import mcp_server, policy as policymod
from chrono_agent.cli import main as cli_main
from chrono_agent.fleet import Fleet
from chrono_agent.snapshot import SnapshotStore


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old = os.getcwd()
        os.chdir(self.root)
        self.store = SnapshotStore(self.root)
        self.store.init()
        self.f = self.root / "app.py"
        self.f.write_text("GOOD\n")
        self.v1 = self.store.snapshot("v1 safe state")["id"]

    def tearDown(self):
        os.chdir(self.old)
        self.tmp.cleanup()

    def call(self, name, **args):
        r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name, "arguments": args}})
        return json.loads(r["result"]["content"][0]["text"]), r["result"].get("isError", False)

    def policy(self, text):
        (self.root / "chrono-policy.yaml").write_text(text)


class RescueRedoTests(Base):
    def test_mcp_rollback_keeps_unsaved_edits_and_redo_restores_them(self):
        self.f.write_text("BROKEN\n")
        (self.root / "new.txt").write_text("new")
        out, err = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertFalse(err)
        self.assertEqual(self.f.read_text(), "GOOD\n")
        self.assertFalse((self.root / "new.txt").exists())
        redo = out["redo"]
        self.assertTrue(redo)
        self.assertEqual(self.store.get(redo)["kind"], "rescue")
        out2, _ = self.call("chrono_rollback", id=redo, confirm=True)       # redo
        self.assertEqual(self.f.read_text(), "BROKEN\n")
        self.assertEqual((self.root / "new.txt").read_text(), "new")
        self.assertTrue(out2["redo"])

    def test_clean_tree_redo_points_at_previous_head(self):
        out, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertEqual(out["redo"], self.v1)

    def test_rollback_still_requires_confirm(self):
        self.f.write_text("BROKEN\n")
        out, err = self.call("chrono_rollback", id=self.v1)
        self.assertTrue(err)
        self.assertEqual(self.f.read_text(), "BROKEN\n")

    def test_cli_rollback_saves_rescue_and_prints_undo(self):
        self.f.write_text("BROKEN\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli_main(["rollback", self.v1, "--yes"])
        self.assertIn(code, (0, None))
        self.assertEqual(self.f.read_text(), "GOOD\n")
        self.assertIn("undo this rollback", buf.getvalue())
        rescue = [m for m in self.store.list() if m["kind"] == "rescue"]
        self.assertEqual(len(rescue), 1)
        self.store.restore(rescue[0]["id"])
        self.assertEqual(self.f.read_text(), "BROKEN\n")

    def test_rollback_audit_stays_intact(self):
        self.f.write_text("BROKEN\n")
        self.call("chrono_rollback", id=self.v1, confirm=True)
        out, _ = self.call("chrono_audit_verify")
        self.assertTrue(out["ok"])


class ApprovalGateTests(Base):
    GATE = "gates:\n  mcp.rollback: approve\napprovers:\n  - sara\n"

    def test_gate_blocks_until_a_named_human_approves(self):
        self.policy(self.GATE)
        self.f.write_text("BROKEN\n")
        out, err = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertFalse(err)
        self.assertEqual(out["status"], "approval_required")
        self.assertEqual(self.f.read_text(), "BROKEN\n")          # nothing restored
        aid = out["approval_id"]
        self.assertIn(aid, out["next"])
        # repeating the request does not mint a second approval
        again, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertEqual(again["approval_id"], aid)
        self.assertEqual(self.f.read_text(), "BROKEN\n")
        # an unlisted person cannot approve
        with self.assertRaises(ValueError):
            Fleet(".").decide(aid, True, "mallory")
        Fleet(".").decide(aid, True, "sara")
        done, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertEqual(done["restored"], self.v1)
        self.assertEqual(self.f.read_text(), "GOOD\n")
        self.assertTrue(done["redo"])

    def test_approval_is_single_use(self):
        self.policy(self.GATE)
        out, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        Fleet(".").decide(out["approval_id"], True, "sara")
        self.call("chrono_rollback", id=self.v1, confirm=True)       # consumes it
        self.f.write_text("BROKEN AGAIN\n")
        again, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertEqual(again["status"], "approval_required")
        self.assertNotEqual(again["approval_id"], out["approval_id"])
        self.assertEqual(self.f.read_text(), "BROKEN AGAIN\n")

    def test_approval_is_bound_to_the_snapshot(self):
        self.policy(self.GATE)
        self.f.write_text("TWO\n")
        v2 = self.store.snapshot("v2")["id"]
        out, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        Fleet(".").decide(out["approval_id"], True, "sara")
        other, _ = self.call("chrono_rollback", id=v2, confirm=True)   # different target
        self.assertEqual(other["status"], "approval_required")

    def test_denied_approval_does_not_roll_back(self):
        self.policy(self.GATE)
        self.f.write_text("BROKEN\n")
        out, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        Fleet(".").decide(out["approval_id"], False, "sara")
        again, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertEqual(again["status"], "approval_required")
        self.assertEqual(self.f.read_text(), "BROKEN\n")

    def test_pending_approval_shows_what_it_is_for(self):
        self.policy(self.GATE)
        out, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        rows = Fleet(".").state()["approvals"]
        self.assertIn(self.v1, [r["summary"] for r in rows if r["id"] == out["approval_id"]][0])

    def test_gate_events_are_in_the_fleet_audit_chain(self):
        self.policy(self.GATE)
        self.call("chrono_rollback", id=self.v1, confirm=True)
        st = Fleet(".").state()
        self.assertTrue(st["audit_intact"])
        self.assertIn("gate.approve", [e["action"] for e in st["events"]])

    def test_policy_gate_syntax_is_validated(self):
        self.policy("gates:\n  mcp.rollback: maybe\n")
        with self.assertRaises(policymod.PolicyError):
            policymod.load(".")
        self.policy("gates:\n  mcp.rollback: approve\n")
        self.assertEqual(policymod.load(".")["gates"], {"mcp.rollback": "approve"})

    def test_no_gate_means_rollback_proceeds_with_rescue(self):
        self.f.write_text("BROKEN\n")
        out, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertEqual(out["restored"], self.v1)


class RoleTests(Base):
    def test_mcp_rollback_respects_policy_roles(self):
        self.policy("roles:\n  rollback: admin\n")
        os.environ["CHRONO_USER"] = "nobody-here"
        try:
            self.f.write_text("BROKEN\n")
            out, err = self.call("chrono_rollback", id=self.v1, confirm=True)
            self.assertTrue(err)
            self.assertIn("needs role admin", out["error"])
            self.assertEqual(self.f.read_text(), "BROKEN\n")
        finally:
            del os.environ["CHRONO_USER"]

    def test_mcp_specific_role_can_be_stricter_than_cli(self):
        from chrono_agent.team import Team
        Team(".").add("boss", "admin")
        Team(".").add("dev", "developer")
        self.policy("roles:\n  rollback: developer\n  mcp.rollback: admin\n")
        os.environ["CHRONO_USER"] = "dev"
        try:
            out, err = self.call("chrono_rollback", id=self.v1, confirm=True)
            self.assertTrue(err)
            os.environ["CHRONO_USER"] = "boss"
            out, err = self.call("chrono_rollback", id=self.v1, confirm=True)
            self.assertFalse(err)
        finally:
            del os.environ["CHRONO_USER"]


class PolicySurvivesRollbackTests(Base):
    """A rollback must never remove or revert the rules that govern rollbacks."""
    RULES = "gates:\n  mcp.rollback: approve\n"

    def test_policy_added_after_a_snapshot_survives_rollback(self):
        self.policy(self.RULES)
        self.f.write_text("BROKEN\n")
        self.store.restore(self.v1)
        self.assertTrue((self.root / "chrono-policy.yaml").is_file())
        self.assertEqual(self.f.read_text(), "GOOD\n")

    def test_policy_edits_are_not_reverted_by_rollback(self):
        self.policy(self.RULES)
        self.store.snapshot("with policy")
        later = self.store.list()[-1]["id"]
        self.policy("gates:\n  mcp.rollback: approve\napprovers:\n  - sara\n")
        self.store.restore(later)
        self.assertIn("sara", (self.root / "chrono-policy.yaml").read_text())

    def test_old_snapshot_containing_policy_does_not_overwrite_current_one(self):
        from unittest import mock
        from chrono_agent import snapshot as snapmod
        self.policy("approvers:\n  - old\n")
        with mock.patch.object(snapmod, "IGNORE", snapmod.IGNORE - {"chrono-policy.yaml"}):
            legacy = self.store.snapshot("legacy snapshot that tracked the policy")
        self.assertIn("chrono-policy.yaml", legacy["files"])
        self.policy("approvers:\n  - current\n")
        self.store.restore(legacy["id"])
        self.assertIn("current", (self.root / "chrono-policy.yaml").read_text())
        self.assertEqual(self.store.diff(legacy["id"])["deleted"], [])

    def test_gate_stays_active_after_a_rollback_to_a_pre_policy_snapshot(self):
        self.policy("gates:\n  mcp.rollback: approve\napprovers:\n  - sara\n")
        out, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        Fleet(".").decide(out["approval_id"], True, "sara")
        self.call("chrono_rollback", id=self.v1, confirm=True)
        again, _ = self.call("chrono_rollback", id=self.v1, confirm=True)
        self.assertEqual(again["status"], "approval_required")


class PolicyLevelTests(Base):
    def test_level_follows_final_score_when_policy_raises_it(self):
        self.policy('rules:\n  - name: scary\n    pattern: "launch missiles"\n    score: 97\n    action: block\n')
        r = policymod.evaluate("launch missiles", policymod.load("."))
        self.assertEqual((r["score"], r["level"], r["action"]), (97, "CRITICAL", "block"))


class FleetScanTests(Base):
    def test_gateway_decision_sees_through_json_escaping(self):
        fleet = Fleet(".")
        action = {"tool": "shell", "arguments": {"command": "r\u200bm -rf /"}}
        self.assertEqual(fleet.decision("agent1", action)["action"], "block")
        action = {"tool": "shell", "arguments": {"command": 'bash -c "rm -rf /"'}}
        self.assertEqual(fleet.decision("agent1", action)["action"], "block")

    def test_gateway_decision_allows_harmless_actions(self):
        fleet = Fleet(".")
        self.assertEqual(fleet.decision("agent1", {"tool": "shell", "arguments": {"command": "ls -la"}})["action"], "allow")


class HookTests(Base):
    def test_hook_calls_the_installing_interpreter_not_a_bare_chrono(self):
        from chrono_agent import gitlink
        text = gitlink._hook_text()
        self.assertIn(Path(sys.executable).as_posix(), text)
        self.assertIn("-m chrono_agent snapshot", text)
        self.assertNotIn("\nchrono snapshot", text)
        self.assertIn("failed", text)              # failures are no longer silent


if __name__ == "__main__":
    unittest.main()
