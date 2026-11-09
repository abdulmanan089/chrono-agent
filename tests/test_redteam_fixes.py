"""Regression tests for problems found by the enterprise red-team round."""
import csv
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _home  # noqa: F401  (temporary Chrono home for keys and witnesses)

from chrono_agent import policy as policymod
from chrono_agent.audit import AuditLog, redact
from chrono_agent.interceptor import MAX_SCAN, assess
from chrono_agent.snapshot import SnapshotStore

ROOT = str(Path(__file__).resolve().parent.parent)


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


class AuditFixes(Base):
    def test_many_writers_never_fork_the_chain(self):
        code = "from chrono_agent.audit import AuditLog\na = AuditLog('.')\nfor i in range(25): a.record('scan', command='c%d' % i)"
        env = {**os.environ, "PYTHONPATH": ROOT}
        procs = [subprocess.Popen([sys.executable, "-c", code], cwd=self.root, env=env) for _ in range(8)]
        for p in procs:
            self.assertEqual(p.wait(timeout=120), 0)
        v = AuditLog(self.root).verify()
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["records"], 200)
        seqs = [r["seq"] for r in AuditLog(self.root).read()]
        self.assertEqual(seqs, list(range(1, 201)))

    def test_secrets_are_redacted_before_they_reach_the_log(self):
        a = AuditLog(self.root)
        secrets = ["sk-live-ABCDEF1234567890SECRET", "hunter2pw", "ghp_abcdefghijklmnopqrstuvwxyz0123", "AKIAABCDEFGHIJKLMNOP",
                   "s3cr3tvalue", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"]
        cmd = ('curl -H "Authorization: Bearer %s" https://x && psql postgres://admin:%s@db/prod && '
               'export GITHUB_TOKEN=%s AWS_KEY=%s && tool --password %s && echo %s') % (
               secrets[0], secrets[1], secrets[2], secrets[3], secrets[4], secrets[5])
        a.record("scan", command=cmd, detail="token=" + secrets[4])
        text = a.path.read_text()
        for s in secrets:
            self.assertNotIn(s, text)
        self.assertIn("[REDACTED", text)
        self.assertTrue(a.verify()["ok"])          # the chain is built over the redacted text

    def test_redaction_leaves_ordinary_commands_alone(self):
        for cmd in ["git status", "ls -la /tmp", "python app.py --verbose", "echo token expired", "grep -r password docs/"]:
            self.assertEqual(redact(cmd), cmd)

    def test_csv_export_neutralises_formulas(self):
        a = AuditLog(self.root)
        a.record("scan", command='=HYPERLINK("http://evil","x")', detail="+cmd|' /C calc'!A0")
        rows = list(csv.DictReader(io.StringIO(a.to_csv(a.read()))))
        self.assertTrue(rows[0]["command"].startswith("'="))
        self.assertTrue(rows[0]["detail"].startswith("'+"))

    def test_corrupt_last_line_is_detected_and_does_not_crash_writers(self):
        a = AuditLog(self.root)
        a.record("scan", command="one")
        with open(a.path, "ab") as f:
            f.write(b"{not json\n")
        a.record("scan", command="two")            # falls back to a full scan
        self.assertFalse(a.verify()["ok"])


class SnapshotFixes(Base):
    def test_empty_directories_survive_rollback(self):
        (self.root / "app.py").write_text("v1"); (self.root / "logs").mkdir(); (self.root / "a/b").mkdir(parents=True)
        sid = self.store.snapshot("v1")["id"]
        self.store.restore(sid)
        self.assertTrue((self.root / "logs").is_dir())
        self.assertTrue((self.root / "a/b").is_dir())

    def test_directories_emptied_by_the_restore_are_still_cleaned(self):
        (self.root / "app.py").write_text("v1")
        sid = self.store.snapshot("v1")["id"]
        (self.root / "new/deep").mkdir(parents=True); (self.root / "new/deep/x.txt").write_text("x")
        self.store.restore(sid)
        self.assertFalse((self.root / "new").exists())

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_chrono_directory_is_private(self):
        os.chmod(self.root / ".chrono", 0o755)
        (self.root / "a.txt").write_text("x")
        self.store.snapshot("v1")
        self.assertEqual(os.stat(self.root / ".chrono").st_mode & 0o077, 0)


class PolicyAllowList(Base):
    def setUp(self):
        super().setUp()
        (self.root / "chrono-policy.yaml").write_text("allow:\n  - rm -rf node_modules\n  - rm -rf dist/*\n")
        self.policy = policymod.load(".")

    def ev(self, cmd):
        return policymod.evaluate(cmd, self.policy)

    def test_exact_entries_are_allowed(self):
        for cmd in ["rm -rf node_modules", "  rm -rf node_modules  ", "rm -rf dist/cache", "rm -rf dist/app.js"]:
            r = self.ev(cmd)
            self.assertEqual(r["action"], "allow", cmd)
            self.assertIn("allowlisted", r)

    def test_nothing_beyond_the_entry_is_allowed(self):
        for cmd in ["rm -rf node_modules; rm -rf /", "rm -rf node_modules && rm -rf ~", "rm -rf node_modules/../..",
                    "rm -rf node_modules /", "rm -rf dist/a/b", "rm -rf dist/../..", "rm -rf node_modules\nrm -rf /",
                    "rm -rf node_modules | sh", "sudo rm -rf node_modules", "rm -rf node_modules2"]:
            self.assertEqual(self.ev(cmd)["action"], "block", cmd)

    def test_custom_block_rules_still_beat_the_allow_list(self):
        (self.root / "chrono-policy.yaml").write_text(
            "allow:\n  - rm -rf node_modules\nrules:\n  - name: no-nm\n    pattern: \"node_modules\"\n    score: 99\n    action: block\n")
        r = policymod.evaluate("rm -rf node_modules", policymod.load("."))
        self.assertEqual(r["action"], "block")

    def test_unsafe_entries_are_rejected_when_loading(self):
        for bad in ["rm -rf x; rm -rf /", "rm -rf $HOME", "rm `x`", "a | b", "rm **", "x > y"]:
            (self.root / "chrono-policy.yaml").write_text('allow:\n  - "%s"\n' % bad)
            with self.assertRaises(policymod.PolicyError, msg=bad):
                policymod.load(".")


class ScannerFixes(unittest.TestCase):
    def test_always_true_where_is_not_a_where(self):
        for cmd in ["DELETE FROM t WHERE 1=1", "delete from t where 1 = 1;", "UPDATE t SET a=0 WHERE true", "DELETE FROM t WHERE 1"]:
            self.assertTrue(assess(cmd)["blocked"], cmd)
        for cmd in ["DELETE FROM t WHERE id=1", "DELETE FROM t WHERE id=1 AND 1=1", "UPDATE t SET a=0 WHERE id=7"]:
            self.assertFalse(assess(cmd)["blocked"], cmd)

    def test_oversized_input_fails_closed_and_stays_fast(self):
        import time
        payload = "ls " + "a" * (MAX_SCAN + 10) + " ; rm -rf /"
        t = time.time(); r = assess(payload); el = time.time() - t
        self.assertTrue(r["blocked"])
        self.assertIn("Input larger than 64 KB was not fully inspected", r["reasons"])
        for hostile in ["x" * 4_000_000, "rm " + "-" * 4_000_000, "sudo " * 800_000]:
            t = time.time(); self.assertTrue(assess(hostile)["blocked"]); el = max(el, time.time() - t)
        self.assertLess(el, 1.0)

    def test_padding_cannot_hide_a_payload(self):
        self.assertTrue(assess("rm -rf /" + " " * 200000 + "# padding")["blocked"])
        self.assertTrue(assess("# padding " * 30000 + "\nrm -rf /")["blocked"])

    def test_grep_patterns_are_data_but_substitutions_still_run(self):
        self.assertFalse(assess("grep -rn 'DROP TABLE' migrations/")["blocked"])
        self.assertTrue(assess("grep \"$(rm -rf /)\" f")["blocked"])
        self.assertTrue(assess("grep x f; rm -rf /")["blocked"])
        self.assertTrue(assess("grep -rl x . | xargs rm -rf")["blocked"])


if __name__ == "__main__":
    unittest.main()
