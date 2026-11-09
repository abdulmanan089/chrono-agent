import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _home  # noqa: F401  (temporary Chrono home for keys and witnesses)

from chrono_agent.interceptor import assess, level_for
from scanner_corpus import EVASIONS, MUST_ALLOW, MUST_BLOCK, MUST_FLAG


class ScannerCorpusTests(unittest.TestCase):
    def test_dangerous_commands_are_blocked(self):
        for cmd in MUST_BLOCK:
            with self.subTest(cmd=cmd):
                r = assess(cmd)
                self.assertTrue(r["blocked"], "not blocked: %r -> %s" % (cmd, r))

    def test_obfuscated_commands_are_blocked(self):
        for cmd in EVASIONS:
            with self.subTest(cmd=cmd):
                r = assess(cmd)
                self.assertTrue(r["blocked"], "evasion not blocked: %r -> %s" % (cmd, r))

    def test_partly_understood_commands_are_visible_but_not_blocked(self):
        for cmd in MUST_FLAG:
            with self.subTest(cmd=cmd):
                r = assess(cmd)
                self.assertFalse(r["blocked"])
                self.assertGreaterEqual(r["score"], 30)

    def test_everyday_commands_have_no_false_alarms(self):
        for cmd in MUST_ALLOW:
            with self.subTest(cmd=cmd):
                r = assess(cmd)
                self.assertFalse(r["blocked"], "false alarm: %r -> %s" % (cmd, r))
                self.assertLess(r["score"], 30, "flagged: %r -> %s" % (cmd, r))

    def test_docker_rm_flag_is_not_rm_rf(self):
        self.assertEqual(assess("docker run --rm -it --entrypoint bash ubuntu")["score"], 5)

    def test_git_rm_cached_is_safe_but_git_rm_r_is_not(self):
        self.assertFalse(assess("git rm --cached secrets.txt")["blocked"])
        self.assertTrue(assess("git rm -rf src")["blocked"])

    def test_python_rmtree_is_named_correctly(self):
        r = assess("python -c \"import shutil; shutil.rmtree('.')\"")
        self.assertTrue(r["blocked"])
        self.assertEqual(r["reasons"][0], "Recursive delete (Python)")

    def test_reasons_are_unique_and_levels_match_scores(self):
        for cmd in MUST_BLOCK + EVASIONS:
            r = assess(cmd)
            self.assertEqual(len(r["reasons"]), len(set(r["reasons"])))
            self.assertEqual(r["level"], level_for(r["score"]))

    def test_scan_is_fast_on_hostile_input(self):
        import time
        nasty = "rm " + "-" * 5000 + " " + "a" * 5000
        start = time.time()
        assess(nasty)
        assess("x" * 20000)
        assess("delete from " + "a" * 20000)
        self.assertLess(time.time() - start, 3.0)


if __name__ == "__main__":
    unittest.main()
