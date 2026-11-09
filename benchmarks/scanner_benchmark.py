"""Compare the 0.4.0rc1 scanner with the current one on the shared corpus.

    python benchmarks/scanner_benchmark.py            # print a report
    python benchmarks/scanner_benchmark.py --markdown # Markdown for BENCHMARK.md

The corpus is self-authored (see tests/scanner_corpus.py), so these numbers
show regressions and progress, not accuracy on unseen real-world commands.
"""
import importlib.util
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from scanner_corpus import EVASIONS, KNOWN_GAPS, MUST_ALLOW, MUST_BLOCK, MUST_FLAG  # noqa: E402
from chrono_agent.interceptor import assess as new_assess  # noqa: E402

spec = importlib.util.spec_from_file_location("old_scanner", HERE / "interceptor_0_4_0rc1.py")
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)


def rate(assess, commands, test):
    hits = [c for c in commands if test(assess(c))]
    return len(hits), len(commands), [c for c in commands if c not in hits]


def main(markdown=False):
    rows = [
        ("Dangerous commands blocked", MUST_BLOCK, lambda r: r["blocked"]),
        ("Obfuscated dangerous commands blocked", EVASIONS, lambda r: r["blocked"]),
        ("Everyday commands left alone (no false alarm)", MUST_ALLOW, lambda r: not r["blocked"] and r["score"] < 30),
        ("Inline-code commands visible (score >= 30, not blocked)", MUST_FLAG,
         lambda r: 30 <= r["score"] < 70),
    ]
    out = []
    for label, cmds, test in rows:
        o_ok, n, _ = rate(old.assess, cmds, test)
        n_ok, _, n_missed = rate(new_assess, cmds, test)
        out.append((label, o_ok, n_ok, n, n_missed))

    t = time.perf_counter()
    allc = MUST_BLOCK + EVASIONS + MUST_ALLOW + MUST_FLAG
    for _ in range(20):
        for c in allc:
            new_assess(c)
    per_ms = (time.perf_counter() - t) / (20 * len(allc)) * 1000

    if markdown:
        print("| Check | 0.4.0rc1 | Current | Commands |\n|---|---|---|---|")
        for label, o, n_, total, _ in out:
            print("| %s | %d (%.0f%%) | %d (%.0f%%) | %d |" % (label, o, 100.0 * o / total, n_, 100.0 * n_ / total, total))
    else:
        print("%-58s %10s %10s %6s" % ("Check", "0.4.0rc1", "current", "of"))
        for label, o, n_, total, missed in out:
            print("%-58s %10d %10d %6d" % (label, o, n_, total))
            for c in missed:
                print("    still wrong: %r" % c)
    print("\nScan time: %.3f ms per command (average over %d commands)" % (per_ms, len(allc)))
    print("\nKnown gaps (a text scanner cannot know these):")
    for cmd, why in KNOWN_GAPS:
        r = new_assess(cmd)
        print("  %-42r -> %-6s score %-3d  (%s)" % (cmd, "BLOCK" if r["blocked"] else "allow", r["score"], why))


if __name__ == "__main__":
    main("--markdown" in sys.argv)
