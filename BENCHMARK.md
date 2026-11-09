# Scanner benchmark

Reproduce: `python benchmarks/scanner_benchmark.py` (prints the same table). For the wider attack suite
(recovery, audit, access control, gateway) see `RED_TEAM_REPORT.md` and `python benchmarks/redteam.py`.

## What this is — and is not

The corpus (`tests/scanner_corpus.py`) was written by the same people who wrote the rules. These numbers show
**progress and regressions**, not accuracy on commands nobody has seen. Treat 100% on this table as
"no known failures", not as "catches everything". Add commands from real incidents to the corpus as you meet
them; every miss you add becomes a permanent test.

## Shared corpus: 0.4.0rc1 scanner vs current

| Check | 0.4.0rc1 | Current | Commands |
|---|---|---|---|
| Dangerous commands blocked | 33 (31%) | 108 (100%) | 108 |
| Obfuscated dangerous commands blocked | 15 (68%) | 22 (100%) | 22 |
| Everyday commands left alone (no false alarm) | 82 (93%) | 88 (100%) | 88 |
| Inline-code commands visible (score >= 30, not blocked) | 1 (17%) | 6 (100%) | 6 |

Average scan time is about 0.07 ms per command.

## Unseen spot-checks

Round 1 (50 fresh commands, written after the rules): old scanner 16/25 dangerous blocked, current 24/25, no false alarms.

Round 2 (the red-team: 43 dangerous + 41 everyday commands, written after the rules existed and aimed at likely gaps):
**28/43 dangerous blocked, 41/41 everyday clean.** The 15 misses were then fixed and added to the corpus, so
the corpus numbers above are no longer "unseen". Full detail in `RED_TEAM_REPORT.md`.

The author of the rules and of both test sets is the same, so treat these as honest self-checks, not an independent audit.

## Known gaps (cannot be closed by text matching)

Variables (`a=rm; $a -rf /`), encoded payloads that are not piped to a shell, compiled programs, and disk-filling.
Closing these needs enforcement outside the scanner: least-privilege credentials, OS sandboxing, containers, Git
and backups. Run `python benchmarks/scanner_benchmark.py` to see them.

**Closed in 0.5.0: what a script file does.** When the scanner knows the folder a command runs in, which every
enforcing path does (`chrono_run`, the guard hook, `chrono run`, `chrono scan`), it reads and scans the scripts, package
scripts and make targets the command starts (`python cleanup.py`, `node cleanup.js`, `./deploy.sh`, `npm test`,
`make nuke`). The numbers in the table above are for `assess(cmd)` without a folder, so they did not change.
`python benchmarks/redteam.py` checks the script cases.
