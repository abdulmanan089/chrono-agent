# Verification — chrono-agent 0.5.0

Environment: **Windows 11 Pro 10.0.26200, Python 3.13.5 (64-bit)**, Microsoft Defender on, git not installed, no
symlink privilege (no Developer Mode). Run on 9 November 2026. Earlier releases were verified on Linux only; this is
the first full run on Windows.

## Automated tests
`python -m unittest discover -s tests` → **235 tests, OK, 5 skipped** (about 4 minutes).

The 5 skipped tests need things this machine does not have: 2 need symlink rights, 2 test POSIX file permissions,
1 needs git. They run on Linux and macOS CI (`.github/workflows/tests.yml`).

New in 0.5.0: `tests/test_v050.py` (62 tests: signed audit log and witness, guard hook, script inspection, read-only
savepoints, prune and retention, policy pin, control-file rules). `tests/test_persistence_round.py` now runs
without pytest.

## Benchmarks
- `python benchmarks/scanner_benchmark.py`: 108/108 dangerous commands blocked, 22/22 obfuscated variants blocked,
  88/88 everyday commands left alone, 6/6 inline-code commands visible. About 0.4 ms per command on this machine.
- `python benchmarks/redteam.py`: **45 PASS, 0 FAIL, 8 LIMIT (by design) of 53**, in 81 s. The first snapshot of
  5,000 files took 23.0 s. Details are in `RED_TEAM_REPORT.md`.

## The 0.4.1rc2 audit, re-run against 0.5.0
The original audit probes ran again through a real MCP server process over stdio, in a throwaway project:
**30 of 30 checks passed**.

| Area | Result |
|---|---|
| Gate | `robocopy /MIR` through `chrono_run` refused (`executed: false`, dummy files byte-identical). `vssadmin delete shadows` (both forms), `bcdedit ... recoveryenabled No`, `sc stop WinDefend`, Run-key `reg add`, `rd /s /q C:\Users`: all blocked (92-96). |
| Benign | `cd && dir /a` and `python --version` ran with no savepoint (read-only). `python app.py` ran with a savepoint and a `covers` note. `pip install requests` and `npm test` allowed (LOW); `python -c` allowed (MEDIUM). |
| Recovery | status saw exactly 1 added, 2 deleted, 1 modified; rollback restored byte-identical SHA-256; redo savepoint returned; the reply states its scope. |
| Audit | live log: all records signed, external witness matches. On copies: an edited record, a deleted record, **a deleted record with every later hash recomputed (the 0.4.1rc2 finding)**, a signature-stripping downgrade and a cut-off tail were all detected. |
| H2/H3/H6 | guard hook refused `rm -rf /`, a script with `shutil.rmtree`, and `chrono approvals approve` (exit 2); allowed `echo hello` (exit 0); refused an agent edit of `chrono-policy.yaml`. `python cleanup.py` with `rmtree` inside: blocked (90). An allow-listed registry edit was allowed while the Run key stayed blocked (95). |

## Performance on this machine
Snapshot of 1,000 small files in the temp folder (Microsoft Defender scans every file opened there):

| | 0.4.1rc2 | 0.5.0 |
|---|---|---|
| first snapshot | 13.7 s | 4.9 s |
| next savepoint, nothing changed (the usual automatic savepoint) | 9.7 s | 1.8 s |

Existing objects are size-checked instead of re-hashed (restore still verifies every digest), the "did files
change during the snapshot" check compares size and modification time instead of hashing everything again, and
larger projects are stored by up to 8 threads. Every file is still written atomically and fsynced.

## Installed-package smoke test
`python -m pip install chrono-agent-0.5.0.zip` into a fresh virtual environment (pip fetched setuptools for the
build), then the installed `chrono` command in a new project, all real commands:

- `chrono --version` → `chrono-agent 0.5.0`
- `chrono init`; `chrono scan "vssadmin delete shadows /all /quiet"` → 95/100 CRITICAL, block
- `chrono run <python> app.py` → savepoint, program output, COMMIT
- `chrono guard install` → settings written, self-test: harmless sample exit 0, dangerous sample exit 2; `chrono guard status` → installed
- `chrono policy pin` → pinned; `chrono audit --verify` → chain intact (HMAC-signed), external witness matches
- MCP over stdio: `tools/list` → 7 tools; `chrono_run` of `del .chrono\audit.jsonl` → blocked (92)

## Not verified
- Linux and macOS for this release (the CI workflow is included but has not run, because there is no GitHub repository).
- The guard hook inside a live Claude Code session. The hook protocol (JSON on stdin, exit code 2 refuses, `permissionDecision: ask`) was exercised by running the exact command the client runs, not through the client itself.
- Postgres/MySQL rollback, the git post-commit hook, and symlink handling on this machine (no git, no symlink rights).
- An independent human penetration test. These results come from the author's tests and an AI-run re-test; they are not a certification.
