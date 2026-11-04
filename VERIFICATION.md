# Verification — chrono-agent 0.3.0

Environment: Linux (Python 3.13), build sandbox. Windows/macOS were NOT available.

## Automated tests
- `python3 -m unittest discover -s tests` → **88 tests, OK, 1 skipped**.
  The skipped test is the Git post-commit hook end-to-end test: the build
  sandbox forbids `git init`, so hook install/commit was not exercised here.
  `gitlink` read functions (`is_repo`, `head`, status fields) are pure
  `git rev-parse` calls and ran against a real repository. Run the suite on
  your own machine to exercise the hook test.

## Installed-CLI smoke test (clean venv, `pip install` from source)
All of the following ran successfully as real shell commands:
1. `chrono init` → snapshot → edit file → `status` shows diff → `rollback -y` → file back to V1.
2. Policy file with approver list: `chrono policy` validates; `chrono run --approver manan --approval-reason test -- python3 -c ...` executes and COMMITs.
3. `chrono team add manan --role admin`, `chrono team list`.
4. sqlite: `db add` → `db snapshot` → DELETE all rows → `db restore -y` → rows back (`[('row1',)]`).
5. `chrono dashboard --out report.html` → report contains "CHAIN INTACT".
6. `chrono mcp` over stdio: `initialize` returns serverInfo chrono-agent 0.3.0; `chrono_scan` on `rm -rf /` returns blocked=true.
7. Remote audit push: unit test with a local HTTP sink — only new records are sent, `--verify-remote` chain-head comparison matches, `file://` URLs rejected.

## Unit-tested behaviors (new in 0.3.0)
- Policy: custom block/approve rules, thresholds, approvers; invalid files and bad regexes rejected; approve-threshold validation.
- Approval flow: unknown/missing approver → exit 3, command never executes, denial audited; named approver → executes, `run.approved` recorded.
- Team: first member must be admin, last admin protected, role gate blocks viewer and passes admin, no policy → no gate.
- MCP: initialize, tools/list (6 tools), scan/snapshot/status/rollback/audit-verify flow; rollback without `confirm:true` refused with file untouched; notifications ignored; unknown method → -32601; stdio framing.
- Remote audit: incremental push, verify-remote, bad scheme rejection.
- Dashboard: report contains snapshots, audit records, risk levels, chain status.

## NOT verified (be honest with users)
- **Windows and macOS**: no native run. Platform-specific code paths (msvcrt locking, ANSI enable, cmdline quoting) exist but are untested on real Windows/macOS.
- **Git post-commit hook**: skipped in this sandbox (see above).
- **Postgres/MySQL rollback**: code uses standard pg_dump/psql/mysqldump/mysql CLI tools but no live server was available to test against.
- **PyPI publish**: package is prepared (LICENSE, metadata, PUBLISHING.md) but publishing requires the owner's PyPI account.
- **Company dashboard / central team accounts**: not built — the local HTML report and local roster are single-project, single-machine features.
