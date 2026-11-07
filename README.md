# ChronoAgent 0.4.0rc1 — local file recovery CLI with a tamper-evident audit trail

A dependency-free Python tool for snapshots, granular savepoints, rollback, branches, conservative three-way merges, advisory command scanning and an append-only audit log of every action. The website is a separate simulator. The fleet pilot can proxy OpenAI-compatible Chat Completions and Anthropic Messages; see FLEET.md for setup and coverage limits.

## Install / upgrade in Windows CMD
Download the ZIP without extracting it. In its download folder:

```cmd
python -m pip install --user --upgrade chrono-agent-0.4.0rc1.zip
python -m chrono_agent --version
```
Expected: `chrono-agent 0.4.0rc1`. If `chrono` is not on PATH, all examples also work by replacing `chrono` with `python -m chrono_agent`. Restart CMD after a permanent PATH change. Python 3.8 or newer is required. This release candidate has not been published to PyPI.

## Continue the test folder from 0.1.0
```cmd
cd /d "%USERPROFILE%\chrono-dev-test-01"
chrono run python success_agent.py
python app.py
chrono status
chrono log
```
Expected: `COMMIT sp_...`, `VERSION_3`, `(no changes)`, and a new `COMMIT: python success_agent.py` snapshot at HEAD. Existing 0.1.0 snapshots are readable; do not delete `.chrono`.

## Command reference (one command at a time, never a pipeline)
```cmd
chrono init
chrono snapshot -m "before agent"
chrono run python agent.py
chrono status
chrono diff
chrono log
chrono rollback
chrono branch feature
chrono checkout main
chrono merge feature
chrono scan "rm -rf /"
chrono audit
chrono audit --verify
chrono audit --csv --out audit-report.csv
chrono audit --push https://audit.example.com/ingest --verify-remote
chrono policy
chrono team add sara --role developer
chrono team list
chrono git install-hook
chrono git status
chrono db add appdb --engine sqlite --path app.db
chrono db snapshot appdb
chrono db restore appdb
chrono dashboard --out report.html
chrono mcp
chrono --help
```
Use these only inside a disposable test project initially. `init` is idempotent. Default rollback restores the current branch HEAD, not automatically its parent; choose an ID from `log` to restore an older version. It asks `[y/n]`; enter `y` before typing any further command. `rollback -y` skips confirmation and discards unsaved tracked changes.

`branch NAME` creates **and switches** to that branch. Branch creation and checkout save dirty source work before leaving it. Merge requires clean work, preserves independent changes, records both parents, and stops without changes if both branches alter the same file differently. It is file-level merge, not automatic line-level conflict resolution.

## Run / rescue behavior
Programs run with exact argument boundaries, without a shell by default. Use `--` if needed:

```cmd
chrono run -- python "my agent.py"
```
A successful run saves a post-command snapshot **before** printing COMMIT. On failure:
- `r`: rollback tracked files to the pre-command snapshot; the CLI still returns the child's failure code.
- `d`: inspect diff only; the program is NOT rerun.
- `t`: explicitly retry the program against the current changed files; non-idempotent actions can repeat.
- `k`: keep changes without committing; returns the failure code.
- EOF / redirected input: rollback by default.

Intentional shell execution must pass one quoted string. In Windows CMD:
```cmd
chrono run --shell "echo hello"
```
In Unix, the shell is `/bin/sh`; in Windows it is CMD/COMSPEC, not the invoking PowerShell. Batch files require explicit shell mode. `--force` bypasses the advisory detector, NOT OS permissions; never use it just to suppress a warning on an untrusted command.

## Audit trail
Every action that changes state, plus every risk scan, is appended to `.chrono/audit.jsonl`: who ran it, when, from which host and folder, which snapshot it produced, the risk score of any command, and the outcome (`ok`, `blocked`, `aborted`, `uncommitted`, `rolled back`).

```cmd
chrono audit                    " newest 25 records
chrono audit -n 0               " all records
chrono audit --action run.commit
chrono audit --verify           " check the chain for tampering
chrono audit --csv --out audit-report.csv
chrono audit --json --out audit-report.json
```

Each record stores the digest of the record before it, so editing, deleting or reordering an entry breaks the chain and `--verify` reports the first bad record. Every snapshot also stores the log head that existed when it was taken, so a log that was rewritten *and* re-chained still fails the cross-check (`snapshot anchors do not match the log`).

To make records unforgeable for anyone who only has the files, set a signing key before the first action and keep it somewhere else (a secret manager, not this folder):

```cmd
set CHRONO_AUDIT_KEY=copy-the-long-secret-from-your-vault
```
Digests then become HMACs; without the key, `--verify` fails loudly instead of reporting a clean chain. Attribution for AI use is taken from the environment:

```cmd
set CHRONO_MODEL=claude-3.5-sonnet
set CHRONO_AGENT=cursor
```
Those two fields are written into every later record, so a report shows which model and which client did what. They are self-reported labels, not proof.

## Demo
```cmd
chrono demo "fix login page and update database"
```
The older quoted-task shorthand still works. Demo runs in an isolated temporary folder and is fully scripted: there is no real AI, login test or database migration. Demo menu letters differ from real `run`: `u` undo failed step, `d` diff, `r` scripted retry, `f` full rollback. Demo files remain in the printed temporary path for inspection.

## Python SDK
```python
from chrono_agent import Transaction

with Transaction(".", "trusted agent") as tx:
    # make first set of local file edits
    tx.savepoint("models")
    # make another set of edits
    # tx.rollback_to("models") preserves the first set
# exception: restore BEGIN; successful exit: save COMMIT
```
Later named savepoints are invalidated after rollback to an earlier one. Duplicate names are rejected. A failed commit triggers recovery; if recovery also fails, the error preserves the original exception as its cause. Locks prevent another cooperating Chrono process from changing the same project's state during a transaction.

## What 0.3.0 adds
- **Policy file** (`chrono-policy.yaml` in the project root): your own command rules with scores and actions (`block` / `approve` / `allow`), custom risk thresholds, a named approver list, and role gates (`rollback: admin` etc.). `chrono policy` validates and shows the active policy. A broken policy file fails closed with a clear error.
- **Approval flow**: when a rule says `approve`, `chrono run` stops until a named human approves — interactively, or with `chrono run --approver manan --approval-reason "release fix" -- <cmd>`. Approvals and denials are written to the audit log.
- **Team roster** (`chrono team add/list/remove`): local per-project names and roles (viewer/developer/admin). The first member must be an admin; the last admin cannot be removed. Role gates come from the policy file; the acting user is `CHRONO_USER` or the OS account. This is a local file, not company accounts — anyone with write access to the folder can edit it.
- **Git integration**: every snapshot records the current Git commit (`git_head` in the snapshot metadata). `chrono git status` shows whether the last savepoint matches the checked-out commit; `chrono git install-hook` adds a post-commit hook that snapshots after every commit (it refuses to touch a hook it did not install).
- **Database rollback** (`chrono db add/snapshot/restore/list/remove`): sqlite is fully supported via SQLite's backup API with an integrity check before restore. Postgres (`pg_dump`/`psql`) and MySQL (`mysqldump`/`mysql`) are implemented against their standard client tools but were NOT tested against a live server in the build environment — verify on your own database before relying on them. A restore overwrites current data and asks `[y/n]` unless `-y` is given.
- **MCP connector** (`chrono mcp`): a Model Context Protocol server over stdio exposing six tools (`chrono_scan`, `chrono_snapshot`, `chrono_status`, `chrono_log`, `chrono_rollback`, `chrono_audit_verify`) to AI clients such as Claude Desktop or Cursor. Client config: `{ "mcpServers": { "chrono": { "command": "chrono", "args": ["mcp"] } } }`. Rollback requires `confirm: true`. Actions are recorded in the audit log with `CHRONO_AGENT`/`CHRONO_MODEL` attribution.
- **Remote audit push** (`chrono audit --push URL [--verify-remote]`): sends only the records the remote has not seen to an append-only HTTP(S) store and can compare chain heads. This closes the "newest records deleted locally" gap — but the remote service itself is not included; the expected request/response contract is documented in `chrono_agent/remote_audit.py`.
- **Local dashboard** (`chrono dashboard --out report.html`): a self-contained HTML report of the audit chain status, actions, outcomes, risk levels, branches, savepoints and records. Single project, offline, no tracking — not the multi-team company dashboard from the roadmap.
- **MIT license** (`LICENSE`) and a step-by-step `PUBLISHING.md` for releasing to PyPI with your own account.

## What 0.2.0 adds
- Append-only, hash-chained audit log of every state-changing action and risk scan (`.chrono/audit.jsonl`).
- `chrono audit` report with `--verify`, `--json`, `--csv`, `--out`, `-n` and `--action`.
- Snapshot anchors: each snapshot stores the audit log head, so a rewritten and re-chained log is still detected.
- Optional HMAC signing with `CHRONO_AUDIT_KEY` so a writer without the key cannot forge records.
- Model and client attribution from `CHRONO_MODEL` / `CHRONO_AGENT` on every record.
- Audit storage is checked for symlinks and is never included in a snapshot.

## What 0.1.1 fixes
- Real successful-run COMMIT snapshots and clean HEAD/status.
- Diff viewing no longer executes a failed program again.
- Exact subprocess arguments, empty-command rejection and explicit shell mode.
- File-level three-way merges instead of wholesale source-tree replacement.
- Conflict detection, source ancestry, clean-work checks and safer checkout.
- Atomic individual object/state writes, verified hashes and UUID snapshot IDs.
- Interprocess operation locks and snapshot mutation checks.
- Traversal/symlink rejection and restore object preflight before deleting files.
- Best-effort in-process recovery on restore write errors and file/directory transitions.
- Per-file POSIX mode restoration; identical bytes need not share permissions.
- Commit-failure, launch-failure, EOF and interrupt recovery paths.
- Idempotent init, readable expected errors, typo rejection and module execution fallback.
- More command-risk variants and removal of misleading ACID/security guarantees.

## Important boundaries — do not call this production ACID or a sandbox
- Only regular files under the selected root are tracked. Run commands from the initialized root; parent discovery is not implemented.
- Symlinks and special files are rejected; symlink-based project layouts need another tool.
- Empty directories, ownership, ACLs, timestamps, hard-link relationships and Windows alternate streams are not preserved. POSIX file mode preservation is supported, not a Windows ACL backup.
- `.chrono`, `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `.idea`, `.vscode` are excluded. Changes in these locations cannot be rolled back. Secret files elsewhere are NOT automatically excluded; do not share snapshot storage.
- Files outside the root, network calls, messages, payments, detached processes and other external effects cannot be undone. Database rollback is limited to databases you explicitly register with `chrono db add`, and only to the point of the last `chrono db snapshot` — it is a dump restore, not a transaction log, so writes after the snapshot are lost on restore.
- The detector is a text heuristic with false positives and bypasses; a Python script can be dangerous despite a LOW score. No real quarantine or OS containment is provided.
- Cooperating CLI processes are serialized. Editors/untrusted children can still alter files or `.chrono`; stop other writers. Checks are not resistant to malicious concurrent symlink replacement.
- Atomic replacement of individual files is not an atomic entire-tree transaction. Power loss, kill -9, disk failure/fullness or a second recovery failure can leave a partial restore. Keep independent backups outside the project. Files are buffered in memory during restore; very large projects are not the target.
- Snapshots inside `.chrono` are not tamper-proof or independent backups. Hard adversarial isolation, crash-safe journals, external backups, universal model routing, distributed multi-agent transactions and database transactions are NOT implemented.
- The audit log is a local file. It detects records that were edited, deleted, reordered or re-chained, but **deleting the newest records leaves no local gap** — use `chrono audit --push` to a store you do not control to close that. The push itself is only as trustworthy as the remote service.
- Team roles and approvals are enforced only inside this CLI on this machine. A developer can bypass them by editing files directly; they are guardrails for cooperating users, not security boundaries. Real company accounts and a central dashboard need a server product that does not exist yet.
- With `CHRONO_AUDIT_KEY`, anyone holding the key can still forge the whole log; the key must live outside the project folder, and losing it makes a signed log unverifiable.
- `CHRONO_MODEL` / `CHRONO_AGENT` are self-reported labels taken from the environment, not verified identity.

## Tests
After extracting the ZIP, in the extracted package folder:
```cmd
python -m unittest discover -s tests -v
```
Tests use temporary projects and safe child scripts, not your real project. Test results and verification environment are in `VERIFICATION.md`.
