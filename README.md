# Chrono Agent — a safety layer for AI coding agents

[![PyPI](https://img.shields.io/pypi/v/chrono-agent?label=PyPI)](https://pypi.org/project/chrono-agent/)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-source--available-orange)
![Tests](https://img.shields.io/badge/tests-235%20run%20%C2%B7%200%20failed-brightgreen)
![Red team](https://img.shields.io/badge/red%20team-45%20pass%20%C2%B7%200%20fail%20%C2%B7%208%20limits-brightgreen)
![Tested on](https://img.shields.io/badge/tested%20on-Windows%2011-informational)

```bash
pip install --upgrade chrono-agent
```

| What was measured (Windows 11, Python 3.13) | Result |
|---|---|
| Dangerous commands blocked (scanner corpus) | **108 / 108** |
| Obfuscated variants blocked | **22 / 22** |
| Everyday developer commands left alone | **88 / 88** (no false alarms on this corpus) |
| Unit and integration tests | **235 run · 230 passed · 5 skipped · 0 failed** |
| Red-team suite | **45 pass · 0 fail · 8 known limits** of 53 |
| First snapshot, 5,000 files | **23.0 s** (137.5 s before the 0.5.0 optimisation, about 6× faster) |
| Savepoint with nothing changed, 1,000 files | **1.8 s** (9.7 s in 0.4.1rc2) |

The corpus and the red-team suite were written by the project and extended with an AI assistant (Claude). They catch regressions; they are not an independent security audit. Details: `VERIFICATION.md`, `RED_TEAM_REPORT.md`, `docs/`.

```
  AI agent: Claude Code / Claude Desktop / any MCP client / chrono run
        |
        v
  [1] GATE         105 rules + de-obfuscation + scripts, npm scripts and make targets it runs
        |          risk >= 70 -> refused before any process starts
        v
  [2] SAVEPOINT    content-addressed copy of the project files (skipped for read-only commands)
        |
        v
      command runs
        |
        v
  [3] ROLLBACK     byte-identical restore, every rollback can be undone (rescue savepoint)
        |
        v
  [4] AUDIT LOG    HMAC-SHA256 signed chain; key and external witness kept outside the project
```

Chrono Agent sits between an AI coding agent and your machine. It does four things:

1. **Stops dangerous commands before they run.** This includes the scripts a command starts (`python cleanup.py`, `npm test`, `make clean`, `x.bat`), not only the command text.
2. **Takes a savepoint before every command that can change files** (and whenever you ask), so a bad change to your project files can be rolled back, and the rollback itself can be undone.
3. **Keeps a signed, tamper-evident audit log** of everything that was scanned, blocked, run, restored or approved.
4. **Guards the agent's own shell and edit tools** (Claude Code hook), not only the commands it chooses to send to Chrono.

It is a dependency-free Python package (3.8+) with a CLI (`chrono`), an MCP server for AI clients, and a Python SDK. The fleet gateway pilot is described in `FLEET.md`.

> **Read "What Chrono cannot do" below before you rely on it.** It is a guardrail for cooperating tools on one machine. It is not a sandbox, an antivirus or a backup.

## Install / upgrade
```cmd
python -m pip install --upgrade chrono-agent
python -m chrono_agent --version
```
Expected: `chrono-agent 0.5.0`. If `chrono` is not on PATH, every example also works as `python -m chrono_agent ...`. Python 3.8 or newer is required.

Upgrading from 0.4.x keeps your `.chrono` folders. Old audit records keep verifying, and new records are signed from the first action after the upgrade (see *Audit trail*).

## Quick start with an AI agent (Claude Code, Claude Desktop, Cursor)
In your project folder:

```cmd
chrono init
chrono guard install
chrono policy pin
```

* `chrono init` starts tracking the folder and takes the first savepoint.
* `chrono guard install` adds a PreToolUse hook to `.claude/settings.json`. From then on, every Bash/PowerShell command and every file edit the agent makes goes through Chrono first. The command runs a self-test and tells you if the hook works with your Python. Restart the client afterwards.
* `chrono policy pin` (optional, after you write a `chrono-policy.yaml`) locks the policy. If anyone edits it later, every command is refused until a person reviews the change and pins again.

For clients that use MCP, add Chrono as a server (`examples/mcp-config.json`):

```json
{ "mcpServers": { "chrono": { "command": "python", "args": ["-m", "chrono_agent", "mcp"] } } }
```

OpenAI Codex CLI reads MCP servers from `~/.codex/config.toml`:

```toml
[mcp_servers.chrono]
command = "python"
args = ["-m", "chrono_agent", "mcp"]
```

Claude Desktop and Claude Code were tested with this release. Codex and other MCP clients use the same stdio protocol but have not been tested yet.

The MCP server exposes `chrono_scan`, `chrono_run`, `chrono_snapshot`, `chrono_status`, `chrono_log`, `chrono_rollback` and `chrono_audit_verify`. `chrono_run` is the enforced path: blocked commands never start.

To make `chrono_run` the **only** way the agent can run commands, deny the client's own shell tools:

```cmd
chrono guard install --deny-raw-shell
```

## Command reference (one command at a time)
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
chrono guard install
chrono guard status
chrono guard uninstall
chrono policy
chrono policy pin
chrono prune --keep-auto 200 --dry-run
chrono audit
chrono audit --verify
chrono audit --keys
chrono audit --rotate-key
chrono audit --reset-witness
chrono audit --csv --out audit-report.csv
chrono audit --push https://audit.example.com/ingest --verify-remote
chrono team add sara --role developer
chrono git install-hook
chrono db add appdb --engine sqlite --path app.db
chrono db snapshot appdb
chrono db restore appdb
chrono dashboard --out report.html
chrono mcp
chrono --help
```
Try these in a disposable test project first. `init` is idempotent. Default rollback restores the current branch HEAD; choose an ID from `log` to go further back. Every rollback first saves a **rescue savepoint** of unsaved changes and prints `undo this rollback: chrono rollback ID`.

## The guard hook (closes the "other shell" gap)
An MCP server only sees what the agent sends to it. An agent that also has the client's own Bash or PowerShell tool could run anything around Chrono. `chrono guard install` closes that gap for Claude Code and compatible clients. The client runs `python -m chrono_agent guard hook` before each tool call and passes the call as JSON:

| Chrono decision | What the client does |
|---|---|
| block (risk 70+, or a policy `block` rule) | refuses the call (exit code 2) and shows the reason to the agent; nothing runs |
| approve (policy approval band) | asks the person at the keyboard (`permissionDecision: ask`) |
| allow | takes a savepoint first (not for read-only commands), then follows the client's normal permission rules; the guard never auto-approves |

File edits (Write, Edit, MultiEdit, NotebookEdit) are refused when they target Chrono's own control files: `.chrono/`, `chrono-policy.yaml`, `.claude/settings*.json` and the Chrono home with its keys. Any error inside the guard blocks the call (fail closed). The hook settings are control data: a rollback never removes or reverts them.

`--scope user` installs into `~/.claude/settings.json` instead, so dangerous commands are refused in every folder, not just Chrono projects. `chrono guard status` shows what is installed and runs the self-test again; do that after every Python or Chrono upgrade.

## What the scanner reads
Every command is matched against 100+ rules: recursive and forced deletes in shells and languages, disk and partition wipes, shadow-copy/backup/recovery wiping, firewall and Defender tampering, autostart registry keys and scheduled tasks, secret exfiltration, reverse shells, encoded payloads, database wipes, git history rewrites, cloud and Kubernetes deletes, and more. It looks through common text obfuscation (quote splitting, backslashes, zero-width characters, `$IFS`, brace expansion).

**New in 0.5.0:** on every enforcing path (`chrono_run`, the guard, `chrono run`, `chrono scan`) it also reads what the command will run, in the project folder:

* script files: `python x.py`, `python -m pkg.mod`, `node x.js`, `deno run`, `bun run`, `ruby`, `perl`, `php`, `bash x.sh`, `./x.sh`, `x.bat`, `cmd /c x.cmd`, `powershell -File x.ps1`, and the scripts those batch/shell files start;
* package scripts: `npm test`, `npm run build` (including `pre`/`post` scripts), `npm install` / `yarn` (the project's own `preinstall`/`install`/`postinstall`/`prepare`), `yarn X`, `pnpm X`;
* make targets: `make`, `make clean`, and the targets they depend on.

Inside files only clear findings count (score 60+), and comment lines are skipped. Files over 1 MB, more than 16 scripts per command, or nesting deeper than 4 levels are refused rather than half-checked. Without the project folder (`assess(cmd)` in the SDK) nothing is read, as before.

## Savepoints, rollback and what they cover
`chrono_run` and the guard take an automatic savepoint before each command that could change files. Read-only commands (`dir`, `ls`, `type`, `git status`, `git log`, `python --version`, `pip list`, `chrono status` and similar) skip it, because they cannot change anything. Set `CHRONO_SAVEPOINTS=always` to take one anyway. On Windows a program with the same name in the project folder (for example a `where.bat`) is never treated as read-only.

**A rollback restores the tracked files in the project folder, and nothing else.** It does not undo:

* system changes: registry, services, scheduled tasks, shadow copies, boot settings, firewall/Defender settings, installed software;
* files outside the project folder, or in ignored folders (`.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `.idea`, `.vscode`);
* network calls, messages, payments, cloud resources;
* databases you did not register with `chrono db add` (and registered ones only back to their last `chrono db snapshot`).

For those, the scanner's block is the only protection, which is why Chrono blocks them. Every `chrono_run` and `chrono_rollback` reply states this scope in its `covers` field, so an agent cannot mistake the time machine for a whole-system restore.

Old automatic savepoints can be pruned: `chrono prune --keep-auto 200` or `--older-than 30` (days), with `--dry-run` first. Manual snapshots, commits, merges and branch heads are never pruned. History stays linked and unused file versions are removed. A `retention:` section in the policy applies the same limits automatically after each `chrono_run`.

## Audit trail
Every state change, scan, block, approval, guard decision and policy change is appended to `.chrono/audit.jsonl`: who, when, from which host and folder, which snapshot, the risk score and the outcome.

**Since 0.5.0 the log is signed by default.** Each record carries an HMAC-SHA256 made with a key stored **outside the project**, in `%USERPROFILE%\.chrono-agent\keys` (or `$CHRONO_HOME/keys`), created on first use. Someone who can only write the project folder can no longer rebuild a valid-looking chain after editing it. After each record Chrono also updates an **external witness** (the newest record's number and digest, in the same home folder). Cutting off the newest records, or replacing the whole log, is therefore detected too, and the next write does not hide it.

```cmd
chrono audit --verify            " chain, signatures, witness and snapshot anchors
chrono audit --keys              " key id and key-store location (never the key itself)
chrono audit --rotate-key        " new key; older records keep verifying
chrono audit --reset-witness     " after you restored .chrono from a backup on purpose (recorded)
```

* **Back up `.chrono-agent\keys`.** A log whose key is lost can no longer be verified.
* `CHRONO_AUDIT_KEY=<secret>` uses a key you manage yourself (a vault, a CI secret) instead of the key store.
* `CHRONO_AUDIT_REQUIRE_KEY=1` is strict mode: unsigned records fail verification and unsigned writing is refused.
* `CHRONO_AUDIT_UNSIGNED=1` switches signing off (the 0.4 behaviour). Use it only for testing.
* Records from 0.4 stay valid as an older-format prefix. A signed log that later contains an unsigned record fails, because that is what a downgrade attack looks like.
* `CHRONO_MODEL` / `CHRONO_AGENT` label every record with the model and client. They are self-reported labels, not proof of identity.

## Policy file (`chrono-policy.yaml`)
A starting point is in `examples/chrono-policy.yaml`. It covers thresholds (`block`, `approve`), custom `rules`, an exact-command `allow:` list (backslashes allowed since 0.5.0, for example `reg add HKCU\Software\MyCompany\MyApp /v * /d * /f`), named `approvers`, `roles`, the `gates: mcp.rollback: approve` human gate, and `retention`. `chrono policy` validates the file. A broken policy blocks every enforced command until it is fixed (fail closed).

* `chrono policy pin` stores the file's fingerprint (signed) in the Chrono home. After that, any edit blocks every command on the enforcing paths until a person runs `chrono policy pin` again.
* Every change Chrono notices is written to the audit log as `policy.changed`.
* The policy is control data: snapshots ignore it, so a rollback never deletes or reverts it.

## Run / rescue behaviour (`chrono run`)
Programs run with exact argument boundaries, without a shell by default (`chrono run -- python "my agent.py"`). A successful run saves a post-command snapshot before printing COMMIT. On failure: `r` rolls back, `d` shows the diff (the program is not rerun), `t` retries, `k` keeps changes uncommitted, and end of input rolls back. Shell mode needs one quoted string: `chrono run --shell "echo hello"`. `--force` bypasses the scanner, not OS permissions. It needs the `run.force` role if the policy sets one, and the scanner refuses `chrono run --force` when an agent tries it through the guard or `chrono_run`.

## Python SDK
```python
from chrono_agent import Transaction

with Transaction(".", "trusted agent") as tx:
    # first set of edits
    tx.savepoint("models")
    # more edits; tx.rollback_to("models") keeps the first set
# an exception restores BEGIN; a clean exit saves COMMIT
```

## What Chrono cannot do (read this)
- **It is not a sandbox.** A program that is allowed to run can do anything your account can do. The scanner reads command text and the scripts a command starts. It cannot follow variables (`a=rm; $a -rf /`), decode arbitrary payloads, see inside compiled programs (`.exe`, `.pyc`) or modules a script imports, or know what a remote server does. For hostile code, run agents with least privilege in a container or VM.
- **Enforcement covers the paths that go through Chrono:** MCP `chrono_run`, the guard hook, `chrono run`. An agent with an unguarded shell, an IDE extension that runs its own commands, or a person at a terminal are not covered.
- **Rollback covers project files only** (see *Savepoints, rollback and what they cover*). Keep independent backups.
- **Local trust boundary:** keys, witnesses and pins live in the Chrono home of the same OS account. Anyone who can read that folder can forge records, and anyone who can write it can move the witness or pin. Use `CHRONO_AUDIT_KEY` from a vault and `chrono audit --push` to a store the agent cannot reach when that matters.
- **Approvals and roles are named, not authenticated.** A process with its own unguarded shell can run `chrono approvals approve`. The guard refuses that command from the agent, but only the guard path is covered.
- Symlinks and special files are not tracked. Empty directories, ACLs, timestamps and alternate streams are not preserved. Very large files are held in memory during snapshot and restore.
- Power loss or `kill -9` in the middle of a restore can leave a partial restore. `.chrono` is not an independent backup.
- The fleet gateway's own event chain (`FLEET.md`) is still plain SHA-256. It is a pilot.

## Tests
In the extracted package folder:
```cmd
python -m unittest discover -s tests -v
python benchmarks\scanner_benchmark.py
python benchmarks\redteam.py
```
Tests use temporary projects and a temporary Chrono home, never your real project or keys. Results and the test environment are in `VERIFICATION.md`. What changed since the 0.4.1rc2 audit is in `docs/REMEDIATION.md`, and the threat model is in `SECURITY.md`.

## Reports
- `docs/Chrono-0.5.0-Release-Report.md`: architecture and verification report for 0.5.0.
- `docs/chrono-audit-report.html`: the functional test of 0.4.1rc2 and the re-test of 0.5.0 (30/30 checks). It was run by an AI assistant and is not a certification.

## License
Copyright (c) 2026 Abdul Manan. Chrono Agent is **source-available, not open source**. You may install and use it, including inside your company, and read the code. You may not resell it, offer it as a hosted service, or distribute modified versions without a commercial license. See `LICENSE`; for commercial terms see `LICENSE-COMMERCIAL.txt` or write to manandogar112@gmail.com.
