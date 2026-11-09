# Chrono Agent 0.5.0 — Architecture and Verification Report

**Chrono: a reversible, gated execution layer for AI coding agents**

| | |
|---|---|
| Release | chrono-agent 0.5.0 (PyPI classifier: Development Status 4 - Beta) |
| Report date | 9 November 2026 |
| Test platform | Windows 11 Pro 10.0.26200, Python 3.13.5 (64-bit), Microsoft Defender on |
| Evidence | `VERIFICATION.md`, `RED_TEAM_REPORT.md`, `docs/REMEDIATION.md`, `SECURITY.md` in the release ZIP |
| Report type | Technical release report: what Chrono does, how it works, and what was measured. **Not a certification.** |

> **How to read this report.** Every number below was measured on the platform above, and the commands to reproduce it are in Appendix A. The tests and the re-test were written and run by the project author and an AI assistant (Claude). Nobody independent of the project has audited this release. Where Chrono stops protecting you, the report says so: section 7 lists those limits.

---

## 1. Executive summary

### 1.1 The problem
AI coding agents such as Claude Code, Codex, Cursor agents and custom tool-use loops run real shell commands and edit real files. One wrong command can:

- delete a working tree or a home directory (`rm -rf`, `rd /s /q`, `Remove-Item -Recurse`);
- remove the machine's own recovery options (`vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit ... recoveryenabled No`);
- switch off defences (`netsh advfirewall ... state off`, `Set-MpPreference -Disable...`, `sc stop WinDefend`);
- add persistence (Run keys, scheduled tasks, hidden PowerShell);
- wipe data stores (`DROP TABLE`, `DELETE` without `WHERE`, `FLUSHALL`, `terraform destroy`).

The agent did not have to be malicious. A hallucinated cleanup step or a prompt-injected instruction is enough. Most of these actions are one-way: once they run, nothing undoes them.

### 1.2 Why security teams hesitate
Teams that want agents in the terminal usually face three gaps:

1. **No gate before execution.** The agent's shell runs whatever the model writes.
2. **No undo.** When a change is wrong, recovery depends on Git discipline and backups.
3. **No trustworthy record.** Afterwards nobody can prove what ran, who approved it, or whether the log was edited.

### 1.3 What Chrono changes
Chrono puts four controls between the agent and the machine:

| Gap | Chrono control |
|---|---|
| no gate | a pre-execution scanner that refuses dangerous commands **and dangerous scripts** before any process starts |
| no undo | an automatic savepoint before every command that can change files, a rollback, and a redo for the rollback itself |
| no record | an HMAC-signed, hash-chained audit log with an external witness kept outside the project |
| agent bypasses the gate | a hook in the AI client that sends the agent's own shell and file-edit tools through the same gate |

> **Scope in one sentence.** Chrono makes the **project folder** reversible and puts a deterministic gate in front of the **commands that pass through it**. It is not a sandbox, and it cannot undo changes outside the project. For those, blocking before execution is the protection, which is why the gate exists.

---

## 2. Architecture

### 2.1 Overview

```
                 AI agent (Claude Code, MCP clients, CLI users)
                                     |
          +--------------------------+---------------------------+
          |                          |                           |
   client's own Bash /       MCP tool chrono_run          chrono run -- <cmd>
   PowerShell / Write / Edit         |                           |
          |                          |                           |
   [ guard hook ]                    |                           |
   chrono guard hook                 |                           |
          +--------------------------+---------------------------+
                                     |
                     +---------------v----------------+
   Layer 1           |  GATE (deterministic)          |  command text (105 rules, de-obfuscated forms)
                     |  scanner + policy + policy pin |  + scripts / npm scripts / make targets it runs
                     +---------------+----------------+
                       block (>=70)  |  approve band   |  allow
                     exit 2 / "executed: false"        |
                                     |                 |
                     +---------------v----------------+
   Layer 2           |  SAVEPOINT                     |  content-addressed copy of tracked files
                     |  skipped for read-only cmds    |  (SHA-256 objects, atomic writes, fsync)
                     +---------------+----------------+
                                     |
                              command runs
                                     |
                     +---------------v----------------+
   Layer 3           |  ROLLBACK / REDO               |  digests verified before anything is touched;
                     |                                |  rescue savepoint makes every rollback undoable
                     +---------------+----------------+
                                     |
                     +---------------v----------------+
   Layer 4           |  SIGNED AUDIT LOG              |  .chrono/audit.jsonl (HMAC-SHA256 chain)
                     |  + external witness            |  keys, witness, pins in ~/.chrono-agent
                     +--------------------------------+
```

### 2.2 Layer 1: the deterministic gate
**What it is.** A rule engine of 105 regular-expression rules with scores from 0 to 100. Each command is scanned in its original form and in de-obfuscated forms: line continuations, quote splitting, backslash insertion, zero-width characters, `$IFS`, ANSI-C quoting and brace expansion are removed first. It is a text and content scanner, not a parser that builds an abstract syntax tree.

**What it reads (new in 0.5.0).** On enforcing paths it also opens what the command will run, in the project folder:

- script files in Python, Node/Deno/Bun, Ruby, Perl, PHP, shell, batch and PowerShell;
- npm, yarn, pnpm and bun package scripts, including `pre`/`post` scripts and the project's install lifecycle scripts;
- make targets and the targets they depend on;
- the scripts those start in turn, up to 4 levels deep.

**Decisions.**

| Score | Default action |
|---|---|
| 70-100 | **block**: nothing is spawned (`executed: false` in MCP, exit code 2 in the guard, exit 2 in the CLI) |
| configurable band (for example 40-69) | **approve**: a named person must approve (policy `thresholds.approve`) |
| below that | **allow** |

Policy rules can raise scores, force `block` or `approve`, and exempt exact routine commands (`allow:`). A broken policy file blocks every enforced command.

**Fail-closed behaviour.** The command is refused, not half-checked, when inputs are over 64 KB, scripts are over 1 MB, a command starts more than 16 scripts, nesting goes deeper than 4 levels, inspection hits an error, or the guard has an internal error.

**Examples measured in this release:** `vssadmin delete shadows` 95, `bcdedit ... recoveryenabled No` 95, autostart Run-key `reg add` 95, `rd /s /q C:\Users` 96, `robocopy ... /MIR` 92, `sc stop WinDefend` 92, and `python cleanup.py` 90 when the script contains `shutil.rmtree`.

**Self-protection.** Agents are refused when they try to change Chrono's own controls: approving their own requests, pinning or unpinning policy, editing team roles, uninstalling the guard, pruning history, rotating keys, resetting the witness, `chrono run --force`, or touching `.chrono`, `~/.chrono-agent`, the policy file or the client settings.

### 2.3 Layer 2: savepoints
- Before a command that can change files, Chrono stores every tracked file under its SHA-256 digest (content-addressed, deduplicated). Each new object is written to a temporary file, fsynced and atomically renamed. A savepoint records the file list, POSIX modes, the Git commit and the audit-log head.
- **Read-only filter.** Commands that cannot change files skip the savepoint: `dir`, `ls`, `type`, `cat`, `git status/log/diff/show`, `--version` queries, `pip list`, `chrono status` and similar. A command with redirection or substitution is never read-only, and neither is one that names a program found in the project folder.
- **Databases.** Database files inside the project are copied like any other file. A consistent, point-in-time database snapshot needs `chrono db snapshot` (SQLite through its backup API; Postgres and MySQL through their dump tools, which were not tested in this release).
- **Retention.** `chrono prune` and a `retention:` policy remove old automatic savepoints. History is re-linked and unused objects are deleted. Branch heads and manual snapshots are never pruned.

### 2.4 Layer 3: rollback and redo
- Before deleting or writing anything, a rollback verifies the digest of every object it needs. A missing or corrupt object means nothing is restored.
- Unsaved changes are first saved as a **rescue savepoint**, so every rollback can itself be undone.
- Restores are byte-identical. The re-test compared SHA-256 hashes before and after.
- The policy file and the AI client settings that hold the guard are control data. Rollback never deletes or reverts them.

### 2.5 Layer 4: signed audit log with an external witness
- Every scan, block, run, guard decision, approval, policy change, rollback and prune is appended to `.chrono/audit.jsonl`. Each record contains the previous record's digest.
- Since 0.5.0 each digest is an **HMAC-SHA256** made with a key kept **outside the project**, in `~/.chrono-agent/keys`, or supplied through `CHRONO_AUDIT_KEY` from a vault. Keys can be rotated, and older records keep verifying.
- After each record an **external witness** (newest sequence number and digest, itself MACed) is stored outside the project. Cutting off the newest records or replacing the whole log is detected, and the next write does not hide it.
- Snapshot anchors cross-check the log against savepoints. Optional `chrono audit --push` sends records to a remote append-only store.

> **What this protects against, precisely.** Someone who can write only the project folder, an AI agent included, cannot edit, delete, reorder, truncate or re-chain the log without detection. Someone who can read the user's Chrono home, such as the same OS account through an unguarded shell or an administrator, can forge records. This is detection, not impossibility. A vault-held key, strict mode and a remote copy narrow that gap.

### 2.6 Enforcement points
| Path | What enforces it |
|---|---|
| MCP `chrono_run` | blocked commands are never spawned |
| Guard hook (`chrono guard install`) | Claude Code PreToolUse hook on Bash, PowerShell, Write, Edit, MultiEdit and NotebookEdit; exit 2 refuses; never auto-approves |
| `chrono run -- <cmd>` | CLI transaction with savepoint, commit and rescue menu |
| `chrono scan`, `chrono_scan` | advisory only |

`chrono guard install --deny-raw-shell` removes the client's own shell tools, so MCP `chrono_run` becomes the only way the agent can run commands.

---

## 3. Verification results

### 3.1 Summary
| Check | Result | Notes |
|---|---|---|
| Unit and integration tests | **235 run: 230 passed, 5 skipped, 0 failed** | skipped tests need symlink rights (2), POSIX permissions (2) or git (1), which this machine lacks |
| Red-team suite (`benchmarks/redteam.py`) | **45 PASS · 0 FAIL · 8 LIMIT of 53** | LIMIT = a known design limit, listed in 3.3 |
| Scanner corpus: dangerous commands | **108 / 108 blocked** | author-written corpus; measures regressions, not accuracy on unseen commands |
| Scanner corpus: obfuscated variants | **22 / 22 blocked** | same corpus caveat |
| Scanner corpus: everyday commands | **88 / 88 left alone** | 0 false alarms on this corpus |
| Inline-code commands | **6 / 6 visible** (MEDIUM, not blocked) | |
| Original 0.4.1rc2 audit, re-run on 0.5.0 | **30 / 30 checks passed** | through a real MCP server over stdio |
| Installed-package smoke test | passed | `pip install` of the ZIP into a fresh venv, then the installed CLI, guard self-test and MCP tool list |
| Scan time | about 0.4 ms per command | average over 224 commands |

### 3.2 The 0.4.1rc2 findings and their status in 0.5.0
| # | Finding in 0.4.1rc2 | Status in 0.5.0 | Evidence |
|---|---|---|---|
| H1 | audit log unsigned; delete + re-hash verified as intact | **Fixed**: HMAC signing, external witness | re-test: rehash, signature strip and tail cut all detected |
| H2 | only `chrono_run` enforced; agent shell bypassed it | **Fixed**: guard hook | `rm -rf /`, rmtree script, self-approval all refused (exit 2) |
| H3 | scanner read command text only | **Fixed**: script, package-script and make-target inspection | `python cleanup.py` with rmtree: 90, blocked |
| H4 | rollback scope not stated to agents | **Fixed**: `covers` field, `SECURITY.md` | rollback reply states "project folder only" |
| H5 | savepoint for every command | **Fixed**: read-only filter, prune, retention | `dir`, `--version`: no savepoint |
| H6 | every `reg add` blocked; no backslash allow entries | **Fixed** | allow-listed app key allowed; Run key 95, blocked |

### 3.3 Red-team results (53 tests)
| Category | Representative attacks | Outcome |
|---|---|---|
| Scanner | unseen dangerous commands, obfuscation, hostile oversized input, script contents | PASS, except text-level limits below |
| Recovery | 150 MB file, 5,000 files, Unicode and deep paths, ignored folders, concurrent snapshot and rollback | PASS |
| Audit | edit, delete, reorder, truncate, rewrite without the key, concurrent writers, secret redaction, CSV injection | PASS |
| Control | approval binding and expiry, unlisted approvers, guard self-protection, pinned policy | PASS |
| Gateway | auth, withheld dangerous tool calls (OpenAI and Anthropic formats), obfuscated arguments, malformed replies, oversized and streaming requests | PASS |
| Fleet | lane isolation and overlap rejection | PASS (symlink part not run on this machine) |

**The 8 LIMIT results, by design:**
1. runtime variables and decoded payloads (`a=rm; $a -rf /`) are not visible to a text scanner;
2. the symlink test was not run (no symlink rights here);
3. POSIX permission checks do not apply on Windows;
4. someone who can read the user's key store can forge records;
5. an agent with an **unguarded** shell can run `chrono approvals approve` itself;
6. `CHRONO_USER` can be set by any process;
7. an **unpinned** policy can be edited silently (pinning closes this);
8. agent labels are not workload identities.

### 3.4 Performance (Windows 11, Defender scanning the test folder)
| Measurement | Before | 0.5.0 |
|---|---|---|
| First snapshot, 1,000 files | 13.7 s (0.4.1rc2) | **4.9 s** |
| Savepoint with nothing changed, 1,000 files (the usual automatic savepoint) | 9.7 s (0.4.1rc2) | **1.8 s** |
| First snapshot, 5,000 files | 137.5 s (0.5.0 before optimisation) | **23.0 s** (about 6× faster) |
| Snapshot of a 1-file project | — | about 11 ms |

Timings depend on file count, disk and antivirus. They are measurements on one machine, not guarantees.

### 3.5 Who verified what
- **Unit tests, corpus and red-team suite:** written by the project author and extended for 0.5.0. They are self-checks: they show regressions and known cases, not accuracy on unknown attacks.
- **Functional audit of 0.4.1rc2 and re-test of 0.5.0:** run by an AI assistant (Claude) in Claude Code on Windows 11, through the live MCP tools and a real MCP server process. The same assistant wrote the 0.5.0 fixes, so the re-test is **not independent**.
- **Other clients:** this report contains no evidence from Codex, Cursor or other clients. Results from other tools should be published with their own logs.

---

## 4. Value for engineering and security teams

| Need | What Chrono provides | What it does not replace |
|---|---|---|
| Let agents work locally without fear of one bad command | gate before execution; script inspection; self-protection | containers or VMs for untrusted code (see section 7) |
| Fast recovery from bad edits | automatic savepoints, rollback and redo, branches | Git and off-machine backups |
| Evidence of what agents did | signed, chained log with witness, model and agent labels, CSV and JSON export, remote push | an organisation's SIEM and log retention |
| Human control over risky actions | approval band, named approvers, rollback gate, policy pin | authenticated identity (approvals are named, not authenticated) |

**Compliance.** Chrono can supply evidence that auditors look for under change-management and logging controls in frameworks such as SOC 2 and ISO 27001: a record of what changed, who or what ran it, who approved it, and whether the record was tampered with. It does not make an organisation compliant on its own, and it has no compliance certification.

**Developer flow.** Read-only commands run with no savepoint. A typical automatic savepoint takes from milliseconds in small projects to about 2 seconds for 1,000 unchanged files on the test machine. Blocks name the reason, so the agent can explain itself instead of retrying blindly.

---

## 5. Deployment

### 5.1 Install
Chrono Agent is published on PyPI (https://pypi.org/project/chrono-agent/):

```cmd
python -m pip install --upgrade chrono-agent
python -m chrono_agent --version
```

### 5.2 Protect a project
```cmd
cd /d C:\path\to\project
chrono init
chrono guard install
chrono policy pin
```

### 5.3 Connect an MCP client
```json
{ "mcpServers": { "chrono": { "command": "python", "args": ["-m", "chrono_agent", "mcp"] } } }
```
Seven tools: `chrono_scan`, `chrono_run`, `chrono_snapshot`, `chrono_status`, `chrono_log`, `chrono_rollback`, `chrono_audit_verify`. Verified with Claude Desktop / Claude Code on Windows 11. Other MCP clients use the same stdio protocol but were not tested for this report. The guard hook targets Claude Code's hook interface.

### 5.4 Run a command through the gate
```cmd
chrono run -- python agent.py
chrono run --shell "npm test"
```

### 5.5 Operate
| Task | Command |
|---|---|
| verify the log | `chrono audit --verify` |
| show the key id and store (never the key) | `chrono audit --keys` |
| rotate the signing key | `chrono audit --rotate-key` |
| accept a deliberate restore of `.chrono` | `chrono audit --reset-witness` |
| check the guard | `chrono guard status` |
| clean old automatic savepoints | `chrono prune --keep-auto 200 --dry-run` |

**Back up `~/.chrono-agent/keys`.** A log whose key is lost can no longer be verified.

---

## 6. Release assessment

### 6.1 Readiness by area
| Area | Status | Basis |
|---|---|---|
| Command gate (Windows) | Ready | 108/108 corpus, red-team scanner tests, re-test |
| Script inspection | Ready | unit tests, red-team, re-test |
| Savepoints and rollback | Ready | byte-identical restore, red-team recovery tests, performance |
| Signed audit log and witness | Ready | tamper tests on copies, red-team audit tests |
| Guard hook | Ready to use; not yet observed in a live Claude Code session | exact hook command tested, self-test |
| Linux and macOS | Not verified for 0.5.0 | CI workflow included, not run |
| Fleet gateway | Pilot | its own event chain is unsigned |
| Independent security review | Not done | required before enterprise security claims |

### 6.2 Verdict
**Chrono Agent 0.5.0 is ready for a public developer release** (beta), with its limits published in `SECURITY.md`. All six findings from the 0.4.1rc2 audit are fixed and re-tested, the full test suite passes on Windows 11, and the red-team suite reports no failures.

**Before Chrono is offered as an enterprise security control**, the following should be complete:
1. an independent human penetration test, including scanner evasion;
2. CI passing on Linux and macOS;
3. the guard observed in live Claude Code sessions, plus integrations or documented MCP-only setups for other clients;
4. signing for the fleet gateway's event chain;
5. signed releases (for example PyPI Trusted Publishing with attestations).

> This report carries no certification, numeric "readiness score" or "production stable" designation. None was earned by an independent body, and stating one would mislead readers.

---

## 7. Threat model and limits

- **Not a sandbox.** An allowed program can do anything the OS account can do. Variables and payloads decoded at run time, compiled programs and imported modules are not inspected. Run untrusted code as a low-privilege user in a container or VM.
- **Rollback covers project files only.** Registry, services, scheduled tasks, shadow copies, boot settings, installed software, files outside the project or in ignored folders (`.git`, `node_modules`, `.venv`), network effects and unregistered databases are not restored.
- **Coverage.** Only the paths in section 2.6 are enforced. An unguarded shell, an IDE plugin or a person at a terminal are outside.
- **Local trust boundary.** Keys, witnesses and pins live in the user's Chrono home. The same OS account can read them.
- **Identity.** Approvals and roles are named, not authenticated. Agent labels are self-reported.
- **Durability.** `.chrono` lives on the same disk as the project and is not an independent backup. Power loss during a restore can leave a partial restore.

---

## Appendix A. Reproduce the results
From the extracted release folder:

```cmd
python -m unittest discover -s tests -v
python benchmarks\scanner_benchmark.py
python benchmarks\redteam.py
```

The test suite uses temporary projects and a temporary Chrono home. It never touches your real projects or keys.

## Appendix B. Evidence files in the release
| File | Contents |
|---|---|
| `VERIFICATION.md` | Windows 11 test results, re-test summary, performance, install smoke test |
| `RED_TEAM_REPORT.md` | all 53 red-team tests, 0.5.0 and 0.4.1rc2 results |
| `docs/REMEDIATION.md` | each audit finding mapped to code changes and tests |
| `SECURITY.md` | threat model, trust boundary, limits |
| `BENCHMARK.md` | scanner corpus method and known gaps |
| `CHANGELOG.md` | every change in 0.5.0 |
