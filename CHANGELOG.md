# Changelog

## 0.5.0 — fixes for the independent audit of 0.4.1rc2

An independent hands-on audit of 0.4.1rc2 on Windows 11 found the gate, rollback and audit chain working, plus
six gaps (H1-H6). All six are addressed here. `docs/REMEDIATION.md` maps each finding to the change and to its tests.

### Security
- **H1. The audit log is signed by default.** Records carry an HMAC-SHA256 made with a key kept outside the
  project, in the user's Chrono home (`~/.chrono-agent/keys`, or `CHRONO_HOME`), created on first use. Rewriting the
  chain without the key is detected. `CHRONO_AUDIT_KEY` (your own secret), `CHRONO_AUDIT_REQUIRE_KEY=1` (strict:
  no unsigned records) and `CHRONO_AUDIT_UNSIGNED=1` (opt-out) are supported. A signed log that later contains an
  unsigned record fails (downgrade). Key rotation: `chrono audit --rotate-key`; older records keep verifying.
- **H1. External witness.** After every record Chrono stores the newest record's number and digest (signed) outside
  the project. Cutting off the newest records or replacing the whole log is now detected without any snapshot, and
  the next write cannot hide it: the witness stays frozen and the new record carries an `alert`. A person accepts a
  deliberate restore with `chrono audit --reset-witness` (recorded). A brand-new project in a folder where an older
  one lived keeps the old witness in `witness/archive` and says so in its first record.
- **H2. Guard hook for the agent's own tools.** `chrono guard install [--scope project|user] [--deny-raw-shell]`
  adds a Claude Code PreToolUse hook. Every Bash/PowerShell command goes through the same decision as `chrono_run`.
  Blocked commands get exit code 2, the approval band asks the person, and allowed commands get a savepoint first.
  The guard never auto-approves. Agent edits to `.chrono/`, `chrono-policy.yaml`, `.claude/settings*.json` and the
  Chrono home are refused. Errors fail closed. `chrono guard status` shows the hook and runs a self-test.
- **H3. The scanner reads what a command runs.** With the project folder known (every enforcing path), it scans
  script files (Python, Node, Deno, Bun, Ruby, Perl, PHP, shell, batch, PowerShell), npm/yarn/pnpm/bun package
  scripts including pre/post and install lifecycle scripts, and make targets with their dependencies, following the
  scripts those start. Oversized files, too many scripts and very deep nesting are refused, not half-checked.
- **Policy pin.** `chrono policy pin` locks `chrono-policy.yaml`. Any later edit blocks every enforced command
  until a person pins again. Every policy change Chrono notices is written to the audit log (`policy.changed`).
- New rules: agents changing Chrono's own controls (`chrono approvals approve`, `policy pin`, `team add`,
  `guard uninstall`, `prune`, `audit --reset-witness/--rotate-key`, `run --force`) and tampering with `.chrono`,
  `.chrono-agent`, the policy file or the client settings are blocked (88-92). Commands wrapped in `chrono run` /
  `python -m chrono_agent run` are inspected like the command itself. Autostart/persistence registry keys (Run,
  RunOnce, Winlogon, IFEO, services...) now score 95 with their own reason.

### Performance
- Savepoints of an unchanged tree are much faster, especially on Windows (1,000 files: 9.7 s → 1.8 s on the test
  machine). Existing stored versions get a size check instead of a full re-hash (restore still verifies every
  digest before it changes anything), and "did files change while the snapshot read them" compares size and
  modification time instead of hashing every file a second time.
- Projects with more than 32 files are read and stored by up to 8 threads (each file is still written atomically
  and fsynced). First snapshot of 1,000 files on the test machine: 14.2 s → 4.9 s.
- The MCP server ignores a byte-order mark at the start of its input (some Windows shells add one).

### Usability
- **H4.** Every `chrono_run` and `chrono_rollback` reply has a `covers` field that says plainly that rollback
  restores project files only, not registry, services, shadow copies, outside files or network effects.
  `SECURITY.md` documents the full threat model.
- **H5.** Read-only commands (`dir`, `ls`, `type`, `git status/log/diff`, `--version`, `pip list`...) no longer
  take a savepoint (`CHRONO_SAVEPOINTS=always` restores the old behaviour). New `chrono prune --keep-auto N
  --older-than DAYS [--dry-run]` and a `retention:` policy section remove old automatic savepoints. History is
  re-linked so merges keep working, and unused file versions are deleted. Heads and manual snapshots are never pruned.
- **H6.** Allow-list entries may contain backslashes (`reg add HKCU\Software\MyApp /v * /d * /f`).
  `examples/chrono-policy.yaml` is a reviewed starting policy. Examples for Claude Code settings and MCP config are included.
- A policy rule's reason no longer appears next to "No dangerous pattern detected".
- `.claude/settings.json` and `.claude/settings.local.json` are control data like the policy: snapshots ignore
  them and a rollback never removes the guard.

### Fixed
- `tests/test_persistence_round.py` needed pytest, which is not a dependency, so `python -m unittest discover`
  reported an import error. It is plain unittest now.
- `benchmarks/redteam.py` imported the POSIX-only `resource` module and could not run on Windows. It now runs on
  both. It also uses a throwaway Chrono home.
- The Windows symlink test could fail when a virus scanner briefly held a folder; it retries now.
- The CI workflow mentioned in 0.4.1rc2 was missing from the package; `.github/workflows/tests.yml` is included.

### Behaviour changes to be aware of
- `chrono audit --verify` fails when the log was deleted or cut short after the witness saw it. Before, it reported
  "no audit records" or a clean shorter chain. Use `--reset-witness` after a deliberate restore.
- Commands that run a script with a recursive delete inside (`python clean.py` with `shutil.rmtree`, `make clean`
  with `rm -rf build`) are now blocked on enforcing paths. Allow routine ones with the policy `allow:` list.
- `chrono_run` returns `"savepoint": null` plus `savepoint_skipped` for read-only commands.

### Licensing and packaging
- License changed from MIT to a source-available license (`LICENSE`): free to install and use, including inside
  a company; no resale, hosted service or redistribution of modified versions without a commercial license
  (`LICENSE-COMMERCIAL.txt`). Copyright (c) 2026 Abdul Manan.
- Copyright headers in every source file; package metadata names the author and the license
  (`LicenseRef-Proprietary`).
- Published on PyPI: `pip install --upgrade chrono-agent`. README updated with badges, measured results and
  MCP setup for Claude and Codex.
- `docs/` holds the release report and the audit report; `.gitignore` keeps keys, `.chrono`, `.pypirc` and
  build output out of the repository.
- The PyPI package was built before the copyright holder's name and contact were filled into `LICENSE`,
  `LICENSE-COMMERCIAL.txt` and the source-file headers. The repository and the `v0.5.0` tag have the completed
  text; the code is the same.

## 0.4.1rc2-winfix
- Scanner: blocks shadow-copy/backup/recovery wiping (vssadmin, wbadmin, bcdedit) at 95.
- Scanner: blocks firewall/Defender disabling, security service stops, log clearing at 92.
- Scanner: blocks persistence (schtasks, reg add/delete, WMI process create, hidden PowerShell, base64 iex, git hook writes) at 88-90.
- Scanner: blocks installs from git/raw URLs or custom package indexes at 85.
- Read-only forms (schtasks /query, reg query, sc query, vssadmin list) stay allowed.

## 0.4.1rc2 (scanner update, OmniCorp 50-agent run)

## 0.4.1rc2 — auditor round (in-place update)
- Scanner: blocks `cipher /e|/w`, `robocopy /MIR|/PURGE`, `certutil -encode|-decode|-urlcache` (benign forms still allowed).
- MCP: new `chrono_run` tool really refuses blocked/approval commands (nothing executes); safe commands run after an automatic savepoint.
- `chrono_scan` now returns `engine_version` and a strict `directive` when blocked.
- Windows: delete/replace/folder cleanup auto-retries on transient "Access is denied".
- Many agents at once: writers wait in a queue instead of failing "Project busy"; snapshots retry if files change mid-save (50 parallel writers tested, audit chain intact).

- Blocks `format.com X:` / `format.exe X:`.
- Secret exfiltration now covers PowerShell `Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm` and files like `production_secret.env`.
- New: `type|cat|Get-Content <secret> | base64` (80), inline code that encodes/sends a secret file (80).
- New ransomware rules: `openssl enc`/`gpg` on databases or producing `.locked` (88), bulk encrypt scripts / `--suffix .locked` (88).
- Regression tests: tests/test_omnicorp_gaps.py.

## 0.4.1rc2 (unreleased; rc1 was the first hardening round)

### Tests only (no code change)
- Two original tests were not portable to Windows: one ran `touch` (a Unix program) and one crashed instead of skipping when `git` is not installed. Both fixed; the product itself already worked without git.

### Second round: enterprise red-team (see RED_TEAM_REPORT.md)
- **Audit log could fork under concurrent writers** (a false "tampering" alarm). Writers now take an
  exclusive lock, and the newest record is read from the end of the file instead of rescanning the whole log.
- **Secrets are redacted from audit records** (bearer tokens, `sk-`/`ghp_`/`AKIA` keys, JWTs, URL passwords,
  `--password`, `API_KEY=...`). **CSV export neutralises formula injection.**
- **Rollback no longer deletes empty directories** it did not empty itself (`logs/`, `uploads/`).
- **Symlinks and special files are skipped with a warning** instead of failing the whole snapshot. They are
  never followed, stored or restored, and a restore never writes through a symlink.
- `.chrono/` is `0700` on POSIX.
- **Policy `allow:` section** for routine commands (`rm -rf node_modules`). Exact whole-command match only; `*`
  never matches a space, slash or shell operator; custom `block` rules still win. (`action: allow` inside `rules`
  never allowed anything and still does not.)
- Scanner: 25+ more rules (`find -exec rm`, tautological `WHERE 1=1`, `git push +ref`, `gh ... delete`, env and
  archive exfiltration, encrypt-then-delete, `sudo -E bash` pipes, script delete loops, file truncation); grep/rg
  patterns are data; inputs over 64 KB are scanned at both ends and refused (fail closed).
- Gateway decisions scan decoded argument strings as well as JSON text.

### Fixed
- **Rollback could delete the policy that governs it.** `chrono-policy.yaml` was
  tracked like project content, so rolling back to a snapshot taken before the
  policy existed removed it and silently switched every gate off (and an older
  version could overwrite a newer one). The policy is now control data: ignored
  by snapshots, never deleted or reverted by rollback. Snapshots made by earlier
  versions that contain it stay valid and load normally.
- **Scanner false alarm:** `docker run --rm ...` scored 98 CRITICAL because `rm`
  matched inside `--rm`. `rm` is now recognised only where a command can start.
  `git rm --cached` and tool subcommands such as `npm rm` are no longer treated
  as `rm -rf`.
- **Git hook** called a bare `chrono` that is often not on PATH and swallowed the
  failure. It now runs the interpreter that installed it and prints a warning
  when a snapshot fails. (This was the cause of the excluded hook test.)
- `evaluate()` reported the level of the built-in scan even when a policy rule
  raised the score; the level now follows the final score.
- Gateway/fleet decisions scan the decoded strings of an action as well as its
  JSON text, so JSON escaping cannot hide a command.

### Added
- **Rescue + redo on every rollback** (CLI and MCP): unsaved changes are saved to
  a rescue savepoint first; its id is returned/printed as the way back.
- **Human approval gate for MCP rollback**: `gates: mcp.rollback: approve` in the
  policy. Approvals are named, single-use, expire after 10 minutes, are bound to
  the exact snapshot and policy, show what they are for, and are written to the
  fleet audit chain.
- MCP rollback now applies the same `roles` check as the CLI (`rollback`) plus an
  optional stricter `mcp.rollback` role.
- Scanner: ~60 new rules (Python/Node/Ruby/Perl deletes, `find -delete`, `shred`,
  SQL `UPDATE` without `WHERE`, git history rewriting, Terraform/kubectl/Helm,
  Docker prune/volumes, AWS/GCP/Azure/rclone/rsync deletes, Redis/MongoDB wipes,
  secret exfiltration, reverse shells, encoded payloads). Inline code
  (`python -c`, `bash -c`, `eval`) now scores MEDIUM instead of LOW.
- Scanner looks through line continuations, quote splitting, backslashes,
  zero-width characters, `$IFS`, ANSI-C `$'..'` quoting and brace expansion.
- `tests/scanner_corpus.py` + `tests/test_scanner.py` (regression corpus),
  `tests/test_hardening.py`, `benchmarks/scanner_benchmark.py`, `BENCHMARK.md`,
  and a CI matrix (`.github/workflows/tests.yml`) for Python 3.8-3.13 on Linux
  and Windows.

### Behaviour changes to be aware of
- Commands containing recursive/bulk deletes inside inline code (for example
  `python -c "shutil.rmtree('.')"`) are now blocked by default.
- `rollback` now creates a rescue savepoint, so `log` can show extra entries of
  kind `rescue`.

### Still true (not changed)
- The scanner is advisory text matching. It cannot follow variables, decode
  arbitrary payloads or know what a script file does. See `BENCHMARK.md`.
- MCP has no authenticated identity: roles use the OS user / `CHRONO_USER`. Use
  the approval gate when an AI client must not act alone.
