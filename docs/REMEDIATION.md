# Remediation of the 0.4.1rc2 audit findings

On 9 November 2026 an independent, hands-on functional test of chrono-agent 0.4.1rc2 ran on Windows 11 Pro through the
seven MCP tools. All gate, benign-command, recovery and audit-chain checks passed. It reported one integrity finding
and six hardening items (H1-H6). This page shows what 0.5.0 changed for each one, where the change is, and which tests
prove it. Every test named here is in `tests/test_v050.py` unless another file is given.

## Findings

| # | Finding in 0.4.1rc2 | Change in 0.5.0 | Code | Tests |
|---|---|---|---|---|
| H1 | Audit log unsigned by default. On a copy of the log, deleting a record and recomputing every later hash produced a chain that verified as intact. | Records are HMAC-SHA256 signed by default with a key kept outside the project (`~/.chrono-agent/keys`, auto-created; `CHRONO_AUDIT_KEY` and strict mode supported). An external witness of the newest record catches truncation and whole-log replacement, even after the next write. Downgrades to unsigned records fail. Keys can be rotated. | `chrono_agent/audit.py` | `SignedAuditTests` (17 tests), `tests/test_audit.py` |
| H2 | Enforcement covered only `chrono_run`; an agent's own shell tool bypassed Chrono. | `chrono guard install` adds a Claude Code PreToolUse hook. Bash/PowerShell commands get the same decision as `chrono_run` (block = exit 2, approve = ask the person, allow = savepoint then normal permissions). Agent edits to Chrono's control files are refused. Errors fail closed. `--deny-raw-shell` leaves `chrono_run` as the only path. | `chrono_agent/guard.py`, `cli.py` | `GuardTests` (16 tests) |
| H3 | The scanner read command text only; `python app.py` scored LOW whatever the script contained. | On enforcing paths the scanner reads what the command runs: script files in 10+ languages, npm/yarn/pnpm/bun scripts (with pre/post and install lifecycle scripts), make targets and their dependencies, and the scripts those start. Limits fail closed. | `chrono_agent/interceptor.py` (`_Inspector`) | `InspectionTests` (9 tests), redteam "what a command runs" |
| H4 | Rollback cannot undo system-level damage, and this was not stated where agents see it. | Every `chrono_run` and `chrono_rollback` reply carries a `covers` field with the scope. README section *Savepoints, rollback and what they cover* and `SECURITY.md` spell it out. | `chrono_agent/mcp_server.py`, docs | `SavepointTests.test_run_and_rollback_say_what_a_rollback_covers` |
| H5 | A savepoint was taken for every allowed command, read-only ones included. | Read-only commands skip the savepoint (conservative allowlist; a same-named program in the project folder is never trusted on Windows). `chrono prune` and a `retention:` policy section remove old automatic savepoints safely. | `interceptor.py` (`is_read_only`), `snapshot.py` (`prune`), `mcp_server.py` | `SavepointTests` (9 tests) |
| H6 | `reg add` was blocked across the board, and allow-list entries could not contain backslashes, so registry setups could not be allowed. | Allow entries may contain backslashes. Autostart/persistence keys get their own 95-point rule, separate from other registry edits (88). `examples/chrono-policy.yaml` is a reviewed starting policy with the human rollback gate on. | `policy.py`, `interceptor.py`, `examples/` | `PolicyTests`, `tests/test_persistence_round.py` |

## Gaps closed beyond H1-H6

| Gap (0.4.1rc2 red-team "LIMIT" or found while fixing) | Change | Tests |
|---|---|---|
| Deleting the newest audit records left no local trace unless a later snapshot anchored them | external witness (H1) | `test_deleting_the_newest_records_is_caught`, `test_the_next_write_does_not_hide_a_truncation` |
| An agent could weaken `chrono-policy.yaml` silently | `chrono policy pin`; every change is recorded as `policy.changed` | `test_pin_blocks_everything_after_an_edit_until_a_person_pins_again`, `test_a_forged_pin_does_not_count`, `test_policy_changes_are_recorded` |
| An agent with a shell could approve its own request (`chrono approvals approve`) or skip the scan with `chrono run --force` | scanner rule for Chrono's own controls + guard; commands wrapped in `chrono run` are inspected too | `ControlPlaneRuleTests`, `test_commands_wrapped_in_chrono_run_are_inspected`, redteam "with the guard hook..." |
| Savepoints were slow on Windows (every unchanged file was hashed three times, one file at a time) | existing objects size-checked, change detection by size + mtime, up to 8 threads for larger projects; restore still verifies every digest | `test_snapshot_notices_a_file_rewritten_while_it_reads` (tests/test_runtime.py), `test_large_snapshot_stores_files_in_parallel_safely`; 1,000 files: first snapshot 13.7 s → 4.9 s, unchanged savepoint 9.7 s → 1.8 s |
| A rollback to an older snapshot could remove the guard settings | `.claude/settings*.json` are control data | `test_guard_settings_survive_a_rollback` |
| `tests/test_persistence_round.py` required pytest | plain unittest | the file itself |
| `benchmarks/redteam.py` could not run on Windows (`import resource`) | optional import | runs on Windows |
| CI workflow named in the changelog was missing | `.github/workflows/tests.yml` | n/a (needs a GitHub repository) |

## What is still a limit (by design)
* Text scanning cannot follow variables or runtime-decoded payloads, and cannot see inside compiled programs.
* Same-OS-account access to the Chrono home allows forging (use `CHRONO_AUDIT_KEY` from a vault and `audit --push`).
* Approvals and roles are named, not authenticated.
* The fleet gateway's own event chain is still unsigned (pilot).

See `SECURITY.md` for the full model.
