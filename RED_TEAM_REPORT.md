# Red-team report

## 0.5.0 on Windows 11 (9 November 2026)
`python benchmarks/redteam.py` now runs on Windows too (0.4.1rc2 imported the POSIX-only `resource` module). It
has 53 tests: the 48 below (one rewritten, because its attack no longer works) plus 5 new ones for the 0.5.0 fixes.

| | First Windows run (before the last fixes) | 0.5.0 final |
|---|---|---|
| PASS | 42 | **45** |
| FAIL | 4 | **0** |
| LIMIT (by design) | 7 | 8 |

The first Windows run found 4 FAILs. Three were problems in the test script on Windows: symlinks need Developer
Mode or admin rights, and one test wrote Arabic/Japanese file names with the system code page instead of UTF-8.
These are now handled; the symlink tests report LIMIT when they cannot run. The fourth was real: the first snapshot
of 5,000 files took 137.5 s against a 60 s budget. Parallel storing and cheaper checks bring it to **23.0 s**.

New in 0.5.0, all PASS:
- what a command runs (script files, make targets, npm scripts) is read and scanned;
- rewriting the default signed log without the key is detected (this was a LIMIT in 0.4.1rc2);
- cutting off the newest records is detected without any snapshot (external witness);
- with the guard hook, the agent's own shell cannot self-approve or edit Chrono's files;
- a pinned policy cannot be weakened silently.

Still LIMIT by design: variables and runtime-decoded payloads; someone who can read the user's key store can forge;
an agent with an **unguarded** shell can approve its own request, spoof `CHRONO_USER`, or edit an **unpinned**
policy; agent labels are not workload identities. On Windows, POSIX file-mode checks do not apply. Symlink tests
are not run without symlink rights.

The 8 LIMIT results of the final Windows run:
1. text scanner cannot see through variables / encoded payloads / compiled programs (4/4 samples not blocked);
2. symlink snapshot test not run (no symlink rights on this machine);
3. POSIX file permissions do not apply on Windows (NTFS ACLs instead);
4. someone who can read the user's key store can forge records;
5. an agent with an unguarded shell can run `chrono approvals approve` itself (the guard refuses it; this test calls the CLI directly);
6. `CHRONO_USER` can be spoofed by a process with its own environment;
7. an **unpinned** policy can be edited silently (with `chrono policy pin` the edit blocks everything: the new PASS test above);
8. agent labels are not workload identities.

---

## 0.4.1rc2 (enterprise-style review)

Reproduce: `python benchmarks/redteam.py` (about 40 seconds, Linux or Windows).
48 attack/robustness tests across the scanner, recovery, audit log, access control, the live gateway and fleet lanes.
Each test ends as **PASS** (attack stopped), **FAIL** (a real, fixable weakness) or **LIMIT** (a design limit that Chrono cannot enforce alone).

## Result

| | First run | After fixes |
|---|---|---|
| PASS | 30 | **42** |
| FAIL | 12 | **0** |
| LIMIT (by design) | 6 | 6 |

"0 FAIL" means no known fixable weakness remains **in these 48 tests**. The tests and the fixes were written by the same
author, so this is not an independent audit. A real company review should still be done by someone else.

## The 12 first-run failures

| # | Finding | Verdict | Fix |
|---|---|---|---|
| 1 | Scanner missed 15 of 43 new dangerous commands (`find -exec rm`, `WHERE 1=1`, `git push origin +main`, `gh repo delete`, `env \| curl`, `tar \| curl`, `scp ~`, encrypt-then-delete, `sudo -E bash` pipe, Python/Node delete loops...) | real | new rules; all now blocked and added to the corpus |
| 2 | `rm -rf node_modules` and other routine cleanup always blocked, and policy `action: allow` did nothing | real (usability) | new `allow:` policy section: exact whole-command match only |
| 3 | `grep 'DROP TABLE' migrations/` blocked | real (false alarm) | quoted grep/rg/man patterns are treated as data; `grep "$(rm -rf /)"` still blocked |
| 4 | 1 MB inputs took 1-3 s to scan (a gateway request may carry 4 MB) | real | inputs over 64 KB are scanned at both ends and **blocked** (fail closed) |
| 5 | One symlink made the whole snapshot fail | real (usability) | symlinks/special files are skipped with a visible warning, never followed, never restored; strict mode still available in code |
| 6 | Rollback deleted empty directories such as `logs/` that were never changed | real (data loss) | only directories emptied by the restore itself are removed |
| 7 | `.chrono/` was world-listable (file contents were already 0600) | real (hardening) | directory set to 0700 on POSIX |
| 8 | 8 processes writing the audit log at once forked the hash chain, so verification reported tampering that never happened | **real bug** | exclusive write lock; the last record is read from the end of the file (also removes a full re-read per record) |
| 9 | Secrets typed into a scanned command (bearer tokens, `sk-...`, `ghp_...`, `AKIA...`, JWTs, URL passwords, `--password x`, `API_KEY=...`) were stored in clear text in the audit log | real | redacted before the record is written; the hash chain covers the redacted text |
| 10 | CSV export was open to spreadsheet formula injection (`=HYPERLINK(...)`) | real | cells starting with `= + - @` are neutralised |
| 11 | Gateway "obfuscation" case with `\\rm` | **my test was wrong**: `\\rm` is not a real alias bypass (`\rm` is, and it was already blocked) | test corrected |
| 12 | Oversized/chunked gateway request test crashed with BrokenPipe | **my test was wrong**: the server closing the connection without reading a 5 MB body is a refusal | test corrected |

One more real bug was found while writing the fixes: **rolling back to a snapshot taken before the policy file existed deleted
`chrono-policy.yaml` and silently switched every gate off.** That was fixed earlier in this release (the policy is now control data
that snapshots ignore).

## What stays LIMIT (and what to do about it)

| Limit | Why Chrono cannot close it | What a company should do |
|---|---|---|
| Variables, script files, encoded payloads (`a=rm; $a -rf /`, `python cleanup.py`, `make nuke`) | A text scanner sees text, not behaviour | run agents with least privilege in containers/VMs, keep Git and independent backups |
| Approvals are named, not authenticated: an agent **with a shell on the same machine** can run `chrono approvals approve` itself | no secret or identity separates the human from the agent | give the agent MCP/gateway access only, no shell; or approve from another machine |
| Roles come from the OS user / `CHRONO_USER` and can be spoofed by a process with shell access | same reason | same as above; use the approval gate, not roles, against an AI client |
| The policy file can be edited by whoever can write the project folder | it lives next to the project | keep it in Git, review changes, protect it with OS permissions |
| Without `CHRONO_AUDIT_KEY` (kept out of the agent's reach) an attacker can rewrite history consistently | an unkeyed chain can be recomputed | set the key, ship the log to a remote store |
| Agent labels are not workload identities | shared labels/credentials | one credential per agent at the provider |

## Suggested next hardening (not done)

1. Log every policy change in the audit chain (fingerprint of `chrono-policy.yaml`), so silent edits become visible.
2. Authenticated approvals (a passphrase or TOTP held only by the human).
3. Stream large files instead of holding a whole project in memory (a 150 MB file used 177 MB; a multi-GB project would not fit).
4. Windows run of this suite (the new audit lock uses the same pattern as the existing snapshot lock but has only been run on Linux).

## Not covered by this review

A real model driving real tools; very large repositories (>150 MB file, >5,000 files); multi-user machines; TLS/ingress;
disk-full and power-loss crashes; Windows behaviour of the new locking code; anything outside the connected paths (web chats,
IDE edits, traffic that bypasses Chrono).
