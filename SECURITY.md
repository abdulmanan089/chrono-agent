# Security model of ChronoAgent 0.5.0

This page explains what Chrono protects against, what it does not, and where its trust boundary is. Read it before
you describe Chrono to anyone as a security product.

## What Chrono is for
An AI coding agent works in a project folder with a shell and file-editing tools. Chrono reduces three risks:

| Risk | What Chrono does |
|---|---|
| The agent runs a destructive or dangerous command | blocks it before it starts: command text, the scripts it runs, policy rules |
| The agent breaks project files | savepoint before each change; rollback, with a rescue savepoint so the rollback can be undone |
| Nobody can later prove what happened | signed, hash-chained audit log, with an external witness and snapshot anchors |

## Enforcement points
A decision is only enforced when the action passes through one of these:

1. **MCP `chrono_run`**: blocked commands never start.
2. **The guard hook** (`chrono guard install`): the AI client asks Chrono before each Bash/PowerShell command and
   each file edit. Exit code 2 refuses the call.
3. **`chrono run`** on the command line.

`chrono_scan` and `chrono scan` are advisory: they report and record, they do not stop anything.

Not covered: a shell the agent has outside the guard, an IDE extension or plugin that runs its own commands, other
programs on the machine, and people at a terminal. For full coverage, give the agent MCP `chrono_run` only
(`chrono guard install --deny-raw-shell`) and no other way to run code.

## What a rollback restores
Tracked files in the project folder. Not: registry, services, scheduled tasks, shadow copies, boot settings,
firewall or Defender settings, installed software, files outside the folder or in ignored folders (`.git`,
`node_modules`, `.venv`...), network calls, cloud resources, or databases not registered with `chrono db`.
For those, blocking before execution is the only protection. Every `chrono_run` and `chrono_rollback` reply states
this in its `covers` field.

## What the scanner can and cannot see
It sees the command text (with common obfuscation removed) and, on enforcing paths, the content of the scripts,
package scripts and make targets the command starts, in the project folder. It does not see variables resolved at
run time, payloads decoded at run time, compiled programs (`.exe`, `.pyc`), modules a script imports, downloaded
code, or what a remote service does. An allowed program can do anything the OS account can do. **Chrono is not a
sandbox.** For untrusted code, run the agent as a low-privilege user in a container or VM, and keep backups.

When inspection hits its limits (files over 1 MB, more than 16 scripts, nesting deeper than 4 levels, or an error
while reading), the command is blocked (fail closed). The guard also fails closed on any internal error.

## Trust boundary: the Chrono home
Keys, witnesses and policy pins live in `~/.chrono-agent` (`%USERPROFILE%\.chrono-agent` on Windows), or in
`CHRONO_HOME`. It is outside every project, so an agent confined to the project folder, or a person who only has
the project files, cannot forge the log or quietly change a pinned policy. The guard refuses agent edits there,
and the scanner blocks shell commands that tamper with it.

Anyone running as the **same OS account** with an unguarded shell can read the key and forge records. To defend
against that:

* set `CHRONO_AUDIT_KEY` from a secret store the agent cannot read, and `CHRONO_AUDIT_REQUIRE_KEY=1`;
* push the log to a store you do not control (`chrono audit --push URL --verify-remote`);
* run the agent under a different OS account than the person who owns the keys.

Back up `~/.chrono-agent/keys`. A log whose key is lost can no longer be verified.

## Identities
`CHRONO_USER`, `CHRONO_AGENT` and `CHRONO_MODEL` are labels from the environment, not authenticated identities.
Approvals are named, single-use and expire after ten minutes, but they are not authenticated. The guard refuses
`chrono approvals approve` from the agent; a process with its own unguarded shell is outside that.

## Known limits that remain in 0.5.0
- Text-level scanning cannot follow variables or decode runtime payloads.
- The fleet gateway's own SQLite event chain is still unsigned SHA-256 (pilot feature).
- Snapshots hold whole files in memory; very large projects are not the target.
- Power loss during a restore can leave a partial restore; `.chrono` is not an independent backup.
- The guard targets Claude Code's hook interface. Other clients need their own integration, or MCP `chrono_run` only.

## Reporting a problem
Please report security problems privately to the maintainer before publishing them, with the Chrono version
(`python -m chrono_agent --version`), the OS, and the smallest command or steps that show the problem.
