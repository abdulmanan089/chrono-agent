Chrono Agent 0.5.0 - End-user guide
Copyright (c) 2026. All Rights Reserved. Proprietary and confidential.

Chrono puts a safety layer between an AI coding agent and your machine:
it blocks dangerous commands before they run, takes a savepoint before every
change so you can roll back, and keeps a signed, tamper-evident audit log.

--------------------------------------------------------------------------
INSTALL
--------------------------------------------------------------------------
If you received chrono.exe (standalone build):
  1. Put chrono.exe in a folder on your PATH, or call it by full path.
  2. Check it:            chrono.exe --version

If you received a Python wheel:
  python -m pip install --user chrono_agent-0.5.0-*.whl
  chrono --version

--------------------------------------------------------------------------
FIRST USE IN A PROJECT
--------------------------------------------------------------------------
  cd  C:\path\to\your\project
  chrono init                 start tracking this folder
  chrono guard install        route your AI client's commands through Chrono
  chrono policy pin           lock the policy after you set it up

--------------------------------------------------------------------------
EVERYDAY COMMANDS
--------------------------------------------------------------------------
  chrono run -- <command>     run a command safely (savepoint + gate)
  chrono status               what changed since the last savepoint
  chrono log                  list savepoints
  chrono rollback <id>        restore a savepoint (undoable)
  chrono scan "<command>"     check a command without running it
  chrono audit --verify       check the audit log for tampering
  chrono audit --keys         show the signing-key id and where it is stored
  chrono guard status         check the guard and run its self-test
  chrono --help               full command list

--------------------------------------------------------------------------
IMPORTANT
--------------------------------------------------------------------------
- Back up the key folder:  %USERPROFILE%\.chrono-agent\keys
  A log whose signing key is lost can no longer be verified.
- A rollback restores files in the project folder only. It does NOT undo
  system changes (registry, services, shadow copies), files outside the
  project, network actions, or databases not registered with "chrono db".
- Chrono is a guardrail, not a sandbox. Run untrusted code in a container
  or virtual machine.

Support / licensing: manandogar112@gmail.com
