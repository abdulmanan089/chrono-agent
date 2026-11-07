# ChronoAgent ⏱️🛡️

**Savepoints, rollback, risk checks and a tamper-evident audit trail for AI agents that touch real files.**

[![PyPI](https://img.shields.io/pypi/v/chrono-agent.svg)](https://pypi.org/project/chrono-agent/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-server-8A2BE2.svg)](https://modelcontextprotocol.io/)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)

> Give your AI agent a workspace. Take a savepoint. If the agent gets it wrong, put everything back with one command, and keep a record of what happened.

---

## Why we built it

AI agents can now write code, edit files, run commands and change databases by themselves. That is useful, and it is also why many companies are slow to give agents real access. One hallucinated command, a wrong refactor or a corrupted config can cost hours, or it can cost data.

Most teams have two bad options:

- **Don't let the agent act**, and lose most of the value.
- **Let it act and hope**, and find out later what changed.

ChronoAgent adds a third option: **let the agent work inside a recoverable workspace.** Before risky work you take a savepoint. ChronoAgent checks commands against risk rules, records every action in a hash-chained audit log and lets you roll back to any savepoint. Rollback also saves a "redo" point, so you can undo the undo.

It is a small, dependency-free Python tool that runs on your own machine. Your code does not leave it.

---

## What it does

### Core recovery
| Feature | What you get |
|---|---|
| **Savepoints** | `snapshot` records the exact state of the workspace with a message. |
| **Rollback + redo** | `rollback <id>` restores files to a savepoint. It first saves a redo savepoint so nothing is lost by accident. |
| **History, status, diff** | See every savepoint, what changed since the last one and how two states differ. |
| **Branches & merge** | Try different approaches from the same savepoint and merge the one you keep. |
| **Integrity checks** | Stored objects are hash-verified before restore. Restore paths are validated so files can't be written outside the workspace. Locking prevents corruption from two writes at once. |
| **Safe `run`** | Runs a command under protection. A successful run is recorded as a savepoint, and a failed run can be rolled back. Commands run without a shell by default. |

### Safety & governance
| Feature | What you get |
|---|---|
| **Risk scanner** | `scan "<command>"` scores a command from 0 to 100 (LOW → CRITICAL) and returns allow, warn or block. Example: `rm -rf /` → CRITICAL, 98, block. |
| **Policies** | Set the risk levels your team allows, warns on or blocks. |
| **Human approvals & roles** | Risky actions can wait for a person to approve them. Roles control who can approve. |
| **Tamper-evident audit** | Every action goes into a SHA-256 hash-chained log. `verify-audit` reports whether the chain is intact. You can also push the log to a remote endpoint. |
| **HTML report** | A browser report of savepoints, risk checks and audit status that you can share with a reviewer or manager. |

### Beyond files
| Feature | What you get |
|---|---|
| **Git awareness** | Tracks Git state alongside savepoints and includes an optional hook. |
| **SQLite snapshots** | Take and restore snapshots of SQLite databases, not just source files. |

### For AI agents (v0.4.0)
| Feature | What you get |
|---|---|
| **MCP server** | A built-in Model Context Protocol server. Claude Desktop and other MCP clients can call `chrono_scan`, `chrono_snapshot`, `chrono_rollback`, `chrono_log` and `chrono_verify_audit` as tools. |
| **Fleet registry** | Register any number of agents (2, 5 or 40), each with its own ID. |
| **Isolated agent lanes** | Each agent gets its own workspace root. Roots can't overlap, so agents can't overwrite each other, and each lane has separate savepoints and rollback. |
| **Fleet gateway (pilot)** | A token-protected local proxy for OpenAI Chat Completions and Anthropic Messages APIs. It checks tool calls that go through it, logs them and can send risky ones for approval. |
| **Live dashboard** | `http://127.0.0.1:8787/chrono/dashboard` shows agents, pending approvals and the audit trail. |

---

## How companies can use it with confidence

- **Start with a savepoint.** Any agent task that goes wrong can be rolled back.
- **Give each agent its own lane.** A coding agent and a review agent work in separate folders with separate history.
- **Put a person in the loop.** High-risk actions wait for approval, and each decision is logged.
- **Prove what happened.** The hash-chained audit log and HTML report give reviewers evidence instead of guesses.
- **Keep data local.** No cloud account is needed and there are no third-party dependencies. It's MIT-licensed, so you can read every line.

---

## Install

```bash
pip install chrono-agent
```

> PyPI currently has **v0.3.0** (core recovery, scanner, policies, approvals, Git, SQLite, MCP, audit, report).
> The **v0.4.0 fleet features** (registry, lanes, gateway, dashboard) are in the GitHub Release ZIP:
> ```bash
> pip install chrono-agent-0.4.0rc1.zip
> ```

On Windows, if `chrono` isn't recognised, use `python -m chrono_agent` for every command. It works the same way.

---

## Quickstart (5 minutes)

```bash
mkdir C:\chrono-test
cd C:\chrono-test
python -m chrono_agent init

echo print("Hello Safe World") > app.py
python -m chrono_agent snapshot -m "v1 safe state"

:: the agent (or you) makes a bad change
echo print("BROKEN") > app.py

python -m chrono_agent log
python -m chrono_agent rollback <snapshot_id>
type app.py          :: -> print("Hello Safe World")

python -m chrono_agent scan "rm -rf / --no-preserve-root"   :: -> CRITICAL / block
python -m chrono_agent verify-audit                         :: -> chain intact
```

---

## Connect your AI agent

ChronoAgent only sees what is routed to it. Choose the option that matches your agent:

| Your agent | How to connect |
|---|---|
| Claude Desktop or another **MCP client** | MCP server (below) |
| An app or agent that calls the **OpenAI / Anthropic API** and lets you set a custom base URL | Fleet gateway (below) |
| A **script or CLI agent** | Wrap it: `python -m chrono_agent run -- <command>` |
| Your own **Python code** | Import `chrono_agent` and call snapshot/rollback directly |
| IDE or web chat with none of the above | Take manual savepoints before and after the agent's task |

### Claude Desktop (tested on Windows)

1. Initialise the folder the agent will work in (`python -m chrono_agent init` inside it).
2. Open **Claude → Settings → Developer → Edit Config**. That opens `%APPDATA%\Claude\claude_desktop_config.json`.
3. Add `mcpServers` at the **top level**, next to any existing settings rather than inside `preferences`:

```json
{
  "mcpServers": {
    "chrono": {
      "command": "C:\\Program Files\\Python313\\python.exe",
      "args": [
        "-c",
        "import os; os.chdir('C:/chrono-test'); from chrono_agent.mcp_server import serve; serve()"
      ]
    }
  }
}
```

4. Save the file, then quit Claude completely: `taskkill /F /IM Claude.exe`. Reopen it.
5. Ask Claude: *"Take a chrono snapshot called v1 safe state"*, then *"Show the chrono log and verify the audit trail."*

Tips: run `where python` to find the right path. Use the full Python path instead of `python`. The `os.chdir(...)` part makes the server open in your initialised folder. Without it you'll see *"Not a chrono project"*.

### Multi-agent fleet (pilot)

```bash
:: two agents, two separate lanes (outside the control folder)
mkdir C:\workspaces\coder C:\workspaces\reviewer

:: start the gateway: tokens must be different and at least 24 characters each
python -m chrono_agent fleet gateway --host 127.0.0.1 --port 8787 ^
  --gateway-token <your-gateway-token-24+chars> ^
  --admin-token <your-different-admin-token-24+chars>
```

Open `http://127.0.0.1:8787/chrono/dashboard`, enter the admin token, and point your agent's API base URL at the gateway. See `FLEET.md` for registering agents and lanes.

---

## Honest scope

We would rather you trust ChronoAgent than be impressed by it:

- It protects **what is routed through it** (CLI, MCP, SDK or gateway). It does not intercept everything on the operating system, and IDE edits or web chats aren't captured automatically.
- The risk scanner is **heuristic and advisory**. It is not a sandbox.
- The fleet gateway is a **pilot** for local, loopback use. Review it before you use it in production.
- Savepoints are local copies. They don't replace backups or version control.

---

## Contributing & contact

Issues, pull requests and pilot partners are welcome.

- **Author:** Abdul Manan ([@abdulmanan089](https://github.com/abdulmanan089))
- **PyPI:** https://pypi.org/project/chrono-agent/
- **License:** MIT
