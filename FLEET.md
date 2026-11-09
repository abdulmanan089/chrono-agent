# Fleet pilot (introduced in 0.4.0rc1, shipped unchanged in 0.5.0)

Five additions: model gateway, dynamic fleet registry, separate agent recovery lanes,
async expiring approvals + webhook notices, and a live browser fleet report.
This is a **local pilot**, not an enterprise-ready universal agent controller.

## Install from the release ZIP (Windows CMD)

```cmd
python -m pip install --upgrade chrono-agent
python -m chrono_agent --version
```

If `chrono` is not on PATH, use `python -m chrono_agent` instead.
Use a disposable control directory, not a production workspace:

```cmd
mkdir chrono-control
cd chrono-control
chrono init
```

Generate two independent random tokens using a secret manager (at least 24 characters).
Set these privately in the service's environment; never paste real tokens into chat:

```cmd
set CHRONO_GATEWAY_TOKEN=<private-agent-gateway-token>
set CHRONO_ADMIN_TOKEN=<different-private-admin-token>
chrono gateway start --upstream https://api.openai.com
```

For Anthropic run a separate instance/port with `--upstream https://api.anthropic.com`.
For a local OpenAI-compatible server use its loopback origin, e.g. `http://localhost:11434`.
The gateway appends `/v1/chat/completions` or `/v1/messages` to that origin.
One upstream per instance; this is not provider auto-detection.

## Connect the existing AI platform

Keep giving tasks in the platform normally, but configure its model client to send
requests through Chrono. Installation alone does **not** reroute or discover agents.
For OpenAI-compatible SDK clients, use `base_url=http://127.0.0.1:8787/v1`;
for Anthropic use `base_url=http://127.0.0.1:8787`.
Set `stream=False`, keep the provider credential, and add headers:

- `X-Chrono-Token`: the gateway credential
- `X-Chrono-Agent`: a stable distinct agent identity, e.g. `billing-agent`

Every new identity registers automatically on first traffic. No configured agent
count or fixed numerical limit exists; tested with 2, 5, 15 and 40 identities.
This is not a capacity/SLA guarantee. Shared credentials and supplied names are not
strong per-agent authentication; use separate workload identities in a production design.

Dangerous/pending tool replies are withheld entirely with HTTP 403. The platform must
handle this response, show the error and explicitly retry after approval. Chrono does
not execute the tool, automatically retry the model or snapshot downstream actions.
Unrecognized adapters and streaming are refused, not silently passed through.

For custom executors, POST `/chrono/check` with the headers above and a JSON body:

```json
{"model":"custom","action":{"tool":"shell","arguments":{"command":"DROP TABLE users"}}}
```

The response is `allow`, `block` or `approve`. The executor must enforce this before
execution and prevent direct bypass; an HTTP check alone is not mandatory interception.

## Recovery lanes: separate directories, explicit savepoints

Use disjoint absolute workspaces outside the control directory. Each has its own
existing Chrono snapshots, branch/diff/SDK and report capabilities.

```cmd
chrono fleet register architect --workspace "C:\test\architect"
chrono fleet register coder --workspace "C:\test\coder"
chrono fleet savepoint coder
chrono fleet list
chrono fleet rollback coder <snapshot-id> --yes
```

Stop writers before recovery. Only coder's directory is restored. A rescue snapshot
is created first; use its returned `redo` ID for another explicit rollback to redo.
This is filesystem separation, **not containers or enforced process isolation**.
Existing `chrono run`, branches, diff and registered-database commands run inside each
lane directory, not through the model proxy. The gateway cannot undo payments, email,
remote API effects, production cloud state or another agent's shared database writes.

## Approvals and live reporting

Policy lives in the control directory's `chrono-policy.yaml`; existing rules/thresholds
apply. Optional `approvers` names restrict human labels; admin authentication is the
separate admin token. Approvals bind the whole structured action, agent and current
policy, expire in ten minutes and can be used once. Rejected/expired actions need a
new request; changing any action argument or policy invalidates its approval.

```cmd
chrono approvals list
chrono approvals approve <approval-id> --by manan
chrono approvals deny <approval-id> --by manan
```

Local CLI decisions trust the OS user with access to the control directory; the browser
requires the admin token. These are not company accounts or SSO/RBAC.

Open `http://127.0.0.1:8787/chrono/dashboard`, enter the admin token, and view live
agents/calls/blocks, approvals and audit events. It refreshes every three seconds.
The token remains in page memory, not browser storage or URL. Webhook notification:

```cmd
chrono gateway start --upstream https://api.openai.com --webhook https://your-notification-endpoint
```

Webhook is a generic JSON POST with `text`, approval ID, agent and score. It contains
no action arguments; connect a receiver to Slack/Teams as appropriate. Failure is audited;
it never permits the action. No Slack/Teams OAuth app or signed one-click link is included.

## Security / deployment limits

Loopback only; not a remotely deployable company service. Remote TLS ingress, distributed
storage, workload authentication, org accounts/SSO/RBAC, rate limits, durable notification
queues and production observability require further work. Pattern scans have false positives
and bypasses: unknown/hallucinated APIs are not detected automatically. An allowed call is
not evidence of safety. OS monitoring, network enforcement and malicious-editor containment
are not provided. Keep independent backups and test all actual integrations before rollout.

Fleet state uses SQLite transactions; fleet audit is a separate local hash chain in
`.chrono/fleet.sqlite`. `chrono fleet list` verifies it. It detects edits but is not signed,
immutable or independently anchored; a local administrator can rewrite/delete it.
The per-workspace audit logs (`.chrono/audit.jsonl`) are separate. Since 0.5.0 they are
HMAC-signed with a key outside the project and have an external witness (see README).
The fleet chain itself is not signed yet.
