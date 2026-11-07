# 0.4.0rc1 verification — Linux, Python 3.13

- 108 tests passed: 87 existing regressions + 21 fleet/gateway tests.
- One existing Git hook test excluded: sandbox prevents stateful Git operations.
- Concurrent discovery tested for 2, 5, 15 and 40 distinct agent identities.
- Real local HTTP forwarding tested against OpenAI/Anthropic-shaped mock providers:
  dangerous tool responses withheld, other agent passes, missing auth and streaming
  refused before provider traffic; custom action approvals + webhook + read-back tested.
- Separate workspace rollback preserves another agent's file; rescue-based redo tested.
- Browser: admin login, approval decision, persisted read-back, chain status, desktop and
  mobile checked with Playwright; no browser errors. Tables scroll on small screens.

Not verified: live paid model accounts, Antigravity integration, real Slack/Teams receiver,
Windows/macOS for this release, distributed/company deployments, adversarial security,
load/performance guarantees, hosted recovery or external side effects, PyPI publication.
No claim of error-free software or automatic company-wide protection.
