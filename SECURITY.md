# Security and threat model

This project is an experimental local tool, not a security boundary. Use disposable projects and independent backups. Never grant it access to production secrets on the strength of a passing test.

Command detection is heuristic. Scripts and external IDE actions can bypass it. Local names, roles and approval flags do not authenticate people. Anyone able to edit snapshot storage or holding the HMAC key can undermine evidence. File restore cannot undo network effects or guarantee power-loss-safe whole-tree recovery.

Do not put API keys, signing keys, private source, snapshots or database dumps in issues. For a suspected vulnerability, use GitHub private vulnerability reporting if enabled. Otherwise open a minimal issue requesting a private reporting channel without exploit details or secrets. No response-time or compliance certification is promised.
