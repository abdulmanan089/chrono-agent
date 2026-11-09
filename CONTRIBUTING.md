# Contributing

Small reproducible fixes and platform verification are welcome.

1. Install from source: `python -m pip install .`.
2. Run `python -m unittest discover -s tests -v`.
3. Exercise changes only in disposable folders; never run destructive commands as tests.
4. Include Python version, OS, expected behavior, actual behavior and a minimal reproduction in a pull request.
5. Update verification limits when evidence changes. Do not call simulated outcomes benchmarks or claim production readiness.

Priorities: native Windows/macOS verification, authenticated approval boundaries, independent audit retention, real-client MCP compatibility, and live database restore testing. See VERIFICATION.md for current limitations.

## Licensing of contributions
Chrono Agent is source-available (see `LICENSE`), with commercial licenses available (`LICENSE-COMMERCIAL.txt`). By submitting a pull request you confirm that you wrote the contribution, and you grant Abdul Manan a perpetual, worldwide, royalty-free right to use, modify and distribute it under the project's source-available and commercial licenses. Contact: manandogar112@gmail.com.
