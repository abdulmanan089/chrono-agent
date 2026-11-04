# Publishing chrono-agent to PyPI

The package is prepared for PyPI (MIT license, pyproject metadata, console
script). The actual publish needs YOUR PyPI account — it cannot be done for you.

## One-time setup

1. Create an account at https://pypi.org and verify your email.
2. Create an API token: Account settings → API tokens → "Add API token"
   (scope: entire account; narrow it to the project after the first upload).
3. Install the tools:

       pip install build twine

## Publish

From the folder containing `pyproject.toml`:

    python -m build          # creates dist/chrono_agent-<ver>.tar.gz and .whl
    twine check dist/*       # validates metadata
    twine upload dist/*      # asks for username __token__ and your API token

After that, anyone can run:

    pip install chrono-agent

## Before each release

- Bump `version` in `pyproject.toml` and `chrono_agent/__init__.py` together.
- Run the full test suite: `python -m unittest discover -s tests -v`.
- Smoke-test the installed CLI in a clean virtual environment.
- Update README.md / VERIFICATION.md if behavior changed.

## Test on TestPyPI first (optional but recommended)

    twine upload --repository testpypi dist/*
    pip install --index-url https://test.pypi.org/simple/ chrono-agent
