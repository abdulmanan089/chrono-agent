# Publishing Chrono Agent 0.5.0 so anyone can `pip install`

The build is done: `dist/chrono_agent-0.5.0-py3-none-any.whl` and `dist/chrono_agent-0.5.0.tar.gz`.
Both passed `twine check`, and installing only the wheel in a clean environment gives a working `chrono`
command with no source files present. This guide takes it to PyPI.

## 0. First: the package name

`chrono-agent` is **already on PyPI** (version 0.4.0, with this project's old description).

- **If you published that 0.4.0** → you own the name. Go to step 2; publishing 0.5.0 updates it.
- **If someone else did** → you cannot publish under it, and `pip install chrono-agent` would give people
  their package, not yours. Either:
  - pick a free name and change `name =` in `pyproject.toml`, then rebuild (these were free: `chrono-guard`,
    `chrono-safe`, `chrono-sentinel`, `chrono-rewind`, `chrono-agent-ai`); or
  - if that 0.4.0 is your own project uploaded by someone else, contact PyPI support about the name.

## 1. One-time setup
1. Create an account at https://pypi.org and verify your email (and https://test.pypi.org for testing).
2. Create an API token: Account settings -> API tokens -> Add API token (scope: entire account for the first
   upload; narrow it to the project afterward).
3. `build` and `twine` are already installed.

## 2. Fill in the placeholders before publishing
- `LICENSE` and `LICENSE-COMMERCIAL.txt`: replace every `<YOUR LEGAL NAME>`, `<YOUR JURISDICTION>`, `<YOUR EMAIL>`.
- `chrono_agent\*.py` headers: replace `<YOUR NAME or COMPANY>` (one search-and-replace across the folder).
- `pyproject.toml`: set a real `authors` entry and `[project.urls] Homepage`. Set `name =` if you changed it.

## 3. Build cleanly
```cmd
cd /d C:\Users\manan\Downloads\chrono-agent-0_4_1rc2-winfix\chrono-agent-0.5.0
rmdir /s /q dist
python -m build
twine check dist/*
```
Expect two files and `PASSED` for both. Keep only the `.whl` and `.tar.gz` in `dist` before uploading.

## 4. Test on TestPyPI first (recommended)
```cmd
twine upload --repository testpypi dist/*
```
Username: `__token__`  ·  Password: your **TestPyPI** token. Then, in a clean virtual environment:
```cmd
pip install --index-url https://test.pypi.org/simple/ chrono-agent
chrono --version
```

## 5. Publish to real PyPI
```cmd
twine upload dist/*
```
Username: `__token__`  ·  Password: your **PyPI** token.

## 6. Now the one-command install works for everyone
```cmd
pip install chrono-agent
chrono --version
```
If `chrono` is not on PATH, `python -m chrono_agent ...` always works.

## Updating later
You cannot re-upload the same version number. Bump `version` in **both** `pyproject.toml` and
`chrono_agent\__init__.py`, rebuild, and upload again.

## If you want it PRIVATE instead of world-readable
Public PyPI makes the source (`.tar.gz`) downloadable by anyone. For closed distribution:
- run a private index (self-hosted `devpi`, or a paid private registry) and have users install with
  `pip install --index-url https://<your-private-index> chrono-agent`; or
- hand the wheel to each customer directly: `pip install chrono_agent-0.5.0-py3-none-any.whl`.

There is no safe one-line `curl | pip` installer for a PyPI package: the one-liner **is** `pip install <name>`.
Piping a remote script into a shell is exactly the pattern Chrono itself flags as dangerous, so do not ship that.
