# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Git integration: record the Git commit each snapshot belongs to, and
optionally snapshot automatically after every git commit via a post-commit
hook. Chrono never runs git commands that modify the repository."""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

MARKER = "# chrono-agent post-commit hook"
HOOK = """#!/bin/sh
# chrono-agent post-commit hook — snapshot tracked project files after each commit.
%(run)s snapshot -m "git commit $(git rev-parse --short HEAD)" >/dev/null 2>&1 || echo "chrono: snapshot after commit failed (run: chrono snapshot)" >&2
"""


def _hook_text():
    """Hook body that calls the exact interpreter used to install it, so it does
    not depend on a 'chrono' script being on PATH (virtualenvs, Windows)."""
    run = "%s -m chrono_agent" % shlex.quote(Path(sys.executable).as_posix())
    pkg_parent = Path(__file__).resolve().parent.parent
    if not {"site-packages", "dist-packages"} & set(pkg_parent.parts):   # running from a source tree
        run = "PYTHONPATH=%s %s" % (shlex.quote(pkg_parent.as_posix()), run)
    return HOOK % {"run": run}


def _git(root, *args):
    try:
        out = subprocess.run(["git", "-C", str(root)] + list(args),
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def is_repo(root):
    return _git(root, "rev-parse", "--is-inside-work-tree") == "true"


def head(root):
    """Current commit hash, or None (no repo / no commits yet / git missing)."""
    return _git(root, "rev-parse", "HEAD")


def _hook_path(root):
    gitdir = _git(root, "rev-parse", "--git-dir")
    if not gitdir:
        return None
    p = Path(gitdir)
    if not p.is_absolute():
        p = Path(root).resolve() / p
    return p / "hooks" / "post-commit"


def hook_installed(root):
    p = _hook_path(root)
    return bool(p and p.is_file() and MARKER in p.read_text(encoding="utf-8", errors="replace"))


def install_hook(root):
    if not is_repo(root):
        raise RuntimeError("Not a git repository: " + str(root))
    p = _hook_path(root)
    if p is None:
        raise RuntimeError("Cannot locate the git hooks directory")
    if p.exists():
        text = p.read_text(encoding="utf-8", errors="replace")
        if MARKER in text:
            return False
        raise RuntimeError("A post-commit hook already exists at %s; add this line to it manually:\n"
                           '  chrono snapshot -m "git commit $(git rev-parse --short HEAD)"' % p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_hook_text(), encoding="utf-8")
    os.chmod(p, 0o755)
    return True


def uninstall_hook(root):
    p = _hook_path(root)
    if p is None or not p.is_file():
        return False
    if MARKER not in p.read_text(encoding="utf-8", errors="replace"):
        raise RuntimeError("Refusing to remove a hook that Chrono did not install: " + str(p))
    p.unlink()
    return True


def status(root, store=None):
    info = {"repo": is_repo(root), "head": head(root), "hook": hook_installed(root),
            "snapshot_head": None, "in_sync": None}
    if store is not None and store.initialized:
        try:
            meta = store.get()
            info["snapshot_head"] = meta.get("git_head")
            if info["head"] and info["snapshot_head"]:
                info["in_sync"] = info["head"] == info["snapshot_head"]
        except RuntimeError:
            pass
    return info
