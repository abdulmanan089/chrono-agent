"""Keep the test suite away from the real Chrono home (~/.chrono-agent).

Every test module imports this before it uses chrono_agent. The audit signing
keys, witnesses and policy pins created by the tests then live in a temporary
folder that is removed when the run ends. Child processes started by the tests
inherit CHRONO_HOME, so they use the same temporary home.
"""
import atexit
import os
import shutil
import tempfile

if not os.environ.get("CHRONO_TEST_HOME"):
    _home = tempfile.mkdtemp(prefix="chrono-home-test-")
    os.environ["CHRONO_HOME"] = _home
    os.environ["CHRONO_TEST_HOME"] = _home
    atexit.register(shutil.rmtree, _home, True)
