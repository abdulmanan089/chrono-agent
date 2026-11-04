from .snapshot import SnapshotStore


class Transaction:
    """Cooperating local file transaction; no external-effect or crash atomicity."""
    def __init__(self, root=".", message="agent transaction"):
        self.store = SnapshotStore(root)
        if not self.store.initialized:
            self.store.init()
        self.message = message
        self.savepoints = {}
        self.active = False

    def __enter__(self):
        if self.active:
            raise RuntimeError("Transaction already active")
        self._lock = self.store.locked()
        self._lock.__enter__()
        try:
            self.begin = self.store.snapshot("BEGIN " + self.message, kind="begin")
        except BaseException:
            self._lock.__exit__(None, None, None)
            raise
        self.active = True
        self.savepoints = {}
        return self

    def _need_active(self):
        if not self.active:
            raise RuntimeError("Transaction is not active")

    def savepoint(self, name):
        self._need_active()
        if not isinstance(name, str) or not name or name in self.savepoints:
            raise RuntimeError("Savepoint name must be non-empty and unique")
        self.savepoints[name] = self.store.snapshot("SAVEPOINT " + name, kind="savepoint")["id"]
        return self.savepoints[name]

    def rollback_to(self, name):
        self._need_active()
        if name not in self.savepoints:
            raise RuntimeError("Unknown savepoint: " + str(name))
        result = self.store.restore(self.savepoints[name])
        keys = list(self.savepoints)
        for later in keys[keys.index(name)+1:]:
            del self.savepoints[later]
        return result

    def rollback(self):
        self._need_active()
        result = self.store.restore(self.begin["id"])
        self.savepoints.clear()
        return result

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type:
                try:
                    self.rollback()
                except Exception as recovery:
                    raise RuntimeError("Transaction failed and rollback also failed: " + str(recovery)) from exc
            else:
                try:
                    self.store.snapshot("COMMIT " + self.message, kind="commit")
                except BaseException as commit_error:
                    try:
                        self.rollback()
                    except Exception as recovery:
                        raise RuntimeError("Commit and rollback failed: " + str(recovery)) from commit_error
                    raise
        finally:
            self.active = False
            self._lock.__exit__(None, None, None)
        return False
