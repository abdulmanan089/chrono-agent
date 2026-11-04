"""Content-addressed local snapshots; not a database or OS sandbox."""
import contextlib
import hashlib
import json
import os
import re
import stat
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath

from .audit import AuditLog, GENESIS
from . import gitlink

IGNORE = {".chrono", ".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode"}
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
SID = re.compile(r"sp_[A-Za-z0-9_]+\Z")


def _files(root):
    def onerror(error):
        raise RuntimeError("Cannot read project directory: " + str(error))
    for dp, dns, fns in os.walk(root, followlinks=False, onerror=onerror):
        dns[:] = sorted(d for d in dns if d not in IGNORE)
        for name in dns + sorted(fns):
            p = Path(dp) / name
            if p.is_symlink():
                raise RuntimeError("Symlinks are unsupported: " + str(p))
        for name in sorted(fns):
            if name in IGNORE:
                continue
            p = Path(dp) / name
            if not stat.S_ISREG(p.stat().st_mode):
                raise RuntimeError("Unsupported file type: " + str(p))
            yield p.relative_to(root).as_posix()


def _hash(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _atomic(path, data, mode=None):
    """Replace one file without exposing a half-written version."""
    fd, temp = tempfile.mkstemp(prefix=".chrono-write-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


class SnapshotStore:
    def __init__(self, root="."):
        self.root = Path(root).resolve()
        self.dir = self.root / ".chrono"
        self.objects = self.dir / "objects"
        self.snaps = self.dir / "snapshots"
        self.audit = AuditLog(self.root)
        self._depth = 0

    @property
    def initialized(self):
        self._safe_metadata()
        return (self.dir / "state.json").is_file()

    def _safe_metadata(self):
        for p in (self.dir, self.objects, self.snaps, self.dir / "state.json",
                  self.dir / "lock", self.dir / "audit.jsonl"):
            if p.is_symlink():
                raise RuntimeError("Unsafe symlink in snapshot storage: " + str(p))

    def init(self):
        if not self.root.is_dir():
            raise RuntimeError("Project directory does not exist")
        self._safe_metadata()
        self.objects.mkdir(parents=True, exist_ok=True)
        self.snaps.mkdir(parents=True, exist_ok=True)
        with self.locked():
            if not (self.dir / "state.json").exists():
                self.save_state({"branch": "main", "branches": {"main": None}})

    @contextlib.contextmanager
    def locked(self):
        """OS lock serializes cooperating Chrono processes (not arbitrary editors)."""
        self._safe_metadata()
        if self._depth:
            self._depth += 1
            try:
                yield self
            finally:
                self._depth -= 1
            return
        if not self.dir.is_dir():
            raise RuntimeError("Not a chrono project. Run: chrono init")
        f = open(self.dir / "lock", "a+b")
        acquired = False
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0, 2)
                if f.tell() == 0:
                    f.write(b"0"); f.flush()
                f.seek(0)
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as e:
                    raise RuntimeError("Project busy: another Chrono operation is running") from e
            else:
                import fcntl
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as e:
                    raise RuntimeError("Project busy: another Chrono operation is running") from e
            acquired = True
            self._depth = 1
            yield self
        finally:
            self._depth = 0
            if acquired:
                if os.name == "nt":
                    import msvcrt
                    f.seek(0); msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            f.close()

    def _need(self):
        if not self.initialized:
            raise RuntimeError("Not a chrono project. Run: chrono init")

    def state(self):
        self._need()
        try:
            st = json.loads((self.dir / "state.json").read_text(encoding="utf-8"))
            if not isinstance(st, dict) or not isinstance(st.get("branches"), dict):
                raise ValueError("Invalid branches")
            if st.get("branch") not in st["branches"]:
                raise ValueError("Invalid active branch")
            for b, sid in st["branches"].items():
                self.validate_branch(b)
                if sid is not None and (not isinstance(sid, str) or not SID.fullmatch(sid)):
                    raise ValueError("Invalid head")
            return st
        except (ValueError, TypeError) as e:
            raise RuntimeError("Corrupt snapshot state; keep .chrono for recovery") from e

    @staticmethod
    def validate_branch(name):
        if not isinstance(name, str) or not BRANCH.fullmatch(name):
            raise RuntimeError("Branch name: 1-80 letters, digits, dots, underscores or hyphens; start with a letter/digit")

    def save_state(self, st):
        self._safe_metadata()
        _atomic(self.dir / "state.json", json.dumps(st, indent=2).encode("utf-8"))

    def _path(self, rel):
        p = PurePosixPath(rel)
        if (not isinstance(rel, str) or not rel or p.is_absolute() or p.as_posix() != rel
                or any(x in (".", "..") or x in IGNORE or ":" in x or "\\" in x for x in p.parts)):
            raise RuntimeError("Unsafe snapshot path: " + str(rel))
        dst = self.root.joinpath(*p.parts)
        for part in [dst] + list(dst.parents):
            if part == self.root:
                break
            if part.is_symlink():
                raise RuntimeError("Symlink would escape snapshot protection: " + rel)
        return dst

    def current_manifest(self):
        return {rel: _hash(self._path(rel)) for rel in _files(self.root)}

    def snapshot(self, message="snapshot", kind="manual", merge_parent=None):
        self._need()
        with self.locked():
            t0 = time.perf_counter()
            man, modes = {}, {}
            for rel in _files(self.root):
                p = self._path(rel)
                data = p.read_bytes()
                h = hashlib.sha256(data).hexdigest()
                obj = self.objects / h
                if obj.is_symlink():
                    raise RuntimeError("Unsafe object symlink")
                if obj.exists():
                    if _hash(obj) != h:
                        raise RuntimeError("Corrupt snapshot object: " + h)
                else:
                    _atomic(obj, data)
                man[rel] = h
                modes[rel] = stat.S_IMODE(p.stat().st_mode)
            if self.current_manifest() != man:
                raise RuntimeError("Files changed during snapshot; stop other writers and retry")
            st = self.state()
            sid = "sp_" + time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex
            aseq, ahead = self.audit.head()
            meta = {"id": sid, "message": message, "kind": kind, "time": time.time(),
                    "branch": st["branch"], "parent": st["branches"][st["branch"]],
                    "files": man, "modes": modes, "ms": round((time.perf_counter()-t0)*1000, 1),
                    "audit_seq": aseq, "audit_head": ahead,
                    "git_head": gitlink.head(self.root)}
            if merge_parent:
                meta["merge_parent"] = merge_parent
            _atomic(self.snaps / (sid + ".json"), json.dumps(meta, indent=2).encode("utf-8"))
            st["branches"][st["branch"]] = sid
            self.save_state(st)
            self.audit.record("snapshot", kind=kind, detail=message, snapshot=sid,
                              files=len(man))
            return meta

    def list(self):
        self._need()
        return sorted([self.get(p.stem) for p in self.snaps.glob("*.json")], key=lambda m: m["time"])

    def get(self, sid=None):
        self._need()
        if sid is None:
            st = self.state(); sid = st["branches"][st["branch"]]
        if not sid:
            raise RuntimeError("No snapshots yet. Run: chrono snapshot")
        if not isinstance(sid, str) or not SID.fullmatch(sid):
            raise RuntimeError("Invalid snapshot ID")
        matches = [p for p in self.snaps.glob("*.json") if p.stem == sid or p.stem.startswith(sid)]
        if len(matches) != 1:
            raise RuntimeError("Snapshot not found or ambiguous: " + sid)
        if matches[0].is_symlink():
            raise RuntimeError("Unsafe snapshot symlink")
        try:
            meta = json.loads(matches[0].read_text(encoding="utf-8"))
            if not isinstance(meta, dict) or meta.get("id") != matches[0].stem or not isinstance(meta.get("files"), dict):
                raise ValueError("Invalid snapshot")
            self.validate_branch(meta["branch"])
            if not isinstance(meta["time"], (int, float)) or not isinstance(meta["message"], str):
                raise ValueError("Invalid metadata")
            for rel, h in meta["files"].items():
                self._path(rel)
                if not isinstance(h, str) or not HASH.fullmatch(h):
                    raise ValueError("Invalid object digest")
            for key in ("parent", "merge_parent"):
                if meta.get(key) is not None and not SID.fullmatch(meta[key]):
                    raise ValueError("Invalid parent")
            for rel, mode in meta.get("modes", {}).items():
                if rel not in meta["files"] or not isinstance(mode, int) or mode < 0 or mode > 0o7777:
                    raise ValueError("Invalid file mode")
            seq = meta.get("audit_seq")
            if seq is not None and (isinstance(seq, bool) or not isinstance(seq, int) or seq < 0):
                raise ValueError("Invalid audit anchor")
            head = meta.get("audit_head")
            if head is not None and head != GENESIS and not (isinstance(head, str) and HASH.fullmatch(head)):
                raise ValueError("Invalid audit anchor")
            return meta
        except (ValueError, KeyError, TypeError) as e:
            raise RuntimeError("Corrupt snapshot metadata: " + sid) from e

    def diff(self, sid=None):
        with self.locked():
            meta = self.get(sid); old = meta["files"]; new = self.current_manifest()
            modified = {k for k in set(old) & set(new) if old[k] != new[k]}
            if os.name != "nt":
                modified |= {k for k in set(old) & set(new) if k in meta.get("modes", {})
                             and stat.S_IMODE(self._path(k).stat().st_mode) != meta["modes"][k]}
            return {"added": sorted(set(new)-set(old)), "deleted": sorted(set(old)-set(new)),
                    "modified": sorted(modified)}

    def _object(self, h):
        p = self.objects / h
        if p.is_symlink() or not p.is_file() or _hash(p) != h:
            raise RuntimeError("Missing/corrupt snapshot object; nothing restored: " + h)
        return p.read_bytes()

    def _clean_dirs(self):
        # Prune ignored trees before walking: never descend into .git / .chrono.
        dirs = []
        for dp, dns, _ in os.walk(self.root):
            dns[:] = [d for d in dns if d not in IGNORE]
            dirs.append(Path(dp))
        for p in reversed(dirs):
            if p != self.root and not any(p.iterdir()):
                p.rmdir()

    def _apply(self, files, modes):
        current = list(_files(self.root))
        for rel in current:
            if rel not in files:
                self._path(rel).unlink()
        self._clean_dirs()
        for rel, data in files.items():
            dst = self._path(rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            _atomic(dst, data, modes.get(rel))
        self._clean_dirs()

    def _restore_files(self, files, modes):
        # Validate all objects/paths before removing anything. Preserve a recovery copy.
        target = {rel: self._object(h) for rel, h in files.items()}
        for rel in target:
            dst = self._path(rel)
            for other in target:
                if other != rel and other.startswith(rel + "/"):
                    raise RuntimeError("Conflicting snapshot file paths")
            if dst.is_dir():
                for dp, dns, fns in os.walk(dst):
                    if any(n in IGNORE for n in dns + fns):
                        raise RuntimeError("Restore would replace a directory containing ignored data: " + rel)
        original = {rel: self._path(rel).read_bytes() for rel in _files(self.root)}
        original_modes = {rel: stat.S_IMODE(self._path(rel).stat().st_mode) for rel in original}
        try:
            self._apply(target, modes)
        except BaseException:
            self._apply(original, original_modes)
            raise

    def restore(self, sid=None, move_head=True):
        with self.locked():
            meta = self.get(sid)
            self._restore_files(meta["files"], meta.get("modes", {}))
            if move_head:
                st = self.state(); st["branches"][st["branch"]] = meta["id"]; self.save_state(st)
            self.audit.record("restore", kind="rollback", detail=meta["message"],
                              snapshot=meta["id"], files=len(meta["files"]))
            return meta

    def read_old(self, sid, rel):
        h = self.get(sid)["files"].get(rel)
        return self._object(h).decode("utf-8", errors="replace") if h else ""

    def verify_audit(self):
        """Cross-check each snapshot's audit anchor against the current chain.

        This catches a log that was rewritten and re-chained after an edit: every
        snapshot stores the log head that existed when it was taken, so a forged
        log no longer matches the snapshots made after that record.
        """
        by_seq = {}
        for rec in self.audit.read():
            if isinstance(rec.get("seq"), int) and isinstance(rec.get("hash"), str):
                by_seq[rec["seq"]] = rec["hash"]
        problems = []
        for meta in self.list():
            seq, head = meta.get("audit_seq"), meta.get("audit_head")
            if not isinstance(seq, int) or seq == 0:
                continue
            if not isinstance(head, str) or by_seq.get(seq) != head:
                problems.append((meta["id"], "audit record #" + str(seq) + " is missing or edited"))
        return problems

    def create_branch(self, name):
        self.validate_branch(name)
        with self.locked():
            st = self.state()
            if name in st["branches"]:
                raise RuntimeError("Branch already exists: " + name)
            if any(self.diff().values()):
                self.snapshot("leave " + st["branch"])
            st = self.state(); st["branches"][name] = st["branches"][st["branch"]]
            st["branch"] = name; self.save_state(st)

    def checkout(self, name):
        with self.locked():
            st = self.state()
            if name not in st["branches"]:
                raise RuntimeError("No branch: " + name)
            if name == st["branch"]:
                return
            target = self.get(st["branches"][name])
            # Verify target objects before saving or switching the source branch.
            for h in target["files"].values():
                self._object(h)
            if any(self.diff().values()):
                self.snapshot("leave " + st["branch"])
            self.restore(target["id"], move_head=False)
            st = self.state(); st["branch"] = name; self.save_state(st)

    def _ancestors(self, sid):
        out, pending = {}, [(sid, 0)]
        while pending:
            node, depth = pending.pop(0)
            if node is None or node in out:
                continue
            out[node] = depth
            m = self.get(node)
            pending.extend((m.get(k), depth+1) for k in ("parent", "merge_parent"))
        return out

    def merge(self, name):
        with self.locked():
            st = self.state()
            if name not in st["branches"] or name == st["branch"]:
                raise RuntimeError("Choose another existing branch")
            if any(self.diff().values()):
                raise RuntimeError("Save or rollback working changes before merge")
            ours = self.get(); theirs = self.get(st["branches"][name])
            oa, ta = self._ancestors(ours["id"]), self._ancestors(theirs["id"])
            common = set(oa) & set(ta)
            if not common:
                raise RuntimeError("Branches have no common ancestor")
            base = self.get(min(common, key=lambda x: (oa[x]+ta[x], x)))
            merged, modes, conflicts = {}, {}, []
            def value(meta, rel):
                h = meta["files"].get(rel)
                return (h, meta.get("modes", {}).get(rel)) if h else None
            for rel in sorted(set(base["files"]) | set(ours["files"]) | set(theirs["files"])):
                b, o, t = value(base, rel), value(ours, rel), value(theirs, rel)
                if o == t or t == b:
                    chosen = o
                elif o == b:
                    chosen = t
                else:
                    conflicts.append(rel); continue
                if chosen:
                    merged[rel] = chosen[0]
                    if chosen[1] is not None:
                        modes[rel] = chosen[1]
            if conflicts:
                raise RuntimeError("Merge conflict (nothing changed): " + ", ".join(conflicts))
            self._restore_files(merged, modes)
            try:
                return self.snapshot("merge " + name + " into " + st["branch"], kind="merge", merge_parent=theirs["id"])
            except BaseException:
                self.restore(ours["id"])
                raise
