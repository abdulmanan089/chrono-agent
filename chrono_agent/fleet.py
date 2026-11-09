# Chrono Agent  (c) 2026 Abdul Manan.  Source-available; see LICENSE.
# Resale or offering as a hosted service is prohibited.  All rights reserved.
"""Local fleet pilot. Separate workspaces, SQLite coordination and audit chain.
Not an OS sandbox or distributed transaction coordinator.
"""
import contextlib
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from .snapshot import SnapshotStore
from .policy import load, evaluate

IDENTITY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')

def _strings(value):
    """Every string inside a structured action, in order."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k in sorted(value, key=str):
            yield from _strings(value[k])
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

class Fleet:
    def __init__(self, root='.'):
        self.root = Path(root).resolve()
        self.dir = self.root / '.chrono'
        if not SnapshotStore(self.root).initialized:
            raise RuntimeError('Run chrono init in the fleet control directory first')
        self.path = self.dir / 'fleet.sqlite'
        if self.path.is_symlink():
            raise RuntimeError('Unsafe fleet storage symlink')
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, model TEXT, seen REAL, calls INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, workspace TEXT UNIQUE);
            CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY, agent TEXT, digest TEXT, status TEXT, created REAL, expires REAL, actor TEXT, summary TEXT);
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, ts REAL, agent TEXT, action TEXT, detail TEXT, prev TEXT, hash TEXT);
            ''')
            if 'summary' not in [r[1] for r in db.execute('PRAGMA table_info(approvals)')]:
                db.execute('ALTER TABLE approvals ADD COLUMN summary TEXT')

    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(str(self.path), timeout=30)
        db.row_factory = sqlite3.Row
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def event(self, db, agent, action, detail):
        head = db.execute('SELECT hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        prev = head[0] if head else 'GENESIS'
        seq = db.execute('SELECT COALESCE(MAX(seq),0)+1 FROM events').fetchone()[0]
        ts = time.time()
        detail = canonical(detail)
        payload = canonical([seq, ts, agent, action, detail, prev]).encode()
        digest = hashlib.sha256(payload).hexdigest()
        db.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?)', (seq,ts,agent,action,detail,prev,digest))

    def touch(self, agent, model=''):
        if not isinstance(agent,str) or not IDENTITY.fullmatch(agent):
            raise ValueError('Invalid agent identity')
        with self.db() as db:
            new = not db.execute('SELECT 1 FROM agents WHERE id=?',(agent,)).fetchone()
            db.execute('INSERT OR IGNORE INTO agents(id) VALUES(?)',(agent,))
            db.execute('UPDATE agents SET model=?,seen=?,calls=calls+1 WHERE id=?',(str(model)[:120],time.time(),agent))
            if new:
                self.event(db,agent,'discovered',{})

    def register(self, agent, workspace):
        self.touch(agent)
        raw = Path(workspace).absolute()
        if raw.is_symlink() or any(p.is_symlink() for p in raw.parents):
            raise ValueError('Workspace symlinks are unsupported')
        workspace = raw.resolve()
        if not workspace.is_dir():
            raise ValueError('Workspace must exist')
        with self.db() as db:
            paths = [self.root] + [Path(r[0]) for r in db.execute('SELECT workspace FROM agents WHERE workspace IS NOT NULL AND id<>?',(agent,))]
            for other in paths:
                if workspace == other or workspace in other.parents or other in workspace.parents:
                    raise ValueError('Lane workspaces must be disjoint, including the control directory')
            old = db.execute('SELECT workspace FROM agents WHERE id=?',(agent,)).fetchone()[0]
            if old and old != str(workspace):
                raise ValueError('Existing lane cannot be reassigned')
            store = SnapshotStore(workspace)
            if not store.initialized:
                store.init(); store.snapshot('fleet initial')
            db.execute('UPDATE agents SET workspace=? WHERE id=?',(str(workspace),agent))
            self.event(db,agent,'lane.registered',{'workspace':str(workspace)})

    def lane(self, agent):
        with self.db() as db:
            row = db.execute('SELECT workspace FROM agents WHERE id=?',(agent,)).fetchone()
        if not row or not row[0]:
            raise ValueError('Agent has no registered workspace')
        return SnapshotStore(row[0])

    def decision(self, agent, action):
        """Check the complete structured action, not individual strings. Approval is
        bound to agent + entire action + current policy, single-use and expiring."""
        policy = load(self.root)
        text = canonical(action)
        # Scan the decoded strings too: JSON escaping can hide a command.
        flat = '\n'.join(_strings(action))
        r = evaluate(text,policy)
        r2 = evaluate(flat,policy) if flat else r
        if (r2['blocked'], r2['score']) > (r['blocked'], r['score']):
            r = r2
        digest = hashlib.sha256(canonical([action,policy]).encode()).hexdigest()
        result = dict(r)
        with self.db() as db:
            if r['action'] == 'approve':
                now = time.time()
                approved = db.execute("SELECT id FROM approvals WHERE agent=? AND digest=? AND status='approved' AND expires>? ORDER BY created LIMIT 1",(agent,digest,now)).fetchone()
                if approved:
                    db.execute("UPDATE approvals SET status='used' WHERE id=?",(approved[0],))
                    result['action']='allow'; result['approval_id']=approved[0]
                else:
                    pending = db.execute("SELECT id FROM approvals WHERE agent=? AND digest=? AND status='pending' AND expires>?",(agent,digest,now)).fetchone()
                    aid = pending[0] if pending else uuid.uuid4().hex
                    if not pending:
                        db.execute('INSERT INTO approvals(id,agent,digest,status,created,expires,actor) VALUES(?,?,?,?,?,?,?)',(aid,agent,digest,'pending',now,now+600,None))
                    result['approval_id']=aid
                    result['new_approval']=not bool(pending)
            result['blocked'] = result['action'] != 'allow'
            if result['blocked']:
                db.execute('UPDATE agents SET blocked=blocked+1 WHERE id=?',(agent,))
            # Do not retain prompts/arguments/secrets in fleet audit.
            self.event(db,agent,'action.'+result['action'],{'digest':digest,'score':r['score'],'approval':result.get('approval_id')})
        return result

    def gate(self, agent, action, summary):
        """Require a named human approval for one structured action, whatever its
        risk score. Single-use, expires in ten minutes, bound to the action and
        the current policy. A person approves with: approvals approve ID --by NAME."""
        policy = load(self.root)
        digest = hashlib.sha256(canonical([action,policy]).encode()).hexdigest()
        now = time.time()
        with self.db() as db:
            approved = db.execute("SELECT id FROM approvals WHERE agent=? AND digest=? AND status='approved' AND expires>? ORDER BY created LIMIT 1",(agent,digest,now)).fetchone()
            if approved:
                db.execute("UPDATE approvals SET status='used' WHERE id=?",(approved[0],))
                result = {'action':'allow','approval_id':approved[0]}
            else:
                pending = db.execute("SELECT id FROM approvals WHERE agent=? AND digest=? AND status='pending' AND expires>?",(agent,digest,now)).fetchone()
                aid = pending[0] if pending else uuid.uuid4().hex
                if not pending:
                    db.execute('INSERT INTO approvals(id,agent,digest,status,created,expires,actor,summary) VALUES(?,?,?,?,?,?,?,?)',(aid,agent,digest,'pending',now,now+600,None,str(summary)[:300]))
                result = {'action':'approve','approval_id':aid,'new_approval':not bool(pending)}
            self.event(db,agent,'gate.'+result['action'],{'digest':digest,'approval':result['approval_id']})
        return result

    def decide(self, aid, approve, actor):
        if not isinstance(actor,str) or not IDENTITY.fullmatch(actor):
            raise ValueError('Invalid human identity')
        allowed=(load(self.root) or {}).get('approvers',[])
        if allowed and actor not in allowed:
            raise ValueError('Human is not a configured approver')
        with self.db() as db:
            row = db.execute("SELECT agent FROM approvals WHERE id=? AND status='pending' AND expires>?",(aid,time.time())).fetchone()
            if not row:
                raise ValueError('Approval missing, decided or expired')
            db.execute('UPDATE approvals SET status=?,actor=? WHERE id=?',('approved' if approve else 'denied',actor,aid))
            self.event(db,row[0],'approval.approved' if approve else 'approval.denied',{'id':aid,'actor':actor})

    def state(self):
        with self.db() as db:
            agents=[dict(r) for r in db.execute('SELECT * FROM agents ORDER BY id')]
            approvals=[dict(r) for r in db.execute("SELECT * FROM approvals ORDER BY created DESC LIMIT 100")]
            events=[dict(r) for r in db.execute('SELECT * FROM events ORDER BY seq DESC LIMIT 100')]
            prev='GENESIS'; ok=True
            for r in db.execute('SELECT * FROM events ORDER BY seq'):
                payload=canonical([r['seq'],r['ts'],r['agent'],r['action'],r['detail'],r['prev']]).encode()
                if r['prev']!=prev or hashlib.sha256(payload).hexdigest()!=r['hash']:
                    ok=False
                prev=r['hash']
        return {'agents':agents,'approvals':approvals,'events':events,'audit_intact':ok}

    def savepoint(self,agent):
        m=self.lane(agent).snapshot('fleet savepoint: '+agent)
        with self.db() as db:
            self.event(db,agent,'lane.savepoint',{'snapshot':m['id']})
        return m

    def rollback(self,agent,sid):
        store=self.lane(agent)
        # Explicit snapshot only, plus rescue copy for redo. Lane is a separate
        # directory, never a filtered restore of a shared company workspace.
        with store.locked():
            target=store.get(sid)
            rescue=store.snapshot('before fleet rollback',kind='rescue')
            store.restore(target['id'])
        with self.db() as db:
            self.event(db,agent,'lane.rollback',{'snapshot':target['id'],'redo':rescue['id']})
        return {'restored':target['id'],'redo':rescue['id']}
