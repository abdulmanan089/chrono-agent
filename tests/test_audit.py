import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chrono_agent import SnapshotStore
from chrono_agent.audit import AuditLog, GENESIS, KEY_ENV, _digest
from chrono_agent.cli import main


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old = Path.cwd()
        os.chdir(self.root)
        for var in (KEY_ENV, 'CHRONO_MODEL', 'CHRONO_AGENT'):
            os.environ.pop(var, None)
        self.store = SnapshotStore(self.root)
        self.store.init()
        (self.root / 'app.py').write_text('print("VERSION_1")\n')
        self.store.snapshot('initial')

    def tearDown(self):
        os.chdir(self.old)
        for var in (KEY_ENV, 'CHRONO_MODEL', 'CHRONO_AGENT'):
            os.environ.pop(var, None)
        self.tmp.cleanup()

    def cli(self, args, inputs=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch('builtins.input', side_effect=inputs or EOFError):
            try:
                main(args)
                code = 0
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()

    def lines(self):
        text = (self.root / '.chrono' / 'audit.jsonl').read_text(encoding='utf-8')
        return [x for x in text.splitlines() if x.strip()]

    def write_lines(self, rows):
        (self.root / '.chrono' / 'audit.jsonl').write_text(
            ''.join(r + '\n' for r in rows), encoding='utf-8')

    def actions(self):
        return [r.get('action') for r in self.store.audit.read()]

    # ---- recording ----
    def test_state_changing_actions_are_recorded(self):
        self.store.snapshot('second')
        Path('app.py').write_text('BAD')
        self.cli(['rollback'], ['y'])
        self.cli(['scan', 'rm -rf /'])
        actions = self.actions()
        for expected in ('snapshot', 'restore', 'rollback', 'scan'):
            self.assertIn(expected, actions)

    def test_model_and_agent_are_attributed(self):
        os.environ['CHRONO_MODEL'] = 'claude-3.5-sonnet'
        os.environ['CHRONO_AGENT'] = 'cursor'
        self.store.snapshot('ai edit')
        rec = self.store.audit.read()[-1]
        self.assertEqual(rec['model'], 'claude-3.5-sonnet')
        self.assertEqual(rec['agent'], 'cursor')

    def test_blocked_command_is_recorded_without_running(self):
        with patch('chrono_agent.cli.subprocess.call') as child:
            code, _ = self.cli(['run', 'rm', '-rf', '/'])
        self.assertEqual(code, 2)
        child.assert_not_called()
        recs = [r for r in self.store.audit.read() if r.get('action') == 'run.blocked']
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]['risk_score'], 98)
        self.assertEqual(recs[0]['risk_level'], 'CRITICAL')
        self.assertEqual(recs[0]['outcome'], 'blocked')
        self.assertNotIn('run.begin', self.actions())

    def test_successful_run_records_begin_and_commit(self):
        args = [sys.executable, '-c', 'from pathlib import Path; Path("app.py").write_text("VERSION_2")']
        code, _ = self.cli(['run'] + args)
        self.assertEqual(code, 0)
        recs = self.store.audit.read()
        actions = [r.get('action') for r in recs]
        self.assertIn('run.begin', actions)
        self.assertIn('run.commit', actions)
        commit = [r for r in recs if r.get('action') == 'run.commit'][0]
        self.assertEqual(commit['snapshot'], self.store.get()['id'])
        self.assertNotIn('run.interrupted', actions)
        self.assertNotIn('run.rollback', actions)

    def test_kept_changes_recorded_as_uncommitted(self):
        def fail(*a, **k):
            Path('app.py').write_text('BAD'); return 4
        with patch('chrono_agent.cli.subprocess.call', side_effect=fail):
            code, _ = self.cli(['run', 'fake'], ['k'])
        self.assertEqual(code, 4)
        recs = [r for r in self.store.audit.read() if r.get('action') == 'run.keep']
        self.assertEqual(recs[0]['outcome'], 'uncommitted')
        self.assertEqual(recs[0]['snapshot'], self.store.state()['branches']['main'])

    def test_manual_rollback_records_both_answers(self):
        Path('app.py').write_text('BAD')
        self.cli(['rollback'], ['n'])
        self.cli(['rollback'], ['y'])
        pairs = [(r['action'], r['outcome']) for r in self.store.audit.read()
                 if r.get('action') == 'rollback']
        self.assertIn(('rollback', 'aborted'), pairs)
        self.assertIn(('rollback', 'ok'), pairs)

    def test_scan_outside_project_is_not_recorded(self):
        plain = self.root / 'plain'
        plain.mkdir()
        os.chdir(plain)
        code, out = self.cli(['scan', 'rm -rf /'])
        self.assertEqual(code, 0)
        self.assertIn('98/100', out)
        self.assertFalse((plain / '.chrono').exists())

    # ---- tamper evidence ----
    def test_chain_verifies_after_mixed_actions(self):
        self.store.snapshot('second')
        Path('app.py').write_text('BAD')
        self.cli(['rollback'], ['y'])
        result = self.store.audit.verify()
        self.assertTrue(result['ok'])
        self.assertEqual(result['records'], len(self.lines()))
        self.assertIsNone(result['broken_at'])

    def test_edited_record_breaks_chain(self):
        self.store.snapshot('second')
        rows = self.lines()
        rec = json.loads(rows[1])
        rec['detail'] = 'something else happened'
        rows[1] = json.dumps(rec, sort_keys=True, ensure_ascii=True)
        self.write_lines(rows)
        result = self.store.audit.verify()
        self.assertFalse(result['ok'])
        self.assertEqual(result['broken_at'], 2)
        self.assertIn('edited', result['reason'])

    def test_deleted_record_breaks_chain(self):
        self.store.snapshot('second')
        self.store.snapshot('third')
        rows = self.lines()
        del rows[1]
        self.write_lines(rows)
        result = self.store.audit.verify()
        self.assertFalse(result['ok'])
        self.assertEqual(result['broken_at'], 2)
        self.assertIn('deleted or reordered', result['reason'])

    def test_rechained_forgery_is_caught_by_snapshot_anchor(self):
        self.store.snapshot('second')
        forged, prev = [], GENESIS
        for line in self.lines():
            rec = json.loads(line)
            if rec['seq'] == 1:
                rec['detail'] = 'innocent snapshot'
            rec['prev'] = prev
            rec['hash'] = _digest({k: v for k, v in rec.items() if k != 'hash'}, None)
            prev = rec['hash']
            forged.append(json.dumps(rec, sort_keys=True, ensure_ascii=True))
        self.write_lines(forged)
        self.assertTrue(self.store.audit.verify()['ok'])   # chain alone looks clean
        problems = self.store.verify_audit()
        self.assertTrue(problems)
        self.assertIn('missing or edited', problems[0][1])
        code, out = self.cli(['audit', '--verify'])
        self.assertEqual(code, 1)
        self.assertIn('anchors', out)

    def test_signed_log_needs_the_key_to_verify(self):
        os.environ[KEY_ENV] = 'company-key'
        project = self.root / 'signed'
        project.mkdir()
        os.chdir(project)
        store = SnapshotStore(project)
        store.init()
        (project / 'app.py').write_text('x')
        store.snapshot('signed')
        self.assertTrue(store.audit.verify()['ok'])
        os.environ.pop(KEY_ENV)
        result = store.audit.verify()
        self.assertFalse(result['ok'])
        self.assertIn(KEY_ENV, result['reason'])

    def test_audit_log_is_not_snapshotted_and_survives_restore(self):
        files = self.store.snapshot('check')['files']
        self.assertEqual([f for f in files if 'audit' in f], [])
        before = len(self.store.audit.read())
        self.store.restore()
        self.assertEqual(len(self.store.audit.read()), before + 1)

    def test_missing_log_reports_nothing(self):
        (self.root / '.chrono' / 'audit.jsonl').unlink()
        code, out = self.cli(['audit'])
        self.assertEqual(code, 0)
        self.assertIn('no audit records yet', out)
        result = self.store.audit.verify()
        self.assertTrue(result['ok'])
        self.assertEqual(result['records'], 0)

    # ---- reporting ----
    def test_csv_and_json_reports(self):
        code, _ = self.cli(['audit', '--csv', '--out', 'reports/audit.csv'])
        self.assertEqual(code, 0)
        text = Path('reports/audit.csv').read_text(encoding='utf-8')
        self.assertTrue(text.startswith('seq,ts,actor,host,action'))
        self.assertIn('snapshot', text)
        code, _ = self.cli(['audit', '--json', '--out', 'reports/audit.json'])
        self.assertEqual(code, 0)
        data = json.loads(Path('reports/audit.json').read_text(encoding='utf-8'))
        self.assertIsInstance(data, list)
        self.assertIn('hash', data[0])

    def test_limit_shows_newest_records(self):
        for i in range(4):
            self.store.snapshot('s' + str(i))
        code, out = self.cli(['audit', '-n', '2'])
        self.assertEqual(code, 0)
        self.assertEqual(len([x for x in out.splitlines() if x.strip()]), 2)

    def test_action_filter(self):
        self.cli(['scan', 'rm -rf /'])
        self.cli(['scan', 'python app.py'])
        code, out = self.cli(['audit', '--action', 'scan', '--json'])
        self.assertEqual(code, 0)
        recs = json.loads(out)
        self.assertEqual([r['action'] for r in recs], ['scan', 'scan'])
        self.assertEqual([r['risk_score'] for r in recs], [98, 5])

    def test_verify_appends_its_own_record(self):
        before = len(self.store.audit.read())
        code, out = self.cli(['audit', '--verify'])
        self.assertEqual(code, 0)
        self.assertIn('chain intact', out)
        recs = self.store.audit.read()
        self.assertEqual(len(recs), before + 1)
        self.assertEqual(recs[-1]['action'], 'audit.verify')
        self.assertEqual(recs[-1]['outcome'], 'ok')


if __name__ == '__main__':
    unittest.main()
