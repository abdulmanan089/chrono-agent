import argparse
import contextlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chrono_agent import SnapshotStore, Transaction, assess
from chrono_agent.cli import main


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old = Path.cwd()
        os.chdir(self.root)
        self.store = SnapshotStore(self.root)
        self.store.init()
        (self.root / 'app.py').write_text('print("VERSION_1")\n')
        self.begin = self.store.snapshot('initial')

    def tearDown(self):
        os.chdir(self.old)
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

    def test_success_commits_post_command_snapshot(self):
        args = [sys.executable, '-c', 'from pathlib import Path; Path("app.py").write_text("VERSION_3")']
        code, out = self.cli(['run'] + args)
        self.assertEqual(code, 0)
        self.assertIn('COMMIT', out)
        self.assertEqual(self.store.get()['kind'], 'commit')
        self.assertEqual(self.store.read_old(None, 'app.py'), 'VERSION_3')
        self.assertFalse(any(self.store.diff().values()))

    def test_repeated_diff_does_not_rerun(self):
        def fail(*args, **kwargs):
            Path('app.py').write_text('BROKEN')
            return 1
        with patch('chrono_agent.cli.subprocess.call', side_effect=fail) as run:
            code, out = self.cli(['run', 'fake'], ['d', 'd', 'r'])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(code, 1)
        self.assertEqual(Path('app.py').read_text(), 'print("VERSION_1")\n')
        self.assertFalse(any(self.store.diff().values()))

    def test_retry_is_explicit_and_commits(self):
        def execute(*a, **k):
            Path('app.py').write_text('OK' if count[0] else 'BAD')
            count[0] += 1
            return 0 if count[0] == 2 else 1
        count = [0]
        with patch('chrono_agent.cli.subprocess.call', side_effect=execute):
            code, _ = self.cli(['run', 'fake'], ['t'])
        self.assertEqual(count[0], 2)
        self.assertEqual(code, 0)
        self.assertEqual(self.store.read_old(None, 'app.py'), 'OK')

    def test_eof_rolls_back(self):
        def fail(*a, **k):
            Path('app.py').write_text('BAD'); return 1
        with patch('chrono_agent.cli.subprocess.call', side_effect=fail):
            code, _ = self.cli(['run', 'fake'])
        self.assertEqual(code, 1)
        self.assertEqual(Path('app.py').read_text(), 'print("VERSION_1")\n')

    def test_keep_remains_uncommitted(self):
        def fail(*a, **k):
            Path('app.py').write_text('BAD'); return 4
        with patch('chrono_agent.cli.subprocess.call', side_effect=fail):
            code, _ = self.cli(['run', 'fake'], ['k'])
        self.assertEqual(code, 4)
        self.assertEqual(self.store.diff()['modified'], ['app.py'])
        self.assertNotEqual(self.store.get()['kind'], 'commit')

    def test_argument_boundaries_real_child(self):
        args = ['space value', '', 'quote"value', 'trailing\\', 'a&b|c<>^%', 'اردو']
        script = 'import sys,json; from pathlib import Path; Path("args.json").write_text(json.dumps(sys.argv[1:]))'
        code, _ = self.cli(['run', '--', sys.executable, '-c', script] + args)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(Path('args.json').read_text()), args)

    def test_empty_run_rejected_without_snapshot(self):
        count = len(self.store.list())
        self.assertEqual(self.cli(['run'])[0], 1)
        self.assertEqual(len(self.store.list()), count)

    def test_launch_failure_rolls_back(self):
        with patch('chrono_agent.cli.subprocess.call', side_effect=FileNotFoundError('missing')):
            code, out = self.cli(['run', 'does-not-exist'])
        self.assertEqual(code, 1)
        self.assertIn('could not start', out)
        self.assertFalse(any(self.store.diff().values()))

    def test_interruption_restores(self):
        def stop(*a, **k):
            Path('app.py').write_text('BAD'); raise KeyboardInterrupt
        with patch('chrono_agent.cli.subprocess.call', side_effect=stop):
            code, _ = self.cli(['run', 'fake'])
        self.assertEqual(code, 130)
        self.assertFalse(any(self.store.diff().values()))

    def test_commit_failure_rolls_back(self):
        real = SnapshotStore.snapshot
        def snap(s, *args, **kwargs):
            if kwargs.get('kind') == 'commit':
                raise RuntimeError('injected failure')
            return real(s, *args, **kwargs)
        def success(*a, **k):
            Path('app.py').write_text('BAD'); return 0
        with patch.object(SnapshotStore, 'snapshot', snap), patch('chrono_agent.cli.subprocess.call', side_effect=success):
            code, _ = self.cli(['run', 'fake'])
        self.assertEqual(code, 1)
        self.assertFalse(any(self.store.diff().values()))

    def test_scan_blocks_before_execution(self):
        count = len(self.store.list())
        with patch('chrono_agent.cli.subprocess.call') as child:
            code, _ = self.cli(['run', 'rm', '-r', '-f', '/'])
        self.assertEqual(code, 2)
        child.assert_not_called()
        self.assertEqual(len(self.store.list()), count)

    def test_force_override_is_explicit(self):
        with patch('chrono_agent.cli.subprocess.call', return_value=0) as child:
            code, _ = self.cli(['run', '--force', 'rm', '-rf', 'dummy'])
        self.assertEqual(code, 0)
        child.assert_called_once_with(['rm', '-rf', 'dummy'], shell=False)

    def test_shell_requires_single_string(self):
        self.assertEqual(self.cli(['run', '--shell', 'echo', 'a'])[0], 1)
        with patch('chrono_agent.cli.subprocess.call', return_value=0) as child:
            self.assertEqual(self.cli(['run', '--shell', 'echo hello'])[0], 0)
        child.assert_called_once_with('echo hello', shell=True)

    def test_init_idempotent(self):
        head = self.store.get()['id']
        self.assertEqual(self.cli(['init'])[0], 0)
        self.assertEqual(self.store.get()['id'], head)

    def test_typos_not_demo(self):
        self.assertEqual(self.cli(['snapshott'])[0], 2)
        self.assertEqual(self.cli(['--bogus'])[0], 2)

    def test_manual_rollback_confirmation_no(self):
        Path('app.py').write_text('BAD')
        self.cli(['rollback'], ['n'])
        self.assertEqual(Path('app.py').read_text(), 'BAD')
        self.cli(['rollback'], ['y'])
        self.assertEqual(Path('app.py').read_text(), 'print("VERSION_1")\n')

    def test_add_delete_binary_restore(self):
        Path('data.bin').write_bytes(bytes(range(256)))
        snap = self.store.snapshot('binary')
        Path('data.bin').unlink(); Path('app.py').unlink(); Path('extra.txt').write_text('remove me')
        self.store.restore(snap['id'])
        self.assertEqual(Path('data.bin').read_bytes(), bytes(range(256)))
        self.assertTrue(Path('app.py').exists())
        self.assertFalse(Path('extra.txt').exists())

    def test_file_directory_transitions(self):
        Path('swap').write_text('file'); first = self.store.snapshot()
        Path('swap').unlink(); Path('swap').mkdir(); Path('swap/child').write_text('child')
        second = self.store.snapshot()
        self.store.restore(first['id']); self.assertEqual(Path('swap').read_text(), 'file')
        self.store.restore(second['id']); self.assertEqual(Path('swap/child').read_text(), 'child')

    def test_missing_object_no_data_loss(self):
        h = self.begin['files']['app.py']; (self.store.objects/h).unlink()
        Path('new').write_text('preserve')
        with self.assertRaises(RuntimeError):
            self.store.restore(self.begin['id'])
        self.assertEqual(Path('new').read_text(), 'preserve')

    def test_corrupt_object_no_data_loss(self):
        h = self.begin['files']['app.py']; (self.store.objects/h).write_bytes(b'corrupt')
        Path('app.py').write_text('preserve')
        with self.assertRaises(RuntimeError):
            self.store.restore(self.begin['id'])
        self.assertEqual(Path('app.py').read_text(), 'preserve')

    def test_restore_write_failure_recovers_original(self):
        import chrono_agent.snapshot as module
        Path('app.py').write_text('preserve')
        real = module._atomic; calls = [0]
        def injected(path, data, mode=None):
            if path.name == 'app.py' and not calls[0]:
                calls[0] += 1; raise OSError('injected')
            return real(path, data, mode)
        with patch.object(module, '_atomic', injected), self.assertRaises(OSError):
            self.store.restore(self.begin['id'])
        self.assertEqual(Path('app.py').read_text(), 'preserve')

    def test_traversal_manifest_rejected(self):
        for rel in ('../outside', '/tmp/outside', 'C:/outside', '\\\\server\\share', '.chrono/state.json', '.git/config', 'a/../b'):
            m = dict(self.begin); m['files'] = {rel: self.begin['files']['app.py']}
            (self.store.snaps/(m['id']+'.json')).write_text(json.dumps(m))
            with self.assertRaises(RuntimeError):
                self.store.restore(m['id'])
        self.assertEqual(Path('app.py').read_text(), 'print("VERSION_1")\n')

    def test_symlink_rejected_without_external_write(self):
        outside = self.root.parent / (self.root.name + '-outside')
        outside.write_text('external')
        try:
            try:
                Path('link').symlink_to(outside)
            except OSError:
                self.skipTest('Symlink privilege unavailable')
            with self.assertRaises(RuntimeError):
                self.store.snapshot()
            with self.assertRaises(RuntimeError):
                self.store.restore()
            self.assertEqual(outside.read_text(), 'external')
        finally:
            outside.unlink()

    def test_ignored_data_preserved(self):
        Path('.git').mkdir(); Path('.git/sentinel').write_text('git')
        Path('node_modules').mkdir(); Path('node_modules/sentinel').write_text('node')
        self.store.restore()
        self.assertEqual(Path('.git/sentinel').read_text(), 'git')
        self.assertEqual(Path('node_modules/sentinel').read_text(), 'node')

    @unittest.skipIf(os.name == 'nt', 'POSIX permission semantics')
    def test_permission_only_diff_and_restore(self):
        Path('tool').write_text('same'); Path('other').write_text('same')
        os.chmod('tool', 0o755); os.chmod('other', 0o644)
        snap = self.store.snapshot()
        os.chmod('tool', 0o644)
        self.assertIn('tool', self.store.diff()['modified'])
        self.store.restore(snap['id'])
        self.assertEqual(stat.S_IMODE(Path('tool').stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(Path('other').stat().st_mode), 0o644)

    def test_lock_rejects_other_process(self):
        script = 'from chrono_agent import SnapshotStore; SnapshotStore(".").snapshot()'
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parent.parent))
        with self.store.locked():
            result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Project busy', result.stderr)

    def test_branch_switch_preserves_both_versions(self):
        self.store.create_branch('feature')
        Path('app.py').write_text('feature')
        self.store.checkout('main')
        self.assertEqual(Path('app.py').read_text(), 'print("VERSION_1")\n')
        self.store.checkout('feature')
        self.assertEqual(Path('app.py').read_text(), 'feature')

    def test_same_checkout_no_extra_snapshot(self):
        count = len(self.store.list()); self.store.checkout('main')
        self.assertEqual(len(self.store.list()), count)

    def test_checkout_missing_object_keeps_branch(self):
        self.store.create_branch('feature'); Path('app.py').write_text('feature'); self.store.snapshot()
        self.store.checkout('main')
        m = self.store.get(self.store.state()['branches']['feature'])
        (self.store.objects/m['files']['app.py']).unlink()
        with self.assertRaises(RuntimeError):
            self.store.checkout('feature')
        self.assertEqual(self.store.state()['branch'], 'main')
        self.assertEqual(Path('app.py').read_text(), 'print("VERSION_1")\n')

    def test_branch_validation(self):
        for name in ('../evil', '', '-bad', 'x y', 'x/y'):
            with self.assertRaises(RuntimeError):
                self.store.create_branch(name)
        self.assertEqual(self.store.state()['branch'], 'main')

    def test_merge_preserves_independent_files_and_ancestry(self):
        self.store.create_branch('feature'); Path('feature.txt').write_text('feature'); f = self.store.snapshot()
        self.store.checkout('main'); Path('main.txt').write_text('main'); m = self.store.snapshot()
        merged = self.store.merge('feature')
        self.assertEqual(Path('feature.txt').read_text(), 'feature')
        self.assertEqual(Path('main.txt').read_text(), 'main')
        self.assertEqual(merged['parent'], m['id'])
        self.assertEqual(merged['merge_parent'], f['id'])
        self.assertFalse(any(self.store.diff().values()))

    def test_merge_conflict_no_changes(self):
        self.store.create_branch('feature'); Path('app.py').write_text('feature'); self.store.snapshot()
        self.store.checkout('main'); Path('app.py').write_text('main'); before = self.store.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'Merge conflict'):
            self.store.merge('feature')
        self.assertEqual(Path('app.py').read_text(), 'main')
        self.assertEqual(self.store.get()['id'], before['id'])

    def test_merge_dirty_rejected(self):
        self.store.create_branch('feature'); self.store.checkout('main'); Path('app.py').write_text('dirty')
        with self.assertRaisesRegex(RuntimeError, 'working changes'):
            self.store.merge('feature')
        self.assertEqual(Path('app.py').read_text(), 'dirty')

    def test_delete_modify_conflict(self):
        self.store.create_branch('feature'); Path('app.py').unlink(); self.store.snapshot()
        self.store.checkout('main'); Path('app.py').write_text('modified'); self.store.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'Merge conflict'):
            self.store.merge('feature')
        self.assertEqual(Path('app.py').read_text(), 'modified')

    def test_context_commits(self):
        with Transaction(self.root):
            Path('app.py').write_text('COMMITTED')
        self.assertEqual(self.store.get()['kind'], 'commit')
        self.assertFalse(any(self.store.diff().values()))

    def test_context_exception_rolls_back(self):
        with self.assertRaisesRegex(ValueError, 'original'):
            with Transaction(self.root):
                Path('app.py').write_text('BAD'); raise ValueError('original')
        self.assertEqual(Path('app.py').read_text(), 'print("VERSION_1")\n')

    def test_savepoint_rollback_is_granular(self):
        with Transaction(self.root) as tx:
            Path('one').write_text('kept'); tx.savepoint('one')
            Path('two').write_text('removed'); tx.savepoint('two')
            tx.rollback_to('one')
            self.assertTrue(Path('one').exists()); self.assertFalse(Path('two').exists())
            with self.assertRaises(RuntimeError):
                tx.rollback_to('two')

    def test_context_commit_failure_rolls_back(self):
        real = SnapshotStore.snapshot
        def snap(s, *args, **kwargs):
            if kwargs.get('kind') == 'commit':
                raise RuntimeError('commit failure')
            return real(s, *args, **kwargs)
        with patch.object(SnapshotStore, 'snapshot', snap), self.assertRaisesRegex(RuntimeError, 'commit failure'):
            with Transaction(self.root):
                Path('app.py').write_text('BAD')
        self.assertEqual(Path('app.py').read_text(), 'print("VERSION_1")\n')

    def test_context_inactive_and_duplicate_savepoints(self):
        tx = Transaction(self.root)
        with self.assertRaises(RuntimeError):
            tx.rollback()
        with tx:
            tx.savepoint('a')
            with self.assertRaises(RuntimeError):
                tx.savepoint('a')

    def test_ids_unique(self):
        ids = {self.store.snapshot()['id'] for _ in range(30)}
        self.assertEqual(len(ids), 30)

    def test_snapshot_rejects_corrupt_existing_object(self):
        h = self.begin['files']['app.py']
        (self.store.objects/h).write_bytes(b'bad')
        head = self.store.get()['id']
        with self.assertRaisesRegex(RuntimeError, 'Corrupt snapshot object'):
            self.store.snapshot()
        self.assertEqual(self.store.get()['id'], head)

    def test_snapshot_detects_external_mutation(self):
        head = self.store.get()['id']
        with patch.object(self.store, 'current_manifest', return_value={}):
            with self.assertRaisesRegex(RuntimeError, 'Files changed'):
                self.store.snapshot()
        self.assertEqual(self.store.get()['id'], head)

    def test_restore_does_not_replace_ignored_data(self):
        Path('swap').write_text('old file'); saved = self.store.snapshot()
        Path('swap').unlink(); Path('swap/node_modules').mkdir(parents=True)
        Path('swap/node_modules/keep').write_text('preserve')
        with self.assertRaisesRegex(RuntimeError, 'ignored data'):
            self.store.restore(saved['id'])
        self.assertEqual(Path('swap/node_modules/keep').read_text(), 'preserve')

    def test_metadata_symlink_rejected(self):
        redirected = self.root/'redirected'
        self.store.dir.rename(redirected)
        try:
            self.store.dir.symlink_to(redirected, target_is_directory=True)
        except OSError:
            redirected.rename(self.store.dir)
            self.skipTest('Symlink privilege unavailable')
        with self.assertRaisesRegex(RuntimeError, 'Unsafe symlink'):
            self.store.init()

    def test_rollback_failure_preserves_original_exception(self):
        tx = Transaction(self.root)
        with self.assertRaises(RuntimeError) as result:
            with patch.object(tx.store, 'restore', side_effect=OSError('recovery failed')):
                with tx:
                    raise ValueError('original body error')
        self.assertIsInstance(result.exception.__cause__, ValueError)
        self.assertIn('rollback also failed', str(result.exception))

    def test_failing_real_child_adds_and_deletes_files(self):
        script = 'from pathlib import Path; Path("app.py").unlink(); Path("new.txt").write_text("new"); raise RuntimeError("test")'
        code, _ = self.cli(['run', sys.executable, '-c', script], ['r'])
        self.assertEqual(code, 1)
        self.assertTrue(Path('app.py').exists())
        self.assertFalse(Path('new.txt').exists())

    def test_corrupt_state_concise_error(self):
        (self.store.dir/'state.json').write_text('{broken')
        code, out = self.cli(['status'])
        self.assertEqual(code, 1); self.assertIn('Corrupt snapshot state', out)

    def test_risk_rules_concrete_scores(self):
        checks = {'rm -rf /': 98, 'rm -r -f /': 98, 'rm --recursive --force /': 98,
                  'DROP TABLE users': 95, 'rmdir /s /q test': 96, 'format C:': 99,
                  'DELETE FROM users; SELECT 1': 88, 'git push origin main --force-with-lease': 85,
                  'python app.py': 5, 'DELETE FROM users WHERE id=3': 5}
        for command, score in checks.items():
            with self.subTest(command=command):
                self.assertEqual(assess(command)['score'], score)


if __name__ == '__main__':
    unittest.main()
