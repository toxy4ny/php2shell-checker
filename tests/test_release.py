import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from test_php2shell import a


class ReportTests(unittest.TestCase):
    def test_json_error_is_a_single_document(self):
        output = io.StringIO()
        with patch.object(a, 'collect_report', side_effect=RuntimeError('fixture failure')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(a.main(['--format', 'json']), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result['schema_version'], '1.0')
        self.assertEqual(result['errors'], ['fixture failure'])
        self.assertEqual(result['summary']['exit_code'], 2)

    def test_cve_rules_are_independent(self):
        rule = dict(a.CVE_RULES['CVE-2026-109619'])
        rule['upstream'] = {'8.3': '8.3.99'}
        with patch.dict(a.CVE_RULES, {'CVE-2026-109619': rule}), \
                patch.object(a, 'ge', side_effect=lambda left, right: right != '8.3.99'):
            result = a.package_cves('php8.3', '8.3.36-1+vendor')
        self.assertEqual(result['CVE-2026-109618']['status'], 'FIXED')
        self.assertEqual(result['CVE-2026-109619']['status'], 'UNKNOWN')

    def test_empty_inventory_does_not_pass(self):
        with patch.object(a.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(a.Path, 'read_text', return_value='ID=debian\nVERSION_ID=12\n'), \
                patch.object(a, 'inventory', return_value=[]), \
                patch.object(a, 'extra_runtimes', return_value=([], [])), \
                patch.object(a, 'inspect_processes', return_value={'status': 'UNKNOWN', 'records': [], 'errors': ['denied'], 'vanished': 0}), \
                patch.object(a, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            report = a.collect_report([])
        self.assertEqual(report['summary']['package_exit_code'], 2)
        self.assertEqual(report['summary']['process_exit_code'], 2)
        self.assertEqual(report['cves']['CVE-2026-109618']['status'], 'UNKNOWN')


class ProcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / '42'
        self.proc.mkdir()
        (self.proc / 'ns').mkdir()
        (self.proc / 'ns/mnt').symlink_to('mnt:[100]')
        (self.proc / 'root').symlink_to('/')
        (self.proc / 'stat').write_text('42 (php worker) ' + ' '.join(['S'] + ['0'] * 18 + ['123']))
        (self.proc / 'comm').write_text('php-fpm8.2\n')
        (self.proc / 'maps').write_text('')
        (self.proc / 'cgroup').write_text('0::/system.slice/php8.2-fpm.service\n')
        self.exe = self.root / 'php-fpm8.2'
        self.exe.write_text('fixture; never executed')
        (self.proc / 'exe').symlink_to(self.exe)

    def inspect(self):
        return a.inspect_process(self.proc, 'mnt:[100]')

    def test_unchanged_executable_is_not_called_fixed(self):
        result = self.inspect()
        self.assertEqual(result['status'], 'NO_STALE_FILES_FOUND')
        self.assertEqual(result['service'], 'php8.2-fpm.service')
        self.assertEqual(result['evidence'], [])

    def test_deleted_executable(self):
        (self.proc / 'exe').unlink()
        (self.proc / 'exe').symlink_to(str(self.exe) + ' (deleted)')
        result = self.inspect()
        self.assertEqual(result['status'], 'RESTART_REQUIRED')
        self.assertEqual(result['evidence'][0]['type'], 'deleted_executable')

    def test_apache_deleted_php_module(self):
        (self.proc / 'comm').write_text('apache2')
        (self.proc / 'exe').unlink()
        apache = self.root / 'apache2'
        apache.write_text('fixture')
        (self.proc / 'exe').symlink_to(apache)
        (self.proc / 'maps').write_text('100-200 r-xp 0 00:01 77 /usr/lib/apache2/modules/libphp8.2.so (deleted)\n')
        result = self.inspect()
        self.assertEqual(result['status'], 'RESTART_REQUIRED')
        self.assertEqual(result['evidence'][0]['type'], 'deleted_php_mapping')

    def test_mapping_inode_mismatch(self):
        module = self.root / 'libphp8.2.so'
        module.write_text('fixture')
        stat = module.stat()
        (self.proc / 'maps').write_text(f'100-200 r-xp 0 {os.major(stat.st_dev):x}:{os.minor(stat.st_dev):x} {stat.st_ino + 1} {module}\n')
        self.assertEqual(self.inspect()['evidence'][0]['type'], 'php_mapping_inode_changed')

    def test_unrelated_deleted_library_does_not_trigger_restart(self):
        (self.proc / 'maps').write_text('100-200 r-xp 0 00:01 77 /usr/lib/libunrelated.so (deleted)\n')
        self.assertEqual(self.inspect()['status'], 'NO_STALE_FILES_FOUND')

    def test_foreign_namespace_is_unknown(self):
        result = a.inspect_process(self.proc, 'mnt:[999]')
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertIn('different mount namespace', result['errors'][0])

    def test_permission_denied_maps(self):
        original = Path.read_text
        def read(path, *args, **kwargs):
            if path == self.proc / 'maps':
                raise PermissionError('fixture denied')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', read):
            result = self.inspect()
        self.assertEqual(result['status'], 'UNKNOWN')

    def test_pid_reuse_is_rejected(self):
        with patch.object(a, 'process_identity', side_effect=[('1', 'S'), ('2', 'S')]):
            with self.assertRaisesRegex(RuntimeError, 'PID was reused'):
                self.inspect()

    def test_vanished_process_is_counted(self):
        (self.root / 'self/ns').mkdir(parents=True)
        (self.root / 'self/ns/mnt').symlink_to('mnt:[100]')
        def vanish(*args):
            shutil.rmtree(self.proc)
            raise FileNotFoundError('fixture exit')
        with patch.object(a, 'inspect_process', side_effect=vanish), patch.object(os, 'geteuid', return_value=0):
            result = a.inspect_processes(self.root)
        self.assertEqual(result['vanished'], 1)
        self.assertEqual(result['records'], [])

    def test_restart_evidence_survives_permission_gaps(self):
        (self.root / 'self/ns').mkdir(parents=True)
        (self.root / 'self/ns/mnt').symlink_to('mnt:[100]')
        record = {'status': 'RESTART_REQUIRED', 'errors': ['maps denied']}
        with patch.object(a, 'inspect_process', return_value=record), patch.object(os, 'geteuid', return_value=0):
            result = a.inspect_processes(self.root)
        self.assertEqual(result['status'], 'RESTART_REQUIRED')
        self.assertEqual(result['records'][0]['errors'], ['maps denied'])


@unittest.skipUnless(Path('/proc/self/exe').exists(), 'requires Linux procfs')
class LiveProcTests(unittest.TestCase):
    def test_real_deleted_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'php8.2'
            shutil.copy2('/bin/sleep', executable)
            process = subprocess.Popen([str(executable), '30'])
            try:
                # Popen returns after exec succeeds. This is a harmless system sleep binary.
                executable.unlink()
                namespace = os.readlink('/proc/self/ns/mnt')
                result = a.inspect_process(Path('/proc') / str(process.pid), namespace)
                self.assertEqual(result['status'], 'RESTART_REQUIRED')
                self.assertTrue(any(e['type'] == 'deleted_executable' for e in result['evidence']))
            finally:
                process.terminate()
                process.wait(timeout=5)
