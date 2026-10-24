import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('audit', Path(__file__).parents[1] / 'check-php2shell.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class AuditTests(unittest.TestCase):
    def test_exit_codes_and_incomplete_installation(self):
        for status, state, expected in [('FIXED', 'installed', 0),
                                        ('UPDATE', 'installed', 1),
                                        ('UNKNOWN', 'installed', 2),
                                        ('FIXED', 'unpacked', 2)]:
            with self.subTest(status=status, state=state), \
                 patch.object(a.shutil, 'which', return_value='/usr/bin/tool'), \
                 patch.object(a.Path, 'read_text', return_value='ID=debian\nVERSION_ID="13"\n'), \
                 patch.object(a, 'inventory', return_value=[(state, 'php8.4-cli', '8.4.27', 'php8.4', '8.4.27')]), \
                 patch.object(a, 'classify', return_value=(status, 'test fixture')), \
                 patch.object(a, 'candidates', return_value={'php8.4-cli': '(none)'}), \
                 patch.object(a, 'extra_runtimes', return_value=([], [])), \
                 patch.object(a, 'inspect_processes', return_value={'status': 'NO_MATCHING_PROCESSES', 'records': [], 'errors': [], 'vanished': 0}), \
                 patch.object(a, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')), \
                 patch('sys.argv', ['check-php2shell.py']), contextlib.redirect_stdout(io.StringIO()):
                report = a.collect_report([])
                self.assertEqual(report['summary']['package_exit_code'], expected)
                self.assertEqual(report['summary']['exit_code'], 2)
                self.assertEqual(report['cves']['CVE-2026-115560']['status'], 'REVIEW')

    @unittest.skipUnless(shutil.which('dpkg'), 'requires real dpkg (Debian CI)')
    def test_real_dpkg_release_boundaries(self):
        cases = [
            ('php8.2', '8.2.34-1~deb12u1', 'UPDATE'),
            ('php8.2', '8.2.35-1~deb12u1', 'FIXED'),
            ('php8.2', '8.2.35-1~deb12u1+b1', 'FIXED'),
            ('php8.2', '8.2.36-1~deb12u1', 'FIXED'),
            ('php8.4', '8.4.26-1~deb13u1', 'UPDATE'),
            ('php8.4', '8.4.27-1~deb13u1', 'FIXED'),
            ('php8.2', '8.2.35~rc1-1+vendor', 'UNKNOWN'),
            ('php8.2', '99:8.2.34-999+vendor', 'UNKNOWN'),
            ('php8.2', '8.2.34-999~deb12u999', 'UPDATE'),
            ('php8.2', '8.2.35-1+vendor', 'FIXED'),
            ('php8.3', '8.3.35-1+vendor', 'UNKNOWN'),
            ('php8.3', '8.3.36-1+vendor', 'FIXED'),
            ('php8.4', '8.4.27~RC1-1+vendor', 'UNKNOWN'),
            ('php8.5', '8.5.11-1+vendor', 'UNKNOWN'),
            ('php8.5', '8.5.12-1+vendor', 'FIXED'),
            ('php8.1', '8.1.99-1+vendor', 'UNKNOWN'),
        ]
        for source, version, expected in cases:
            with self.subTest(version=version):
                self.assertEqual(a.classify(source, version)[0], expected)

    def test_thresholds(self):
        cases = [
            ('php8.2', '8.2.34-1~deb12u1', False, 'UPDATE', '8.2.35-1~deb12u1'),
            ('php8.2', '8.2.35-1~deb12u1', True, 'FIXED', '8.2.35-1~deb12u1'),
            ('php8.4', '8.4.26-1~deb13u1', False, 'UPDATE', '8.4.27-1~deb13u1'),
            ('php8.4', '8.4.27-1~deb13u1+b1', True, 'FIXED', '8.4.27-1~deb13u1'),
            ('php8.3', '8.3.36-1+vendor', True, 'FIXED', '8.3.36'),
            ('php8.5', '8.5.12-1+vendor', True, 'FIXED', '8.5.12'),
            ('php8.2', '9:8.2.34-999+vendor', False, 'UNKNOWN', '8.2.35'),
            ('php8.2', '8.2.35~rc1-1+vendor', False, 'UNKNOWN', '8.2.35'),
        ]
        for source, version, comparison, expected, threshold in cases:
            with self.subTest(version=version), patch.object(a, 'ge', return_value=comparison) as ge:
                self.assertEqual(a.classify(source, version)[0], expected)
                self.assertEqual(ge.call_args.args[1], threshold)
                self.assertNotIn(':', ge.call_args.args[0])

    def test_unmapped_never_green(self):
        for source, version in [('php8.1', '8.1.99'), ('php8.6', '8.6.1'),
                                ('php8.2', '8.4.27'), ('php8.2', 'nonsense')]:
            self.assertEqual(a.classify(source, version)[0], 'UNKNOWN')

    def test_inventory_keeps_held_and_partial_excludes_extension_versions(self):
        output = ('installed\tphp8.2-fpm\t8.2.35-1~deb12u1\tphp8.2\t8.2.35-1~deb12u1\n'
                  'installed\tphp8.2-redis\t6.0.2-1\tphp-redis\t6.0.2-1\n'
                  'config-files\tphp8.1-fpm\t8.1.1\tphp8.1\t8.1.1\n'
                  'unpacked\tphp8.4-cli\t8.4.27-1~deb13u1\tphp8.4\t8.4.27-1~deb13u1\n')
        with patch.object(a, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
            rows = a.inventory()
            self.assertEqual([r[1] for r in rows], ['php8.2-fpm', 'php8.4-cli'])

    def test_candidate_multiarch_and_missing(self):
        output = 'php8.2-fpm:\n  Installed: 8.2.34\n  Candidate: 8.2.35-1~deb12u1\nphp8.4-cli:arm64:\n  Candidate: (none)\n'
        with patch.object(a, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
            values = a.candidates(['php8.2-fpm:amd64', 'php8.4-cli:arm64', 'missing'])
            self.assertEqual(values['php8.2-fpm:amd64'], '8.2.35-1~deb12u1')
            self.assertEqual(values['missing'], '(none)')

    def test_unassessed_packaged_runtime_remains_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'php'
            path.write_text('never executed')
            def owner(args):
                return subprocess.CompletedProcess(args, 0, 'vendor-php: ' + str(path), '')
            with patch.object(a, 'run', side_effect=owner):
                self.assertEqual(a.extra_runtimes([directory], {'php8.2-cli'})[0], [str(path)])
                self.assertEqual(a.extra_runtimes([directory], {'vendor-php'})[0], [])

    def test_report_update_hold_and_mixed_versions(self):
        rows = [('installed', 'php8.2-fpm', '8.2.34-1~deb12u1', 'php8.2', '8.2.34-1~deb12u1'),
                ('installed', 'php8.2-cli', '8.2.34-1~deb12u1', 'php8.2', '8.2.34-1~deb12u1'),
                ('installed', 'php8.1-fpm', '8.1.99', 'php8.1', '8.1.99')]
        def run(args):
            if args == ['apt-mark', 'showhold']:
                return subprocess.CompletedProcess(args, 0, 'php8.2-fpm\n', '')
            raise AssertionError('Unexpected command: ' + str(args))
        def comparison(left, right):
            return left == right or left.startswith('8.2.35')
        output = io.StringIO()
        with patch.object(a.shutil, 'which', return_value='/usr/bin/tool'), \
             patch.object(a.Path, 'read_text', return_value='ID=debian\nVERSION_ID="12"\n'), \
             patch.object(a, 'inventory', return_value=rows), \
             patch.object(a, 'candidates', return_value={'php8.2-fpm': '8.2.35-1~deb12u1',
                 'php8.2-cli': '8.2.35-1~deb12u1', 'php8.1-fpm': '(none)'}), \
             patch.object(a, 'extra_runtimes', return_value=([], [])), \
                 patch.object(a, 'inspect_processes', return_value={'status': 'NO_MATCHING_PROCESSES', 'records': [], 'errors': [], 'vanished': 0}), \
             patch.object(a, 'run', side_effect=run), patch.object(a, 'ge', side_effect=comparison), \
             patch('sys.argv', ['check-php2shell.py']), contextlib.redirect_stdout(output):
            self.assertEqual(a.main(), 2)
        text = output.getvalue()
        self.assertIn('HOLD', text)
        self.assertIn('UPDATE=2', text)
        self.assertIn('UNKNOWN=1', text)
        commands = [line for line in text.splitlines() if line.startswith('sudo apt-get')]
        self.assertEqual(len(commands), 2)
        self.assertTrue(all('php8.2-cli' in command and 'php8.2-fpm' not in command for command in commands))


if __name__ == '__main__':
    unittest.main(verbosity=2)
