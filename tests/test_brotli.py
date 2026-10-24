import contextlib
import io
import json
import shutil
import subprocess
import unittest
from unittest.mock import patch

from test_php2shell import a


class BrotliTests(unittest.TestCase):
    def test_known_debian_versions_and_binary_rebuilds(self):
        for release, version in [('12', '1.0.9-2'), ('13', '1.1.0-2')]:
            for suffix in ('', '+b1'):
                with self.subTest(release=release, suffix=suffix):
                    self.assertEqual(a.classify_brotli('brotli', version + suffix, release)[0], 'UPDATE')

    @unittest.skipUnless(shutil.which('dpkg'), 'requires real dpkg (Debian CI)')
    def test_real_dpkg_brotli_boundaries(self):
        cases = {
            '1.0.9-2': 'UPDATE', '1.0.9-2+deb12u1': 'UNKNOWN',
            '1.0.9-999+vendor': 'UNKNOWN', '99:1.0.9-2': 'UNKNOWN',
            '1.0.10-1': 'FIXED', '1.0.11-1': 'FIXED',
            '1.1.0-2': 'UNKNOWN', '1.1.1-1': 'FIXED', '1.1.2-1': 'FIXED',
            '1.2.0-4': 'UNKNOWN', '1.2.1-1': 'FIXED', '1.2.2-1': 'FIXED',
            '1.0.10~rc1-1': 'UNKNOWN', '1.1.1~rc1-1': 'UNKNOWN',
            '1.2.1~rc1-1': 'UNKNOWN', '1.2.1+really1.2.0-1': 'UNKNOWN',
            '1.3.0-1': 'UNKNOWN', '2.0.0-1': 'UNKNOWN', 'broken': 'UNKNOWN',
        }
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(a.classify_brotli('brotli', version, '12')[0], expected)

    def test_source_mismatch_and_unknown_backport(self):
        self.assertEqual(a.classify_brotli('vendor-brotli', '1.2.1-1', '13')[0], 'UNKNOWN')
        with patch.object(a, 'ge', return_value=False):
            self.assertEqual(a.classify_brotli('brotli', '1.1.0-2+deb13u1', '13')[0], 'UNKNOWN')

    def test_inventory_multiarch_source_metadata_and_residual_config(self):
        data = ('installed\tlibbrotli1:amd64\t1.0.9-2+b1\tbrotli\t1.0.9-2\n'
                'unpacked\tpython3-brotli\t1.0.9-2\tbrotli\t1.0.9-2\n'
                'installed\tlibbrotli-dev\t1.0.9-2\tbrotli\t1.0.9-2\n'
                'installed\tcustom-binding\t1.0.9-2\tbrotli\t1.0.9-2\n'
                'installed\tlibbrotli2\t1.2.1\tvendor-brotli\t1.2.1\n'
                'config-files\tbrotli\t1.0.9-2\tbrotli\t1.0.9-2\n'
                'installed\tphp8.2-curl\t8.2.35-1~deb12u1\tphp8.2\t8.2.35-1~deb12u1\n')
        with patch.object(a, 'run', return_value=subprocess.CompletedProcess([], 0, data, '')):
            rows = a.inventory()
        self.assertEqual(len(rows), 6)
        self.assertIn(('installed', 'libbrotli1:amd64', '1.0.9-2+b1', 'brotli', '1.0.9-2'), rows)
        self.assertNotIn('brotli', [r[1] for r in rows])

    def test_absence_is_not_a_host_safety_verdict(self):
        report = a.brotli_report([], {}, set(), '12')
        self.assertEqual(report['status'], 'NOT_INSTALLED')
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['reachability'], 'NOT_CHECKED')
        self.assertEqual(report['embedded_copies'], 'NOT_AUDITED')
        self.assertEqual(report['packages'], [])

    def test_affected_candidate_is_not_suggested_as_a_fix(self):
        report = a.brotli_report(
            [('installed', 'libbrotli1', '1.0.9-2', 'brotli', '1.0.9-2')],
            {'libbrotli1': '1.0.9-2'}, set(), '12')
        self.assertEqual(report['status'], 'UPDATE')
        self.assertEqual(report['exit_code'], 1)
        self.assertTrue(report['updates_required'])
        self.assertEqual(report['upgrade_packages'], [])
        self.assertIsNone(report['debian_fixed_version'])
        self.assertEqual(report['packages'][0]['candidate']['cves'][a.BROTLI_CVE]['status'], 'UPDATE')

    def test_unknown_candidate_and_missing_candidate(self):
        row = ('installed', 'libbrotli1', '1.1.0-2', 'brotli', '1.1.0-2')
        with patch.object(a, 'ge', return_value=False):
            unknown = a.brotli_report([row], {'libbrotli1': '1.1.0-2+deb13u1'}, set(), '13')
        self.assertEqual(unknown['packages'][0]['candidate']['cves'][a.BROTLI_CVE]['status'], 'UNKNOWN')
        self.assertEqual(unknown['upgrade_packages'], [])
        missing = a.brotli_report([row], {'libbrotli1': '(none)'}, set(), '13')
        self.assertEqual(missing['packages'][0]['candidate'], {'version': None, 'cves': {}})

    def test_fixed_candidate_holds_partial_install_and_mixed_findings(self):
        rows = [('installed', 'brotli', '1.1.0-2', 'brotli', '1.1.0-2'),
                ('installed', 'libbrotli1:amd64', '1.1.0-2', 'brotli', '1.1.0-2'),
                ('unpacked', 'python3-brotli', '1.1.1-1', 'brotli', '1.1.1-1')]
        with patch.object(a, 'ge', return_value=True):
            report = a.brotli_report(rows, {r[1]: '1.1.1-1' for r in rows}, {'libbrotli1'}, '13')
        self.assertEqual(report['status'], 'UPDATE')
        self.assertEqual(report['exit_code'], 2)
        self.assertEqual(report['counts'], {'FIXED': 0, 'UPDATE': 2, 'UNKNOWN': 1})
        self.assertEqual(report['upgrade_packages'], ['brotli'])
        self.assertTrue(report['packages'][1]['held'])
        self.assertEqual(report['packages'][2]['status'], 'UNKNOWN')

    def test_no_downgrade_recommended(self):
        # A vendor epoch can sort higher than a fixed upstream candidate.
        with patch.object(a, 'ge', side_effect=lambda left, right: ':' not in right):
            report = a.brotli_report(
                [('installed', 'libbrotli1', '9:1.0.9-2', 'brotli', '9:1.0.9-2')],
                {'libbrotli1': '1.0.10-1'}, set(), '12')
        self.assertEqual(report['upgrade_packages'], [])

    def test_json_and_text_keep_php_and_brotli_separate(self):
        rows = [('installed', 'libbrotli1:amd64', '1.1.0-2', 'brotli', '1.1.0-2'),
                ('installed', 'php8.4-cli', '8.4.27', 'php8.4', '8.4.27')]
        with patch.object(a.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(a.Path, 'read_text', return_value='ID=debian\nVERSION_ID=13\n'), \
                patch.object(a, 'inventory', return_value=rows), \
                patch.object(a, 'candidates', return_value={'libbrotli1:amd64': '1.1.1-1', 'php8.4-cli': '(none)'}), \
                patch.object(a, 'extra_runtimes', return_value=([], [])), \
                patch.object(a, 'inspect_processes', return_value={'status': 'NO_MATCHING_PROCESSES', 'records': [], 'errors': [], 'vanished': 0}), \
                patch.object(a, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')), \
                patch.object(a, 'ge', return_value=True):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(a.main(['--format', 'json']), 2)
        report = json.loads(output.getvalue())
        self.assertEqual([p['name'] for p in report['packages']], ['php8.4-cli'])
        self.assertEqual(report['summary']['package_exit_code'], 0)
        self.assertEqual(report['summary']['brotli_exit_code'], 1)
        self.assertTrue(report['summary']['updates_required'])
        self.assertTrue(report['summary']['brotli_updates_required'])
        self.assertEqual(report['actions']['upgrade_packages'], ['libbrotli1:amd64'])
        self.assertEqual(report['actions']['upgrade_argv'][-1], 'libbrotli1:amd64')
        self.assertEqual(report['cves'][a.BROTLI_CVE]['status'], 'UPDATE')
        self.assertEqual(report['brotli']['loaded_libraries'], 'NOT_CHECKED')
        rendered = io.StringIO()
        with contextlib.redirect_stdout(rendered):
            a.render_text(report)
        self.assertIn('Brotli / CVE-2026-111497: UPDATE', rendered.getvalue())
        self.assertIn('Candidate: 1.1.1-1', rendered.getvalue())
        self.assertIn('PHP core package totals: FIXED=1, UPDATE=0, UNKNOWN=0', rendered.getvalue())

    def test_brotli_only_host_does_not_claim_php_fixed(self):
        with patch.object(a.shutil, 'which', return_value='/usr/bin/tool'), \
                patch.object(a.Path, 'read_text', return_value='ID=debian\nVERSION_ID=12\n'), \
                patch.object(a, 'inventory', return_value=[('installed', 'libbrotli1', '1.0.9-2', 'brotli', '1.0.9-2')]), \
                patch.object(a, 'candidates', return_value={'libbrotli1': '(none)'}), \
                patch.object(a, 'extra_runtimes', return_value=([], [])), \
                patch.object(a, 'inspect_processes', return_value={'status': 'NO_MATCHING_PROCESSES', 'records': [], 'errors': [], 'vanished': 0}), \
                patch.object(a, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            report = a.collect_report([])
        self.assertEqual(report['packages'], [])
        self.assertEqual(report['summary']['package_exit_code'], 2)
        self.assertEqual(report['summary']['brotli_exit_code'], 1)
        self.assertEqual(report['cves']['CVE-2026-109618']['status'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
