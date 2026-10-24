"""Exercise real dpkg/APT inventory with PHP installed; mirror patch state may vary."""
from pathlib import Path
import json
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
result = subprocess.run([sys.executable, str(root / "check-php2shell.py")],
                        capture_output=True, text=True)
print(result.stdout)
print(result.stderr, file=sys.stderr)
assert result.returncode in (0, 1, 2), result.returncode
assert not result.stderr, result.stderr
assert "PHP core package totals:" in result.stdout
assert "Result:" in result.stdout
assert "php8.2-cli  installed=" in result.stdout or "php8.4-cli  installed=" in result.stdout
assert "Candidate:" in result.stdout

worker = subprocess.Popen(['php', '-n', '-r', 'sleep(30);'])
try:
    structured = subprocess.run([sys.executable, str(root / "check-php2shell.py"), '--format', 'json'],
                                capture_output=True, text=True)
finally:
    worker.terminate()
    worker.wait(timeout=5)
assert not structured.stderr, structured.stderr
report = json.loads(structured.stdout)
assert report['schema_version'] == '1.1'
assert report['tool_version'] == '0.3.0'
assert set(report['cves']) == {'CVE-2026-109618', 'CVE-2026-109619', 'CVE-2026-115560', 'CVE-2026-111497'}
assert report['cves']['CVE-2026-115560']['status'] == 'REVIEW'
assert report['packages']
assert all(set(p['cves']) == {'CVE-2026-109618', 'CVE-2026-109619'} for p in report['packages'])
assert report['processes']['status'] in ('NO_MATCHING_PROCESSES', 'NO_STALE_FILES_FOUND', 'UNKNOWN', 'RESTART_REQUIRED')
assert structured.returncode == report['summary']['exit_code'] == 2
assert report['summary']['review_required'] == ['CVE-2026-115560']
brotli = report['brotli']
assert brotli['packages'], brotli
assert any(p['name'].split(':')[0] == 'libbrotli1' for p in brotli['packages'])
assert all(p['source_package'] == 'brotli' for p in brotli['packages'])
assert all(set(p['cves']) == {'CVE-2026-111497'} for p in brotli['packages'])
assert brotli['reachability'] == brotli['loaded_libraries'] == 'NOT_CHECKED'
assert report['cves']['CVE-2026-111497']['status'] == brotli['status']
assert report['summary']['brotli_exit_code'] == brotli['exit_code']
assert 'Brotli / CVE-2026-111497:' in result.stdout
assert any(p['pid'] == worker.pid and p['status'] == 'NO_STALE_FILES_FOUND'
           for p in report['processes']['records']), report['processes']
print('JSON report parsed and checked; overall exit 2 correctly preserves advisory review.')
