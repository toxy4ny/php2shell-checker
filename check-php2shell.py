#!/usr/bin/env python3
"""Read-only PHP2Shell and Brotli audit for Debian 12/13; Python 3 standard library.

Rules verified 2026-10-23:
https://security-tracker.debian.org/tracker/CVE-2026-109618
https://security-tracker.debian.org/tracker/CVE-2026-109619
https://security-tracker.debian.org/tracker/CVE-2026-111497
https://www.php.net/archive/2026.php

Exit codes: 0 = no action found within scope; 1 = update/restart required;
2 = unknown, incomplete or advisory review required (takes precedence).
No exit code certifies every website, container or running worker as patched.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

FIXED = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
DEBIAN_FIXED = {"php8.2": "8.2.35-1~deb12u1", "php8.4": "8.4.27-1~deb13u1"}
CORE_SOURCE = re.compile(r"^php(?:\d+(?:\.\d+)?)?$")
RUNTIME_NAME = re.compile(
    r"^(?:php(?:\d+(?:\.\d+)?)?(?:-fpm|-cgi)?|"
    r"php-(?:fpm|cgi)(?:\d+(?:\.\d+)?)?|lsphp(?:\d+(?:\.\d+)?)?|"
    r"frankenphp|libphp.*\.so)$"
)
CORE_BINARY = re.compile(r"^(?:php\d+(?:\.\d+)?-(?:cli|fpm|cgi|common)|"
                         r"libapache2-mod-php\d+(?:\.\d+)?|libphp\d.*-embed)$")
ENV = dict(os.environ, LC_ALL="C", LANG="C")
VERSION = "0.3.0"
SCHEMA_VERSION = "1.1"
RULES_DATE = "2026-10-23"
BROTLI_CVE = 'CVE-2026-111497'
BROTLI_REFERENCE = 'https://security-tracker.debian.org/tracker/' + BROTLI_CVE
BROTLI_FIXED = {'1.0': '1.0.10', '1.1': '1.1.1', '1.2': '1.2.1'}
# Exact source versions recorded by Debian, not a guessed future Debian fix.
BROTLI_AFFECTED = {'12': '1.0.9-2', '13': '1.1.0-2'}
BROTLI_BINARY = re.compile(r'^(?:brotli|libbrotli\d+|libbrotli-dev|python3-brotli)$')
CVE_RULES = {
    cve: {"upstream": dict(FIXED), "debian": dict(DEBIAN_FIXED),
          "reference": "https://security-tracker.debian.org/tracker/" + cve}
    for cve in ("CVE-2026-109618", "CVE-2026-109619")
}
NOTICE = {
    "cve": "CVE-2026-115560", "status": "REVIEW", "date": "2026-10-23",
    "reference": "https://www.php.net/archive/2026.php",
    "reason": "PHP's session upload progress advisory requires configuration/application review; "
              "no fixed-version threshold is encoded for this CVE.",
    "conditions": ["session.upload_progress.enabled is enabled",
                   "session.serialize_handler is configured as php_binary or php_serialize",
                   "application code switches it to php with ini_set() before session_start()"],
    "recommendation": "PHP recommends session.upload_progress.enabled=0 until the next regular "
                      "bugfix release. Apply it before request parsing in the effective web SAPI "
                      "configuration and restart affected workers. Do not rely on ini_set() or "
                      "FPM .user.ini for this mitigation.",
    "assessment": "Configuration and application code are not inspected. Enabled upload progress "
                  "alone does not establish vulnerability. Original PHP2Shell fixes do not "
                  "establish remediation of this separate advisory.",
}


def run(args):
    try:
        return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=ENV, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Command failed: " + shlex.join(args) + ": " + str(exc)) from exc


def ge(a, b):
    result = run(["dpkg", "--compare-versions", a, "ge", b])
    if result.returncode not in (0, 1):
        raise RuntimeError("Could not compare versions: " + a + " / " + b)
    return result.returncode == 0


def classify(source, version, cve="CVE-2026-109618"):
    """Return status, explanation. Never infer a backport from a large epoch/revision."""
    rule = CVE_RULES[cve]
    without_epoch = version.split(":", 1)[-1]
    upstream = without_epoch.rsplit("-", 1)[0]
    match = re.match(r"^(\d+\.\d+)\.\d+", upstream)
    if not match or match[1] not in rule["upstream"]:
        return "UNKNOWN", "no rule for this branch; consult the vendor advisory"
    branch = match[1]
    if source != "php" + branch:
        return "UNKNOWN", "source package branch does not match the version"
    # Limit Debian-specific assertions to recognizable stable-update package versions.
    suite = {"php8.2": "12", "php8.4": "13"}.get(source)
    official_style = suite and re.fullmatch(
        r"\d+\.\d+\.\d+-\d+~deb" + suite + r"u\d+(?:\+b\d+)?", without_epoch)
    if official_style:
        threshold = rule["debian"][source]
        if ge(without_epoch, threshold):
            return "FIXED", "Debian package version >= " + threshold
        return "UPDATE", "Debian package version below " + threshold
    if ge(upstream, rule["upstream"][branch]):
        return "FIXED", "upstream version >= " + rule["upstream"][branch]
    return "UNKNOWN", "below " + rule["upstream"][branch] + "; vendor backport not verified"


def is_brotli_package(name, source):
    return source == 'brotli' or bool(BROTLI_BINARY.fullmatch(name.split(':')[0]))


def classify_brotli(source, version, release):
    """Assess source version metadata; never infer reachability or vendor backports."""
    if source != 'brotli':
        return 'UNKNOWN', 'Brotli binary name has an unrecognized source package'
    if re.fullmatch(re.escape(BROTLI_AFFECTED[release]) + r'(?:\+b\d+)?', version):
        return 'UPDATE', ('source version listed as affected by Debian; no Debian fixed '
                          'version recorded in embedded rules')
    upstream = version.split(':', 1)[-1].rsplit('-', 1)[0]
    match = re.fullmatch(r'(1\.[012])\.\d+', upstream)
    if match and ge(upstream, BROTLI_FIXED[match[1]]):
        return 'FIXED', 'upstream Brotli version >= ' + BROTLI_FIXED[match[1]]
    return 'UNKNOWN', ('no verified fix for this build; consult the vendor for backports '
                       'or unmapped/prerelease versions')


def inventory():
    fmt = "${db:Status-Status}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n"
    result = run(["dpkg-query", "-W", "-f=" + fmt])
    if result.returncode:
        raise RuntimeError("dpkg-query: " + result.stderr.strip())
    rows = []
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            raise RuntimeError("Unexpected dpkg database output")
        state, name, version, source, source_version = fields
        if state in ("not-installed", "config-files"):
            continue
        source = source or name.split(":")[0]
        source_version = source_version or version
        bare = name.split(":")[0]
        if CORE_SOURCE.fullmatch(source) or CORE_BINARY.fullmatch(bare) or is_brotli_package(name, source):
            rows.append((state, name, version, source, source_version))
    return sorted(rows, key=lambda row: (row[3], row[1]))


def candidates(names):
    result = run(["apt-cache", "policy", *names])
    if result.returncode:
        raise RuntimeError("apt-cache policy: " + result.stderr.strip())
    result_map, current = {}, None
    for line in result.stdout.splitlines():
        if line and not line[0].isspace() and line.endswith(":"):
            current = line[:-1]
        elif current and line.strip().startswith("Candidate:"):
            result_map[current] = line.split("Candidate:", 1)[1].strip()
    return {name: result_map.get(name, result_map.get(name.split(":")[0], "(none)")) for name in names}


def extra_runtimes(roots, audited_packages):
    """Find runtime paths not covered by the package audit, without executing PHP."""
    found, errors, seen = [], [], set()
    def walk_error(error):
        errors.append(str(error))
    for root in roots:
        if not os.path.exists(root):
            continue
        for directory, _, files in os.walk(root, followlinks=False, onerror=walk_error):
            for name in files:
                if not RUNTIME_NAME.fullmatch(name):
                    continue
                path = os.path.join(directory, name)
                real = os.path.realpath(path)
                if real in seen:
                    continue
                seen.add(real)
                owned = False
                for candidate in dict.fromkeys((path, real)):
                    owner = run(["dpkg-query", "-S", candidate])
                    if owner.returncode == 0:
                        owners = {item.strip().split(":")[0]
                                  for line in owner.stdout.splitlines()
                                  for item in line.split(": ", 1)[0].split(",")}
                        if owners & audited_packages:
                            owned = True
                            break
                    if owner.returncode not in (0, 1):
                        errors.append("Could not check package ownership: " + candidate)
                if not owned:
                    found.append(path)
    return sorted(found), errors


def process_identity(directory):
    """Start time guards against PID reuse; comm can contain spaces/parentheses."""
    fields = (directory / 'stat').read_text().rsplit(')', 1)[1].split()
    return fields[19], fields[0]


def php_maps(text):
    mappings = []
    for line in text.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            continue
        path = fields[5]
        clean = path.removesuffix(' (deleted)')
        if re.fullmatch(r'libphp[^/]*\.so(?:\.\d+)*', Path(clean).name):
            mappings.append((path, fields[3], fields[4]))
    return sorted(set(mappings))


def inspect_process(directory, observer_ns):
    """Read procfs metadata only. Never read environment, command arguments or memory."""
    start, state = process_identity(directory)
    if state in ('Z', 'X'):
        return None
    errors, evidence = [], []
    comm = (directory / 'comm').read_text().strip()
    executable = None
    try:
        executable = os.readlink(directory / 'exe')
    except FileNotFoundError:
        # Kernel threads have no executable. Relevant userspace processes must not disappear silently.
        pass
    except OSError as exc:
        errors.append('executable metadata unavailable: ' + str(exc))
    try:
        mappings = php_maps((directory / 'maps').read_text())
    except OSError as exc:
        mappings = []
        errors.append('memory mapping metadata unavailable: ' + str(exc))
    clean_exe = (executable or '').removesuffix(' (deleted)')
    is_php = bool(RUNTIME_NAME.fullmatch(Path(clean_exe).name) or RUNTIME_NAME.fullmatch(comm))
    is_apache = Path(clean_exe).name in ('apache2', 'httpd') or comm in ('apache2', 'httpd')
    relevant = is_php or is_apache or bool(mappings)
    if not relevant and not errors:
        return None
    if relevant and executable is None:
        errors.append('executable unavailable for a recognized process')
    same_namespace = False
    if relevant:
        try:
            same_namespace = (observer_ns is not None and
                              os.readlink(directory / 'ns/mnt') == observer_ns and
                              os.path.samestat(os.stat(directory / 'root'), os.stat('/')))
            if not same_namespace:
                errors.append('different mount namespace or root; host package inventory does not apply')
        except OSError as exc:
            errors.append('process namespace/root unavailable: ' + str(exc))
        # Only inspect Apache's executable when a PHP module is mapped.
        if executable and (is_php or mappings):
            if executable.endswith(' (deleted)'):
                evidence.append({'type': 'deleted_executable', 'path': executable})
            elif same_namespace:
                try:
                    running = os.stat(directory / 'exe')
                    current = os.stat(directory / 'root' / clean_exe.lstrip('/'))
                    if not os.path.samestat(running, current):
                        evidence.append({'type': 'executable_inode_changed', 'path': clean_exe})
                except OSError as exc:
                    errors.append('cannot compare executable with disk: ' + str(exc))
        for path, device, inode in mappings:
            if path.endswith(' (deleted)'):
                evidence.append({'type': 'deleted_php_mapping', 'path': path})
            elif same_namespace:
                try:
                    current = os.stat(directory / 'root' / path.lstrip('/'))
                    major, minor = (int(part, 16) for part in device.split(':'))
                    if (current.st_ino != int(inode) or os.major(current.st_dev) != major or
                            os.minor(current.st_dev) != minor):
                        evidence.append({'type': 'php_mapping_inode_changed', 'path': path})
                except (OSError, ValueError) as exc:
                    errors.append('cannot compare PHP mapping with disk: ' + str(exc))
    service = None
    if relevant:
        try:
            units = re.findall(r'(?:^|/)([^/\n]+\.service)(?:/|$)',
                               (directory / 'cgroup').read_text(), re.MULTILINE)
            service = units[-1] if units else None
        except OSError:
            # Optional hint; missing cgroup metadata does not invalidate inode evidence.
            pass
    if process_identity(directory)[0] != start:
        raise RuntimeError('PID was reused during inspection')
    status = ('RESTART_REQUIRED' if evidence else 'UNKNOWN' if errors else
              'NO_PHP_MAPPING' if is_apache and not is_php and not mappings else 'NO_STALE_FILES_FOUND')
    return {'pid': int(directory.name), 'start_time_ticks': start, 'name': comm,
            'executable': executable, 'service': service, 'status': status,
            'evidence': evidence, 'errors': errors, 'recognized_runtime': relevant}


def inspect_processes(proc_root=Path('/proc')):
    records, errors, raced = [], [], 0
    try:
        directories = sorted((p for p in proc_root.iterdir() if p.name.isdigit()),
                             key=lambda p: int(p.name))
    except OSError as exc:
        return {'status': 'UNKNOWN', 'records': [], 'errors': [str(exc)], 'vanished': 0}
    try:
        observer_ns = os.readlink(proc_root / 'self/ns/mnt')
    except OSError as exc:
        observer_ns = None
        errors.append('observer mount namespace unavailable: ' + str(exc))
    if os.geteuid() != 0:
        errors.append('non-root scan: procfs permissions/hidepid may conceal processes; rerun with sudo')
    for directory in directories:
        if int(directory.name) == os.getpid():
            continue
        try:
            record = inspect_process(directory, observer_ns)
            if record:
                records.append(record)
        except (FileNotFoundError, ProcessLookupError):
            if directory.exists():
                errors.append('PID ' + directory.name + ': incomplete procfs metadata')
            else:
                raced += 1
        except (OSError, RuntimeError, IndexError, ValueError) as exc:
            errors.append('PID ' + directory.name + ': ' + str(exc))
    if not directories:
        errors.append('no process entries visible; procfs coverage cannot be established')
    restart = any(r['status'] == 'RESTART_REQUIRED' for r in records)
    incomplete = bool(errors or any(r['errors'] for r in records))
    status = ('RESTART_REQUIRED' if restart else 'UNKNOWN' if incomplete else
              'NO_STALE_FILES_FOUND' if records else 'NO_MATCHING_PROCESSES')
    return {'status': status, 'records': records, 'errors': errors, 'vanished': raced}


def package_cves(source, version, state='installed'):
    findings = {}
    for cve, rule in CVE_RULES.items():
        status, reason = classify(source, version, cve)
        if state != 'installed':
            status, reason = 'UNKNOWN', 'incomplete dpkg installation: ' + state
        findings[cve] = {'status': status, 'reason': reason, 'reference': rule['reference']}
    return findings


def aggregate_status(statuses):
    statuses = list(statuses)
    if 'UPDATE' in statuses:
        return 'UPDATE'
    if not statuses or 'UNKNOWN' in statuses:
        return 'UNKNOWN'
    return 'FIXED'


def brotli_report(rows, available, holds, release):
    packages, recommended = [], []
    for state, name, version, source, source_version in rows:
        status, reason = classify_brotli(source, source_version, release)
        if state != 'installed':
            status, reason = 'UNKNOWN', 'incomplete dpkg installation: ' + state
        held = name in holds or name.split(':')[0] in holds
        candidate = available[name]
        candidate_findings = {}
        if candidate != '(none)':
            candidate_status, candidate_reason = classify_brotli(source, candidate, release)
            candidate_findings[BROTLI_CVE] = {'status': candidate_status,
                                             'reason': candidate_reason,
                                             'reference': BROTLI_REFERENCE}
            if (status != 'FIXED' and not held and candidate_status == 'FIXED' and
                    candidate != version and ge(candidate, version)):
                recommended.append(name)
        packages.append({'name': name, 'installed_version': version, 'source_package': source,
                         'source_version': source_version, 'dpkg_state': state, 'held': held,
                         'status': status,
                         'cves': {BROTLI_CVE: {'status': status, 'reason': reason,
                                              'reference': BROTLI_REFERENCE}},
                         'candidate': {'version': None if candidate == '(none)' else candidate,
                                       'cves': candidate_findings}})
    counts = {s: sum(p['status'] == s for p in packages) for s in ('FIXED', 'UPDATE', 'UNKNOWN')}
    status = aggregate_status(p['status'] for p in packages) if packages else 'NOT_INSTALLED'
    code = 2 if counts['UNKNOWN'] else 1 if counts['UPDATE'] else 0
    return {'cve': BROTLI_CVE, 'status': status, 'scope': 'dpkg_brotli_source_packages',
            'packages': packages, 'counts': counts, 'exit_code': code,
            'updates_required': bool(counts['UPDATE']), 'upgrade_packages': recommended,
            'reference': BROTLI_REFERENCE, 'debian_fixed_version': None,
            'known_affected_debian_version': BROTLI_AFFECTED[release],
            'upstream_fixed_versions': dict(BROTLI_FIXED),
            'reachability': 'NOT_CHECKED', 'loaded_libraries': 'NOT_CHECKED',
            'embedded_copies': 'NOT_AUDITED',
            'assessment': 'Package/source version metadata only; decoder use and exploitability '
                          'in PHP/cURL, Node.js or other applications are not established. '
                          'Custom, vendored and static copies are not inventoried. '
                          'NOT_INSTALLED means no matching dpkg package, not no Brotli on the host.'}


def collect_report(scan_roots):
    for executable in ('dpkg', 'dpkg-query', 'apt-cache', 'apt-mark'):
        if not shutil.which(executable):
            raise RuntimeError('Missing command: ' + executable + '; Debian 12 or 13 is required')
    system = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            system[key] = value.strip('"')
    if system.get('ID') != 'debian' or system.get('VERSION_ID') not in ('12', '13'):
        raise RuntimeError('This script supports Debian 12 and 13')
    all_rows = inventory()
    brotli_rows = [r for r in all_rows if is_brotli_package(r[1], r[3])]
    rows = [r for r in all_rows if not is_brotli_package(r[1], r[3])]
    hold_result = run(['apt-mark', 'showhold'])
    if hold_result.returncode:
        raise RuntimeError('Could not list held packages')
    holds = set(hold_result.stdout.splitlines())
    available = candidates([r[1] for r in all_rows]) if all_rows else {}
    brotli = brotli_report(brotli_rows, available, holds, system['VERSION_ID'])
    packages, recommended = [], []
    for state, name, version, source, source_version in rows:
        findings = package_cves(source, source_version, state)
        status = aggregate_status(f['status'] for f in findings.values())
        held = name in holds or name.split(':')[0] in holds
        candidate = available[name]
        candidate_findings = package_cves(source, candidate) if candidate != '(none)' else {}
        if (status != 'FIXED' and not held and candidate_findings and
                all(f['status'] == 'FIXED' for f in candidate_findings.values()) and
                candidate != version and ge(candidate, version)):
            recommended.append(name)
        packages.append({'name': name, 'installed_version': version, 'source_package': source,
                         'source_version': source_version, 'dpkg_state': state, 'held': held,
                         'status': status, 'cves': findings,
                         'candidate': {'version': None if candidate == '(none)' else candidate,
                                       'cves': candidate_findings}})
    roots = ['/usr/bin', '/usr/sbin', '/usr/lib/cgi-bin', '/usr/lib/apache2/modules',
             '/usr/local', '/opt', *scan_roots]
    extra, scan_errors = extra_runtimes(roots, {r[1].split(':')[0] for r in rows})
    for root in scan_roots:
        if not os.path.isdir(root):
            scan_errors.append('Requested scan root is not an accessible directory: ' + root)
    processes = inspect_processes()
    package_counts = {s: sum(p['status'] == s for p in packages) for s in ('FIXED', 'UPDATE', 'UNKNOWN')}
    cves = {}
    for cve, rule in CVE_RULES.items():
        statuses = [p['cves'][cve]['status'] for p in packages]
        cves[cve] = {'status': aggregate_status(statuses), 'scope': 'installed_package_metadata',
                     'counts': {s: statuses.count(s) for s in ('FIXED', 'UPDATE', 'UNKNOWN')},
                     'reference': rule['reference']}
    cves[NOTICE['cve']] = {**NOTICE, 'scope': 'advisory_only'}
    cves[BROTLI_CVE] = {key: brotli[key] for key in
                       ('status', 'scope', 'counts', 'reference', 'reachability', 'assessment')}
    package_unknown = not packages or package_counts['UNKNOWN'] > 0 or bool(extra or scan_errors)
    package_exit = 2 if package_unknown else 1 if package_counts['UPDATE'] else 0
    restart_pids = [p['pid'] for p in processes['records'] if p['status'] == 'RESTART_REQUIRED']
    process_unknown = bool(processes['errors'] or any(p['errors'] for p in processes['records']))
    process_exit = 2 if process_unknown else 1 if restart_pids else 0
    # The supplemental advisory is deliberately not declared resolved by version checks.
    review = [cve for cve, finding in cves.items() if finding['status'] == 'REVIEW']
    component_codes = (package_exit, process_exit, brotli['exit_code'])
    exit_code = 2 if review or 2 in component_codes else max(component_codes)
    recommended.extend(brotli['upgrade_packages'])
    return {
        'schema_version': SCHEMA_VERSION, 'tool_version': VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat(), 'rules_verified_at': RULES_DATE,
        'system': {'id': system['ID'], 'version': system['VERSION_ID'],
                   'name': system.get('PRETTY_NAME', 'Debian')},
        'cves': cves, 'packages': packages, 'processes': processes, 'brotli': brotli,
        'coverage': {'scan_roots': roots, 'unassessed_runtimes': extra, 'scan_errors': scan_errors,
                     'configuration': 'NOT_CHECKED', 'application_code': 'NOT_CHECKED',
                     'containers_and_chroots': 'NOT_AUDITED', 'file_integrity': 'NOT_CHECKED',
                     'process_scope': 'visible procfs snapshot; renamed/static embedded runtimes may be missed',
                     'apt_indexes': 'local; freshness not verified'},
        'actions': {'upgrade_packages': recommended, 'restart_pids': restart_pids,
                    'simulation_argv': ['sudo', 'apt-get', '-s', 'install', '--only-upgrade', *recommended] if recommended else [],
                    'upgrade_argv': ['sudo', 'apt-get', 'install', '--only-upgrade', *recommended] if recommended else []},
        'summary': {'package_counts': package_counts, 'package_exit_code': package_exit,
                    'process_exit_code': process_exit, 'review_required': review,
                    'brotli_exit_code': brotli['exit_code'],
                    'brotli_updates_required': brotli['updates_required'],
                    'updates_required': bool(package_counts['UPDATE']) or brotli['updates_required'],
                    'restart_required': bool(restart_pids), 'exit_code': exit_code},
        'errors': [],
    }


def render_text(report):
    print('PHP2Shell Checker ' + report['tool_version'])
    if report['errors']:
        for error in report['errors']:
            print('ERROR: ' + error)
        return
    print('System: ' + report['system']['name'])
    print('Rules verified: ' + report['rules_verified_at'])
    print('APT uses local indexes; run sudo apt update separately to refresh candidates.')
    print('\nPer-CVE results:')
    for cve, finding in report['cves'].items():
        print(f"[{finding['status']}] {cve} ({finding['scope']})")
        print('  Source: ' + finding['reference'])
        if finding['status'] == 'REVIEW':
            print('  ' + finding['reason'])
            print('  Conditions: ' + '; '.join(finding['conditions']))
            print('  ' + finding['recommendation'])
            print('  ' + finding['assessment'])
    for package in report['packages']:
        print(f"\n[{package['status']}] {package['name']}  installed={package['installed_version']}" +
              ('  HOLD' if package['held'] else ''))
        for cve, finding in package['cves'].items():
            print(f"  {cve}: {finding['status']} — {finding['reason']}")
        candidate = package['candidate']
        print('  Candidate: ' + (candidate['version'] or 'unavailable'))
        for cve, finding in candidate['cves'].items():
            print(f"    {cve}: {finding['status']} — {finding['reason']}")
    print('\nPHP core package totals: ' + ', '.join(f'{s}={n}' for s, n in report['summary']['package_counts'].items()))
    brotli = report['brotli']
    print(f"\nBrotli / {BROTLI_CVE}: {brotli['status']}")
    print('  ' + brotli['assessment'])
    print('  Debian fixed version: not recorded in embedded rules; check the vendor advisory.')
    for package in brotli['packages']:
        finding = package['cves'][BROTLI_CVE]
        print(f"  [{package['status']}] {package['name']} installed={package['installed_version']}" +
              (' HOLD' if package['held'] else ''))
        print('    ' + finding['reason'])
        candidate = package['candidate']
        print('    Candidate: ' + (candidate['version'] or 'unavailable'))
        if candidate['cves']:
            finding = candidate['cves'][BROTLI_CVE]
            print(f"      {finding['status']} — {finding['reason']}")
    print('  Brotli component exit code: ' + str(brotli['exit_code']))
    print('\nProcess scan: ' + report['processes']['status'])
    for process in report['processes']['records']:
        print(f"[{process['status']}] PID {process['pid']} {json.dumps(process['name'])} service={json.dumps(process['service'])}")
        for item in process['evidence']:
            print('  ' + item['type'] + ': ' + json.dumps(item['path']))
        for error in process['errors']:
            print('  UNKNOWN: ' + error)
    for error in report['processes']['errors']:
        print('  UNKNOWN: ' + error)
    for path in report['coverage']['unassessed_runtimes']:
        print('[UNKNOWN] outside assessed packages: ' + json.dumps(path))
    for error in report['coverage']['scan_errors']:
        print('[UNKNOWN] ' + error)
    if report['actions']['upgrade_packages']:
        print('\nSuggested commands (NOT executed; review simulation first):')
        print(shlex.join(report['actions']['simulation_argv']))
        print(shlex.join(report['actions']['upgrade_argv']))
    print('\nResult: ' + ('REVIEW / INCOMPLETE' if report['summary']['exit_code'] == 2 else
                            'ACTION REQUIRED' if report['summary']['exit_code'] else 'NO ACTION FOUND WITHIN SCOPE'))
    print('Package status and restart findings remain actionable even when review is required.')
    print('FIXED applies only to the named CVE and package metadata, not running code or file integrity.')
    print('Process checks detect stale-file evidence, not runtime PHP versions or compromise.')
    print('Brotli loaded libraries and affected applications are not checked by the PHP process scan.')
    print('Configuration, application code, containers and chroots are not audited.')
    print('Directory symlinks are not traversed; add target directories using --scan-root.')
    print('Restart affected PHP-FPM/Apache/long-running workers after updating. Holds are never removed.')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only PHP2Shell and Brotli audit for Debian 12 and 13')
    parser.add_argument('--version', action='version', version='%(prog)s ' + VERSION)
    parser.add_argument('--format', choices=('text', 'json'), default='text', help='output format (default: text)')
    parser.add_argument('--scan-root', action='append', default=[], metavar='DIR',
                        help='additional runtime search directory; repeatable')
    args = parser.parse_args(argv)
    try:
        report = collect_report(args.scan_root)
    except (RuntimeError, OSError, UnicodeError) as exc:
        report = {'schema_version': SCHEMA_VERSION, 'tool_version': VERSION,
                  'generated_at': datetime.now(timezone.utc).isoformat(), 'rules_verified_at': RULES_DATE,
                  'system': None, 'cves': {}, 'packages': [], 'processes': None, 'brotli': None,
                  'coverage': None, 'actions': None, 'summary': {'exit_code': 2}, 'errors': [str(exc)]}
    if args.format == 'json':
        print(json.dumps(report, indent=2, ensure_ascii=True))
    else:
        render_text(report)
    return report['summary']['exit_code']


if __name__ == '__main__':
    sys.exit(main())
