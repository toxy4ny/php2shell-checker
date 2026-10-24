# JSON report contract — schema 1.1

Run `sudo python3 check-php2shell.py --format json`. Stdout contains one JSON object;
the checker does not refresh APT or write the report to disk itself. Shell redirection
is optional. Operational errors also produce JSON and exit 2. CLI usage errors from
argument parsing go to stderr; `--help` and `--version` produce plain text.

Consumers should check `errors` first, then the summary and coverage. Unknown keys
may be added within schema 1.x; incompatible changes require a new major version.
Paths, process names and service hints are untrusted host metadata. Do not execute
strings from a report as shell commands. Reports may contain sensitive local paths;
redact them before sharing.

| Key | Content |
| --- | --- |
| `schema_version` | Contract version, currently `1.1`. |
| `tool_version` | Checker release, currently `0.3.0`. |
| `generated_at` | UTC ISO 8601 timestamp. |
| `rules_verified_at` | Date of embedded advisory review, not a live feed timestamp. |
| `system` | OS ID, version and display name. |
| `cves` | Findings keyed by CVE. The two original PHP CVEs and CVE-2026-111497 have separate package status, counts and references. The supplemental PHP CVE has `REVIEW`, conditions, recommendation and reference. Do not assume a fixed set of CVE keys. |
| `packages` | PHP-only packages: name, binary/source versions, dpkg state, hold, aggregate status, per-CVE installed results and candidate results. Missing candidate: `version: null`, `cves: {}`. |
| `brotli` | Separate CVE-2026-111497 component, described below. Null on fatal errors. |
| `processes` | Aggregate status, individual records, scan errors and number of processes that vanished. |
| `coverage` | Search roots, unassessed runtimes, scan errors and explicit unassessed areas. |
| `actions` | Eligible PHP and Brotli upgrade packages, PHP restart PIDs and simulation/update command argument arrays. Empty arrays mean no recommendation, not no affected packages. Nothing is executed. |
| `summary` | PHP package counts, independent PHP package/process and Brotli exit codes, updates/restarts found, CVEs needing review and overall exit code. |
| `errors` | Fatal operational error messages; empty for a completed audit. |

On fatal errors, `system`, `processes`, `coverage`, `actions` and `brotli` are null;
`cves` is empty, `packages` is empty and `summary` contains only `exit_code: 2`.
Do not interpret empty error-report data as a successful empty scan.

## Status interpretation

Package results: `FIXED`, `UPDATE`, `UNKNOWN`. A CVE aggregate shows `UPDATE` when
any package needs an update, otherwise `UNKNOWN` if a package is unknown or no
packages were found, otherwise `FIXED`. Counts retain concurrent unknowns.
Unpackaged PHP runtime findings are in `coverage`, not silently added to package counts.

## Brotli component (added in 1.1)

`brotli.packages` has the same package record shape as `packages`, but its `cves`
contains only CVE-2026-111497. It includes all matching dpkg source-package records,
not only loaded decoder libraries. Binary-name fallbacks with a source mismatch
remain `UNKNOWN`. Residual config-only and not-installed records are excluded.

`brotli.status` aggregates installed findings: `UPDATE` takes precedence over
`UNKNOWN`, then `FIXED`. Empty inventory is `NOT_INSTALLED`, not `FIXED`.
`counts` retains all three package counts. `exit_code` is 2 if any installed record
is unknown, otherwise 1 if any is affected, otherwise 0 (also for `NOT_INSTALLED`).
This code covers matching dpkg metadata only. Missing APT candidates do not change
installed findings. Candidate status and installed status are independent.

`updates_required` preserves known affected-package findings even when the code
is 2. `upgrade_packages` lists only unheld packages with a newer candidate assessed
as `FIXED`, and is also included in the top-level combined `actions`.
`debian_fixed_version` is null because no fixed Debian package version is recorded
in these embedded rules. `known_affected_debian_version` records the release's
known affected source version; `upstream_fixed_versions` maps the supported
upstream branches. Unknown Debian revisions/backports are not presumed patched.

`reachability` and `loaded_libraries` are `NOT_CHECKED`; `embedded_copies` is
`NOT_AUDITED`. `assessment` explains the scope. No finding demonstrates that
PHP/cURL, Node.js or another application actually decompresses attacker-controlled
Brotli data. The existing process evidence is PHP-only, including restart PIDs.
Static/vendored/custom copies can exist even when dpkg finds none.

`summary.brotli_exit_code` mirrors the component code and
`summary.brotli_updates_required` mirrors its update finding. The existing
`summary.package_counts` and `package_exit_code` remain PHP-only.
`summary.updates_required` now covers either PHP or Brotli. Overall status includes
the Brotli code, while the supplemental PHP `REVIEW` still makes completed audits
exit 2. Schema 1.0 reports have no Brotli result: consumers must say "not assessed"
for these reports, never infer `NOT_INSTALLED` from a missing field.

## Process and summary status

Process records: `RESTART_REQUIRED`, `UNKNOWN`, `NO_STALE_FILES_FOUND`,
`NO_PHP_MAPPING`. The aggregate can additionally be `NO_MATCHING_PROCESSES`.
Restart evidence takes priority in the process status, but errors remain visible
and force `summary.process_exit_code` to 2. `recognized_runtime: false` means the
checker could not rule out PHP in an inaccessible process; it is not a PHP detection.

Process evidence types: `deleted_executable`, `executable_inode_changed`,
`deleted_php_mapping`, `php_mapping_inode_changed`. Each includes a path.
`service` may be null. `start_time_ticks` is the kernel start-time field used to
guard against PID reuse, not a wall-clock timestamp.

Summary codes: 0 = no action found within that check; 1 = update/restart required;
2 = unknown/incomplete. Overall exit 2 also includes unresolved advisory review.
The overall code currently remains 2 on completed scans because CVE-2026-115560
requires manual review. Positive findings are preserved in booleans, counts and
action lists. A zero component code never means the entire host is secure.

Example automation after saving `report.json`:

```python
import json

with open('report.json') as stream:
    report = json.load(stream)
if report['errors']:
    raise RuntimeError(report['errors'])
summary = report['summary']
print('Package check:', summary['package_exit_code'])
print('Process check:', summary['process_exit_code'])
print('Brotli check:', summary.get('brotli_exit_code', 'not assessed by this report'))
print('Updates required:', summary['updates_required'])
print('Restart required:', summary['restart_required'])
print('Manual review:', summary['review_required'])
```
