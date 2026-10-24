# JSON report contract — schema 1.0

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
| `schema_version` | Contract version, currently `1.0`. |
| `tool_version` | Checker release, currently `0.2.0`. |
| `generated_at` | UTC ISO 8601 timestamp. |
| `rules_verified_at` | Date of embedded advisory review, not a live feed timestamp. |
| `system` | OS ID, version and display name. |
| `cves` | Findings keyed by CVE. The two original CVEs have package status, counts and a reference. The supplemental CVE has `REVIEW`, conditions, recommendation and reference. |
| `packages` | Name, binary/source versions, dpkg state, hold, aggregate status, per-CVE installed results and candidate results. Missing candidate: `version: null`, `cves: {}`. |
| `processes` | Aggregate status, individual records, scan errors and number of processes that vanished. |
| `coverage` | Search roots, unassessed runtimes, scan errors and explicit unassessed areas. |
| `actions` | Eligible upgrade packages, restart PIDs and simulation/update command argument arrays. Empty arrays mean no recommendation. Nothing is executed. |
| `summary` | Package counts, independent package/process exit codes, updates/restarts found, CVEs needing review and overall exit code. |
| `errors` | Fatal operational error messages; empty for a completed audit. |

On fatal errors, `system`, `processes`, `coverage` and `actions` are null;
`cves` is empty, `packages` is empty and `summary` contains only `exit_code: 2`.
Do not interpret empty error-report data as a successful empty scan.

## Status interpretation

Package results: `FIXED`, `UPDATE`, `UNKNOWN`. A CVE aggregate shows `UPDATE` when
any package needs an update, otherwise `UNKNOWN` if a package is unknown or no
packages were found, otherwise `FIXED`. Counts retain concurrent unknowns.
Unpackaged runtime findings are in `coverage`, not silently added to package counts.

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
print('Updates required:', summary['updates_required'])
print('Restart required:', summary['restart_required'])
print('Manual review:', summary['review_required'])
```
