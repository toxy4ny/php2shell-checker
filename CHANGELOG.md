# Changelog

## 0.2.0 — 2026-10-23

- Report installed-package and APT candidate findings separately for CVE-2026-109618
  and CVE-2026-109619, with advisory references and aggregate counts.
- Add the PHP session upload progress notice for CVE-2026-115560 as `REVIEW`.
  Configuration/application conditions are not automatically assessed; original
  fixed package versions do not resolve this notice.
- Inspect visible procfs processes for deleted/replaced PHP executables and PHP
  module mappings. Report PID, service hint, evidence and permission/namespace gaps.
- Add `--format json`, schema 1.0, structured operational errors and `--version`.
- Preserve independent package/process results when overall manual review is needed.
  **Behavior change:** completed v0.2.0 scans return 2 due to the supplemental
  advisory. Automation can use the documented component results while retaining
  the manual-review finding.
- Add process fixtures, a real Linux deleted-executable test, independent-CVE tests,
  JSON error checks and installed-PHP text/JSON smoke tests for Debian 12 and 13.

## Initial publication — 2026-10-22

- Read-only Debian 12/13 PHP package checks, APT candidates, holds and additional
  runtime discovery, with text reports and MIT licensing.
