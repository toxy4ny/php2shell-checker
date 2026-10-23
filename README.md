# PHP2Shell Checker

A read-only PHP package audit for **Debian 12 (bookworm)** and **Debian 13 (trixie)**.
Checks package versions against the published fixes for **CVE-2026-109618** and
**CVE-2026-109619**, commonly called PHP2Shell.

It inventories PHP core packages across installed branches, including PHP-FPM,
CLI, CGI and Apache mod_php, instead of relying on the default `php -v` command.
It also reports APT candidates, package holds and common runtime paths outside
the assessed packages.

**This is a package-version checker, not a vulnerability exploit or a certificate
that a server is safe.** It does not install packages, change configuration,
refresh APT indexes, restart services, execute PHP binaries or make network requests.

## Quick start

Requirements: Debian 12 or 13, Python 3.9+ and the standard `dpkg`/APT tools.
There are no third-party Python dependencies. Root is not required for the checker;
inaccessible scan paths are reported as incomplete.

```sh
git clone https://github.com/toxy4ny/php2shell-checker.git
cd php2shell-checker

# Optional, separate operation: refresh available package versions.
sudo apt update

python3 check-php2shell.py
```

GitLab mirror: https://gitlab.com/toxy4ny/php2shell-checker

You can also download just `check-php2shell.py`, inspect it and run it locally.
To include a custom installation directory:

```sh
python3 check-php2shell.py --scan-root /www/server/php --scan-root /srv/php
```

The default scan covers `/usr/bin`, `/usr/sbin`, `/usr/lib/cgi-bin`,
`/usr/lib/apache2/modules`, `/usr/local` and `/opt`. It recognizes common PHP,
PHP-FPM, CGI, LiteSpeed PHP, FrankenPHP and Apache module filenames. Directory
symlinks are not traversed; pass their target directories explicitly.

## Reading the report

| Status | Meaning |
| --- | --- |
| `FIXED` | Package metadata meets a known patched release threshold. |
| `UPDATE` | A recognizable Debian package version is below its fixed threshold. |
| `UNKNOWN` | Remediation cannot be verified automatically. Consult the package vendor. |

Older third-party packages are **not automatically declared vulnerable**: their
vendor may have backported the fix. They remain `UNKNOWN` until a supported fixed
release is installed or the backport is independently verified. An epoch or a large
packaging revision alone never counts as an upstream fix. Version naming is not
proof of repository authenticity or package integrity.

Example output (illustrative, not a scan of your host):

```text
[UPDATE] php8.2-fpm  installed=8.2.34-1~deb12u1
  Debian package version below 8.2.35-1~deb12u1; source=php8.2 (8.2.34-1~deb12u1)
  Candidate: 8.2.35-1~deb12u1 [FIXED] — Debian package version >= 8.2.35-1~deb12u1
```

If APT offers a newer fixed candidate, the report prints a simulation command and
an update command for eligible packages. **Neither is executed.** Held packages
are identified and excluded from the suggested command. Dependencies and holds
can still affect the full transaction: review the simulation before proceeding.

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | All discovered PHP core packages meet known fixed thresholds, with no additional unknown findings in the scanned scope. |
| `1` | At least one package needs an update, with no unknown findings. |
| `2` | Unknown findings, incomplete audit, no PHP core packages found, unsupported system or execution error. Takes precedence over `1`. |

## Fixed versions and sources

Rules verified on **2026-10-22**. They are embedded in the script and are not
automatically refreshed. A future/unmapped branch is reported as `UNKNOWN`.

| Package or branch | Fixed threshold |
| --- | --- |
| Debian 12 `php8.2` source package | `8.2.35-1~deb12u1` |
| Debian 13 `php8.4` source package | `8.4.27-1~deb13u1` |
| Upstream PHP 8.2 | `8.2.35` |
| Upstream PHP 8.3 | `8.3.36` |
| Upstream PHP 8.4 | `8.4.27` |
| Upstream PHP 8.5 | `8.5.12` |

Primary references:

- [Debian CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618)
- [Debian CVE-2026-109619](https://security-tracker.debian.org/tracker/CVE-2026-109619)
- [Debian 12: DLA-4848-1](https://security-tracker.debian.org/tracker/DLA-4848-1)
- [Debian 13: DSA-6574-1](https://security-tracker.debian.org/tracker/DSA-6574-1)
- [PHP security advisory, 21 October 2026](https://www.php.net/archive/2026.php)

## Scope and limitations

- All recognized PHP core packages in the local dpkg database are assessed,
  including packages from branches other than the distribution default.
- Arbitrary vendor package names, renamed binaries and PHP installed outside the
  searched paths may not be discovered. This is not a full filesystem inventory.
- Containers, chroots, remote servers and application code are not inspected.
  Run an appropriate check inside each relevant environment separately.
- File contents and running workers are not verified. An updated package can
  coexist with old processes still serving requests. Restart affected PHP-FPM,
  Apache mod_php and long-running workers after updating, then check your sites.
- Third-party extensions have their own version numbers and are not compared to
  PHP engine thresholds. This tool does not audit extension vulnerabilities.
- APT candidate information can be stale. Refresh indexes separately and resolve
  any `apt update` errors before relying on the suggested upgrade plan.
- A `FIXED` result does not establish that a host has never been compromised.

## Development and testing

```sh
python3 -m unittest discover -s tests -v
```

Fixture tests run without Debian. On Debian, additional tests use real
`dpkg --compare-versions` to cover release boundaries, prereleases, epochs and
packaging revisions. CI runs tests and an installed-PHP smoke check on both
Debian releases, on GitHub and GitLab.

For changes to version rules, include a primary vendor advisory and a regression
test. Please redact hostnames and sensitive paths from bug reports. Do not include
credentials or production configuration dumps.

## License

MIT. Copyright (c) 2026 PHP2Shell Checker contributors.
