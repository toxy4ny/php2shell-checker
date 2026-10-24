# PHP2Shell Checker

[![Tests on GitHub Actions](https://github.com/toxy4ny/php2shell-checker/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/toxy4ny/php2shell-checker/actions/workflows/test.yml?query=branch%3Amain)

**CI status:** tests run on [GitHub Actions](https://github.com/toxy4ny/php2shell-checker/actions/workflows/test.yml)
for Debian 12 and 13. The badge above shows the `main` branch status; open a workflow
run to see individual jobs and logs. [GitLab](https://gitlab.com/toxy4ny/php2shell-checker)
currently serves as a source and release mirror, with GitLab CI disabled.

A read-only PHP and Brotli package audit for **Debian 12 (bookworm)** and **Debian 13 (trixie)**.
Version **0.3.0** reports package results separately for **CVE-2026-109618** and
**CVE-2026-109619**, inspects running processes for stale PHP files, and produces
text or JSON reports. A separate Brotli component checks **CVE-2026-111497**.
It also surfaces the **2026-10-23 PHP advisory for
CVE-2026-115560** as a separate manual-review finding.

It inventories PHP core packages across installed branches, including PHP-FPM,
CLI, CGI and Apache mod_php, instead of relying on the default `php -v` command.
It also reports APT candidates, package holds and common runtime paths outside
the assessed packages. A process check inspects visible Linux procfs metadata;
it does not execute PHP or inspect process memory, arguments or environment variables.

**This is a package-version checker, not a vulnerability exploit or a certificate
that a server is safe.** It does not install packages, change configuration,
refresh APT indexes, restart services, execute PHP binaries or make network requests.

## Quick start

Requirements: Debian 12 or 13, Python 3.9+ and the standard `dpkg`/APT tools.
There are no third-party Python dependencies. Package inventory works without root.
Use `sudo` for more complete process access. Permission failures and non-root process
coverage are reported as incomplete; root still does not guarantee visibility outside
the current PID/mount namespace.

```sh
git clone https://github.com/toxy4ny/php2shell-checker.git
cd php2shell-checker

# Optional, separate operation: refresh available package versions.
sudo apt update

sudo python3 check-php2shell.py
```

Repositories: [GitHub (primary)](https://github.com/toxy4ny/php2shell-checker) · [GitLab (mirror)](https://gitlab.com/toxy4ny/php2shell-checker)

You can also download just `check-php2shell.py`, inspect it and run it locally.
To include a custom installation directory:

```sh
python3 check-php2shell.py --scan-root /www/server/php --scan-root /srv/php
```

The default scan covers `/usr/bin`, `/usr/sbin`, `/usr/lib/cgi-bin`,
`/usr/lib/apache2/modules`, `/usr/local` and `/opt`. It recognizes common PHP,
PHP-FPM, CGI, LiteSpeed PHP, FrankenPHP and Apache module filenames. Directory
symlinks are not traversed; pass their target directories explicitly.

## Using with AI agents

The repository includes an agent skill at [SKILL.md](SKILL.md), named
`php2shell-checker`. It guides an agent through running the checker on the intended
Debian 12/13 host and interpreting PHP/Brotli per-CVE results, process evidence, JSON errors
and incomplete coverage. It can also interpret an existing JSON report.

Keep the repository folder together when registering it with an agent's skill
loader: `SKILL.md` uses the adjacent `check-php2shell.py` and
`docs/report-format.md`. Copying only `SKILL.md` does not include the checker.
Registration and skill discovery depend on the agent application. An agent with
repository access can also follow the file directly, for example:

> Read SKILL.md in this checkout and use it to audit this Debian server with
> check-php2shell.py. Explain the per-CVE results, required updates, restart
> evidence and unresolved findings. Keep this task read-only.

The agent needs access to the target host; a local scan does not inspect a remote
server. The skill preserves `UNKNOWN` and `REVIEW` findings, including v0.3.0's
expected overall exit code 2, and does not treat `FIXED` as a whole-host safety
verdict. Brotli package findings do not establish application exposure. The skill
does not authorize exploit probes or automatic remediation.

## Reading the report

| Status | Meaning |
| --- | --- |
| `FIXED` | Package metadata meets a known patched release threshold. |
| `UPDATE` | PHP is below a known fixed threshold, or the Brotli source version is listed as affected by Debian. A fixed candidate may not be available. |
| `UNKNOWN` | Remediation cannot be verified automatically. Consult the package vendor. |
| `REVIEW` | Supplemental advisory needs manual configuration/application review. |
| `NOT_INSTALLED` | Brotli component only: no matching dpkg packages were found. Embedded/custom copies are not excluded. |

Older third-party packages are **not automatically declared vulnerable**: their
vendor may have backported the fix. They remain `UNKNOWN` until a supported fixed
release is installed or the backport is independently verified. An epoch or a large
packaging revision alone never counts as an upstream fix. Version naming is not
proof of repository authenticity or package integrity.

Example output (illustrative, not a scan of your host):

```text
[UPDATE] php8.2-fpm  installed=8.2.34-1~deb12u1
  CVE-2026-109618: UPDATE — Debian package version below 8.2.35-1~deb12u1
  CVE-2026-109619: UPDATE — Debian package version below 8.2.35-1~deb12u1
  Candidate: 8.2.35-1~deb12u1
    CVE-2026-109618: FIXED — Debian package version >= 8.2.35-1~deb12u1
    CVE-2026-109619: FIXED — Debian package version >= 8.2.35-1~deb12u1
```

If APT offers a newer fixed candidate, the report prints a simulation command and
an update command for eligible packages. **Neither is executed.** Held packages
are identified and excluded from the suggested command. Dependencies and holds
can still affect the full transaction: review the simulation before proceeding.

## JSON reports and exit codes

```sh
sudo python3 check-php2shell.py --format json > report.json
# Capture this immediately: a review finding intentionally produces exit code 2.
result=$?
printf 'Checker exit code: %s\n' "$result"
```

JSON stdout contains exactly one document, including on operational errors. It
includes `schema_version`, `tool_version`, per-CVE results, per-package installed
and candidate results, process evidence, coverage gaps and suggested command
argument arrays. See [the report contract](docs/report-format.md).

| Code | Meaning |
| --- | --- |
| `0` | No update/restart or unresolved finding within the implemented checks. This is not a whole-host safety verdict. |
| `1` | An update or restart is required, with no unresolved findings. |
| `2` | Manual review, unknown findings, incomplete audit or execution error. Takes precedence over `1`. |

**In v0.3.0, every completed audit includes `CVE-2026-115560: REVIEW`, so its overall
exit code is 2.** The tool does not inspect the configuration/application conditions
needed to resolve that advisory. An operational error also returns 2, with an
`errors` array explaining the failure.

For automation, use `summary.package_exit_code` (PHP packages),
`summary.process_exit_code` (PHP processes) and `summary.brotli_exit_code`
for independent component checks, and retain `review_required` in alerts.
`updates_required` (PHP or Brotli) and `restart_required` preserve positive findings even
when the overall result is incomplete. A package result of 0 does not resolve the
supplemental advisory. Text output is for humans; JSON schema version 1.1 is the
machine-readable interface.

## Brotli / CVE-2026-111497

The decoder flaw associated with Node2Shell is in the Brotli library. This check
inventories dpkg packages from source package `brotli`, including `libbrotli1`,
`brotli`, `python3-brotli` and `libbrotli-dev`. It assesses source-version metadata;
it does not establish whether a particular binary contains or uses the decoder.
Recognized Brotli binary names with a different source package remain `UNKNOWN`.

At the **2026-10-23** rule review, the [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-111497)
listed `1.0.9-2` in Debian 12 and `1.1.0-2` in Debian 13 as affected, with no fixed
Debian package version recorded. These exact source versions (and binary rebuild
suffixes) produce `UPDATE`. A newer revision with the same old upstream version
remains `UNKNOWN` until its backport is verified; the checker does not guess a
future Debian security-update version.

Upstream fixed thresholds are **1.0.10**, **1.1.1** and **1.2.1**, each within its
own mapped 1.0/1.1/1.2 branch. Stable version metadata meeting the applicable
threshold produces `FIXED`; prereleases, ambiguous suffixes and unmapped branches
remain `UNKNOWN`. Version metadata does not establish package authenticity.

JSON keeps this component in `brotli`, separate from the PHP-only `packages` list.
It contains installed/candidate per-CVE results, holds, counts, its exit code and
eligible upgrade packages. `cves["CVE-2026-111497"]` contains its aggregate finding.
An affected installed library may have no fixed APT candidate: `UPDATE` still
requires attention, but no update command is suggested as a fix unless the
candidate is classified `FIXED`, is newer and is not held.

**Application reachability is not checked.** PHP/cURL or other software could use
the decoder when processing untrusted Brotli data, but package presence alone does
not demonstrate this path or a working exploit. Debian's Node.js uses the system
Brotli library; official Node.js builds and other applications can bundle their
own copy, which this dpkg audit does not inventory. `NOT_INSTALLED` only describes
the matching dpkg inventory. `--scan-root` discovers PHP runtimes, not custom Brotli
copies. The PHP process scan does not inspect loaded Brotli libraries or identify
all consumers needing restart after a Brotli update. Rebuild/redeploy embedded
copies and restart affected consumers as appropriate to their vendor guidance.

## Running-process checks

The checker reads visible `/proc/<pid>/stat`, `comm`, `exe`, `maps`, namespace/root
metadata and, when available, `cgroup`. It recognizes common PHP/FPM/CGI/LiteSpeed/
FrankenPHP executable names, Apache processes and `libphp*.so` mappings in other
processes.

- `RESTART_REQUIRED`: deleted executable/PHP module or a device/inode mismatch
  with the corresponding file on disk. This is restart evidence, not proof of a
  particular runtime CVE or compromise.
- `NO_STALE_FILES_FOUND`: no supported stale-file evidence found in that process.
  Its loaded PHP version and integrity are not verified.
- `NO_PHP_MAPPING`: an Apache process has no recognized PHP module mapping; it
  might still proxy requests to a separate FPM service.
- `UNKNOWN`: permissions, a foreign namespace/root or another inspection gap
  prevent a complete assessment.

Records include PID, process start time, a service hint when available, evidence
and errors. Processes that exit during the snapshot are counted; detected PID
reuse is reported as incomplete. Command arguments, environments, memory contents
and application data are not read. Containers/chroots are not entered or audited.
Do not interpret the absence of stale files as proof that every worker is patched.

## PHP advisory: 23 October 2026

PHP published an [informational session upload progress advisory](https://www.php.net/archive/2026.php)
for **CVE-2026-115560**. It describes a conditional scenario combining enabled upload
progress, a configured `php_binary` or `php_serialize` session serializer, and an
application switching to `php` at runtime before `session_start()`.

PHP recommends `session.upload_progress.enabled=0` until the next regular bugfix
release. Apply the mitigation in the effective web SAPI configuration before
request parsing, then restart affected workers. Do not rely on runtime `ini_set()`
or FPM `.user.ini` for this setting. See the linked PHP advisory and its original
CVE-2026-109619 guidance.

The checker displays this notice but **does not inspect effective configuration or
application behavior**, and does not invent a fixed-version threshold. Enabled
upload progress alone is not evidence of vulnerability. `FIXED` for the two original
CVEs does not establish remediation of this separate advisory.

## Fixed versions and sources

Rules verified on **2026-10-23**. They are embedded in the script and are not
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
- [Debian CVE-2026-111497 (Brotli)](https://security-tracker.debian.org/tracker/CVE-2026-111497)
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
- File contents and loaded runtime versions are not verified. Procfs inspection
  detects specific stale-file evidence only. Restart affected PHP-FPM, Apache
  mod_php and long-running workers after updating, then check your sites.
- Third-party extensions have their own version numbers and are not compared to
  PHP engine thresholds. The separate Brotli check assesses dpkg source versions;
  other third-party extension vulnerabilities are outside scope.
- APT candidate information can be stale. Refresh indexes separately and resolve
  any `apt update` errors before relying on the suggested upgrade plan.
- A `FIXED` result does not establish that a host has never been compromised.

## Development and testing

```sh
python3 -m unittest discover -s tests -v
```

Fixture tests run without Debian. On Debian, additional tests use real
`dpkg --compare-versions` to cover release boundaries, prereleases, epochs and
packaging revisions. Linux tests also exercise an actual deleted executable via
procfs. [GitHub Actions](https://github.com/toxy4ny/php2shell-checker/actions/workflows/test.yml)
runs the test suite on both Debian releases, including text and JSON smoke checks
with PHP and Brotli packages installed, on pushes, pull requests and manual workflow runs. Check the
workflow run for the relevant commit or pull request when reviewing changes.

GitLab is currently a source and release mirror. Its CI pipelines are disabled
while GitLab-hosted CI requires account verification. Historical failed GitLab
pipelines with an identity-verification error did not execute the tests; use
GitHub Actions for the project's test status. See [the changelog](CHANGELOG.md).

For changes to version rules, include a primary vendor advisory and a regression
test. Please redact hostnames and sensitive paths from bug reports. Do not include
credentials or production configuration dumps.

## License

MIT. Copyright (c) 2026 toxy4ny with Love.
