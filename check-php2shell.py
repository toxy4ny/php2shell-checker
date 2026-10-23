#!/usr/bin/env python3
"""Read-only PHP2Shell package audit for Debian 12/13; Python 3 standard library.

Rules verified 2026-10-22:
https://security-tracker.debian.org/tracker/CVE-2026-109618
https://security-tracker.debian.org/tracker/CVE-2026-109619
https://www.php.net/archive/2026.php

Exit codes: 0 = all discovered PHP core packages meet fixed release thresholds;
1 = packages requiring an update; 2 = unknown/incomplete audit (takes precedence).
No exit code certifies every website, container or running worker as patched.
"""

import argparse
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


def classify(source, version):
    """Return status, explanation. Never infer a backport from a large epoch/revision."""
    without_epoch = version.split(":", 1)[-1]
    upstream = without_epoch.rsplit("-", 1)[0]
    match = re.match(r"^(\d+\.\d+)\.\d+", upstream)
    if not match or match[1] not in FIXED:
        return "UNKNOWN", "no rule for this branch; consult the vendor advisory"
    branch = match[1]
    if source != "php" + branch:
        return "UNKNOWN", "source package branch does not match the version"
    # Limit Debian-specific assertions to recognizable stable-update package versions.
    suite = {"php8.2": "12", "php8.4": "13"}.get(source)
    official_style = suite and re.fullmatch(
        r"\d+\.\d+\.\d+-\d+~deb" + suite + r"u\d+(?:\+b\d+)?", without_epoch)
    if official_style:
        threshold = DEBIAN_FIXED[source]
        if ge(without_epoch, threshold):
            return "FIXED", "Debian package version >= " + threshold
        return "UPDATE", "Debian package version below " + threshold
    if ge(upstream, FIXED[branch]):
        return "FIXED", "upstream version >= " + FIXED[branch]
    return "UNKNOWN", "below " + FIXED[branch] + "; vendor backport not verified"


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
        if CORE_SOURCE.fullmatch(source) or CORE_BINARY.fullmatch(bare):
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


def main():
    parser = argparse.ArgumentParser(description="Read-only PHP2Shell package audit for Debian 12 and 13")
    parser.add_argument("--scan-root", action="append", default=[], metavar="DIR",
                        help="additional directory to search for unassessed PHP runtimes; repeatable")
    args = parser.parse_args()
    for executable in ("dpkg", "dpkg-query", "apt-cache", "apt-mark"):
        if not shutil.which(executable):
            raise RuntimeError("Missing command: " + executable + "; Debian 12 or 13 is required")
    os_release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip('"')
    if os_release.get("ID") != "debian" or os_release.get("VERSION_ID") not in ("12", "13"):
        raise RuntimeError("This script supports Debian 12 and 13")

    print("PHP2Shell: CVE-2026-109618 / CVE-2026-109619")
    print("System:", os_release.get("PRETTY_NAME", "Debian"))
    print("Rules verified: 2026-10-22. Package-version audit; no exploit attempts.")
    print("APT uses local indexes. Run sudo apt update separately to refresh candidate versions.")
    print("FIXED = meets patched version threshold; UPDATE = update required; UNKNOWN = unverified.\n")
    rows = inventory()
    hold_result = run(["apt-mark", "showhold"])
    if hold_result.returncode:
        raise RuntimeError("Could not list held packages")
    holds = set(hold_result.stdout.splitlines())
    available = candidates([row[1] for row in rows]) if rows else {}
    unknown, needs_update = not bool(rows), False
    recommended = []
    counts = {"FIXED": 0, "UPDATE": 0, "UNKNOWN": 0}
    if not rows:
        print("No PHP core packages found in dpkg. This does not prove PHP is absent from this host.")
    for state, name, version, source, source_version in rows:
        status, reason = classify(source, source_version)
        if state != "installed":
            status, reason = "UNKNOWN", "incomplete dpkg installation: " + state
        counts[status] += 1
        unknown |= status == "UNKNOWN"
        needs_update |= status == "UPDATE"
        held = name in holds or name.split(":")[0] in holds
        print(f"[{status}] {name}  installed={version}" + ("  HOLD" if held else ""))
        print(f"  {reason}; source={source} ({source_version})")
        candidate = available[name]
        if candidate == "(none)":
            print("  Candidate: unavailable; check repositories and APT indexes.")
        else:
            candidate_status, candidate_reason = classify(source, candidate)
            print(f"  Candidate: {candidate} [{candidate_status}] — {candidate_reason}")
            if status != "FIXED" and candidate_status == "FIXED" and ge(candidate, version) and candidate != version:
                if held:
                    print("  A patched candidate is available, but HOLD blocks a normal update.")
                else:
                    recommended.append(name)
            elif status != "FIXED":
                print("  No automatically verified patched upgrade is available.")
        if status != "FIXED" and source_version.split(":")[-1].startswith(("5.", "7.", "8.0.", "8.1.")):
            print("  Legacy branch: obtain a verified vendor backport or migrate to supported PHP.")

    roots = ["/usr/bin", "/usr/sbin", "/usr/lib/cgi-bin", "/usr/lib/apache2/modules",
             "/usr/local", "/opt", *args.scan_root]
    print("\nSearch for unassessed PHP runtimes:", ", ".join(roots))
    extra, scan_errors = extra_runtimes(roots, {row[1].split(":")[0] for row in rows})
    for root in args.scan_root:
        if not os.path.isdir(root):
            scan_errors.append("Requested scan root is not an accessible directory: " + root)
    for path in extra:
        print("[UNKNOWN] outside assessed PHP packages:", path)
    for error in scan_errors:
        print("[UNKNOWN] incomplete scan:", error)
    unknown |= bool(extra or scan_errors)
    if not extra and not scan_errors:
        print("No unassessed PHP runtime with a recognized filename found in the scanned directories.")
    print("Directory symlinks are not traversed; pass their target paths using --scan-root.")
    print("\nPHP core package totals:", ", ".join(f"{key}={value}" for key, value in counts.items()))
    if recommended:
        print("\nAPT offers a patched candidate for these packages (commands NOT executed):")
        print(shlex.join(["sudo", "apt-get", "-s", "install", "--only-upgrade", *recommended]))
        print("After reviewing the simulated plan:")
        print(shlex.join(["sudo", "apt-get", "install", "--only-upgrade", *recommended]))
    if unknown:
        print("\nResult: INCOMPLETE / UNKNOWN findings. PHP2Shell remediation cannot be confirmed.")
    elif needs_update:
        print("\nResult: PHP PACKAGE UPDATES REQUIRED.")
    else:
        print("\nResult: discovered PHP core packages meet patched version thresholds.")
    print("\nScope and limitations:")
    print("- Containers, chroots, custom/renamed builds and application code are not audited.")
    print("- Third-party extensions have independent versions; these are not PHP engine versions.")
    print("- FIXED refers to package metadata, not running processes or file integrity.")
    print("- After updating, restart every affected PHP-FPM, Apache mod_php and long-running PHP worker.")
    print("- Review why a package is held before removing HOLD; this script never removes holds.")
    return 2 if unknown else 1 if needs_update else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        sys.exit(2)
