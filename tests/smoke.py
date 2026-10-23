"""Exercise real dpkg/APT inventory with PHP installed; mirror patch state may vary."""
from pathlib import Path
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
