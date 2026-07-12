#!/usr/bin/env bash
set -euo pipefail

# End-to-end verification for Debian/Kali systems.
# Run from the repository root on a Kali (or Debian/Ubuntu) machine.

if [[ "${EUID}" -eq 0 ]]; then
  echo "Run this script as a normal user (it will use sudo for package installs)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "==> Installing Kali/Debian dependencies"
sudo apt update
sudo apt install -y \
  nmap \
  python3 \
  python3-gi \
  gir1.2-gtk-4.0 \
  gir1.2-adw-1 \
  libadwaita-1-0 \
  policykit-1 \
  git

echo "==> Running Linux native smoke test"
"${SCRIPT_DIR}/verify-linux-native.sh"

echo "==> Checking nmap and pkexec"
command -v nmap
command -v pkexec
nmap --version | head -2

echo "==> Quick localhost ping scan (non-privileged)"
export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"
SCAN_XML="$(mktemp /tmp/zenmap-kali-test-XXXXXX.xml)"
nmap -sn -oX "${SCAN_XML}" 127.0.0.1 >/dev/null
python3 - <<PY
from zenmap.linux.native.xml_parsing import parse_nmap_xml
hosts = parse_nmap_xml("${SCAN_XML}")
print(f"Parsed {len(hosts)} host(s) from localhost ping scan")
assert hosts, "expected at least one parsed host"
print("XML parsing check passed.")
PY
rm -f "${SCAN_XML}"

cat <<EOF

Kali/Debian verification passed.

Next manual GUI check (requires a desktop session):
  cd ${REPO_ROOT}
  ./zenmap/linux/zenmap-native

Suggested GUI smoke test:
  1. Target: scanme.nmap.org
  2. Profile: Quick Scan
  3. Confirm Output, Hosts, and Saved Scans tabs populate

Privileged scan check:
  1. Profile: Intense Scan + UDP
  2. Approve the pkexec prompt
  3. Confirm scan output streams and completes

EOF
