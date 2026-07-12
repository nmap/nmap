#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

if [[ "$(uname -s)" == "Darwin" ]]; then
  if [[ -d /opt/homebrew/lib/girepository-1.0 ]]; then
    export GI_TYPELIB_PATH="/opt/homebrew/lib/girepository-1.0${GI_TYPELIB_PATH:+:${GI_TYPELIB_PATH}}"
    export DYLD_FALLBACK_LIBRARY_PATH="/opt/homebrew/lib${DYLD_FALLBACK_LIBRARY_PATH:+:${DYLD_FALLBACK_LIBRARY_PATH}}"
  fi
  PYTHON_BIN="${PYTHON_BIN:-/opt/homebrew/bin/python3}"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

echo "Using Python: ${PYTHON_BIN}"
"${PYTHON_BIN}" - <<'PY'
import sys

checks = []

def check(name, fn):
    try:
        fn()
        checks.append((name, True, ""))
    except Exception as exc:
        checks.append((name, False, str(exc)))

check("import gi", lambda: __import__("gi"))
check("gtk/adw", lambda: (
    __import__("gi").require_version("Gtk", "4.0"),
    __import__("gi").require_version("Adw", "1"),
))
check("models", lambda: __import__("zenmap.linux.native.models"))
check("xml parsing", lambda: __import__("zenmap.linux.native.xml_parsing"))
check("scan comparison", lambda: __import__("zenmap.linux.native.scan_comparison"))
check("profile storage", lambda: __import__("zenmap.linux.native.profile_storage"))
check("scan history", lambda: __import__("zenmap.linux.native.scan_history_store"))
check("main window module", lambda: __import__("zenmap.linux.native.main_window"))

from gi.repository import Adw, Gtk
from zenmap.linux.native.app import ZenmapApplication
from zenmap.linux.native.xml_parsing import parse_nmap_xml
from zenmap.linux.native.scan_comparison import compare_scans

sample_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

import tempfile
from pathlib import Path

with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as handle:
    handle.write(sample_xml)
    xml_path = handle.name

hosts = parse_nmap_xml(xml_path)
assert len(hosts) == 1 and hosts[0].address == "127.0.0.1"
comparison = compare_scans(hosts, hosts)
assert comparison.new_hosts == []

app = ZenmapApplication()
assert app.get_application_id() == "org.nmap.ZenmapNativeLinux"

Path(xml_path).unlink(missing_ok=True)
checks.append(("core logic smoke", True, ""))

failed = [item for item in checks if not item[1]]
for name, ok, detail in checks:
    status = "ok" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))

if failed:
    raise SystemExit(1)

print("Linux native smoke test passed.")
PY
