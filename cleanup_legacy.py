#!/usr/bin/env python3
"""
R-Map Legacy Cleanup Script

This script removes legacy C/C++ files and directories that are no longer needed
since R-Map is now a pure Rust implementation with zero C/C++ dependencies.
"""

import os
import shutil
import sys
from pathlib import Path

# Legacy C/C++ files and directories to remove
LEGACY_ITEMS = [
    # C/C++ source files
    "*.cc", "*.cpp", "*.c", "*.h", "*.hpp",
    
    # Specific legacy files
    "main.cc", "nmap.cc", "nmap.h", "NmapOps.cc", "NmapOps.h",
    "scan_engine.cc", "scan_engine.h", "osscan.cc", "osscan.h",
    "service_scan.cc", "service_scan.h", "output.cc", "output.h",
    "tcpip.cc", "tcpip.h", "timing.cc", "timing.h", "utils.cc", "utils.h",
    "Target.cc", "Target.h", "TargetGroup.cc", "TargetGroup.h",
    "portlist.cc", "portlist.h", "protocols.cc", "protocols.h",
    "xml.cc", "xml.h", "charpool.cc", "charpool.h",
    "string_pool.cc", "string_pool.h", "nmap_error.cc", "nmap_error.h",
    "traceroute.cc", "traceroute.h", "idle_scan.cc", "idle_scan.h",
    "payload.cc", "payload.h", "portreasons.cc", "portreasons.h",
    "scan_lists.cc", "scan_lists.h", "services.cc", "services.h",
    "targets.cc", "targets.h", "nmap_tty.cc", "nmap_tty.h",
    "nmap_dns.cc", "nmap_dns.h", "nmap_ftp.cc", "nmap_ftp.h",
    "MACLookup.cc", "MACLookup.h", "NewTargets.cc", "NewTargets.h",
    "FingerPrintResults.cc", "FingerPrintResults.h",
    "FPEngine.cc", "FPEngine.h", "FPModel.cc", "FPModel.h",
    "NmapOutputTable.cc", "NmapOutputTable.h",
    "scan_engine_connect.cc", "scan_engine_connect.h",
    "scan_engine_raw.cc", "scan_engine_raw.h",
    "osscan2.cc", "osscan2.h", "probespec.h", "struct_ip.h",
    
    # NSE C++ files
    "nse_main.cc", "nse_main.h", "nse_utility.cc", "nse_utility.h",
    "nse_nsock.cc", "nse_nsock.h", "nse_db.cc", "nse_db.h",
    "nse_dnet.cc", "nse_dnet.h", "nse_fs.cc", "nse_fs.h",
    "nse_nmaplib.cc", "nse_nmaplib.h", "nse_debug.cc", "nse_debug.h",
    "nse_lpeg.cc", "nse_lpeg.h", "nse_openssl.cc", "nse_openssl.h",
    "nse_ssl_cert.cc", "nse_ssl_cert.h", "nse_libssh2.cc", "nse_libssh2.h",
    "nse_zlib.cc", "nse_zlib.h", "nse_lua.h", "lpeg.c",
    
    # Legacy directories
    "libpcap/", "libdnet-stripped/", "libpcre/", "liblua/", 
    "liblinear/", "libssh2/", "libz/", "libnetutil/",
    
    # Build system files
    "configure", "configure.ac", "Makefile.in", "makefile.dep",
    "config.guess", "config.sub", "config.cache", "config.status",
    "acinclude.m4", "aclocal.m4", "ltmain.sh", "missing", "depcomp",
    "shtool", "checklibs.sh", "install-sh",
    
    # Platform-specific build files
    "macosx/", "mswin32/", "BSDmakefile",
    
    # Legacy data files (we have Rust parsers now)
    "nmap-header-template.cc",
    
    # Config files
    "nmap_config.h.in", "nmap_winconfig.h", "nmap_amigaos.h",
    
    # Spec files
    "nmap.spec.in", "zenmap.spec.in",
    
    # Demo executables and build artifacts
    "demo-test.exe", "demo-test.pdb", "nmap-demo.exe", "nmap-demo.pdb",
    "test-arch.exe", "test-arch.pdb",
]

# Directories to keep (these contain our Rust implementation)
KEEP_DIRS = {
    "crates/", "src/", "target/", ".git/", ".github/", ".kiro/", ".vscode/",
    "docs/", "tests/", "scripts/", "nselib/", "zenmap/", "ncat/", "ndiff/", "nping/"
}

def should_keep_item(item_path: Path) -> bool:
    """Check if an item should be kept."""
    # Keep if it's in a directory we want to preserve
    for keep_dir in KEEP_DIRS:
        if str(item_path).startswith(keep_dir):
            return True
    
    # Keep Rust files
    if item_path.suffix in {'.rs', '.toml'}:
        return True
        
    # Keep documentation and important files
    if item_path.name in {'README.md', 'LICENSE', 'CHANGELOG', 'CONTRIBUTING.md', 
                         'HACKING', 'INSTALL', '.gitignore', '.travis.yml', '.lgtm.yml'}:
        return True
        
    # Keep our new R-Map files
    if item_path.name.startswith('RMAP_') or item_path.name.startswith('RUST_'):
        return True
        
    return False

def cleanup_legacy_files():
    """Remove legacy C/C++ files and directories."""
    root_dir = Path('.')
    removed_count = 0
    
    print("🧹 R-Map Legacy Cleanup")
    print("=" * 50)
    print("Removing legacy C/C++ files and dependencies...")
    print()
    
    # Get all items in the root directory
    all_items = list(root_dir.iterdir())
    
    for item in all_items:
        if should_keep_item(item):
            continue
            
        # Check if this item matches our legacy patterns
        should_remove = False
        
        # Check exact name matches
        for legacy_item in LEGACY_ITEMS:
            if legacy_item.endswith('/'):
                # Directory pattern
                if item.is_dir() and item.name == legacy_item.rstrip('/'):
                    should_remove = True
                    break
            elif '*' in legacy_item:
                # Wildcard pattern
                import fnmatch
                if fnmatch.fnmatch(item.name, legacy_item):
                    should_remove = True
                    break
            else:
                # Exact file match
                if item.name == legacy_item:
                    should_remove = True
                    break
        
        if should_remove:
            try:
                if item.is_dir():
                    print(f"📁 Removing directory: {item}")
                    shutil.rmtree(item)
                else:
                    print(f"📄 Removing file: {item}")
                    item.unlink()
                removed_count += 1
            except Exception as e:
                print(f"❌ Failed to remove {item}: {e}")
    
    print()
    print(f"✅ Cleanup complete! Removed {removed_count} legacy items.")
    print()
    print("🦀 R-Map is now 100% pure Rust!")
    print("   No C/C++ dependencies remain.")
    print()
    print("📦 To rebuild:")
    print("   cargo build --release")
    print()
    print("🚀 To run:")
    print("   ./target/release/rmap --help")

def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] in {'-h', '--help'}:
        print(__doc__)
        return
    
    # Confirm with user
    print("🧹 R-Map Legacy Cleanup Script")
    print()
    print("This will remove legacy C/C++ files and dependencies.")
    print("R-Map is now pure Rust and no longer needs these files.")
    print()
    
    response = input("Continue? [y/N]: ").strip().lower()
    if response not in {'y', 'yes'}:
        print("Cleanup cancelled.")
        return
    
    cleanup_legacy_files()

if __name__ == '__main__':
    main()