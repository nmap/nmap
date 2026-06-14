# Nmap macOS Xcode scaffold

This overlay adds an Xcode project to an upstream Nmap checkout. It does not fork or rewrite Nmap yet; the first target delegates to the upstream `./configure && make` build so we get a known-good native macOS binary before building a deeper GUI integration.

## Use

```sh
git clone https://github.com/nmap/nmap.git
cd nmap
# copy this overlay's contents into this directory
open NmapMac.xcodeproj
```

Build the `NmapCLI` target first. It runs:

```sh
./configure --prefix=/usr/local
make -j$(sysctl -n hw.ncpu)
make install DESTDIR=.xcode-products/nmap-root
```

The `NmapGUI` target is a minimal SwiftUI starter app. In this first scaffold it runs either a bundled `nmap` binary at `NmapGUI.app/Contents/Resources/nmap` or `/usr/local/bin/nmap`.

## Next steps

1. Add an Xcode copy-files phase that copies the just-built `./nmap` into the app bundle resources.
2. Copy Nmap data files into the app bundle and set `NMAPDIR` when launching scans.
3. Replace the simple argument splitter with structured scan options.
4. Add XML output parsing so the GUI renders hosts, ports, services, and scripts natively.
5. Later, consider splitting Nmap internals into a library-style target if the CLI wrapper proves too limiting.

## Package a portable development app

Build the GUI first, then bundle the Homebrew OpenSSL and libssh2 dylibs into the app:

    bash xcode/scripts/package-nmapgui-macos.sh

If the script cannot find the built app automatically, pass APP_PATH:

    APP_PATH="/path/to/NmapGUI.app" bash xcode/scripts/package-nmapgui-macos.sh

This performs development ad-hoc signing. Final external distribution will still need proper Developer ID signing and notarization.

## macOS installer validation

The official-style macOS installer staging flow builds component packages that match the current Nmap macOS installer layout:

- `org.insecure.nmap` installs `/Applications/nmap.app`
- `org.insecure.nmap.ncat` installs `/Applications/ncat.app`
- `org.insecure.nmap.nping` installs `/Applications/nping.app`
- `org.insecure.nmap.ndiff` installs `/usr/local/bin/ndiff`, `/usr/local/bin/ndiff.py`, and the ndiff man page
- `org.insecure.nmap.zenmap` installs `/Applications/Zenmap.app`

Build and install locally:

```sh
bash xcode/scripts/release-nmap-cli-macos.sh
bash xcode/scripts/stage-nmap-replacement-root-macos.sh
bash xcode/scripts/pkg-nmap-macos.sh
sudo installer -pkg dist/pkg/NmapComplete.pkg -target /
/Applications/nmap.app/Contents/Resources/bin/nmap --version
/Applications/ncat.app/Contents/Resources/bin/ncat --version
/Applications/nping.app/Contents/Resources/bin/nping --version
/usr/local/bin/ndiff -h >/dev/null && echo "ndiff OK"
/Applications/nmap.app/Contents/Resources/bin/nmap -A -T4 -v --stats-every 5s scanme.nmap.org

```

A successful installed scan should load NSE scripts from the bundled /Applications/nmap.app share/nmap directory and complete without NSE load failures.
