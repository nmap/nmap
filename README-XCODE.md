# Nmap macOS Xcode project

This overlay adds an Xcode project for building a native macOS Zenmap app from an upstream Nmap checkout. The Xcode build delegates the command-line scanner build to the upstream `./configure && make` flow, then bundles the resulting `nmap` binary and runtime data into the app.

## Use

```sh
git clone https://github.com/nmap/nmap.git
cd nmap
# copy this overlay's contents into this directory
open NmapMac.xcodeproj
```

The Xcode build helper scripts run the normal command-line build flow:

```sh
./configure --prefix=/usr/local
make -j$(sysctl -n hw.ncpu)
make install DESTDIR=.xcode-products/nmap-root
```

The `Zenmap` target is a native SwiftUI app. It runs the bundled scanner at `Zenmap.app/Contents/Resources/bin/nmap` and uses bundled runtime data from `Zenmap.app/Contents/Resources/share/nmap`.

## Layout

- `zenmap/macos/native/` contains the native SwiftUI macOS GUI source.
- `xcode/scripts/` contains scripts used directly by Xcode build phases.
- `macosx/` contains macOS release, packaging, installer, and legacy bundling support files.

## Package a portable development app

Build the GUI first, then bundle the Homebrew OpenSSL and libssh2 dylibs into the app:

    bash macosx/package-zenmap-macos.sh

If the script cannot find the built app automatically, pass APP_PATH:

    APP_PATH="/path/to/Zenmap.app" bash macosx/package-zenmap-macos.sh

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
bash macosx/release-nmap-cli-macos.sh
bash macosx/stage-nmap-replacement-root-macos.sh
bash macosx/pkg-nmap-macos.sh
sudo installer -pkg dist/pkg/NmapComplete.pkg -target /
/Applications/nmap.app/Contents/Resources/bin/nmap --version
/Applications/ncat.app/Contents/Resources/bin/ncat --version
/Applications/nping.app/Contents/Resources/bin/nping --version
/usr/local/bin/ndiff -h >/dev/null && echo "ndiff OK"
/Applications/nmap.app/Contents/Resources/bin/nmap -A -T4 -v --stats-every 5s scanme.nmap.org

```

A successful installed scan should load NSE scripts from the bundled /Applications/nmap.app share/nmap directory and complete without NSE load failures.


## Native macOS GUI layout

The `zenmap/macos/native/` directory contains the native SwiftUI macOS GUI target. It is intentionally separate from `zenmap/`, which contains the existing legacy Zenmap Python/GTK frontend.

The Xcode project builds the native GUI and uses `xcode/scripts/build-nmap-macos.sh` to build the Nmap command-line binary from the current source tree. The `xcode/scripts/bundle-nmap-runtime.sh` script then copies the runtime files into the app bundle using an app-local layout:

```text
Zenmap.app/Contents/Resources/bin/nmap
Zenmap.app/Contents/Resources/share/nmap/
```

This keeps the SwiftUI frontend, legacy Zenmap frontend, Nmap command-line source, and macOS app-bundling logic separate.

