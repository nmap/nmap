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
