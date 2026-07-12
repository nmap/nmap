# Linux packaging for Zenmap Native

This directory mirrors the packaging style used elsewhere in the nmap tree:

- **RPM:** `zenmap-native.spec.in` at the repository root, like `zenmap.spec.in`
- **Autotools:** `configure.ac` + `Makefile.in` install targets, like classic Zenmap
- **Debian:** `packaging/debian/` overlay for `.deb` builds
- **Arch:** `packaging/arch/PKGBUILD`

## Autotools install

```bash
./configure
make build-zenmap-native
sudo make install-zenmap-native
```

Or install everything, including native Zenmap:

```bash
./configure
make
sudo make install
```

Disable native Zenmap while keeping classic Zenmap:

```bash
./configure --without-zenmap-native
```

## RPM

```bash
./packaging/build-zenmap-native-rpm.sh
```

Artifacts land in `packaging/rpm-build/RPMS/`.

## Debian / Kali / Ubuntu

```bash
sudo apt install debhelper dh-python python3-build python3-wheel devscripts
./packaging/build-zenmap-native-deb.sh
```

Packages are written to `packaging/deb-build/`.

## Arch Linux

```bash
./packaging/build-zenmap-native-arch.sh
```

Or copy `packaging/arch/PKGBUILD` into an `nmap-${pkgver}.tar.gz` source tree and run `makepkg -sf`.

## Package contents

Installed files match the classic Zenmap RPM layout:

| Path | Purpose |
|------|---------|
| `/usr/bin/zenmap-native` | GUI launcher |
| `/usr/share/applications/org.nmap.ZenmapNativeLinux.desktop` | Desktop entry |
| `/usr/share/icons/hicolor/256x256/apps/zenmap.png` | Application icon |
| `/usr/share/man/man1/zenmap-native.1` | Man page |
| Python site-packages `zenmap.linux*` | Application code |

## Dependencies

- `nmap`
- `python3`
- `python3-gobject` / `PyGObject`
- `gtk4`
- `libadwaita`
- `polkit` / `pkexec`

Classic GTK3 `zenmap` and native GTK4 `zenmap-native` can be installed side by side.
