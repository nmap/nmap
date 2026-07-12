# Native Linux Zenmap (GTK 4 + Libadwaita)

This directory contains a native Linux GUI for Zenmap, parallel to the SwiftUI
app in `zenmap/macos/native/`.

The stack is intentionally Qt-free:

- **GTK 4**
- **Libadwaita**
- **PyGObject**

## Feature parity

- Native GNOME-style shell with sidebar navigation
- Target/profile/arguments scan form with live command preview
- Live nmap stdout output and progress footer
- Hosts, ports, services, and details result views with filtering
- Topology map for the current scan
- Saved scan history under XDG config
- Scan comparison between saved scans
- Custom profile add/edit/delete/import/export
- Settings for nmap path, defaults, and scan output behavior
- `pkexec` privileged scan runner for root-only nmap options

## Dependencies

### Fedora

```bash
sudo dnf install nmap python3-gobject gtk4 libadwaita polkit
```

### Ubuntu / Debian

```bash
sudo apt install nmap python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 pkexec
```

### Arch

```bash
sudo pacman -S nmap python-gobject gtk4 libadwaita polkit
```

## Run from source

```bash
chmod +x zenmap/linux/zenmap-native
./zenmap/linux/zenmap-native
```

Or directly:

```bash
export PYTHONPATH="/path/to/nmap"
python3 -m zenmap.linux.native.app
```

## Storage layout

Zenmap stores Linux-native state under XDG config:

```text
~/.config/zenmap-native/
  settings.json
  custom-profiles.json
  saved-scans.json
  saved-scans/*.xml
```

## Architecture

```text
zenmap/linux/native/
  models.py              # platform-neutral scan/session models
  scan_execution.py      # user + pkexec scan runners
  privileged_runner.py   # root wrapper for privileged scans
  scan_history_store.py  # saved scans
  profile_storage.py     # custom profiles
  settings_store.py      # app settings
  scan_comparison.py     # diff engine
  scan_progress.py       # progress parsing
  main_window.py         # GTK4/Libadwaita shell
  views/                 # per-tab UI
```

## Desktop entry

```bash
cp zenmap/linux/data/org.nmap.ZenmapNativeLinux.desktop ~/.local/share/applications/
chmod +x zenmap/linux/zenmap-native
```

Edit the desktop file `Exec=` line if `zenmap-native` is not on your `PATH`.

## Packaging

Linux packages follow the same layout as classic `zenmap` RPM packaging. See
`packaging/README.md` at the repository root for `.deb`, `.rpm`, and Arch
build instructions, plus autotools `make install-zenmap-native`.

## Privileged scans

Scans that need raw sockets (`-sS`, `-sU`, `-A`, etc.) trigger a Zenmap
confirmation dialog first, then `pkexec` launches a root wrapper around nmap.
Stopping a privileged scan uses the same wrapper PID tracking approach as the
macOS native app.
