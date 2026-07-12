"""GTK application entry point for native Linux Zenmap."""

from __future__ import annotations

import gi

gi.require_version("Adw", "1")
gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, Gio, Gtk

from .main_window import MainWindow


class ZenmapApplication(Adw.Application):
    def __init__(self) -> None:
        super().__init__(
            application_id="org.nmap.ZenmapNativeLinux",
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )

    def do_activate(self) -> None:
        window = self.props.active_window
        if window is None:
            window = MainWindow(self)
        window.present()


def main() -> int:
    Adw.init()
    app = ZenmapApplication()
    return app.run(None)


if __name__ == "__main__":
    raise SystemExit(main())
