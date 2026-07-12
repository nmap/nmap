"""Application settings view."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gtk

from ..settings_store import AppSettings
from .common import section_header


class SettingsView(Gtk.Box):
    def __init__(self, on_save_settings) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._on_save_settings = on_save_settings

        self.append(section_header("Settings", subtitle="Stored in ~/.config/zenmap-native/settings.json"))

        grid = Gtk.Grid(column_spacing=12, row_spacing=10)
        grid.set_margin_start(12)
        grid.set_margin_end(12)

        self._nmap_entry = Gtk.Entry()
        self._target_entry = Gtk.Entry()
        self._profile_entry = Gtk.Entry()
        self._stats_entry = Gtk.Entry()
        self._verbose_switch = Gtk.Switch()
        self._stats_switch = Gtk.Switch()

        rows = (
            ("Nmap binary", self._nmap_entry),
            ("Default target", self._target_entry),
            ("Default profile name", self._profile_entry),
            ("Stats every value", self._stats_entry),
        )
        for index, (label, widget) in enumerate(rows):
            grid.attach(Gtk.Label(label=label, xalign=0), 0, index, 1, 1)
            grid.attach(widget, 1, index, 1, 1)

        grid.attach(Gtk.Label(label="Auto-add --stats-every", xalign=0), 0, len(rows), 1, 1)
        grid.attach(self._stats_switch, 1, len(rows), 1, 1)
        grid.attach(Gtk.Label(label="Auto-add -v", xalign=0), 0, len(rows) + 1, 1, 1)
        grid.attach(self._verbose_switch, 1, len(rows) + 1, 1, 1)
        self.append(grid)

        save_button = Gtk.Button(label="Save Settings")
        save_button.add_css_class("suggested-action")
        save_button.set_halign(Gtk.Align.START)
        save_button.set_margin_start(12)
        save_button.connect("clicked", lambda *_: self._save())
        self.append(save_button)

    def set_settings(self, settings: AppSettings) -> None:
        self._nmap_entry.set_text(settings.nmap_binary)
        self._target_entry.set_text(settings.default_target)
        self._profile_entry.set_text(settings.default_profile_name)
        self._stats_entry.set_text(settings.stats_every_value)
        self._stats_switch.set_active(settings.auto_add_stats_every)
        self._verbose_switch.set_active(settings.auto_add_verbose)

    def _save(self) -> None:
        settings = AppSettings(
            nmap_binary=self._nmap_entry.get_text().strip() or "nmap",
            default_target=self._target_entry.get_text().strip(),
            default_profile_name=self._profile_entry.get_text().strip() or "Quick Scan",
            stats_every_value=self._stats_entry.get_text().strip() or "1s",
            auto_add_stats_every=self._stats_switch.get_active(),
            auto_add_verbose=self._verbose_switch.get_active(),
        )
        self._on_save_settings(settings)
