"""Saved scan history view."""

from __future__ import annotations

import gi

gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Gio, Gtk

from ..gobject_models import SavedScanRow
from ..models import SavedScan
from ..results_filtering import filter_saved_scans
from .column_table import build_column_view
from .common import empty_state, filter_bar, section_header


class SavedScansView(Gtk.Box):
    def __init__(
        self,
        on_load_scan,
        on_open_xml,
        on_import_xml,
        on_delete_scan,
        on_clear_scans,
        on_save_metadata,
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._on_load_scan = on_load_scan
        self._on_open_xml = on_open_xml
        self._on_import_xml = on_import_xml
        self._on_delete_scan = on_delete_scan
        self._on_clear_scans = on_clear_scans
        self._on_save_metadata = on_save_metadata
        self._scans: list[SavedScan] = []
        self._filter_text = ""
        self._store = Gio.ListStore.new(SavedScanRow)
        self._table, self._selection = build_column_view(
            self._store,
            [
                ("Title", "title"),
                ("Scanned At", "scanned_at"),
                ("Hosts", "hosts"),
                ("Ports", "ports"),
                ("Command", "command"),
            ],
        )
        self._empty = empty_state("Completed scans are saved automatically under XDG config.")
        self._stack = Gtk.Stack()
        self._stack.set_vexpand(True)
        self._stack.add_named(self._table, "table")
        self._stack.add_named(self._empty, "empty")

        self._count_label = Gtk.Label(label="0 scans", xalign=1)
        header = section_header("Saved Scans", subtitle="Stored in ~/.config/zenmap-native/")
        header.append(self._count_label)
        self.append(header)
        self.append(filter_bar("Filter saved scans", self._set_filter))

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_margin_start(12)
        actions.set_margin_end(12)
        actions.set_margin_bottom(8)
        self._load_button = Gtk.Button(label="Load")
        self._open_button = Gtk.Button(label="Open XML")
        self._import_button = Gtk.Button(label="Import XML")
        self._delete_button = Gtk.Button(label="Delete")
        self._clear_button = Gtk.Button(label="Clear All")
        self._load_button.connect("clicked", lambda *_: self._load_selected())
        self._open_button.connect("clicked", lambda *_: self._open_selected())
        self._import_button.connect("clicked", lambda *_: self._on_import_xml())
        self._delete_button.connect("clicked", lambda *_: self._delete_selected())
        self._clear_button.connect("clicked", lambda *_: self._on_clear_scans())
        for button in (
            self._load_button,
            self._open_button,
            self._import_button,
            self._delete_button,
            self._clear_button,
        ):
            actions.append(button)
        self.append(actions)

        self._notes_entry = Gtk.Entry()
        self._notes_entry.set_placeholder_text("Notes")
        self._tags_entry = Gtk.Entry()
        self._tags_entry.set_placeholder_text("Tags")
        metadata = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        metadata.set_margin_start(12)
        metadata.set_margin_end(12)
        metadata.set_margin_bottom(8)
        metadata.append(self._notes_entry)
        metadata.append(self._tags_entry)
        self._save_metadata_button = Gtk.Button(label="Save Metadata")
        self._save_metadata_button.connect("clicked", lambda *_: self._save_metadata())
        metadata.append(self._save_metadata_button)
        self.append(metadata)

        self._selection.connect("notify::selected", self._on_selection_changed)
        self.append(self._stack)

    def set_scans(self, scans: list[SavedScan]) -> None:
        self._scans = scans
        self._refresh()

    def selected_scan(self) -> SavedScan | None:
        position = self._selection.get_selected()
        if position == Gtk.INVALID_LIST_POSITION:
            return None
        row = self._store.get_item(position)
        return row.saved_scan if row is not None else None

    def _set_filter(self, text: str) -> None:
        self._filter_text = text
        self._refresh()

    def _refresh(self) -> None:
        filtered = filter_saved_scans(self._scans, self._filter_text)
        self._store.remove_all()
        for scan in filtered:
            self._store.append(SavedScanRow(scan))
        count_text = (
            f"{len(filtered)} of {len(self._scans)} scans"
            if self._filter_text.strip()
            else f"{len(self._scans)} scan(s)"
        )
        self._count_label.set_label(count_text)
        if not self._scans:
            self._stack.set_visible_child_name("empty")
        elif not filtered:
            self._stack.set_visible_child_name("empty")
            self._empty.get_first_child().set_label("No saved scans match the current filter.")
        else:
            self._stack.set_visible_child_name("table")
        self._on_selection_changed()

    def _on_selection_changed(self, *_args) -> None:
        scan = self.selected_scan()
        has_selection = scan is not None
        self._load_button.set_sensitive(has_selection)
        self._open_button.set_sensitive(has_selection)
        self._delete_button.set_sensitive(has_selection)
        self._save_metadata_button.set_sensitive(has_selection)
        if scan is not None:
            self._notes_entry.set_text(scan.notes)
            self._tags_entry.set_text(scan.tags)
        else:
            self._notes_entry.set_text("")
            self._tags_entry.set_text("")

    def _load_selected(self) -> None:
        scan = self.selected_scan()
        if scan is not None:
            self._on_load_scan(scan)

    def _open_selected(self) -> None:
        scan = self.selected_scan()
        if scan is not None:
            self._on_open_xml(scan)

    def _delete_selected(self) -> None:
        scan = self.selected_scan()
        if scan is not None:
            self._on_delete_scan(scan)

    def _save_metadata(self) -> None:
        scan = self.selected_scan()
        if scan is None:
            return
        self._on_save_metadata(scan, self._notes_entry.get_text(), self._tags_entry.get_text())
