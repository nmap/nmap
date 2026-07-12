"""Hosts table view."""

from __future__ import annotations

import gi

gi.require_version("Gio", "2.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Gio, Gdk, Gtk

from ..gobject_models import HostRow
from ..models import ScannedHost
from ..results_filtering import filter_hosts
from .column_table import build_column_view
from .common import empty_state, filter_bar, section_header


class HostsView(Gtk.Box):
    def __init__(self, on_show_details) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._on_show_details = on_show_details
        self._hosts: list[ScannedHost] = []
        self._filter_text = ""
        self._store = Gio.ListStore.new(HostRow)
        self._table, self._selection = build_column_view(
            self._store,
            [
                ("Address", "address"),
                ("Hostname", "hostname"),
                ("Status", "status"),
                ("Open Ports", "open_ports"),
            ],
        )
        self._empty = empty_state("Run a scan to populate discovered hosts.")
        self._stack = Gtk.Stack()
        self._stack.set_vexpand(True)
        self._stack.add_named(self._table, "table")
        self._stack.add_named(self._empty, "empty")

        self._count_label = Gtk.Label(label="0 hosts", xalign=1)
        header = section_header("Hosts")
        header.append(self._count_label)
        self.append(header)
        self.append(
            filter_bar(
                "Filter results by host, port, state, service, or version",
                self._set_filter,
            )
        )

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_margin_start(12)
        actions.set_margin_end(12)
        actions.set_margin_bottom(8)
        self._details_button = Gtk.Button(label="Show Details")
        self._details_button.connect("clicked", lambda *_: self._show_details())
        self._copy_button = Gtk.Button(label="Copy Address")
        self._copy_button.connect("clicked", lambda *_: self._copy_address())
        actions.append(self._details_button)
        actions.append(self._copy_button)
        self.append(actions)

        self._selection.connect("notify::selected", self._on_selection_changed)
        self.append(self._stack)

    def set_hosts(self, hosts: list[ScannedHost]) -> None:
        self._hosts = hosts
        self._refresh()

    def select_host(self, host: ScannedHost | None) -> None:
        if host is None:
            return
        for index in range(self._store.get_n_items()):
            row = self._store.get_item(index)
            if row.host.address == host.address:
                self._selection.set_selected(index)
                return

    def selected_host(self) -> ScannedHost | None:
        position = self._selection.get_selected()
        if position == Gtk.INVALID_LIST_POSITION:
            return None
        row = self._store.get_item(position)
        return row.host if row is not None else None

    def _set_filter(self, text: str) -> None:
        self._filter_text = text
        self._refresh()

    def _refresh(self) -> None:
        filtered = filter_hosts(self._hosts, self._filter_text)
        self._store.remove_all()
        for host in filtered:
            self._store.append(HostRow(host))
        count_text = (
            f"{len(filtered)} of {len(self._hosts)} hosts"
            if self._filter_text.strip()
            else f"{len(self._hosts)} host(s)"
        )
        self._count_label.set_label(count_text)
        if not self._hosts:
            self._stack.set_visible_child_name("empty")
            self._empty.get_first_child().set_label("Run a scan to populate discovered hosts.")
        elif not filtered:
            self._stack.set_visible_child_name("empty")
            self._empty.get_first_child().set_label("No hosts match the current filter.")
        else:
            self._stack.set_visible_child_name("table")
        self._update_buttons()

    def _on_selection_changed(self, *_args) -> None:
        self._update_buttons()

    def _update_buttons(self) -> None:
        has_selection = self.selected_host() is not None
        self._details_button.set_sensitive(has_selection)
        self._copy_button.set_sensitive(has_selection)

    def _show_details(self) -> None:
        host = self.selected_host()
        if host is not None:
            self._on_show_details(host)

    def _copy_address(self) -> None:
        host = self.selected_host()
        if host is None:
            return
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(host.address)
