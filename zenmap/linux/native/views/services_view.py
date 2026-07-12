"""Services table view."""

from __future__ import annotations

import gi

gi.require_version("Gio", "2.0")
gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Gio, Gdk, Gtk

from ..gobject_models import PortRow
from ..models import ScannedHost, ScannedPort
from ..results_filtering import filter_ports, service_ports
from .column_table import build_column_view
from .common import empty_state, filter_bar, section_header


class ServicesView(Gtk.Box):
    def __init__(self, on_show_host_details) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._on_show_host_details = on_show_host_details
        self._hosts: list[ScannedHost] = []
        self._filter_text = ""
        self._store = Gio.ListStore.new(PortRow)
        self._table, self._selection = build_column_view(
            self._store,
            [
                ("Host", "host"),
                ("Service", "service"),
                ("Version", "version"),
                ("Port", "port"),
                ("State", "state"),
            ],
        )
        self._empty = empty_state("Run a service detection scan to populate service results.")
        self._stack = Gtk.Stack()
        self._stack.set_vexpand(True)
        self._stack.add_named(self._table, "table")
        self._stack.add_named(self._empty, "empty")

        self._count_label = Gtk.Label(label="0 services", xalign=1)
        header = section_header("Services")
        header.append(self._count_label)
        self.append(header)
        self.append(filter_bar("Filter service results", self._set_filter))

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_margin_start(12)
        actions.set_margin_end(12)
        actions.set_margin_bottom(8)
        self._details_button = Gtk.Button(label="Host Details")
        self._details_button.connect("clicked", lambda *_: self._show_host_details())
        self._copy_button = Gtk.Button(label="Copy Service")
        self._copy_button.connect("clicked", lambda *_: self._copy_service())
        actions.append(self._details_button)
        actions.append(self._copy_button)
        self.append(actions)

        self._selection.connect("notify::selected", self._on_selection_changed)
        self.append(self._stack)

    def set_hosts(self, hosts: list[ScannedHost]) -> None:
        self._hosts = hosts
        self._refresh()

    def selected_port(self) -> ScannedPort | None:
        position = self._selection.get_selected()
        if position == Gtk.INVALID_LIST_POSITION:
            return None
        row = self._store.get_item(position)
        return row.scanned_port if row is not None else None

    def _set_filter(self, text: str) -> None:
        self._filter_text = text
        self._refresh()

    def _refresh(self) -> None:
        ports = service_ports(self._hosts)
        filtered = filter_ports(ports, self._filter_text)
        self._store.remove_all()
        for port in filtered:
            self._store.append(PortRow(port))
        count_text = (
            f"{len(filtered)} of {len(ports)} services"
            if self._filter_text.strip()
            else f"{len(ports)} service result(s)"
        )
        self._count_label.set_label(count_text)
        if not ports:
            self._stack.set_visible_child_name("empty")
            self._empty.get_first_child().set_label(
                "Run a service detection scan to populate service results."
            )
        elif not filtered:
            self._stack.set_visible_child_name("empty")
            self._empty.get_first_child().set_label("No services match the current filter.")
        else:
            self._stack.set_visible_child_name("table")
        self._update_buttons()

    def _on_selection_changed(self, *_args) -> None:
        self._update_buttons()

    def _update_buttons(self) -> None:
        has_selection = self.selected_port() is not None
        self._details_button.set_sensitive(has_selection)
        self._copy_button.set_sensitive(has_selection)

    def _show_host_details(self) -> None:
        port = self.selected_port()
        if port is None:
            return
        host = next((item for item in self._hosts if item.address == port.host_address), None)
        if host is not None:
            self._on_show_host_details(host)

    def _copy_service(self) -> None:
        port = self.selected_port()
        if port is None:
            return
        clipboard = Gdk.Display.get_default().get_clipboard()
        clipboard.set(
            f"{port.host_address} {port.port_number}/{port.protocol_name} "
            f"{port.service_name} {port.service_summary}".strip()
        )
