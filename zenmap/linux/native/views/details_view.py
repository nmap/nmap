"""Scan and host details view."""

from __future__ import annotations

import gi

gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Gio, Gtk

from ..gobject_models import PortRow
from ..models import ScannedHost
from ..results_filtering import all_ports
from .column_table import build_column_view
from .common import empty_state, section_header


class DetailsView(Gtk.Box):
    def __init__(self) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._hosts: list[ScannedHost] = []
        self._selected_host: ScannedHost | None = None
        self._status = "Idle"
        self._last_command = ""
        self._exit_status: int | None = None
        self._xml_path = ""
        self._nmap_binary = ""
        self._nmapdir = ""

        self.append(section_header("Scan Details"))

        metrics = Gtk.Grid(column_spacing=12, row_spacing=8)
        metrics.set_margin_start(12)
        metrics.set_margin_end(12)
        self._metric_labels: dict[str, Gtk.Label] = {}
        for index, (key, title) in enumerate(
            (
                ("hosts", "Hosts"),
                ("ports", "Ports"),
                ("open", "Open"),
                ("filtered", "Filtered"),
                ("closed", "Closed"),
            )
        ):
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            box.add_css_class("card")
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            box.set_margin_start(10)
            box.set_margin_end(10)
            title_label = Gtk.Label(label=title, xalign=0)
            title_label.add_css_class("dim-label")
            value_label = Gtk.Label(label="0", xalign=0)
            value_label.add_css_class("title-3")
            box.append(title_label)
            box.append(value_label)
            metrics.attach(box, index, 0, 1, 1)
            self._metric_labels[key] = value_label
        self.append(metrics)

        context = Gtk.ListBox()
        context.add_css_class("boxed-list")
        context.set_margin_start(12)
        context.set_margin_end(12)
        self._context_labels: dict[str, Gtk.Label] = {}
        for key, title in (
            ("status", "Status"),
            ("command", "Last command"),
            ("exit", "Exit status"),
            ("xml", "XML output"),
            ("binary", "Nmap binary"),
            ("nmapdir", "NMAPDIR"),
        ):
            row = Gtk.ListBoxRow()
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            box.set_margin_top(8)
            box.set_margin_bottom(8)
            box.set_margin_start(12)
            box.set_margin_end(12)
            heading = Gtk.Label(label=title, xalign=0)
            heading.add_css_class("heading")
            value = Gtk.Label(label="-", xalign=0, wrap=True, selectable=True)
            value.add_css_class("monospace")
            box.append(heading)
            box.append(value)
            row.set_child(box)
            context.append(row)
            self._context_labels[key] = value
        self.append(context)

        self._host_title = Gtk.Label(label="Selected Host", xalign=0)
        self._host_title.add_css_class("title-4")
        self._host_title.set_margin_start(12)
        self.append(self._host_title)

        self._store = Gio.ListStore.new(PortRow)
        self._host_ports_table, _selection = build_column_view(
            self._store,
            [
                ("Port", "port"),
                ("State", "state"),
                ("Service", "service"),
                ("Version", "version"),
            ],
        )
        self._empty = empty_state("Select a host in the Hosts tab to view host details here.")
        self._host_stack = Gtk.Stack()
        self._host_stack.set_vexpand(True)
        self._host_stack.add_named(self._host_ports_table, "table")
        self._host_stack.add_named(self._empty, "empty")
        self.append(self._host_stack)

    def set_scan_context(
        self,
        status: str,
        last_command: str,
        exit_status: int | None,
        xml_path: str,
        nmap_binary: str,
        nmapdir: str,
    ) -> None:
        self._status = status
        self._last_command = last_command
        self._exit_status = exit_status
        self._xml_path = xml_path
        self._nmap_binary = nmap_binary
        self._nmapdir = nmapdir
        self._context_labels["status"].set_label(status or "Idle")
        self._context_labels["command"].set_label(last_command or "None")
        self._context_labels["exit"].set_label("None" if exit_status is None else str(exit_status))
        self._context_labels["xml"].set_label(xml_path or "None")
        self._context_labels["binary"].set_label(nmap_binary or "Not found")
        self._context_labels["nmapdir"].set_label(nmapdir or "Unavailable")

    def set_hosts(self, hosts: list[ScannedHost]) -> None:
        self._hosts = hosts
        self._metric_labels["hosts"].set_label(str(len(hosts)))
        ports = all_ports(hosts)
        self._metric_labels["ports"].set_label(str(len(ports)))
        self._metric_labels["open"].set_label(str(sum(1 for port in ports if port.state == "open")))
        self._metric_labels["filtered"].set_label(
            str(sum(1 for port in ports if port.state == "filtered"))
        )
        self._metric_labels["closed"].set_label(str(sum(1 for port in ports if port.state == "closed")))
        if self._selected_host is not None:
            refreshed = next((host for host in hosts if host.address == self._selected_host.address), None)
            self.set_selected_host(refreshed)

    def set_selected_host(self, host: ScannedHost | None) -> None:
        self._selected_host = host
        if host is None:
            self._host_title.set_label("Selected Host")
            self._host_stack.set_visible_child_name("empty")
            return

        self._host_title.set_label(f"{host.display_name} ({host.address})")
        self._store.remove_all()
        for port in sorted(host.ports, key=lambda item: int(item.port_number or "0")):
            self._store.append(PortRow(port))
        if host.ports:
            self._host_stack.set_visible_child_name("table")
        else:
            self._host_stack.set_visible_child_name("empty")
            self._empty.get_first_child().set_label("No port results were parsed for this host.")
