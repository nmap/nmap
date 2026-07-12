"""Scan comparison view."""

from __future__ import annotations

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Gdk, Gtk

from ..models import SavedScan
from ..scan_comparison import compare_scans, comparison_report_text, scan_label
from ..xml_parsing import parse_nmap_xml
from .common import section_header


class CompareView(Gtk.Box):
    def __init__(self, on_export_report) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self._on_export_report = on_export_report
        self._scans: list[SavedScan] = []
        self._baseline_dropdown = Gtk.DropDown()
        self._comparison_dropdown = Gtk.DropDown()
        self._summary_label = Gtk.Label(label="Select two saved scans to compare.", xalign=0, wrap=True)
        self._report_view = Gtk.TextView()
        self._report_view.set_editable(False)
        self._report_view.set_monospace(True)
        self._report_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)

        self.append(section_header("Compare", subtitle="Diff two saved scans like Zenmap compare."))

        selectors = Gtk.Grid(column_spacing=12, row_spacing=8)
        selectors.set_margin_start(12)
        selectors.set_margin_end(12)
        selectors.attach(Gtk.Label(label="Baseline", xalign=0), 0, 0, 1, 1)
        selectors.attach(self._baseline_dropdown, 1, 0, 1, 1)
        selectors.attach(Gtk.Label(label="Comparison", xalign=0), 0, 1, 1, 1)
        selectors.attach(self._comparison_dropdown, 1, 1, 1, 1)
        self.append(selectors)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_margin_start(12)
        actions.set_margin_end(12)
        copy_button = Gtk.Button(label="Copy Report")
        copy_button.connect("clicked", lambda *_: self._copy_report())
        export_button = Gtk.Button(label="Export Report")
        export_button.connect("clicked", lambda *_: self._export_report())
        actions.append(copy_button)
        actions.append(export_button)
        self.append(actions)

        self._summary_label.set_margin_start(12)
        self._summary_label.set_margin_end(12)
        self.append(self._summary_label)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_child(self._report_view)
        scrolled.set_margin_start(12)
        scrolled.set_margin_end(12)
        scrolled.set_margin_bottom(12)
        self.append(scrolled)

        self._baseline_dropdown.connect("notify::selected", self._refresh_report)
        self._comparison_dropdown.connect("notify::selected", self._refresh_report)

    def set_scans(self, scans: list[SavedScan]) -> None:
        self._scans = scans
        labels = [scan_label(scan) for scan in scans] or ["No saved scans"]
        self._baseline_dropdown.set_model(Gtk.StringList.new(labels))
        self._comparison_dropdown.set_model(Gtk.StringList.new(labels))
        if scans:
            self._baseline_dropdown.set_selected(0)
            self._comparison_dropdown.set_selected(min(1, len(scans) - 1))
        self._refresh_report()

    def _selected_scan(self, dropdown: Gtk.DropDown) -> SavedScan | None:
        index = dropdown.get_selected()
        if index == Gtk.INVALID_LIST_POSITION or index >= len(self._scans):
            return None
        return self._scans[index]

    def _refresh_report(self, *_args) -> None:
        baseline = self._selected_scan(self._baseline_dropdown)
        comparison = self._selected_scan(self._comparison_dropdown)
        buffer = self._report_view.get_buffer()
        if baseline is None or comparison is None or baseline.id == comparison.id:
            self._summary_label.set_label("Select two different saved scans to compare.")
            buffer.set_text("")
            return

        baseline_hosts = parse_nmap_xml(baseline.xml_path)
        comparison_hosts = parse_nmap_xml(comparison.xml_path)
        result = compare_scans(baseline_hosts, comparison_hosts)
        self._summary_label.set_label(
            "New hosts: {new_hosts} · Missing hosts: {missing_hosts} · "
            "New open ports: {new_open_ports} · Closed ports: {closed_ports} · "
            "Service changes: {changed_services}".format(
                new_hosts=len(result.new_hosts),
                missing_hosts=len(result.missing_hosts),
                new_open_ports=len(result.new_open_ports),
                closed_ports=len(result.closed_ports),
                changed_services=len(result.changed_services),
            )
        )
        buffer.set_text(comparison_report_text(baseline, comparison, result))

    def _copy_report(self) -> None:
        text = self._report_view.get_buffer().get_text(
            self._report_view.get_buffer().get_start_iter(),
            self._report_view.get_buffer().get_end_iter(),
            False,
        )
        if text:
            Gdk.Display.get_default().get_clipboard().set(text)

    def _export_report(self) -> None:
        text = self._report_view.get_buffer().get_text(
            self._report_view.get_buffer().get_start_iter(),
            self._report_view.get_buffer().get_end_iter(),
            False,
        )
        if text:
            self._on_export_report(text)
