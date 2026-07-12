"""Simple topology map view."""

from __future__ import annotations

import math

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gtk

from ..models import ScannedHost
from ..results_filtering import all_ports
from .common import empty_state, section_header


class TopologyView(Gtk.DrawingArea):
    def __init__(self, on_show_details) -> None:
        super().__init__()
        self._on_show_details = on_show_details
        self._hosts: list[ScannedHost] = []
        self._selected_index: int | None = None
        self.set_draw_func(self._draw)
        self.set_content_width(900)
        self.set_content_height(500)
        gesture = Gtk.GestureClick.new()
        gesture.connect("pressed", self._on_pressed)
        self.add_controller(gesture)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._wrapper = box
        box.append(section_header("Topology", subtitle="Simple radial host map from the current scan."))
        self._count_label = Gtk.Label(label="0 hosts", xalign=1)
        header = box.get_first_child()
        header.append(self._count_label)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_child(self)
        box.append(scrolled)
        self._empty = empty_state("Run or open a scan to populate the topology map.")
        self._stack = Gtk.Stack()
        self._stack.set_vexpand(True)
        self._stack.add_named(box, "map")
        self._stack.add_named(self._empty, "empty")

        self._container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_margin_start(12)
        actions.set_margin_end(12)
        actions.set_margin_top(8)
        actions.set_margin_bottom(8)
        self._details_button = Gtk.Button(label="Host Details")
        self._details_button.connect("clicked", lambda *_: self._show_details())
        actions.append(self._details_button)
        self._container.append(actions)
        self._container.append(self._stack)

    def get_widget(self) -> Gtk.Widget:
        return self._container

    def set_hosts(self, hosts: list[ScannedHost]) -> None:
        self._hosts = hosts
        self._selected_index = None
        self._count_label.set_label(f"{len(hosts)} host(s)")
        if hosts:
            self._stack.set_visible_child_name("map")
        else:
            self._stack.set_visible_child_name("empty")
        self.queue_draw()
        self._details_button.set_sensitive(False)

    def _point_for_host(self, index: int, width: float, height: float) -> tuple[float, float]:
        center_x = width / 2
        center_y = height / 2
        radius = min(width, height) * 0.34
        if len(self._hosts) == 1:
            return center_x, center_y - radius * 0.35
        angle = (2 * math.pi * index / len(self._hosts)) - math.pi / 2
        return center_x + radius * math.cos(angle), center_y + radius * math.sin(angle)

    def _draw(self, area: Gtk.DrawingArea, context, width: int, height: int) -> None:
        context.set_source_rgba(0.12, 0.12, 0.14, 1.0)
        context.paint()

        center_x = width / 2
        center_y = height / 2
        context.set_source_rgba(0.35, 0.55, 0.95, 1.0)
        context.arc(center_x, center_y, 24, 0, 2 * math.pi)
        context.fill()

        context.set_source_rgba(0.9, 0.9, 0.95, 1.0)
        context.select_font_face("Sans", 0, 600)
        context.set_font_size(12)
        context.move_to(center_x - 18, center_y + 4)
        context.show_text("Scan")

        for index, host in enumerate(self._hosts):
            x, y = self._point_for_host(index, width, height)
            context.set_source_rgba(0.4, 0.4, 0.45, 0.5)
            context.set_line_width(1.2)
            context.move_to(center_x, center_y)
            context.line_to(x, y)
            context.stroke()

            if index == self._selected_index:
                context.set_source_rgba(0.95, 0.75, 0.2, 1.0)
            else:
                context.set_source_rgba(0.25, 0.75, 0.45, 1.0)
            context.arc(x, y, 16, 0, 2 * math.pi)
            context.fill()

            label = host.display_name[:18]
            context.set_source_rgba(0.92, 0.92, 0.96, 1.0)
            context.select_font_face("Sans", 0, 0)
            context.set_font_size(11)
            context.move_to(x - 30, y + 30)
            context.show_text(label)

        ports = all_ports(self._hosts)
        context.set_source_rgba(0.75, 0.75, 0.8, 1.0)
        context.move_to(16, height - 16)
        context.show_text(f"{len(self._hosts)} hosts · {len(ports)} ports")

    def _on_pressed(self, _gesture, _n_press, x, y) -> None:
        width = self.get_width()
        height = self.get_height()
        selected = None
        for index, _host in enumerate(self._hosts):
            host_x, host_y = self._point_for_host(index, width, height)
            if ((host_x - x) ** 2 + (host_y - y) ** 2) ** 0.5 <= 18:
                selected = index
                break
        self._selected_index = selected
        self._details_button.set_sensitive(selected is not None)
        self.queue_draw()

    def _show_details(self) -> None:
        if self._selected_index is None:
            return
        self._on_show_details(self._hosts[self._selected_index])
