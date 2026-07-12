"""Placeholder views for tabs not yet ported from macOS."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gtk


class PlaceholderView(Gtk.Box):
    def __init__(self, title: str, description: str) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.set_valign(Gtk.Align.CENTER)
        self.set_halign(Gtk.Align.CENTER)
        self.set_margin_top(24)
        self.set_margin_bottom(24)
        self.set_margin_start(24)
        self.set_margin_end(24)

        heading = Gtk.Label(label=title)
        heading.add_css_class("title-2")
        self.append(heading)

        body = Gtk.Label(label=description, wrap=True, justify=Gtk.Justification.CENTER)
        body.add_css_class("dim-label")
        body.set_max_width_chars(48)
        self.append(body)
