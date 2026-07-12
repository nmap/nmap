"""Shared GTK widgets for Zenmap result views."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")

from gi.repository import Gtk


def section_header(title: str, subtitle: str = "", count_text: str = "") -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
    box.set_margin_start(12)
    box.set_margin_end(12)
    box.set_margin_top(12)

    text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    heading = Gtk.Label(label=title, xalign=0)
    heading.add_css_class("title-4")
    text_box.append(heading)
    if subtitle:
        sub = Gtk.Label(label=subtitle, xalign=0)
        sub.add_css_class("dim-label")
        text_box.append(sub)
    box.append(text_box)

    spacer = Gtk.Box()
    spacer.set_hexpand(True)
    box.append(spacer)

    if count_text:
        count = Gtk.Label(label=count_text, xalign=1)
        count.add_css_class("dim-label")
        box.append(count)
    return box


def filter_bar(placeholder: str, on_changed) -> Gtk.SearchEntry:
    entry = Gtk.SearchEntry()
    entry.set_placeholder_text(placeholder)
    entry.connect("search-changed", lambda widget: on_changed(widget.get_text()))
    entry.set_margin_start(12)
    entry.set_margin_end(12)
    entry.set_margin_bottom(8)
    return entry


def empty_state(message: str) -> Gtk.Box:
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_valign(Gtk.Align.CENTER)
    box.set_halign(Gtk.Align.CENTER)
    box.set_vexpand(True)
    label = Gtk.Label(label=message, justify=Gtk.Justification.CENTER, wrap=True)
    label.add_css_class("dim-label")
    label.set_max_width_chars(48)
    box.append(label)
    return box


def action_button_row(buttons: list[tuple[str, callable, bool]]) -> Gtk.Box:
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    row.set_margin_start(12)
    row.set_margin_end(12)
    row.set_margin_bottom(8)
    for label, callback, sensitive in buttons:
        button = Gtk.Button(label=label)
        button.set_sensitive(sensitive)
        button.connect("clicked", lambda _btn, cb=callback: cb())
        row.append(button)
    return row
