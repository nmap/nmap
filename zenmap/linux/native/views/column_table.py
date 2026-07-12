"""GTK4 ColumnView helper."""

from __future__ import annotations

import gi

gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Gio, Gtk


def build_column_view(
    store: Gio.ListStore,
    columns: list[tuple[str, str]],
) -> tuple[Gtk.ColumnView, Gtk.SingleSelection]:
    selection = Gtk.SingleSelection.new(store)
    column_view = Gtk.ColumnView(model=selection)
    column_view.set_vexpand(True)

    for title, property_name in columns:
        factory = Gtk.SignalListItemFactory.new()

        def setup(_factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem, prop: str = property_name) -> None:
            label = Gtk.Label(xalign=0)
            label.add_css_class("monospace" if prop in {"address", "host", "port", "command", "arguments"} else "")
            list_item.set_child(label)

        def bind(_factory: Gtk.SignalListItemFactory, list_item: Gtk.ListItem, prop: str = property_name) -> None:
            row = list_item.get_item()
            label = list_item.get_child()
            label.set_label(getattr(row, prop))

        factory.connect("setup", setup)
        factory.connect("bind", bind)
        column = Gtk.ColumnViewColumn(title=title, factory=factory)
        column_view.append_column(column)

    scrolled = Gtk.ScrolledWindow()
    scrolled.set_child(column_view)
    scrolled.set_vexpand(True)
    scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    return scrolled, selection
