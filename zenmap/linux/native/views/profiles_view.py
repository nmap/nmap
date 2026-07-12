"""Custom profile management view."""

from __future__ import annotations

import gi

gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Gio, Gtk

from ..gobject_models import ProfileRow
from ..models import ScanProfile
from ..results_filtering import filter_profiles
from .column_table import build_column_view
from .common import empty_state, filter_bar, section_header


class ProfilesView(Gtk.Box):
    def __init__(
        self,
        on_use_profile,
        on_add_profile,
        on_edit_profile,
        on_delete_profile,
        on_duplicate_profile,
        on_import_profiles,
        on_export_profiles,
    ) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._on_use_profile = on_use_profile
        self._on_add_profile = on_add_profile
        self._on_edit_profile = on_edit_profile
        self._on_delete_profile = on_delete_profile
        self._on_duplicate_profile = on_duplicate_profile
        self._on_import_profiles = on_import_profiles
        self._on_export_profiles = on_export_profiles
        self._profiles: list[ScanProfile] = []
        self._filter_text = ""
        self._store = Gio.ListStore.new(ProfileRow)
        self._table, self._selection = build_column_view(
            self._store,
            [
                ("Name", "name"),
                ("Arguments", "arguments"),
                ("Type", "kind"),
                ("Description", "description"),
            ],
        )
        self._empty = empty_state("Built-in and custom profiles appear here.")
        self._stack = Gtk.Stack()
        self._stack.set_vexpand(True)
        self._stack.add_named(self._table, "table")
        self._stack.add_named(self._empty, "empty")

        self.append(section_header("Profiles", subtitle="Built-in profiles plus custom XDG-backed profiles."))
        self.append(filter_bar("Filter profiles", self._set_filter))

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_margin_start(12)
        actions.set_margin_end(12)
        actions.set_margin_bottom(8)
        self._use_button = Gtk.Button(label="Use Profile")
        self._add_button = Gtk.Button(label="Add Custom")
        self._edit_button = Gtk.Button(label="Edit")
        self._delete_button = Gtk.Button(label="Delete")
        self._duplicate_button = Gtk.Button(label="Duplicate")
        self._import_button = Gtk.Button(label="Import")
        self._export_button = Gtk.Button(label="Export")
        self._use_button.connect("clicked", lambda *_: self._use_selected())
        self._add_button.connect("clicked", lambda *_: self._on_add_profile())
        self._edit_button.connect("clicked", lambda *_: self._edit_selected())
        self._delete_button.connect("clicked", lambda *_: self._delete_selected())
        self._duplicate_button.connect("clicked", lambda *_: self._duplicate_selected())
        self._import_button.connect("clicked", lambda *_: self._on_import_profiles())
        self._export_button.connect("clicked", lambda *_: self._on_export_profiles())
        for button in (
            self._use_button,
            self._add_button,
            self._edit_button,
            self._delete_button,
            self._duplicate_button,
            self._import_button,
            self._export_button,
        ):
            actions.append(button)
        self.append(actions)

        self._selection.connect("notify::selected", self._on_selection_changed)
        self.append(self._stack)

    def set_profiles(self, profiles: list[ScanProfile]) -> None:
        self._profiles = profiles
        self._refresh()

    def selected_profile(self) -> ScanProfile | None:
        position = self._selection.get_selected()
        if position == Gtk.INVALID_LIST_POSITION:
            return None
        row = self._store.get_item(position)
        return row.profile if row is not None else None

    def _set_filter(self, text: str) -> None:
        self._filter_text = text
        self._refresh()

    def _refresh(self) -> None:
        filtered = filter_profiles(self._profiles, self._filter_text)
        self._store.remove_all()
        for profile in filtered:
            self._store.append(ProfileRow(profile))
        if not filtered:
            self._stack.set_visible_child_name("empty")
        else:
            self._stack.set_visible_child_name("table")
        self._on_selection_changed()

    def _on_selection_changed(self, *_args) -> None:
        profile = self.selected_profile()
        has_selection = profile is not None
        self._use_button.set_sensitive(has_selection)
        self._edit_button.set_sensitive(has_selection and profile is not None and not profile.is_built_in)
        self._delete_button.set_sensitive(has_selection and profile is not None and not profile.is_built_in)
        self._duplicate_button.set_sensitive(has_selection)

    def _use_selected(self) -> None:
        profile = self.selected_profile()
        if profile is not None:
            self._on_use_profile(profile)

    def _edit_selected(self) -> None:
        profile = self.selected_profile()
        if profile is not None and not profile.is_built_in:
            self._on_edit_profile(profile)

    def _delete_selected(self) -> None:
        profile = self.selected_profile()
        if profile is not None and not profile.is_built_in:
            self._on_delete_profile(profile)

    def _duplicate_selected(self) -> None:
        profile = self.selected_profile()
        if profile is not None:
            self._on_duplicate_profile(profile)
