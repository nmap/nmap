"""Main GTK4/Libadwaita window for native Linux Zenmap."""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Adw", "1")
gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "4.0")

from gi.repository import Adw, Gio, GLib, Gtk

from .models import SavedScan, ScannedHost, ScanProfile, ZenmapScanLifecycleState
from .nmap_paths import resolve_nmap_binary, resolve_nmap_data_directory
from .profile_storage import ProfileStore
from .scan_execution import ScanRequest, ScanRunner
from .scan_form_utils import scan_form_values_from_command
from .scan_history_store import ScanHistoryStore
from .scan_privilege import privilege_requirement
from .settings_store import AppSettings, SettingsStore
from .shell_utils import shell_split, split_targets
from .xml_parsing import parse_nmap_xml
from .views.compare_view import CompareView
from .views.details_view import DetailsView
from .views.hosts_view import HostsView
from .views.output_view import OutputView
from .views.ports_view import PortsView
from .views.profiles_view import ProfilesView
from .views.saved_scans_view import SavedScansView
from .views.services_view import ServicesView
from .views.settings_view import SettingsView
from .views.topology_view import TopologyView


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, application: Adw.Application) -> None:
        super().__init__(application=application, title="Zenmap")
        self.set_default_size(1250, 850)

        self._settings_store = SettingsStore()
        self._profile_store = ProfileStore()
        self._scan_history = ScanHistoryStore()

        self._profiles = self._profile_store.profiles
        self._selected_profile = self._profile_by_name(self._settings_store.settings.default_profile_name)
        self._target = self._settings_store.settings.default_target
        self._arguments = self._selected_profile.arguments
        self._output_text = ""
        self._status_text = "Idle"
        self._hosts: list[ScannedHost] = []
        self._last_command = ""
        self._last_xml_path = ""
        self._exit_status: int | None = None
        self._pending_privileged = False

        self._scan_runner = ScanRunner(
            on_output=self._append_output,
            on_status=self._set_status,
            on_lifecycle=self._on_lifecycle,
            on_hosts=self._set_hosts,
            on_progress=self._set_progress,
        )

        self._build_ui()
        self._apply_settings_to_form()
        self._refresh_profile_dropdown()
        self._refresh_saved_views()

    def _profile_by_name(self, name: str) -> ScanProfile:
        return next((profile for profile in self._profiles if profile.name == name), self._profiles[0])

    def _build_ui(self) -> None:
        toolbar_view = Adw.ToolbarView()
        self.set_content(toolbar_view)

        header = Adw.HeaderBar()
        self._scan_button = Gtk.Button(label="Scan")
        self._scan_button.add_css_class("suggested-action")
        self._scan_button.connect("clicked", self._on_scan_clicked)
        header.pack_end(self._scan_button)

        self._stop_button = Gtk.Button(label="Stop")
        self._stop_button.add_css_class("destructive-action")
        self._stop_button.set_sensitive(False)
        self._stop_button.connect("clicked", self._on_stop_clicked)
        header.pack_end(self._stop_button)
        toolbar_view.add_top_bar(header)

        split_view = Adw.NavigationSplitView()
        split_view.set_sidebar_width_fraction(0.22)
        split_view.set_min_sidebar_width(220)
        split_view.set_max_sidebar_width(320)
        toolbar_view.set_content(split_view)

        self._sidebar = self._build_sidebar()
        split_view.set_sidebar(Adw.NavigationPage(title="Nmap", child=self._sidebar))

        content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        content_box.append(self._build_scan_form())
        content_box.append(self._build_content_stack())
        content_box.append(self._build_footer())
        split_view.set_content(Adw.NavigationPage(title="Zenmap", child=content_box))

    def _build_sidebar(self) -> Gtk.ListBox:
        list_box = Gtk.ListBox()
        list_box.set_selection_mode(Gtk.SelectionMode.SINGLE)
        list_box.add_css_class("navigation-sidebar")
        self._tab_rows: dict[str, Gtk.ListBoxRow] = {}
        self._row_to_tab: dict[Gtk.ListBoxRow, str] = {}

        for section, items in (
            (
                "Scan",
                (
                    ("Output", "terminal-symbolic"),
                    ("Hosts", "computer-symbolic"),
                    ("Ports", "view-list-symbolic"),
                    ("Services", "network-transmit-receive-symbolic"),
                    ("Details", "dialog-information-symbolic"),
                ),
            ),
            (
                "History",
                (("Saved Scans", "folder-symbolic"), ("Compare", "view-restore-symbolic")),
            ),
            (
                "Tools",
                (
                    ("Topology", "network-workgroup-symbolic"),
                    ("Profiles", "preferences-system-symbolic"),
                    ("Settings", "emblem-system-symbolic"),
                ),
            ),
        ):
            section_label = Gtk.Label(label=section, xalign=0)
            section_label.add_css_class("heading")
            section_label.set_margin_start(12)
            section_label.set_margin_top(12)
            section_label.set_margin_bottom(6)
            list_box.append(section_label)
            for title, icon_name in items:
                row = Adw.ActionRow(title=title)
                row.add_prefix(Gtk.Image.new_from_icon_name(icon_name))
                list_row = Gtk.ListBoxRow()
                list_row.set_child(row)
                list_box.append(list_row)
                self._tab_rows[title] = list_row
                self._row_to_tab[list_row] = title

        list_box.connect("row-activated", self._on_tab_activated)
        list_box.select_row(self._tab_rows["Output"])
        return list_box

    def _build_scan_form(self) -> Gtk.Widget:
        clamp = Adw.Clamp()
        clamp.set_maximum_size(1100)
        clamp.set_margin_top(18)
        clamp.set_margin_bottom(12)
        clamp.set_margin_start(18)
        clamp.set_margin_end(18)

        grid = Gtk.Grid(column_spacing=12, row_spacing=10)
        clamp.set_child(grid)

        title = Gtk.Label(label="Nmap for Linux", xalign=0)
        title.add_css_class("title-1")
        grid.attach(title, 0, 0, 2, 1)

        subtitle = Gtk.Label(
            label="Native GTK front end with pkexec support and XDG-backed history",
            xalign=0,
        )
        subtitle.add_css_class("dim-label")
        grid.attach(subtitle, 0, 1, 2, 1)

        grid.attach(Gtk.Label(label="Target", xalign=0), 0, 2, 1, 1)
        self._target_entry = Gtk.Entry()
        self._target_entry.connect("changed", self._on_target_changed)
        grid.attach(self._target_entry, 1, 2, 1, 1)

        grid.attach(Gtk.Label(label="Profile", xalign=0), 0, 3, 1, 1)
        self._profile_dropdown = Gtk.DropDown()
        self._profile_dropdown.connect("notify::selected", self._on_profile_changed)
        grid.attach(self._profile_dropdown, 1, 3, 1, 1)

        grid.attach(Gtk.Label(label="Arguments", xalign=0), 0, 4, 1, 1)
        self._arguments_entry = Gtk.Entry()
        self._arguments_entry.connect("changed", self._on_arguments_changed)
        grid.attach(self._arguments_entry, 1, 4, 1, 1)

        grid.attach(Gtk.Label(label="Preview", xalign=0), 0, 5, 1, 1)
        self._preview_label = Gtk.Label(label="", xalign=0, wrap=True, selectable=True)
        self._preview_label.add_css_class("monospace")
        self._preview_label.add_css_class("card")
        self._preview_label.set_margin_top(6)
        self._preview_label.set_margin_bottom(6)
        self._preview_label.set_margin_start(10)
        self._preview_label.set_margin_end(10)
        grid.attach(self._preview_label, 1, 5, 1, 1)

        self._profile_description = Gtk.Label(label="", xalign=0, wrap=True)
        self._profile_description.add_css_class("dim-label")
        grid.attach(self._profile_description, 0, 6, 2, 1)
        return clamp

    def _build_content_stack(self) -> Gtk.Widget:
        self._stack = Gtk.Stack()
        self._stack.set_vexpand(True)

        self._output_view = OutputView()
        self._hosts_view = HostsView(on_show_details=self._show_host_details)
        self._ports_view = PortsView(on_show_host_details=self._show_host_details)
        self._services_view = ServicesView(on_show_host_details=self._show_host_details)
        self._details_view = DetailsView()
        self._saved_scans_view = SavedScansView(
            on_load_scan=self._load_saved_scan,
            on_open_xml=self._open_saved_scan_xml,
            on_import_xml=self._import_xml_file,
            on_delete_scan=self._delete_saved_scan,
            on_clear_scans=self._clear_saved_scans,
            on_save_metadata=self._save_saved_scan_metadata,
        )
        self._compare_view = CompareView(on_export_report=self._export_comparison_report)
        self._topology_view = TopologyView(on_show_details=self._show_host_details)
        self._profiles_view = ProfilesView(
            on_use_profile=self._use_profile,
            on_add_profile=self._add_custom_profile,
            on_edit_profile=self._edit_custom_profile,
            on_delete_profile=self._delete_custom_profile,
            on_duplicate_profile=self._duplicate_profile,
            on_import_profiles=self._import_profiles,
            on_export_profiles=self._export_profiles,
        )
        self._settings_view = SettingsView(on_save_settings=self._save_settings)

        for name, widget in (
            ("Output", self._output_view),
            ("Hosts", self._hosts_view),
            ("Ports", self._ports_view),
            ("Services", self._services_view),
            ("Details", self._details_view),
            ("Saved Scans", self._saved_scans_view),
            ("Compare", self._compare_view),
            ("Topology", self._topology_view.get_widget()),
            ("Profiles", self._profiles_view),
            ("Settings", self._settings_view),
        ):
            self._stack.add_named(widget, name)
        self._stack.set_visible_child_name("Output")
        return self._stack

    def _build_footer(self) -> Gtk.Widget:
        footer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        footer.set_margin_top(8)
        footer.set_margin_bottom(8)
        footer.set_margin_start(12)
        footer.set_margin_end(12)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self._status_label = Gtk.Label(label=self._status_text, xalign=0)
        self._status_label.add_css_class("dim-label")
        row.append(self._status_label)
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        row.append(spacer)
        self._host_count_label = Gtk.Label(label="0 hosts", xalign=1)
        self._host_count_label.add_css_class("dim-label")
        row.append(self._host_count_label)
        footer.append(row)

        self._progress_label = Gtk.Label(label="", xalign=0)
        self._progress_label.add_css_class("dim-label")
        footer.append(self._progress_label)
        return footer

    def _apply_settings_to_form(self) -> None:
        settings = self._settings_store.settings
        self._target = settings.default_target
        self._target_entry.set_text(self._target)
        self._arguments = self._selected_profile.arguments
        self._arguments_entry.set_text(self._arguments)
        self._profile_description.set_label(self._selected_profile.description)
        self._preview_label.set_label(self._command_preview)
        self._settings_view.set_settings(settings)
        self._update_scan_context()

    def _refresh_profile_dropdown(self) -> None:
        self._profiles = self._profile_store.profiles
        names = [profile.name for profile in self._profiles]
        self._profile_dropdown.set_model(Gtk.StringList.new(names))
        selected_index = next(
            (index for index, profile in enumerate(self._profiles) if profile.id == self._selected_profile.id),
            0,
        )
        self._profile_dropdown.set_selected(selected_index)
        self._profiles_view.set_profiles(self._profiles)

    def _refresh_saved_views(self) -> None:
        scans = self._scan_history.saved_scans
        self._saved_scans_view.set_scans(scans)
        self._compare_view.set_scans(scans)

    @property
    def _command_preview(self) -> str:
        args = shell_split(self._arguments)
        targets = split_targets(self._target)
        joined_args = " ".join(args)
        joined_targets = " ".join(targets)
        if not joined_args:
            return f"{self._settings_store.settings.nmap_binary} {joined_targets}".strip()
        return f"{self._settings_store.settings.nmap_binary} {joined_args} {joined_targets}".strip()

    def _select_tab(self, title: str) -> None:
        self._stack.set_visible_child_name(title)
        self._sidebar.select_row(self._tab_rows[title])

    def _show_host_details(self, host: ScannedHost) -> None:
        self._details_view.set_selected_host(host)
        self._hosts_view.select_host(host)
        self._select_tab("Details")

    def _on_target_changed(self, _entry: Gtk.Entry) -> None:
        self._target = self._target_entry.get_text()
        self._preview_label.set_label(self._command_preview)
        self._update_scan_button_state()

    def _on_arguments_changed(self, _entry: Gtk.Entry) -> None:
        self._arguments = self._arguments_entry.get_text()
        self._preview_label.set_label(self._command_preview)

    def _on_profile_changed(self, dropdown: Gtk.DropDown, _pspec) -> None:
        index = dropdown.get_selected()
        if index == Gtk.INVALID_LIST_POSITION:
            return
        self._selected_profile = self._profiles[index]
        self._arguments = self._selected_profile.arguments
        self._arguments_entry.set_text(self._arguments)
        self._profile_description.set_label(self._selected_profile.description)
        self._preview_label.set_label(self._command_preview)

    def _on_tab_activated(self, _list_box: Gtk.ListBox, row: Gtk.ListBoxRow) -> None:
        self._stack.set_visible_child_name(self._row_to_tab.get(row, "Output"))

    def _on_scan_clicked(self, _button: Gtk.Button) -> None:
        args = shell_split(self._arguments)
        privilege = privilege_requirement(args)
        if privilege.mode.value == "administrator":
            self._prompt_privileged_scan(privilege.reason)
            return
        self._start_scan(allow_privileged=False)

    def _prompt_privileged_scan(self, reason: str) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Administrator privileges required",
            body=(
                f"{reason}\n\nZenmap will use pkexec to run this scan as root. "
                "Approve the system prompt to continue."
            ),
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("continue", "Continue")
        dialog.set_response_appearance("continue", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_default_response("continue")
        dialog.set_close_response("cancel")
        dialog.connect("response", self._on_privilege_dialog_response)
        dialog.present()

    def _on_privilege_dialog_response(self, dialog: Adw.MessageDialog, response: str) -> None:
        dialog.destroy()
        if response == "continue":
            self._start_scan(allow_privileged=True)

    def _start_scan(self, allow_privileged: bool) -> None:
        self._select_tab("Output")
        self._output_text = ""
        self._output_view.clear()
        self._exit_status = None
        settings = self._settings_store.settings
        self._scan_runner.run(
            ScanRequest(
                target_text=self._target,
                arguments_text=self._arguments,
                auto_add_stats_every=settings.auto_add_stats_every,
                stats_every_value=settings.stats_every_value,
                auto_add_verbose=settings.auto_add_verbose,
                nmap_binary=settings.nmap_binary,
                allow_privileged=allow_privileged,
            )
        )
        self._last_command = self._command_preview
        self._update_scan_button_state()

    def _on_stop_clicked(self, _button: Gtk.Button) -> None:
        self._scan_runner.stop()

    def _append_output(self, text: str) -> None:
        GLib.idle_add(self._append_output_idle, text)

    def _append_output_idle(self, text: str) -> bool:
        self._output_text += text
        self._output_view.append_text(text)
        return False

    def _set_status(self, status: str) -> None:
        GLib.idle_add(self._set_status_idle, status)

    def _set_status_idle(self, status: str) -> bool:
        self._status_text = status
        self._status_label.set_label(status)
        self._update_scan_button_state()
        self._update_scan_context()
        return False

    def _set_progress(self, progress) -> None:
        GLib.idle_add(self._set_progress_idle, progress)

    def _set_progress_idle(self, progress) -> bool:
        parts = [progress.message, progress.phase_text, progress.elapsed_text, progress.estimated_completion_text]
        text = " · ".join(part for part in parts if part)
        self._progress_label.set_label(text)
        return False

    def _on_lifecycle(self, state: ZenmapScanLifecycleState, exit_status: int | None) -> None:
        GLib.idle_add(self._on_lifecycle_idle, state, exit_status)

    def _on_lifecycle_idle(self, state: ZenmapScanLifecycleState, exit_status: int | None) -> bool:
        self._exit_status = exit_status
        self._update_scan_button_state()
        self._update_scan_context()
        if state == ZenmapScanLifecycleState.COMPLETED and self._scan_runner.xml_path:
            self._last_xml_path = self._scan_runner.xml_path
            title = f"{self._target.strip()} - {self._selected_profile.name}"
            self._scan_history.add_scan(
                title=title,
                command=self._last_command,
                xml_path=self._last_xml_path,
                hosts=self._hosts,
            )
            self._refresh_saved_views()
        return False

    def _set_hosts(self, hosts: list[ScannedHost]) -> None:
        GLib.idle_add(self._set_hosts_idle, hosts)

    def _set_hosts_idle(self, hosts: list[ScannedHost]) -> bool:
        self._hosts = hosts
        self._hosts_view.set_hosts(hosts)
        self._ports_view.set_hosts(hosts)
        self._services_view.set_hosts(hosts)
        self._details_view.set_hosts(hosts)
        self._topology_view.set_hosts(hosts)
        self._host_count_label.set_label(f"{len(hosts)} host(s)")
        self._update_scan_context()
        return False

    def _update_scan_context(self) -> None:
        binary = resolve_nmap_binary(self._settings_store.settings.nmap_binary) or ""
        self._details_view.set_scan_context(
            status=self._status_text,
            last_command=self._last_command,
            exit_status=self._exit_status,
            xml_path=self._last_xml_path,
            nmap_binary=binary,
            nmapdir=resolve_nmap_data_directory(binary) if binary else "",
        )

    def _update_scan_button_state(self) -> None:
        running = self._scan_runner.is_running
        has_target = bool(split_targets(self._target))
        self._scan_button.set_sensitive(not running and has_target)
        self._stop_button.set_sensitive(running)
        self._scan_button.set_label("Running..." if running else "Scan")

    def _load_saved_scan(self, scan: SavedScan) -> None:
        hosts = parse_nmap_xml(scan.xml_path)
        arguments, targets = scan_form_values_from_command(scan.command)
        self._target = targets
        self._arguments = arguments
        self._target_entry.set_text(self._target)
        self._arguments_entry.set_text(self._arguments)
        self._last_command = scan.command
        self._last_xml_path = scan.xml_path
        self._exit_status = 0
        self._status_text = "Loaded saved scan"
        self._status_label.set_label(self._status_text)
        self._output_text = f"Loaded saved scan: {scan.title}\nXML: {scan.xml_path}\n"
        self._output_view.set_text(self._output_text)
        self._set_hosts_idle(hosts)
        self._update_scan_context()

    def _open_saved_scan_xml(self, scan: SavedScan) -> None:
        self._load_saved_scan(scan)
        self._select_tab("Output")

    def _import_xml_file(self) -> None:
        dialog = Gtk.FileDialog(title="Import Nmap XML")
        dialog.open(self, None, self._on_import_xml_selected)

    def _on_import_xml_selected(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            file_obj = dialog.open_finish(result)
        except GLib.Error:
            return
        path = file_obj.get_path()
        if not path:
            return
        hosts = parse_nmap_xml(path)
        saved = self._scan_history.import_xml(
            title=Path(path).stem,
            command=f"nmap (imported) {Path(path).name}",
            xml_path=path,
            hosts=hosts,
        )
        self._refresh_saved_views()
        self._load_saved_scan(saved)

    def _delete_saved_scan(self, scan: SavedScan) -> None:
        self._scan_history.remove_scan(scan.id, delete_file=True)
        self._refresh_saved_views()

    def _clear_saved_scans(self) -> None:
        dialog = Adw.MessageDialog(
            transient_for=self,
            heading="Clear saved scans?",
            body="This removes all saved scan metadata and XML copies from XDG config.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("clear", "Clear All")
        dialog.set_response_appearance("clear", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(message_dialog: Adw.MessageDialog, response: str) -> None:
            message_dialog.destroy()
            if response == "clear":
                self._scan_history.clear(delete_files=True)
                self._refresh_saved_views()

        dialog.connect("response", on_response)
        dialog.present()

    def _save_saved_scan_metadata(self, scan: SavedScan, notes: str, tags: str) -> None:
        self._scan_history.update_scan_metadata(scan.id, notes, tags)
        self._refresh_saved_views()

    def _export_comparison_report(self, text: str) -> None:
        dialog = Gtk.FileDialog(title="Export Scan Comparison Report")
        dialog.set_initial_name("nmap-scan-comparison.txt")
        dialog.save(self, None, self._on_export_comparison_selected, text)

    def _on_export_comparison_selected(
        self,
        dialog: Gtk.FileDialog,
        result: Gio.AsyncResult,
        text: str,
    ) -> None:
        try:
            file_obj = dialog.save_finish(result)
        except GLib.Error:
            return
        path = file_obj.get_path()
        if path:
            Path(path).write_text(text, encoding="utf-8")

    def _use_profile(self, profile: ScanProfile) -> None:
        self._selected_profile = profile
        self._refresh_profile_dropdown()
        self._arguments = profile.arguments
        self._arguments_entry.set_text(self._arguments)
        self._profile_description.set_label(profile.description)
        self._preview_label.set_label(self._command_preview)

    def _add_custom_profile(self) -> None:
        self._show_profile_editor()

    def _edit_custom_profile(self, profile: ScanProfile) -> None:
        self._show_profile_editor(profile)

    def _show_profile_editor(self, profile: ScanProfile | None = None) -> None:
        dialog = Adw.Window(transient_for=self, modal=True, title="Custom Profile")
        dialog.set_default_size(480, 320)
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        content.set_margin_top(18)
        content.set_margin_bottom(18)
        content.set_margin_start(18)
        content.set_margin_end(18)

        name_entry = Gtk.Entry(text=profile.name if profile else "")
        args_entry = Gtk.Entry(text=profile.arguments if profile else "")
        description_entry = Gtk.Entry(text=profile.description if profile else "")
        for label, widget in (
            ("Name", name_entry),
            ("Arguments", args_entry),
            ("Description", description_entry),
        ):
            content.append(Gtk.Label(label=label, xalign=0))
            content.append(widget)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        buttons.set_halign(Gtk.Align.END)
        cancel = Gtk.Button(label="Cancel")
        save = Gtk.Button(label="Save")
        save.add_css_class("suggested-action")
        buttons.append(cancel)
        buttons.append(save)
        content.append(buttons)
        dialog.set_content(content)

        def on_cancel(_button: Gtk.Button) -> None:
            dialog.destroy()

        def on_save(_button: Gtk.Button) -> None:
            name = name_entry.get_text().strip()
            if not name:
                return
            if profile is None:
                created = self._profile_store.add_custom_profile(
                    name=name,
                    arguments=args_entry.get_text().strip(),
                    description=description_entry.get_text().strip(),
                )
                self._selected_profile = created
            else:
                self._profile_store.update_custom_profile(
                    profile.id,
                    name=name,
                    arguments=args_entry.get_text().strip(),
                    description=description_entry.get_text().strip(),
                )
                self._selected_profile = next(
                    (item for item in self._profile_store.profiles if item.id == profile.id),
                    self._selected_profile,
                )
            self._refresh_profile_dropdown()
            self._use_profile(self._selected_profile)
            dialog.destroy()

        cancel.connect("clicked", on_cancel)
        save.connect("clicked", on_save)
        dialog.present()

    def _delete_custom_profile(self, profile: ScanProfile) -> None:
        self._profile_store.delete_custom_profile(profile.id)
        self._selected_profile = self._profiles[0]
        self._refresh_profile_dropdown()

    def _duplicate_profile(self, profile: ScanProfile) -> None:
        created = self._profile_store.duplicate_profile(profile)
        self._selected_profile = created
        self._refresh_profile_dropdown()
        self._use_profile(created)

    def _import_profiles(self) -> None:
        dialog = Gtk.FileDialog(title="Import Custom Profiles")
        dialog.open(self, None, self._on_import_profiles_selected)

    def _on_import_profiles_selected(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            file_obj = dialog.open_finish(result)
        except GLib.Error:
            return
        path = file_obj.get_path()
        if not path:
            return
        imported = self._profile_store.import_custom_profiles(path)
        if imported:
            self._selected_profile = imported[-1]
            self._refresh_profile_dropdown()
            self._use_profile(self._selected_profile)

    def _export_profiles(self) -> None:
        dialog = Gtk.FileDialog(title="Export Custom Profiles")
        dialog.set_initial_name("nmap-custom-profiles.json")
        dialog.save(self, None, self._on_export_profiles_selected)

    def _on_export_profiles_selected(self, dialog: Gtk.FileDialog, result: Gio.AsyncResult) -> None:
        try:
            file_obj = dialog.save_finish(result)
        except GLib.Error:
            return
        path = file_obj.get_path()
        if path:
            self._profile_store.export_custom_profiles(path)

    def _save_settings(self, settings: AppSettings) -> None:
        self._settings_store.settings = settings
        self._settings_store.save()
        self._target = settings.default_target
        self._target_entry.set_text(self._target)
        self._selected_profile = self._profile_by_name(settings.default_profile_name)
        self._refresh_profile_dropdown()
        self._apply_settings_to_form()
