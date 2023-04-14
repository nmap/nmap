#!/usr/bin/env python3

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *
# * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
# * Project"). Nmap is also a registered trademark of the Nmap Project.
# *
# * This program is distributed under the terms of the Nmap Public Source
# * License (NPSL). The exact license text applying to a particular Nmap
# * release or source code control revision is contained in the LICENSE
# * file distributed with that version of Nmap or source code control
# * revision. More Nmap copyright/legal information is available from
# * https://nmap.org/book/man-legal.html, and further information on the
# * NPSL license itself can be found at https://nmap.org/npsl/ . This
# * header summarizes some key points from the Nmap license, but is no
# * substitute for the actual license text.
# *
# * Nmap is generally free for end users to download and use themselves,
# * including commercial use. It is available from https://nmap.org.
# *
# * The Nmap license generally prohibits companies from using and
# * redistributing Nmap in commercial products, but we sell a special Nmap
# * OEM Edition with a more permissive license and special features for
# * this purpose. See https://nmap.org/oem/
# *
# * If you have received a written Nmap license agreement or contract
# * stating terms other than these (such as an Nmap OEM license), you may
# * choose to use and redistribute Nmap under those terms instead.
# *
# * The official Nmap Windows builds include the Npcap software
# * (https://npcap.com) for packet capture and transmission. It is under
# * separate license terms which forbid redistribution without special
# * permission. So the official Nmap Windows builds may not be redistributed
# * without special permission (such as an Nmap OEM license).
# *
# * Source is provided to this software because we believe users have a
# * right to know exactly what a program is going to do before they run it.
# * This also allows you to audit the software for security holes.
# *
# * Source code also allows you to port Nmap to new platforms, fix bugs, and add
# * new features. You are highly encouraged to submit your changes as a Github PR
# * or by email to the dev@nmap.org mailing list for possible incorporation into
# * the main distribution. Unless you specify otherwise, it is understood that
# * you are offering us very broad rights to use your submissions as described in
# * the Nmap Public Source License Contributor Agreement. This is important
# * because we fund the project by selling licenses with various terms, and also
# * because the inability to relicense code has caused devastating problems for
# * other Free Software projects (such as KDE and NASM).
# *
# * The free version of Nmap is distributed in the hope that it will be
# * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
# * indemnification and commercial support are all available through the
# * Npcap OEM program--see https://nmap.org/oem/
# *
# ***************************************************************************/

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, GLib

import errno
import os
import time

# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

import xml.sax

from zenmapGUI.higwidgets.hignotebooks import HIGNotebook
from zenmapGUI.higwidgets.higboxes import HIGVBox
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog
from zenmapGUI.higwidgets.higscrollers import HIGScrolledWindow

from zenmapGUI.FilterBar import FilterBar
from zenmapGUI.ScanHostDetailsPage import ScanHostDetailsPage
from zenmapGUI.ScanToolbar import ScanCommandToolbar, ScanToolbar
from zenmapGUI.ScanHostsView import ScanHostsView
from zenmapGUI.ScanOpenPortsPage import ScanOpenPortsPage
from zenmapGUI.ScanNmapOutputPage import ScanNmapOutputPage
from zenmapGUI.ScanScanListPage import ScanScanListPage
from zenmapGUI.ScansListStore import ScansListStore
from zenmapGUI.TopologyPage import TopologyPage

from zenmapCore.NetworkInventory import NetworkInventory,\
        FilteredNetworkInventory
from zenmapCore.NmapCommand import NmapCommand
from zenmapCore.UmitConf import CommandProfile, is_maemo
from zenmapCore.NmapParser import NmapParser
from zenmapCore.Paths import Path, get_extra_executable_search_paths
from zenmapCore.UmitLogging import log
from zenmapCore.NmapOptions import NmapOptions, split_quoted, join_quoted
import zenmapCore.I18N  # lgtm[py/unused-import]

# How often the live output view refreshes, in milliseconds.
NMAP_OUTPUT_REFRESH_INTERVAL = 1000


class ScanInterface(HIGVBox):
    """ScanInterface contains the scan toolbar and the scan results. Each
    ScanInterface represents a single NetworkInventory as well as a set of
    running scans."""

    # The time delay between when you stop typing a filter string and filtering
    # actually begins, in milliseconds.
    FILTER_DELAY = 1000

    def __init__(self):
        HIGVBox.__init__(self)

        # The borders are consuming too much space on Maemo. Setting it to
        # 0 pixels while on Maemo
        if is_maemo():
            self.set_border_width(0)

        self.set_spacing(0)

        # True if nothing has happened here page yet, i.e., it's okay to load a
        # scan from a file here.
        self.empty = True

        # The most recent name the inventory on this page has been saved under.
        self.saved_filename = None

        # The network inventory shown by this page. It may consist of multiple
        # scans.
        self.inventory = FilteredNetworkInventory()

        # The list of currently running scans (NmapCommand objects).
        self.jobs = []

        # The list of running and finished scans shown on the Nmap Output page.
        self.scans_store = ScansListStore()

        self.top_box = HIGVBox()

        self.__create_toolbar()
        self.__create_command_toolbar()

        self.select_default_profile()

        self.scan_result = ScanResult(self.inventory, self.scans_store,
                                      scan_interface=self)
        self.host_view_selection = self.scan_result.get_host_selection()
        self.service_view_selection = self.scan_result.get_service_selection()
        self.host_view_selection.connect(
                'changed', self.host_selection_changed)
        self.service_view_selection.connect(
                'changed', self.service_selection_changed)
        host_page = self.scan_result.scan_result_notebook.open_ports.host
        host_page.host_view.get_selection().connect(
                'changed', self.service_host_selection_changed)
        self.host_view_selection.connect(
                'changed', self.host_selection_changed)

        self.scan_result.scan_result_notebook.nmap_output.connect(
                "changed", self._displayed_scan_change_cb)
        self.scan_result.scan_result_notebook.scans_list.remove_button.connect(
                "clicked", self._remove_scan_cb)

        # The hosts dict maps hostnames (as returned by HostInfo.get_hostname)
        # to HostInfo objects.
        self.hosts = {}
        # The services dict maps service names ("http") to lists of dicts of
        # the form
        # {'host': <HostInfo object>, 'hostname': u'example.com',
        #  'port_state': u'open', 'portid': u'22', 'protocol': u'tcp',
        #  'service_conf': u'10', 'service_extrainfo': u'protocol 2.0',
        #  'service_method': u'probed', 'service_name': u'ssh',
        #  'service_product': u'OpenSSH', 'service_version': u'4.3'}
        # In other words each dict has the same keys as an entry in
        # HostInfo.ports, with the addition of "host" and "hostname" keys.
        self.services = {}

        self.top_box.set_border_width(6)
        self.top_box.set_spacing(5)

        self.top_box._pack_noexpand_nofill(self.toolbar)
        self.top_box._pack_noexpand_nofill(self.command_toolbar)

        self._pack_noexpand_nofill(self.top_box)
        self._pack_expand_fill(self.scan_result)

        self.scan_result.scan_result_notebook.scans_list.cancel_button.connect(
                "clicked", self._cancel_scans_list_cb)
        self.update_cancel_button()

        # Create the filter GUI
        self.filter_bar = FilterBar()
        self.pack_start(self.filter_bar, False, True, 0)
        self.filter_bar.set_no_show_all(True)

        self.filter_timeout_id = None

        self.filter_bar.connect("changed", self.filter_changed)
        self.scan_result.filter_toggle_button.connect("toggled",
            self.filter_toggle_toggled)
        self.scan_result.filter_toggle_button.show()

    def toggle_filter_bar(self):
        self.scan_result.filter_toggle_button.clicked()

    def filter_toggle_toggled(self, widget):
        if self.scan_result.filter_toggle_button.get_active():
            # Show the filter bar
            self.filter_bar.show()
            self.filter_bar.grab_focus()
            self.filter_hosts(self.filter_bar.get_filter_string())
        else:
            # Hide the filter bar
            self.filter_bar.hide()
            self.filter_hosts("")

        self.update_ui()

    def filter_changed(self, filter_bar):
        # Restart the timer to start the filter.
        if self.filter_timeout_id:
            GLib.source_remove(self.filter_timeout_id)
        self.filter_timeout_id = GLib.timeout_add(
                self.FILTER_DELAY, self.filter_hosts,
                filter_bar.get_filter_string())

    def filter_hosts(self, filter_string):
        start = time.perf_counter()
        self.inventory.apply_filter(filter_string)
        filter_time = time.perf_counter() - start
        # Update the gui
        start = time.perf_counter()
        self.update_ui()
        gui_time = time.perf_counter() - start

        if filter_time + gui_time > 0.0:
            log.debug("apply_filter %g ms  update_ui %g ms (%.0f%% filter)" %
                (filter_time * 1000.0, gui_time * 1000.0,
                100.0 * filter_time / (filter_time + gui_time)))

        self.filter_timeout_id = None
        return False

    def is_changed(self):
        """Return true if this window has unsaved changes."""
        for scan in self.inventory.get_scans():
            if scan.unsaved:
                return True
        return False
    changed = property(is_changed)

    def num_scans_running(self):
        return len(self.jobs)

    def select_default_profile(self):
        """Select a "default" profile. Currently this is defined to be the
        first profile."""
        if len(self.toolbar.profile_entry.get_model()) > 0:
            self.toolbar.profile_entry.set_active(0)

    def go_to_host(self, hostname):
        """Scroll the text output to the appearance of the named host."""
        self.scan_result.scan_result_notebook.nmap_output.nmap_output.go_to_host(hostname)  # noqa

    def __create_toolbar(self):
        self.toolbar = ScanToolbar()

        self.target_entry_changed_handler = self.toolbar.target_entry.connect(
                'changed', self._target_entry_changed)
        self.profile_entry_changed_handler = \
            self.toolbar.profile_entry.connect(
                    'changed', self._profile_entry_changed)

        self.toolbar.scan_button.connect('clicked', self.start_scan_cb)
        self.toolbar.cancel_button.connect('clicked', self._cancel_scan_cb)

    def __create_command_toolbar(self):
        self.command_toolbar = ScanCommandToolbar()
        self.command_toolbar.command_entry.connect(
                'activate', lambda x: self.toolbar.scan_button.clicked())
        self.command_entry_changed_handler = \
            self.command_toolbar.command_entry.connect(
                    'changed', self._command_entry_changed)

    def _command_entry_changed(self, editable):
        ops = NmapOptions()
        ops.parse_string(self.command_toolbar.get_command())

        # Set the target and profile without propagating the "changed" signal
        # back to the command entry.
        self.set_target_quiet(join_quoted(ops.target_specs))
        self.set_profile_name_quiet("")

    def _target_entry_changed(self, editable):
        target_string = self.toolbar.get_selected_target()
        targets = split_quoted(target_string)

        ops = NmapOptions()
        ops.parse_string(self.command_toolbar.get_command())
        ops.target_specs = targets
        self.set_command_quiet(ops.render_string())

    def _profile_entry_changed(self, widget):
        """Update the command based on the contents of the target and profile
        entries. If the command corresponding to the current profile is not
        blank, use it. Otherwise use the current contents of the command
        entry."""
        profile_name = self.toolbar.get_selected_profile()
        target_string = self.toolbar.get_selected_target()

        cmd_profile = CommandProfile()
        command_string = cmd_profile.get_command(profile_name)
        del(cmd_profile)
        if command_string == "":
            command_string = self.command_toolbar.get_command()

        ops = NmapOptions()
        ops.parse_string(command_string)

        # Use the targets from the command entry, if there are any, otherwise
        # use any targets from the profile.
        targets = split_quoted(target_string)
        if len(targets) > 0:
            ops.target_specs = targets
        else:
            self.toolbar.set_selected_target(join_quoted(ops.target_specs))

        self.set_command_quiet(ops.render_string())

    def set_command_quiet(self, command_string):
        """Set the command used by this scan interface, ignoring any further
        "changed" signals."""
        self.command_toolbar.command_entry.handler_block(
                self.command_entry_changed_handler)
        self.command_toolbar.set_command(command_string)
        self.command_toolbar.command_entry.handler_unblock(
                self.command_entry_changed_handler)

    def set_target_quiet(self, target_string):
        """Set the target string used by this scan interface, ignoring any
        further "changed" signals."""
        self.toolbar.target_entry.handler_block(
                self.target_entry_changed_handler)
        self.toolbar.set_selected_target(target_string)
        self.toolbar.target_entry.handler_unblock(
                self.target_entry_changed_handler)

    def set_profile_name_quiet(self, profile_name):
        """Set the profile name used by this scan interface, ignoring any
        further "changed" signals."""
        self.toolbar.profile_entry.handler_block(
                self.profile_entry_changed_handler)
        self.toolbar.set_selected_profile(profile_name)
        self.toolbar.profile_entry.handler_unblock(
                self.profile_entry_changed_handler)

    def start_scan_cb(self, widget=None):
        target = self.toolbar.selected_target
        command = self.command_toolbar.command
        profile = self.toolbar.selected_profile

        log.debug(">>> Start Scan:")
        log.debug(">>> Target: '%s'" % target)
        log.debug(">>> Profile: '%s'" % profile)
        log.debug(">>> Command: '%s'" % command)

        if target != '':
            try:
                self.toolbar.add_new_target(target)
            except IOError as e:
                # We failed to save target_list.txt; treat it as read-only.
                # Probably it's owned by root and this is a normal user.
                log.debug(">>> Error saving %s: %s" % (
                    Path.target_list, str(e)))

        if command == '':
            warn_dialog = HIGAlertDialog(
                    message_format=_("Empty Nmap Command"),
                    secondary_text=_("There is no command to execute. "
                        "Maybe the selected/typed profile doesn't exist. "
                        "Please check the profile name or type the nmap "
                        "command you would like to execute."),
                    type=Gtk.MessageType.ERROR)
            warn_dialog.run()
            warn_dialog.destroy()
            return

        self.execute_command(command, target, profile)

    def _displayed_scan_change_cb(self, widget):
        self.update_cancel_button()

    def update_cancel_button(self):
        """Make the Cancel button sensitive or not depending on whether the
        currently displayed scan is running."""
        entry = self.scan_result.scan_result_notebook.nmap_output.get_active_entry()  # noqa
        if entry is None:
            self.toolbar.cancel_button.set_sensitive(False)
        else:
            self.toolbar.cancel_button.set_sensitive(entry.running)

    def _cancel_scan_cb(self, widget):
        """Cancel the scan whose output is shown."""
        entry = self.scan_result.scan_result_notebook.nmap_output.get_active_entry()  # noqa
        if entry is not None and entry.running:
            self.cancel_scan(entry.command)

    def _cancel_scans_list_cb(self, widget):
        """This is like _cancel_scan_cb, but it cancels the scans that are
        currently selected in the scans list, not the one whose output is
        currently shown."""
        model, selection = self.scan_result.scan_result_notebook.scans_list.scans_list.get_selection().get_selected_rows()  # noqa
        for path in selection:
            entry = model.get_value(model.get_iter(path), 0)
            if entry.running:
                self.cancel_scan(entry.command)

    def _remove_scan_cb(self, widget):
        model, selection = self.scan_result.scan_result_notebook.scans_list.scans_list.get_selection().get_selected_rows()  # noqa
        selected_refs = []
        for path in selection:
            # Kill running scans and remove finished scans from the inventory.
            entry = model.get_value(model.get_iter(path), 0)
            if entry.running:
                self.cancel_scan(entry.command)
            try:
                # Remove it from the inventory if present.
                self.inventory.remove_scan(entry.parsed)
            except ValueError:
                pass
            # Create TreeRowReferences because those persist while we change
            # the model.
            selected_refs.append(Gtk.TreeRowReference.new(model, path))
        # Delete the entries from the ScansListStore.
        for ref in selected_refs:
            model.remove(model.get_iter(ref.get_path()))
        self.update_ui()

    def collect_umit_info(self, command, parsed):
        parsed.profile_name = command.profile
        parsed.nmap_command = command.command

    def kill_all_scans(self):
        """Kill all running scans."""
        for scan in self.jobs:
            try:
                scan.kill()
            except AttributeError:
                pass
        del self.jobs[:]

    def cancel_scan(self, command):
        """Cancel a running scan."""
        self.scans_store.cancel_running_scan(command)
        command.kill()
        self.jobs.remove(command)
        self.update_cancel_button()

    def execute_command(self, command, target=None, profile=None):
        """Run the given Nmap command. Add it to the list of running scans.
        Schedule a timer to refresh the output and check the scan for
        completion."""
        try:
            command_execution = NmapCommand(command)
        except IOError as e:
            warn_dialog = HIGAlertDialog(
                        message_format=_("Error building command"),
                        secondary_text=_("Error message: %s") % str(e),
                        type=Gtk.MessageType.ERROR)
            warn_dialog.run()
            warn_dialog.destroy()
            return
        command_execution.profile = profile

        try:
            command_execution.run_scan()
        except OSError as e:
            text = e.strerror
            # Handle ENOENT specially.
            if e.errno == errno.ENOENT:
                # nmap_command_path comes from zenmapCore.NmapCommand.
                path_env = os.getenv("PATH")
                if path_env is None:
                    default_paths = []
                else:
                    default_paths = path_env.split(os.pathsep)
                text += "\n\n{}\n\n{}".format(
                        _("This means that the nmap executable was "
                            "not found in your system PATH, which is"),
                        path_env or _("<undefined>")
                        )
                extra_paths = get_extra_executable_search_paths()
                extra_paths = [p for p in extra_paths if (
                    p not in default_paths)]
                if len(extra_paths) > 0:
                    if len(extra_paths) == 1:
                        text += "\n\n" + _("plus the extra directory")
                    else:
                        text += "\n\n" + _("plus the extra directories")
                    text += "\n\n" + os.pathsep.join(extra_paths)
            else:
                text += " (%d)" % e.errno
            warn_dialog = HIGAlertDialog(
                message_format=_("Error executing command"),
                secondary_text=text, type=Gtk.MessageType.ERROR)
            warn_dialog.run()
            warn_dialog.destroy()
            return
        except Exception as e:
            warn_dialog = HIGAlertDialog(
                message_format=_("Error executing command"),
                secondary_text=str(e),
                type=Gtk.MessageType.ERROR)
            warn_dialog.run()
            warn_dialog.destroy()
            return

        log.debug("Running command: %s" % command_execution.command)
        self.jobs.append(command_execution)

        i = self.scans_store.add_running_scan(command_execution)
        self.scan_result.scan_result_notebook.nmap_output.set_active_iter(i)

        # When scan starts, change to nmap output view tab and refresh output
        self.scan_result.change_to_nmap_output_tab()
        self.scan_result.refresh_nmap_output()

        # Add a timeout function
        self.verify_thread_timeout_id = GLib.timeout_add(
            NMAP_OUTPUT_REFRESH_INTERVAL, self.verify_execution)

    def verify_execution(self):
        """This is a callback that is called periodically to refresh the output
        check whether any running scans have finished. The timer that schedules
        the callback is started in execute_command. When there are no more
        running scans, this function returns True so that it won't be scheduled
        again."""
        self.scan_result.refresh_nmap_output()

        finished_jobs = []
        for scan in self.jobs:
            try:
                alive = scan.scan_state()
                if alive:
                    continue
            except Exception as e:
                log.debug("Scan terminated unexpectedly: %s (%s)" % (scan.command, e))
                self.scans_store.fail_running_scan(scan)
            else:
                log.debug("Scan finished: %s" % scan.command)
                self.load_from_command(scan)
                scan.close()
            self.update_cancel_button()
            finished_jobs.append(scan)

        # Remove finished jobs from the job list
        for finished in finished_jobs:
            self.jobs.remove(finished)
        del(finished_jobs)

        return len(self.jobs) != 0

    def load_from_command(self, command):
        """Load scan results from a completed NmapCommand."""
        parsed = NmapParser()
        try:
            parsed.parse_file(command.get_xml_output_filename())
        except IOError as e:
            # It's possible to run Nmap without generating an XML output file,
            # like with "nmap -V".
            if e.errno != errno.ENOENT:
                raise
        except xml.sax.SAXParseException as e:
            try:
                # Some options like --iflist cause Nmap to emit an empty XML
                # file. Ignore the exception in this case.
                st = os.stat(command.get_xml_output_filename())
            except Exception:
                st = None
            if st is None or st.st_size > 0:
                warn_dialog = HIGAlertDialog(
                        message_format=_("Parse error"),
                        secondary_text=_(
                            "There was an error while parsing the XML file "
                            "generated from the scan:\n\n%s""") % str(e),
                        type=Gtk.MessageType.ERROR)
                warn_dialog.run()
                warn_dialog.destroy()
        else:
            parsed.unsaved = True

            self.scan_result.refresh_nmap_output()
            try:
                self.inventory.add_scan(parsed)
            except Exception as e:
                warn_dialog = HIGAlertDialog(
                        message_format=_("Cannot merge scan"),
                        secondary_text=_(
                            "There was an error while merging the new scan's "
                            "XML:\n\n%s") % str(e),
                        type=Gtk.MessageType.ERROR)
                warn_dialog.run()
                warn_dialog.destroy()
        parsed.set_xml_is_temp(command.xml_is_temp)
        self.collect_umit_info(command, parsed)
        try:
            parsed.nmap_output = command.get_output()
        except MemoryError:
            self.scan_result.scan_result_notebook.nmap_output.nmap_output.show_large_output_message(command)  # noqa
        self.update_ui()
        self.scans_store.finish_running_scan(command, parsed)

    def load_from_file(self, filename):
        """Load scan results from a saved file."""
        parsed = NmapParser()
        parsed.parse(filename)
        parsed.unsaved = False

        self.update_target_profile(parsed)
        self.inventory.add_scan(parsed, filename=filename)
        self.update_ui()
        i = self.scans_store.add_scan(parsed)
        log.info("scans_store.add_scan")
        self.scan_result.scan_result_notebook.nmap_output.set_active_iter(i)
        self.scan_result.change_to_ports_hosts_tab()

    def load_from_parsed_result(self, parsed_result):
        """Load scan results from a parsed NmapParser object."""
        parsed = parsed_result
        parsed.unsaved = False

        self.update_target_profile(parsed)
        self.inventory.add_scan(parsed)
        self.update_ui()
        i = self.scans_store.add_scan(parsed)
        self.scan_result.scan_result_notebook.nmap_output.set_active_iter(i)
        self.scan_result.change_to_ports_hosts_tab()

    def update_target_profile(self, parsed):
        """Update the "Target" and "Profile" entries based on the contents of a
        parsed scan."""
        targets = parsed.get_targets()
        profile_name = parsed.get_profile_name()

        self.set_command_quiet(parsed.get_nmap_command() or "")
        self.set_target_quiet(join_quoted(targets))
        self.set_profile_name_quiet(profile_name or "")

    def update_ui(self):
        """Update the interface's lists of hosts and ports from a parsed
        scan."""
        self.empty = False

        up_hosts = self.inventory.get_hosts_up()

        self.scan_result.scan_host_view.mass_update(up_hosts)

        self.scan_result.scan_result_notebook.topology.update_radialnet()

        self.hosts = {}
        self.services = {}
        for host in up_hosts:
            hostname = host.get_hostname()

            for service in host.services:
                name = service["service_name"]

                if name not in self.services.keys():
                    self.services[name] = []

                hs = {"host": host, "hostname": hostname}
                hs.update(service)

                self.services[name].append(hs)

            self.hosts[hostname] = host

        # If the host and service selection is empty or has become empty,
        # select the first host if there is at least one.
        if (len(self.service_view_selection.get_selected_rows()[1]) == 0 and
                len(self.host_view_selection.get_selected_rows()[1]) == 0 and
                len(self.scan_result.scan_host_view.host_list) > 0):
            self.host_view_selection.select_iter(
                self.scan_result.scan_host_view.host_list.get_iter_first())

        self.filter_bar.set_information_text(_("%d/%d hosts shown") %
            (len(self.inventory.get_hosts_up()),
             len(NetworkInventory.get_hosts_up(self.inventory))))

        mode = self.scan_result.scan_host_view.mode
        if mode == ScanHostsView.HOST_MODE:
            self.refresh_port_output()
        elif mode == ScanHostsView.SERVICE_MODE:
            self.refresh_host_output()

    def refresh_port_output(self):
        """Refresh the "Ports" output of the "Ports / Hosts" tab to reflect the
        current host selection."""
        self.scan_result.scan_result_notebook.port_mode()

        model_host_list, selection = \
                self.host_view_selection.get_selected_rows()
        host_objs = []
        for i in selection:
            hostname = model_host_list[i[0]][2]
            if hostname in self.hosts:
                host_objs.append(self.hosts[hostname])

        if len(host_objs) == 1:
            self.set_single_host_port(host_objs[0])
        else:
            self.set_multiple_host_port(host_objs)
        self.switch_host_details(self.build_host_details(host_objs))

    def refresh_host_output(self):
        """Refresh the "Hosts" output of the "Ports / Hosts" tab to reflect the
        current service selection."""
        self.scan_result.scan_result_notebook.host_mode()

        model_service_list, selection = \
                self.service_view_selection.get_selected_rows()
        serv_objs = []
        for i in selection:
            key = model_service_list[i[0]][0]
            if key in self.services:
                serv_objs.append(self.services[key])

        # Each element of serv_objs is a list of port dicts.
        if len(serv_objs) == 1:
            self.set_single_service_host(serv_objs[0])
        else:
            servs = []
            for s in serv_objs:
                servs.append({
                    "service_name": s[0]["service_name"],
                    "ports": s})
            self.set_multiple_service_host(servs)

    def host_selection_changed(self, widget):
        self.refresh_port_output()
        # Switch nmap output to show first host occurrence
        model, selection = self.host_view_selection.get_selected_rows()
        for path in selection:
            self.go_to_host(model[path][2])
            break

    def service_selection_changed(self, widget):
        self.refresh_host_output()
        # Change scan tab to "Ports/Hosts"
        self.scan_result.change_to_ports_hosts_tab()

    def service_host_selection_changed(self, selection):
        """This is the callback called when the view is in "Services" mode and
        the user changes the selection among the many hosts displayed for a
        given service."""
        model, selection = selection.get_selected_rows()
        host_objs = []
        for path in selection:
            host_objs.append(model.get_value(model.get_iter(path), 2))
        self.switch_host_details(self.build_host_details(host_objs))

    def switch_host_details(self, pages):
        """Switch the "Host Details" view to show the ScanHostDetailsPages in
        the given list."""
        vbox = self.scan_result.scan_result_notebook.host_details_vbox

        # Remove the old children.
        for child in vbox.get_children():
            vbox.remove(child)

        for p in pages:
            p.set_expanded(False)
            vbox._pack_noexpand_nofill(p)
        if len(pages) == 1:
            pages[0].set_expanded(True)
        vbox.show_all()

    def _save_comment(self, widget, extra, host):
        """Sets the comment on a host from the contents of the comment text
        entry."""
        buff = widget.get_buffer()
        comment = buff.get_text(
                buff.get_start_iter(), buff.get_end_iter())
        if host.comment == comment:
            # no change, ignore
            return
        host.comment = comment
        for scan in self.inventory.get_scans():
            for h in scan.get_hosts():
                if (h.get_ip() == host.get_ip() and
                        h.get_ipv6() == host.get_ipv6()):
                    h.set_comment(host.comment)
                    scan.unsaved = True
                    break

    def build_host_details(self, hosts):
        """Builds and returns a list of "Host Details" pages corresponding to
        the given hosts."""
        pages = []
        for host in hosts:
            page = ScanHostDetailsPage(host)
            page.host_details.comment_txt_vw.connect(
                    "insert-at-cursor", self._save_comment, host)
            page.host_details.comment_txt_vw.connect(
                    "focus-out-event", self._save_comment, host)
            pages.append(page)
        return pages

    def set_single_host_port(self, host):
        """Change the "Ports / Hosts" tab to show the port output from the
        single given host."""
        host_page = self.scan_result.scan_result_notebook.open_ports.host
        host_page.switch_port_to_list_store()

        host_page.freeze()
        host_page.clear_port_list()
        for p in host.ports:
            host_page.add_to_port_list(p)
        host_page.thaw()

    def set_single_service_host(self, service):
        """Change the "Ports / Hosts" tab to show the hosts associated with the
        single named service."""
        host_page = self.scan_result.scan_result_notebook.open_ports.host
        host_page.switch_host_to_list_store()

        host_page.freeze()
        host_page.clear_host_list()
        for p in service:
            host_page.add_to_host_list(p["host"], p)
        host_page.thaw()

    def set_multiple_host_port(self, host_list):
        """Change the "Ports / Hosts" tab to show the port output for all of
        the hosts in host_list. When multiple hosts are selected, the port
        output for each is contained in an expander."""
        host_page = self.scan_result.scan_result_notebook.open_ports.host
        host_page.switch_port_to_tree_store()

        host_page.freeze()
        host_page.clear_port_tree()
        for host in host_list:
            host_page.add_to_port_tree(host)
        host_page.thaw()

    def set_multiple_service_host(self, service_list):
        """Change the "Ports / Hosts" tab to show the hosts associated with
        each of the services in service_list. Each element of service_list must
        be a dict with the keys "service_name" and "ports". When multiple
        services are selected, the hosts for each are contained in an
        expander."""
        host_page = self.scan_result.scan_result_notebook.open_ports.host
        host_page.switch_host_to_tree_store()

        host_page.freeze()
        host_page.clear_host_tree()
        for service in service_list:
            host_page.add_to_host_tree(
                    service["service_name"], service["ports"])
        host_page.thaw()


class ScanResult(Gtk.Paned):
    """This is the pane that has the "Host"/"Service" column (ScanHostsView) on
    the left and the "Nmap Output"/"Ports / Hosts"/etc. (ScanResultNotebook) on
    the right. It's the part of the interface below the toolbar."""
    def __init__(self, inventory, scans_store, scan_interface=None):
        Gtk.Paned.__init__(self, orientation=Gtk.Orientation.HORIZONTAL)

        self.scan_host_view = ScanHostsView(scan_interface)
        self.scan_result_notebook = ScanResultNotebook(inventory, scans_store)
        self.filter_toggle_button = Gtk.ToggleButton.new_with_label(_("Filter Hosts"))

        vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)
        vbox.pack_start(self.scan_host_view, True, True, 0)
        vbox.pack_start(self.filter_toggle_button, False, True, 0)
        self.pack1(vbox)
        self.pack2(self.scan_result_notebook, True, False)

    def set_nmap_output(self, msg):
        self.scan_result_notebook.nmap_output.nmap_output.text_view.get_buffer().set_text(msg)  # noqa

    def clear_nmap_output(self):
        self.scan_result_notebook.nmap_output.nmap_output.text_view.get_buffer().set_text("")  # noqa

    def get_host_selection(self):
        return self.scan_host_view.host_view.get_selection()

    def get_service_selection(self):
        return self.scan_host_view.service_view.get_selection()

    def get_nmap_output(self):
        return self.scan_result_notebook.nmap_output.get_nmap_output()

    def clear_port_list(self):
        self.scan_result_notebook.open_ports.host.clear_port_list()

    def change_to_ports_hosts_tab(self):
        self.scan_result_notebook.set_current_page(1)

    def change_to_nmap_output_tab(self):
        self.scan_result_notebook.set_current_page(0)

    def refresh_nmap_output(self):
        """Refresh the Nmap output with the newest output of command_execution,
        if it is not None."""
        self.scan_result_notebook.nmap_output.nmap_output.refresh_output()


class ScanResultNotebook(HIGNotebook):
    """This is the right side of a ScanResult, the notebook with the tabs such
    as "Nmap Output"."""
    def __init__(self, inventory, scans_store):
        HIGNotebook.__init__(self)
        self.set_border_width(5)

        self.__create_widgets(inventory, scans_store)

        self.scans_list.scans_list.connect(
                "row-activated", self._scan_row_activated)

        self.append_page(self.nmap_output_page, Gtk.Label.new(_('Nmap Output')))
        self.append_page(self.open_ports_page, Gtk.Label.new(_('Ports / Hosts')))
        self.append_page(self.topology_page, Gtk.Label.new(_('Topology')))
        self.append_page(self.host_details_page, Gtk.Label.new(_('Host Details')))
        self.append_page(self.scans_list_page, Gtk.Label.new(_('Scans')))

    def host_mode(self):
        self.open_ports.host.host_mode()

    def port_mode(self):
        self.open_ports.host.port_mode()

    def __create_widgets(self, inventory, scans_store):
        self.open_ports_page = HIGVBox()
        self.nmap_output_page = HIGVBox()
        self.topology_page = HIGVBox()
        self.host_details_page = HIGScrolledWindow()
        self.host_details_vbox = HIGVBox()
        self.scans_list_page = HIGVBox()

        self.open_ports = ScanOpenPortsPage()
        self.nmap_output = ScanNmapOutputPage(scans_store)
        self.topology = TopologyPage(inventory)
        self.scans_list = ScanScanListPage(scans_store)

        self.no_selected = Gtk.Label.new(_('No host selected.'))
        self.host_details = self.no_selected

        self.open_ports_page.add(self.open_ports)
        self.nmap_output_page.add(self.nmap_output)
        self.topology_page.add(self.topology)
        self.scans_list_page.add(self.scans_list)

        self.host_details_page.add_with_viewport(self.host_details_vbox)
        self.host_details_vbox._pack_expand_fill(self.host_details)

    def _scan_row_activated(self, treeview, path, view_column):
        """Switch back to the Nmap Output view when a scan is activated
        (double-clicked) on the scans list."""
        self.nmap_output.set_active_iter(treeview.get_model().get_iter(path))
        self.set_current_page(0)
