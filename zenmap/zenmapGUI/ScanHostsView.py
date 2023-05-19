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
from gi.repository import Gtk

from zenmapGUI.higwidgets.higboxes import HIGVBox
from zenmapGUI.Icons import get_os_icon
import zenmapCore.I18N  # lgtm[py/unused-import]


def treemodel_get_addrs_for_sort(model, iter):
    host = model.get_value(iter, 0)
    return host.get_addrs_for_sort()


# Used to sort hosts by address.
def cmp_treemodel_addr(model, iter_a, iter_b, *_):
    def cmp(a, b):
        return (a > b) - (a < b)
    addrs_a = treemodel_get_addrs_for_sort(model, iter_a)
    addrs_b = treemodel_get_addrs_for_sort(model, iter_b)
    return cmp(addrs_a, addrs_b)


class ScanHostsView(HIGVBox):
    HOST_MODE, SERVICE_MODE = list(range(2))

    def __init__(self, scan_interface):
        HIGVBox.__init__(self)

        self._scan_interface = scan_interface
        self._create_widgets()
        self._connect_widgets()
        self._pack_widgets()
        self._set_scrolled()
        self._set_host_list()
        self._set_service_list()

        self._pack_expand_fill(self.main_vbox)

        self.mode = None

        # Default mode is host mode
        self.host_mode(self.host_mode_button)

        self.host_view.show_all()
        self.service_view.show_all()

    def _create_widgets(self):
        # Mode buttons
        self.host_mode_button = Gtk.ToggleButton.new_with_label(_("Hosts"))
        self.service_mode_button = Gtk.ToggleButton.new_with_label(_("Services"))
        self.buttons_box = Gtk.Box.new(Gtk.Orientation.HORIZONTAL, 0)

        # Main window vbox
        self.main_vbox = HIGVBox()

        # Host list
        self.host_list = Gtk.ListStore.new([object, str, str])
        self.host_list.set_sort_func(1000, cmp_treemodel_addr)
        self.host_list.set_sort_column_id(1000, Gtk.SortType.ASCENDING)
        self.host_view = Gtk.TreeView.new_with_model(self.host_list)
        self.pic_column = Gtk.TreeViewColumn(title=_('OS'))
        self.host_column = Gtk.TreeViewColumn(title=_('Host'))
        self.os_cell = Gtk.CellRendererPixbuf()
        self.host_cell = Gtk.CellRendererText()

        # Service list
        self.service_list = Gtk.ListStore.new([str])
        self.service_list.set_sort_column_id(0, Gtk.SortType.ASCENDING)
        self.service_view = Gtk.TreeView.new_with_model(self.service_list)
        self.service_column = Gtk.TreeViewColumn(title=_('Service'))
        self.service_cell = Gtk.CellRendererText()

        self.scrolled = Gtk.ScrolledWindow()

    def _pack_widgets(self):
        self.main_vbox.set_spacing(0)
        self.main_vbox.set_border_width(0)
        self.main_vbox._pack_noexpand_nofill(self.buttons_box)
        self.main_vbox._pack_expand_fill(self.scrolled)

        self.host_mode_button.set_active(True)

        self.buttons_box.set_border_width(5)
        self.buttons_box.pack_start(self.host_mode_button, True, True, 0)
        self.buttons_box.pack_start(self.service_mode_button, True, True, 0)

    def _connect_widgets(self):
        self.host_mode_button.connect("toggled", self.host_mode)
        self.service_mode_button.connect("toggled", self.service_mode)

    def host_mode(self, widget):
        self._remove_scrolled_child()
        if widget.get_active():
            self.mode = self.HOST_MODE
            self.service_mode_button.set_active(False)
            self.scrolled.add(self.host_view)
        else:
            self.service_mode_button.set_active(True)

    def service_mode(self, widget):
        self._remove_scrolled_child()
        if widget.get_active():
            self.mode = self.SERVICE_MODE
            self.host_mode_button.set_active(False)
            self.scrolled.add(self.service_view)
        else:
            self.host_mode_button.set_active(True)

    def _remove_scrolled_child(self):
        try:
            child = self.scrolled.get_child()
            self.scrolled.remove(child)
        except Exception:
            pass

    def _set_scrolled(self):
        self.scrolled.set_border_width(5)
        self.scrolled.set_size_request(150, -1)
        self.scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

    def _set_service_list(self):
        self.service_view.set_enable_search(True)
        self.service_view.set_search_column(0)

        selection = self.service_view.get_selection()
        selection.set_mode(Gtk.SelectionMode.MULTIPLE)
        self.service_view.append_column(self.service_column)

        self.service_column.set_resizable(True)
        self.service_column.set_sort_column_id(0)
        self.service_column.set_reorderable(True)
        self.service_column.pack_start(self.service_cell, True)
        self.service_column.set_attributes(self.service_cell, text=0)

    def _set_host_list(self):
        self.host_view.set_enable_search(True)
        self.host_view.set_search_column(1)

        selection = self.host_view.get_selection()
        selection.set_mode(Gtk.SelectionMode.MULTIPLE)

        self.host_view.append_column(self.pic_column)
        self.host_view.append_column(self.host_column)

        self.host_column.set_resizable(True)
        self.pic_column.set_resizable(True)

        self.host_column.set_sort_column_id(1000)
        self.pic_column.set_sort_column_id(1)

        self.host_column.set_reorderable(True)
        self.pic_column.set_reorderable(True)

        self.pic_column.pack_start(self.os_cell, True)
        self.host_column.pack_start(self.host_cell, True)

        self.pic_column.set_min_width(35)
        self.pic_column.set_attributes(self.os_cell, stock_id=1)
        self.host_column.set_attributes(self.host_cell, text=2)

    def mass_update(self, hosts):
        """Update the internal ListStores to reflect the hosts and services
        passed in. Hosts that have not changed are left alone."""
        hosts = set(hosts)
        services = set()
        for h in hosts:
            services.update([s["service_name"] for s in h.services])

        # Disable sorting while elements are added. See the PyGTK FAQ 13.43,
        # "Are there tips for improving performance when adding many rows to a
        # Treeview?"
        sort_column_id = self.host_list.get_sort_column_id()
        self.host_list.set_default_sort_func(lambda *args: -1)
        self.host_list.set_sort_column_id(-1, Gtk.SortType.ASCENDING)
        self.host_view.freeze_child_notify()
        self.host_view.set_model(None)

        it = self.host_list.get_iter_first()
        # Remove any of our ListStore hosts that aren't in the list passed in.
        while it:
            host = self.host_list.get_value(it, 0)
            if host in hosts:
                hosts.remove(host)
                self.host_list.set(it, 1, get_os_icon(host))
                it = self.host_list.iter_next(it)
            else:
                if not self.host_list.remove(it):
                    it = None
        # Add any remaining hosts into our ListStore.
        for host in hosts:
            self.add_host(host)

        # Reenable sorting.
        if sort_column_id != (None, None):
            self.host_list.set_sort_column_id(*sort_column_id)
        self.host_view.set_model(self.host_list)
        self.host_view.thaw_child_notify()

        it = self.service_list.get_iter_first()
        # Remove any of our ListStore services that aren't in the list passed
        # in.
        while it:
            service_name = self.service_list.get_value(it, 0)
            if service_name in services:
                services.remove(service_name)
                it = self.service_list.iter_next(it)
            else:
                if not self.service_list.remove(it):
                    it = None
        # Add any remaining services into our ListStore.
        for service_name in services:
            self.add_service(service_name)

    def add_host(self, host):
        self.host_list.append([host, get_os_icon(host), host.get_hostname()])

    def add_service(self, service):
        self.service_list.append([service])

if __name__ == "__main__":
    w = Gtk.Window()
    h = ScanHostsView(None)
    w.add(h)

    w.connect("delete-event", lambda x, y: Gtk.main_quit())
    w.show_all()
    Gtk.main()
