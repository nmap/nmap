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

from zenmapCore.UmitLogging import log
import zenmapCore.I18N  # lgtm[py/unused-import]


def findout_service_icon(port_info):
    if port_info["port_state"] in ["open", "open|filtered"]:
        return Gtk.STOCK_YES
    else:
        return Gtk.STOCK_NO


def get_version_string(d):
    """Get a human-readable version string from the dict d. The keys used in d
    are "service_product", "service_version", and "service_extrainfo" (all are
    optional). This produces a string like "OpenSSH 4.3p2 Debian 9etch2
    (protocol 2.0)"."""
    result = []
    if d.get("service_product"):
        result.append(d["service_product"])
    if d.get("service_version"):
        result.append(d["service_version"])
    if d.get("service_extrainfo"):
        result.append("(" + d["service_extrainfo"] + ")")
    return " ".join(result)


def get_addrs(host):
    if host is None:
        return []
    return host.get_addrs_for_sort()


def cmp_addrs(host_a, host_b):
    def cmp(a, b):
        return (a > b) - (a < b)
    return cmp(get_addrs(host_a), get_addrs(host_b))


def cmp_port_list_addr(model, iter_a, iter_b, *_):
    host_a = model.get_value(iter_a, 0)
    host_b = model.get_value(iter_b, 0)
    return cmp_addrs(host_a, host_b)


def cmp_port_tree_addr(model, iter_a, iter_b, *_):
    host_a = model.get_value(iter_a, 0)
    host_b = model.get_value(iter_b, 0)
    return cmp_addrs(host_a, host_b)


def cmp_host_list_addr(model, iter_a, iter_b, *_):
    host_a = model.get_value(iter_a, 2)
    host_b = model.get_value(iter_b, 2)
    return cmp_addrs(host_a, host_b)


def cmp_host_tree_addr(model, iter_a, iter_b, *_):
    host_a = model.get_value(iter_a, 2)
    host_b = model.get_value(iter_b, 2)
    return cmp_addrs(host_a, host_b)


class ScanOpenPortsPage(Gtk.ScrolledWindow):
    def __init__(self):
        Gtk.ScrolledWindow.__init__(self)
        self.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.__create_widgets()

        self.add_with_viewport(self.host)

    def __create_widgets(self):
        self.host = HostOpenPorts()


class HostOpenPorts(HIGVBox):
    def __init__(self):
        HIGVBox.__init__(self)

        self._create_widgets()
        self._set_port_list()
        self._set_host_list()
        self._pack_widgets()

    def _create_widgets(self):
        # Ports view
        self.port_columns = {}
        # host hostname icon port protocol state service version
        # The hostname column is shown only when more than one host is selected
        # (hence port_tree not port_list is used).
        self.port_list = Gtk.ListStore.new([
                object, str, str, int, str, str, str, str])
        self.port_tree = Gtk.TreeStore.new([
                object, str, str, int, str, str, str, str])

        self.port_list.set_sort_func(1000, cmp_port_list_addr)
        self.port_list.set_sort_column_id(1000, Gtk.SortType.ASCENDING)
        self.port_tree.set_sort_func(1000, cmp_port_tree_addr)
        self.port_tree.set_sort_column_id(1000, Gtk.SortType.ASCENDING)

        self.port_view = Gtk.TreeView.new_with_model(self.port_list)

        self.cell_icon = Gtk.CellRendererPixbuf()
        self.cell_port = Gtk.CellRendererText()

        self.port_columns['hostname'] = Gtk.TreeViewColumn(title=_('Host'))
        self.port_columns['icon'] = Gtk.TreeViewColumn(title='')
        self.port_columns['port_number'] = Gtk.TreeViewColumn(title=_('Port'))
        self.port_columns['protocol'] = Gtk.TreeViewColumn(title=_('Protocol'))
        self.port_columns['state'] = Gtk.TreeViewColumn(title=_('State'))
        self.port_columns['service'] = Gtk.TreeViewColumn(title=_('Service'))
        self.port_columns['version'] = Gtk.TreeViewColumn(title=_('Version'))

        # Host services view
        self.host_columns = {}
        # service icon host hostname port protocol state version
        # service is shown only when more than one service is selected (hence
        # host_tree not host_list is used).
        self.host_list = Gtk.ListStore.new([
                str, str, object, str, int, str, str, str])
        self.host_tree = Gtk.TreeStore.new([
                str, str, object, str, int, str, str, str])

        self.host_list.set_sort_func(1000, cmp_host_list_addr)
        self.host_list.set_sort_column_id(1000, Gtk.SortType.ASCENDING)
        self.host_tree.set_sort_func(1000, cmp_host_tree_addr)
        self.host_tree.set_sort_column_id(1000, Gtk.SortType.ASCENDING)

        self.host_view = Gtk.TreeView.new_with_model(self.host_list)

        self.cell_host_icon = Gtk.CellRendererPixbuf()
        self.cell_host = Gtk.CellRendererText()

        self.host_columns['service'] = Gtk.TreeViewColumn(title=_('Service'))
        self.host_columns['icon'] = Gtk.TreeViewColumn(title='')
        self.host_columns['hostname'] = Gtk.TreeViewColumn(title=_('Hostname'))
        self.host_columns['protocol'] = Gtk.TreeViewColumn(title=_('Protocol'))
        self.host_columns['port_number'] = Gtk.TreeViewColumn(title=_('Port'))
        self.host_columns['state'] = Gtk.TreeViewColumn(title=_('State'))
        self.host_columns['version'] = Gtk.TreeViewColumn(title=_('Version'))

        self.scroll_ports_hosts = Gtk.ScrolledWindow()

    def _set_host_list(self):
        self.host_view.set_enable_search(True)
        self.host_view.set_search_column(2)

        selection = self.host_view.get_selection()
        selection.set_mode(Gtk.SelectionMode.MULTIPLE)

        columns = ["service", "icon", "hostname", "port_number",
                   "protocol", "state", "version"]

        for c in columns:
            self.host_view.append_column(self.host_columns[c])
            self.host_columns[c].set_reorderable(True)
            self.host_columns[c].set_resizable(True)

        self.host_columns['service'].set_sort_column_id(0)
        self.host_columns['icon'].set_min_width(35)
        self.host_columns['icon'].set_sort_column_id(6)
        self.host_columns['hostname'].set_sort_column_id(1000)
        self.host_columns['port_number'].set_sort_column_id(4)
        self.host_columns['protocol'].set_sort_column_id(5)
        self.host_columns['state'].set_sort_column_id(6)
        self.host_columns['version'].set_sort_column_id(7)

        self.host_columns['service'].pack_start(self.cell_port, True)
        self.host_columns['icon'].pack_start(self.cell_host_icon, True)
        self.host_columns['hostname'].pack_start(self.cell_port, True)
        self.host_columns['port_number'].pack_start(self.cell_port, True)
        self.host_columns['protocol'].pack_start(self.cell_port, True)
        self.host_columns['version'].pack_start(self.cell_port, True)
        self.host_columns['state'].pack_start(self.cell_port, True)

        self.host_columns['service'].set_attributes(self.cell_port, text=0)
        self.host_columns['icon'].set_attributes(
                self.cell_host_icon, stock_id=1)
        self.host_columns['hostname'].set_attributes(self.cell_port, text=3)
        self.host_columns['port_number'].set_attributes(self.cell_port, text=4)
        self.host_columns['protocol'].set_attributes(self.cell_port, text=5)
        self.host_columns['state'].set_attributes(self.cell_port, text=6)
        self.host_columns['version'].set_attributes(self.cell_port, text=7)

        self.host_columns['service'].set_visible(False)

        self.scroll_ports_hosts.set_policy(
                Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

    def _set_port_list(self):
        self.port_view.set_enable_search(True)
        self.port_view.set_search_column(3)

        selection = self.port_view.get_selection()
        selection.set_mode(Gtk.SelectionMode.MULTIPLE)

        self.port_view.append_column(self.port_columns['hostname'])
        self.port_view.append_column(self.port_columns['icon'])
        self.port_view.append_column(self.port_columns['port_number'])
        self.port_view.append_column(self.port_columns['protocol'])
        self.port_view.append_column(self.port_columns['state'])
        self.port_view.append_column(self.port_columns['service'])
        self.port_view.append_column(self.port_columns['version'])

        for k in self.port_columns:
            self.port_columns[k].set_reorderable(True)
            self.port_columns[k].set_resizable(True)

        self.port_columns['icon'].set_min_width(35)

        self.port_columns['hostname'].set_sort_column_id(1000)
        self.port_columns['icon'].set_sort_column_id(5)
        self.port_columns['port_number'].set_sort_column_id(3)
        self.port_columns['protocol'].set_sort_column_id(4)
        self.port_columns['state'].set_sort_column_id(5)
        self.port_columns['service'].set_sort_column_id(6)
        self.port_columns['version'].set_sort_column_id(7)

        self.port_columns['hostname'].pack_start(self.cell_port, True)
        self.port_columns['icon'].pack_start(self.cell_icon, True)
        self.port_columns['port_number'].pack_start(self.cell_port, True)
        self.port_columns['protocol'].pack_start(self.cell_port, True)
        self.port_columns['service'].pack_start(self.cell_port, True)
        self.port_columns['version'].pack_start(self.cell_port, True)
        self.port_columns['state'].pack_start(self.cell_port, True)

        self.port_columns['hostname'].set_attributes(self.cell_port, text=1)
        self.port_columns['icon'].set_attributes(self.cell_icon, stock_id=2)
        self.port_columns['port_number'].set_attributes(self.cell_port, text=3)
        self.port_columns['protocol'].set_attributes(self.cell_port, text=4)
        self.port_columns['state'].set_attributes(self.cell_port, text=5)
        self.port_columns['service'].set_attributes(self.cell_port, text=6)
        self.port_columns['version'].set_attributes(self.cell_port, text=7)

        self.port_columns['hostname'].set_visible(False)

        self.scroll_ports_hosts.set_policy(
                Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

    def port_mode(self):
        child = self.scroll_ports_hosts.get_child()
        if id(child) != id(self.port_view):
            if child is not None:
                self.scroll_ports_hosts.remove(child)
            self.scroll_ports_hosts.add(self.port_view)
            self.port_view.show_all()
            self.host_view.hide()

    def host_mode(self):
        child = self.scroll_ports_hosts.get_child()
        if id(child) != id(self.host_view):
            if child is not None:
                self.scroll_ports_hosts.remove(child)
            self.scroll_ports_hosts.add(self.host_view)
            self.host_view.show_all()
            self.port_view.hide()

    def freeze(self):
        """Freeze notifications and sorting to make adding lots of elements to
        the model faster."""
        self.frozen_host_list_sort_column_id = \
                self.host_list.get_sort_column_id()
        self.frozen_host_tree_sort_column_id = \
                self.host_tree.get_sort_column_id()
        self.frozen_port_list_sort_column_id = \
                self.port_list.get_sort_column_id()
        self.frozen_port_tree_sort_column_id = \
                self.port_tree.get_sort_column_id()
        self.host_list.set_default_sort_func(lambda *args: -1)
        self.host_tree.set_default_sort_func(lambda *args: -1)
        self.port_list.set_default_sort_func(lambda *args: -1)
        self.port_tree.set_default_sort_func(lambda *args: -1)
        self.frozen_host_view_model = self.host_view.get_model()
        self.frozen_port_view_model = self.port_view.get_model()
        self.host_view.freeze_child_notify()
        self.port_view.freeze_child_notify()
        self.host_view.set_model(None)
        self.port_view.set_model(None)

    def thaw(self):
        """Restore notifications and sorting (after making changes to the
        model)."""
        if self.frozen_host_list_sort_column_id != (None, None):
            self.host_list.set_sort_column_id(
                    *self.frozen_host_list_sort_column_id)
        if self.frozen_host_tree_sort_column_id != (None, None):
            self.host_tree.set_sort_column_id(
                    *self.frozen_host_tree_sort_column_id)
        if self.frozen_port_list_sort_column_id != (None, None):
            self.port_list.set_sort_column_id(
                    *self.frozen_port_list_sort_column_id)
        if self.frozen_port_tree_sort_column_id != (None, None):
            self.port_tree.set_sort_column_id(
                    *self.frozen_port_tree_sort_column_id)
        self.host_view.set_model(self.frozen_host_view_model)
        self.port_view.set_model(self.frozen_port_view_model)
        self.host_view.thaw_child_notify()
        self.port_view.thaw_child_notify()

    def add_to_port_list(self, p):
        entry = [None, "", findout_service_icon(p), int(p.get('portid', '0')),
            p.get('protocol', ''), p.get('port_state', ''),
            p.get('service_name', ''), get_version_string(p)]
        log.debug(">>> Add Port: %s" % entry)
        self.port_list.append(entry)

    def add_to_host_list(self, host, p):
        entry = ["", findout_service_icon(p), host, host.get_hostname(),
            int(p.get('portid', '0')), p.get('protocol', ''),
            p.get('port_state', ''), get_version_string(p)]
        log.debug(">>> Add Host: %s" % entry)
        self.host_list.append(entry)

    def add_to_port_tree(self, host):
        parent = self.port_tree.append(
                None, [host, host.get_hostname(), None, 0, '', '', '', ''])
        for p in host.get_ports():
            self.port_tree.append(parent,
                [None, '', findout_service_icon(p), int(p.get('portid', "0")),
                p.get('protocol', ''), p.get('port_state', ""),
                p.get('service_name', _("Unknown")), get_version_string(p)])

    def add_to_host_tree(self, service_name, ports):
        parent = self.host_tree.append(
                None, [service_name, '', None, '', 0, '', '', ''])
        for p in ports:
            self.host_tree.append(parent,
                    [
                        '',
                        findout_service_icon(p),
                        p["host"],
                        p["host"].get_hostname(),
                        int(p.get('portid', "0")),
                        p.get('protocol', ""),
                        p.get('port_state', _("unknown")),
                        get_version_string(p)
                    ]
                )

    def switch_port_to_list_store(self):
        if self.port_view.get_model() != self.port_list:
            self.port_view.set_model(self.port_list)
            self.port_columns['hostname'].set_visible(False)

    def switch_port_to_tree_store(self):
        if self.port_view.get_model() != self.port_tree:
            self.port_view.set_model(self.port_tree)
            self.port_columns['hostname'].set_visible(True)

    def switch_host_to_list_store(self):
        if self.host_view.get_model() != self.host_list:
            self.host_view.set_model(self.host_list)
            self.host_columns['service'].set_visible(False)

    def switch_host_to_tree_store(self):
        if self.host_view.get_model() != self.host_tree:
            self.host_view.set_model(self.host_tree)
            self.host_columns['service'].set_visible(True)

    def _pack_widgets(self):
        self.scroll_ports_hosts.add(self.port_view)
        self._pack_expand_fill(self.scroll_ports_hosts)

    def clear_port_list(self):
        for i in range(len(self.port_list)):
            iter = self.port_list.get_iter_first()
            del(self.port_list[iter])

    def clear_host_list(self):
        for i in range(len(self.host_list)):
            iter = self.host_list.get_iter_first()
            del(self.host_list[iter])

    def clear_port_tree(self):
        for i in range(len(self.port_tree)):
            iter = self.port_tree.get_iter_first()
            del(self.port_tree[iter])

    def clear_host_tree(self):
        for i in range(len(self.host_tree)):
            iter = self.host_tree.get_iter_first()
            del(self.host_tree[iter])

if __name__ == "__main__":
    w = Gtk.Window()
    h = HostOpenPorts()
    w.add(h)

    w.connect("delete-event", lambda x, y: Gtk.main_quit())
    w.show_all()
    Gtk.main()
