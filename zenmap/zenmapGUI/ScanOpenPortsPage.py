#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
# * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
# * modify, and redistribute this software under certain conditions.  If    *
# * you wish to embed Nmap technology into proprietary software, we sell    *
# * alternative licenses (contact sales@nmap.com).  Dozens of software      *
# * vendors already license Nmap technology such as host discovery, port    *
# * scanning, OS detection, version detection, and the Nmap Scripting       *
# * Engine.                                                                 *
# *                                                                         *
# * Note that the GPL places important restrictions on "derivative works",  *
# * yet it does not provide a detailed definition of that term.  To avoid   *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
# * derivative work for the purpose of this license if it does any of the   *
# * following with any software or content covered by this license          *
# * ("Covered Software"):                                                   *
# *                                                                         *
# * o Integrates source code from Covered Software.                         *
# *                                                                         *
# * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
# * or nmap-service-probes.                                                 *
# *                                                                         *
# * o Is designed specifically to execute Covered Software and parse the    *
# * results (as opposed to typical shell or execution-menu apps, which will *
# * execute anything you tell them to).                                     *
# *                                                                         *
# * o Includes Covered Software in a proprietary executable installer.  The *
# * installers produced by InstallShield are an example of this.  Including *
# * Nmap with other software in compressed or archival form does not        *
# * trigger this provision, provided appropriate open source decompression  *
# * or de-archiving software is widely available for no charge.  For the    *
# * purposes of this license, an installer is considered to include Covered *
# * Software even if it actually retrieves a copy of Covered Software from  *
# * another source during runtime (such as by downloading it from the       *
# * Internet).                                                              *
# *                                                                         *
# * o Links (statically or dynamically) to a library which does any of the  *
# * above.                                                                  *
# *                                                                         *
# * o Executes a helper program, module, or script to do any of the above.  *
# *                                                                         *
# * This list is not exclusive, but is meant to clarify our interpretation  *
# * of derived works with some common examples.  Other people may interpret *
# * the plain GPL differently, so we consider this a special exception to   *
# * the GPL that we apply to Covered Software.  Works which meet any of     *
# * these conditions must conform to all of the terms of this license,      *
# * particularly including the GPL Section 3 requirements of providing      *
# * source code and allowing free redistribution of the work as a whole.    *
# *                                                                         *
# * As another special exception to the GPL terms, Insecure.Com LLC grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * Any redistribution of Covered Software, including any derived works,    *
# * must obey and carry forward all of the terms of this license, including *
# * obeying all GPL rules and restrictions.  For example, source code of    *
# * the whole work must be provided and free redistribution must be         *
# * allowed.  All GPL references to "this License", are to be treated as    *
# * including the terms and conditions of this license text as well.        *
# *                                                                         *
# * Because this license imposes special exceptions to the GPL, Covered     *
# * Work may not be combined (even as part of a larger work) with plain GPL *
# * software.  The terms, conditions, and exceptions of this license must   *
# * be included as well.  This license is incompatible with some other open *
# * source licenses as well.  In some cases we can relicense portions of    *
# * Nmap or grant special permissions to use it in other open source        *
# * software.  Please contact fyodor@nmap.org with any such requests.       *
# * Similarly, we don't incorporate incompatible open source software into  *
# * Covered Software without special permission from the copyright holders. *
# *                                                                         *
# * If you have any questions about the licensing restrictions on using     *
# * Nmap in other works, are happy to help.  As mentioned above, we also    *
# * offer alternative license to integrate Nmap into proprietary            *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@nmap.com for further *
# * information.                                                            *
# *                                                                         *
# * If you have received a written license agreement or contract for        *
# * Covered Software stating terms other than these, you may choose to use  *
# * and redistribute Covered Software under those terms instead of these.   *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes.          *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to the dev@nmap.org mailing list for possible incorporation into the    *
# * main distribution.  By sending these changes to Fyodor or one of the    *
# * Insecure.Org development mailing lists, or checking them into the Nmap  *
# * source code repository, it is understood (unless you specify otherwise) *
# * that you are offering the Nmap Project (Insecure.Com LLC) the           *
# * unlimited, non-exclusive right to reuse, modify, and relicense the      *
# * code.  Nmap will always be available Open Source, but this is important *
# * because the inability to relicense code has caused devastating problems *
# * for other Free Software projects (such as KDE and NASM).  We also       *
# * occasionally relicense the code to third parties as discussed above.    *
# * If you wish to specify special license conditions of your               *
# * contributions, just say so when you send them.                          *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
# * license file for more details (it's in a COPYING file included with     *
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
# *                                                                         *
# ***************************************************************************/

import gtk

from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox
from zenmapGUI.higwidgets.higtables import HIGTable

from zenmapCore.UmitLogging import log
import zenmapCore.I18N


def findout_service_icon(port_info):
    if port_info["port_state"] in ["open", "open|filtered"]:
        return gtk.STOCK_YES
    else:
        return gtk.STOCK_NO


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
        return None
    return host.get_addrs_for_sort()


def cmp_addrs(host_a, host_b):
    return cmp(get_addrs(host_a), get_addrs(host_b))


def cmp_port_list_addr(model, iter_a, iter_b):
    host_a = model.get_value(iter_a, 0)
    host_b = model.get_value(iter_b, 0)
    return cmp_addrs(host_a, host_b)


def cmp_port_tree_addr(model, iter_a, iter_b):
    host_a = model.get_value(iter_a, 0)
    host_b = model.get_value(iter_b, 0)
    return cmp_addrs(host_a, host_b)


def cmp_host_list_addr(model, iter_a, iter_b):
    host_a = model.get_value(iter_a, 2)
    host_b = model.get_value(iter_b, 2)
    return cmp_addrs(host_a, host_b)


def cmp_host_tree_addr(model, iter_a, iter_b):
    host_a = model.get_value(iter_a, 2)
    host_b = model.get_value(iter_b, 2)
    return cmp_addrs(host_a, host_b)


class ScanOpenPortsPage(gtk.ScrolledWindow):
    def __init__(self):
        gtk.ScrolledWindow.__init__(self)
        self.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)

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
        self.port_list = gtk.ListStore(
                object, str, str, int, str, str, str, str)
        self.port_tree = gtk.TreeStore(
                object, str, str, int, str, str, str, str)

        self.port_list.set_sort_func(1000, cmp_port_list_addr)
        self.port_list.set_sort_column_id(1000, gtk.SORT_ASCENDING)
        self.port_tree.set_sort_func(1000, cmp_port_tree_addr)
        self.port_tree.set_sort_column_id(1000, gtk.SORT_ASCENDING)

        self.port_view = gtk.TreeView(self.port_list)

        self.cell_icon = gtk.CellRendererPixbuf()
        self.cell_port = gtk.CellRendererText()

        self.port_columns['hostname'] = gtk.TreeViewColumn(_('Host'))
        self.port_columns['icon'] = gtk.TreeViewColumn('')
        self.port_columns['port_number'] = gtk.TreeViewColumn(_('Port'))
        self.port_columns['protocol'] = gtk.TreeViewColumn(_('Protocol'))
        self.port_columns['state'] = gtk.TreeViewColumn(_('State'))
        self.port_columns['service'] = gtk.TreeViewColumn(_('Service'))
        self.port_columns['version'] = gtk.TreeViewColumn(_('Version'))

        # Host services view
        self.host_columns = {}
        # service icon host hostname port protocol state version
        # service is shown only when more than one service is selected (hence
        # host_tree not host_list is used).
        self.host_list = gtk.ListStore(
                str, str, object, str, int, str, str, str)
        self.host_tree = gtk.TreeStore(
                str, str, object, str, int, str, str, str)

        self.host_list.set_sort_func(1000, cmp_host_list_addr)
        self.host_list.set_sort_column_id(1000, gtk.SORT_ASCENDING)
        self.host_tree.set_sort_func(1000, cmp_host_tree_addr)
        self.host_tree.set_sort_column_id(1000, gtk.SORT_ASCENDING)

        self.host_view = gtk.TreeView(self.host_list)

        self.cell_host_icon = gtk.CellRendererPixbuf()
        self.cell_host = gtk.CellRendererText()

        self.host_columns['service'] = gtk.TreeViewColumn(_('Service'))
        self.host_columns['icon'] = gtk.TreeViewColumn('')
        self.host_columns['hostname'] = gtk.TreeViewColumn(_('Hostname'))
        self.host_columns['protocol'] = gtk.TreeViewColumn(_('Protocol'))
        self.host_columns['port_number'] = gtk.TreeViewColumn(_('Port'))
        self.host_columns['state'] = gtk.TreeViewColumn(_('State'))
        self.host_columns['version'] = gtk.TreeViewColumn(_('Version'))

        self.scroll_ports_hosts = gtk.ScrolledWindow()

    def _set_host_list(self):
        self.host_view.set_enable_search(True)
        self.host_view.set_search_column(2)

        selection = self.host_view.get_selection()
        selection.set_mode(gtk.SELECTION_MULTIPLE)

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
                gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)

    def _set_port_list(self):
        self.port_view.set_enable_search(True)
        self.port_view.set_search_column(3)

        selection = self.port_view.get_selection()
        selection.set_mode(gtk.SELECTION_MULTIPLE)

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
                gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)

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
                        p.get('port_state', _("Unknown")),
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
            iter = self.port_list.get_iter_root()
            del(self.port_list[iter])

    def clear_host_list(self):
        for i in range(len(self.host_list)):
            iter = self.host_list.get_iter_root()
            del(self.host_list[iter])

    def clear_port_tree(self):
        for i in range(len(self.port_tree)):
            iter = self.port_tree.get_iter_root()
            del(self.port_tree[iter])

    def clear_host_tree(self):
        for i in range(len(self.host_tree)):
            iter = self.host_tree.get_iter_root()
            del(self.host_tree[iter])

if __name__ == "__main__":
    w = gtk.Window()
    h = HostOpenPorts()
    w.add(h)
    w.show_all()

    gtk.main()
