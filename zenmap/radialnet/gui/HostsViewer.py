# vim: set fileencoding=utf-8 :

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

import re

from radialnet.bestwidgets.windows import BWMainWindow

from radialnet.gui.NodeNotebook import NodeNotebook
from radialnet.util.misc import ipv4_compare


HOSTS_COLORS = ['#d5ffd5', '#ffffd5', '#ffd5d5']

HOSTS_HEADER = ['ID', '#', 'Hosts']

DIMENSION = (700, 400)

IP_RE = re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')


class HostsViewer(BWMainWindow):
    """
    """
    def __init__(self, nodes):
        """
        """
        BWMainWindow.__init__(self)
        self.set_title(_('Hosts Viewer'))
        self.set_default_size(DIMENSION[0], DIMENSION[1])

        self.__nodes = nodes
        self.__default_view = Gtk.Label.new(_("No node selected"))
        self.__view = self.__default_view

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__panel = Gtk.Paned.new(Gtk.Orientation.HORIZONTAL)
        self.__panel.set_border_width(6)

        self.__list = HostsList(self, self.__nodes)

        self.__panel.add1(self.__list)
        self.__panel.add2(self.__view)
        self.__panel.set_position(int(DIMENSION[0] / 5))

        self.add(self.__panel)

    def change_notebook(self, node):
        """
        """
        if self.__view is not None:
            self.__view.destroy()

        if node is not None:
            self.__view = NodeNotebook(node)
        else:
            self.__view = self.__default_view
        self.__view.show_all()

        self.__panel.add2(self.__view)


class HostsList(Gtk.ScrolledWindow):
    """
    """
    def __init__(self, parent, nodes):
        """
        """
        super(HostsList, self).__init__()
        self.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.set_shadow_type(Gtk.ShadowType.NONE)

        self.__parent = parent
        self.__nodes = nodes

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__cell = Gtk.CellRendererText()

        self.__hosts_store = Gtk.ListStore.new([int, int, str, str, bool])

        self.__hosts_treeview = Gtk.TreeView.new_with_model(self.__hosts_store)
        self.__hosts_treeview.connect('cursor-changed', self.__cursor_callback)

        for i in range(len(self.__nodes)):

            node = self.__nodes[i]

            ports = node.get_info('number_of_open_ports')
            color = HOSTS_COLORS[node.get_info('vulnerability_score')]

            host = node.get_info('hostname') or node.get_info('ip') or ""

            self.__hosts_store.append([i,
                                       ports,
                                       host,
                                       color,
                                       True])

        self.__hosts_column = list()

        for i in range(0, len(HOSTS_HEADER)):

            column = Gtk.TreeViewColumn(title=HOSTS_HEADER[i],
                                        cell_renderer=self.__cell,
                                        text=i)

            self.__hosts_column.append(column)

            self.__hosts_column[i].set_reorderable(True)
            self.__hosts_column[i].set_resizable(True)
            self.__hosts_column[i].set_attributes(self.__cell,
                                                  text=i,
                                                  background=3,
                                                  editable=4)

        self.__hosts_treeview.append_column(self.__hosts_column[2])

        self.__hosts_store.set_sort_func(2, self.__host_sort)

        self.__hosts_column[2].set_sort_column_id(2)

        self.add_with_viewport(self.__hosts_treeview)

        if len(self.__hosts_treeview.get_model()) > 0:
            self.__hosts_treeview.set_cursor((0,))
        self.__cursor_callback(self.__hosts_treeview)

    def __cursor_callback(self, widget):
        """
        """
        path = widget.get_cursor()[0]
        if path is None:
            return

        iter = self.__hosts_store.get_iter(path)

        node = self.__nodes[self.__hosts_store.get_value(iter, 0)]

        self.__parent.change_notebook(node)

    def __host_sort(self, treemodel, iter1, iter2, *_):
        """
        """
        value1 = treemodel.get_value(iter1, 2)
        value2 = treemodel.get_value(iter2, 2)

        value1_is_ip = IP_RE.match(value1)
        value2_is_ip = IP_RE.match(value2)

        if value1_is_ip and value2_is_ip:
            return ipv4_compare(value1, value2)

        if value1_is_ip:
            return -1

        if value2_is_ip:
            return 1

        if value1 < value2:
            return -1

        if value1 > value2:
            return 1

        return 0
