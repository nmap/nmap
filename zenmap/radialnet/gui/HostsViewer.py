# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
# * "derivative work" for the purpose of this license if it does any of the *
# * following:                                                              *
# * o Integrates source code from Nmap                                      *
# * o Reads or includes Nmap copyrighted data files, such as                *
# *   nmap-os-db or nmap-service-probes.                                    *
# * o Executes Nmap and parses the results (as opposed to typical shell or  *
# *   execution-menu apps, which simply display raw Nmap output and so are  *
# *   not derivative works.)                                                *
# * o Integrates/includes/aggregates Nmap into a proprietary executable     *
# *   installer, such as those produced by InstallShield.                   *
# * o Links to a library or executes a program that does any of the above   *
# *                                                                         *
# * The term "Nmap" should be taken to also include any portions or derived *
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
# *                                                                         *
# * As a special exception to the GPL terms, Insecure.Com LLC grants        *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two. You must obey the GNU GPL in all *
# * respects for all of the code used other than OpenSSL.  If you modify    *
# * this file, you may extend this exception to your version of the file,   *
# * but you are not obligated to do so.                                     *
# *                                                                         *
# * If you received these files with a written license agreement or         *
# * contract stating terms other than the terms above, then that            *
# * alternative license agreement takes precedence over these comments.     *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes (none     *
# * have been found so far).                                                *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
# ***************************************************************************/

import re
import gtk
import gobject

from radialnet.bestwidgets.windows import *

from radialnet.gui.NodeNotebook import NodeNotebook
from radialnet.util.misc import ipv4_compare


HOSTS_COLORS = ['#d5ffd5', '#ffffd5', '#ffd5d5']

HOSTS_HEADER = ['ID', '#', 'Hosts']

DIMENSION = (700, 400)

IP_RE = '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'



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
        self.__default_view = gtk.Label(_("No node selected"))
        self.__view = self.__default_view

        self.__create_widgets()


    def __create_widgets(self):
        """
        """
        self.__panel = gtk.HPaned()
        self.__panel.set_border_width(6)

        self.__list = HostsList(self, self.__nodes)

        self.__panel.add1(self.__list)
        self.__panel.add2(self.__view)
        self.__panel.set_position(int(DIMENSION[0] / 5))

        self.add(self.__panel)



    def change_notebook(self, node):
        """
        """
        if self.__view != None:
            self.__view.destroy()

        if node is not None:
            self.__view = NodeNotebook(node)
        else:
            self.__view = self.__default_view
        self.__view.show_all()

        self.__panel.add2(self.__view)



class HostsList(gtk.ScrolledWindow):
    """
    """
    def __init__(self, parent, nodes):
        """
        """
        super(HostsList, self).__init__()
        self.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.set_shadow_type(gtk.SHADOW_NONE)

        self.__parent = parent
        self.__nodes = nodes

        self.__create_widgets()


    def __create_widgets(self):
        """
        """
        self.__cell = gtk.CellRendererText()

        self.__hosts_store = gtk.ListStore(gobject.TYPE_INT,
                                           gobject.TYPE_INT,
                                           gobject.TYPE_STRING,
                                           gobject.TYPE_STRING,
                                           gobject.TYPE_BOOLEAN)

        self.__hosts_treeview = gtk.TreeView(self.__hosts_store)
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

            column = gtk.TreeViewColumn(HOSTS_HEADER[i],
                                        self.__cell,
                                        text = i)

            self.__hosts_column.append(column)

            self.__hosts_column[i].set_reorderable(True)
            self.__hosts_column[i].set_resizable(True)
            self.__hosts_column[i].set_attributes(self.__cell,
                                                  text = i,
                                                  background = 3,
                                                  editable = 4)

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


    def __host_sort(self, treemodel, iter1, iter2):
        """
        """
        value1 = treemodel.get_value(iter1, 2)
        value2 = treemodel.get_value(iter2, 2)

        value1_is_ip = re.search(IP_RE, value1)
        value2_is_ip = re.search(IP_RE, value2)

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
