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

import radialnet.gui.RadialNet as RadialNet
from radialnet.gui.ControlWidget import ControlWidget, ControlFisheye
from radialnet.gui.Toolbar import Toolbar
from radialnet.util.integration import make_graph_from_hosts


SLOW_LIMIT = 1000


class TopologyPage(HIGVBox):
    def __init__(self, inventory):
        HIGVBox.__init__(self)

        self.set_border_width(6)
        self.set_spacing(4)

        self.network_inventory = inventory

        self._create_widgets()
        self._pack_widgets()

    def _create_widgets(self):
        self.rn_hbox = Gtk.Box.new(Gtk.Orientation.HORIZONTAL, 4)
        self.rn_vbox = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)

        # RadialNet's widgets
        self.radialnet = RadialNet.RadialNet(RadialNet.LAYOUT_WEIGHTED)
        self.control = ControlWidget(self.radialnet)
        self.fisheye = ControlFisheye(self.radialnet)
        self.rn_toolbar = Toolbar(self.radialnet,
                               self,
                               self.control,
                               self.fisheye)

        self.display_panel = HIGVBox()

        self.radialnet.set_no_show_all(True)

        self.slow_vbox = HIGVBox()
        self.slow_label = Gtk.Label()
        self.slow_vbox.pack_start(self.slow_label, False, False, 0)
        show_button = Gtk.Button.new_with_label(_("Show the topology anyway"))
        show_button.connect("clicked", self.show_anyway)
        self.slow_vbox.pack_start(show_button, False, False, 0)
        self.slow_vbox.show_all()
        self.slow_vbox.set_no_show_all(True)
        self.slow_vbox.hide()

        self.radialnet.show()

    def _pack_widgets(self):
        self.rn_hbox.pack_start(self.display_panel, True, True, 0)
        self.rn_hbox.pack_start(self.control, False, True, 0)

        self.rn_vbox.pack_start(self.rn_hbox, True, True, 0)
        self.rn_vbox.pack_start(self.fisheye, False, True, 0)

        self.pack_start(self.rn_toolbar, False, False, 0)
        self.pack_start(self.rn_vbox, True, True, 0)

        self.display_panel.pack_start(self.slow_vbox, True, False, 0)
        self.display_panel.pack_start(self.radialnet, True, True, 0)

    def add_scan(self, scan):
        """Parses a given XML file and adds the parsed result to the network
        inventory."""
        self.network_inventory.add_scan(scan)
        self.update_radialnet()

    def update_radialnet(self):
        """Creates a graph from network inventory's host list and displays
        it."""
        hosts_up = self.network_inventory.get_hosts_up()

        self.slow_label.set_text(_("""\
Topology is disabled because too many hosts can cause it
to run slowly. The limit is %d hosts and there are %d.\
""" % (SLOW_LIMIT, len(hosts_up))))

        if len(hosts_up) <= SLOW_LIMIT:
            self.radialnet.show()
            self.slow_vbox.hide()
            self.update_radialnet_unchecked()
        else:
            self.radialnet.hide()
            self.slow_vbox.show()

    def update_radialnet_unchecked(self):
        hosts_up = self.network_inventory.get_hosts_up()
        graph = make_graph_from_hosts(hosts_up)
        self.radialnet.set_empty()
        self.radialnet.set_graph(graph)
        self.radialnet.show()

    def show_anyway(self, widget):
        self.radialnet.show()
        self.slow_vbox.hide()
        self.update_radialnet_unchecked()
