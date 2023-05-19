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

"""
higwidgets/higbuttons.py

   button related classes
"""

__all__ = ['HIGButton', 'HIGToggleButton']

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


class HIGMixButton(Gtk.Box):
    def __init__(self, title, stock):
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.HORIZONTAL,
                         homogeneous=False, spacing=4)
        self.img = Gtk.Image()
        self.img.set_from_stock(stock, Gtk.IconSize.BUTTON)

        self.lbl = Gtk.Label.new(title)

        self.hbox1 = Gtk.Box.new(Gtk.Orientation.HORIZONTAL, 2)
        self.hbox1.set_homogeneous(False)
        self.hbox1.pack_start(self.img, False, False, 0)
        self.hbox1.pack_start(self.lbl, False, False, 0)

        self.align = Gtk.Alignment.new(0.5, 0.5, 0, 0)
        self.pack_start(self.align, True, True, 0)
        self.pack_start(self.hbox1, True, True, 0)


class HIGButton(Gtk.Button):
    def __init__(self, title="", stock=None):
        if title and stock:
            Gtk.Button.__init__(self)
            content = HIGMixButton(title, stock)
            self.add(content)
        elif title and not stock:
            Gtk.Button.__init__(self, label=title)
        elif stock:
            Gtk.Button.__init__(self, stock=stock)
        else:
            Gtk.Button.__init__(self)


class HIGToggleButton(Gtk.ToggleButton):
    def __init__(self, title="", stock=None):
        if title and stock:
            Gtk.ToggleButton.__init__(self)
            content = HIGMixButton(title, stock)
            self.add(content)
        elif title and not stock:
            Gtk.ToggleButton.__init__(self, label=title)
        elif stock:
            Gtk.ToggleButton.__init__(self, stock=stock)
            self.set_use_stock(True)
        else:
            Gtk.ToggleButton.__init__(self)
