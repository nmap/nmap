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
higwidgets/higboxes.py

   box related classes
"""

__all__ = ['HIGHBox', 'HIGVBox']

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


class HIGBox(Gtk.Box):
    def _pack_noexpand_nofill(self, widget):
        self.pack_start(widget, False, False, 0)

    def _pack_expand_fill(self, widget):
        self.pack_start(widget, True, True, 0)

    def add(self, widget):
        # Make default packing arguments same as before (Gtk.Box has expand
        # set to False by default).
        self.pack_start(widget, True, True, 0)


class HIGHBox(HIGBox):
    def __init__(self, homogeneous=False, spacing=12):
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.HORIZONTAL,
                         homogeneous=homogeneous, spacing=spacing)

    pack_section_label = HIGBox._pack_noexpand_nofill
    pack_label = HIGBox._pack_noexpand_nofill
    pack_entry = HIGBox._pack_expand_fill


class HIGVBox(HIGBox):
    def __init__(self, homogeneous=False, spacing=12):
        Gtk.Box.__init__(self, orientation=Gtk.Orientation.VERTICAL,
                         homogeneous=homogeneous, spacing=spacing)

    # Packs a widget as a line, so it doesn't expand vertically
    pack_line = HIGBox._pack_noexpand_nofill


class HIGSpacer(HIGHBox):
    def __init__(self, widget=None):
        HIGHBox.__init__(self)
        self.set_spacing(6)

        self._pack_noexpand_nofill(hig_box_space_holder())

        if widget:
            self._pack_expand_fill(widget)
            self.child = widget

    def get_child(self):
        return self.child


def hig_box_space_holder():
    return Gtk.Label.new("    ")
