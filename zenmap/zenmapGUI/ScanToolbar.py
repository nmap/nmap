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

from zenmapGUI.higwidgets.higboxes import HIGHBox
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel

import zenmapCore.I18N  # lgtm[py/unused-import]

from zenmapGUI.ProfileCombo import ProfileCombo
from zenmapGUI.TargetCombo import TargetCombo


class ScanCommandToolbar(HIGHBox):
    """This class builds the toolbar devoted to Command entry. It allows you to
    retrieve and edit the current command entered."""
    def __init__(self):
        """Initialize command toolbar"""
        HIGHBox.__init__(self)

        self.command_label = HIGEntryLabel(_("Command:"))
        self.command_entry = Gtk.Entry()

        self._pack_noexpand_nofill(self.command_label)
        self._pack_expand_fill(self.command_entry)

    def get_command(self):
        """Retrieve command entry"""
        return self.command_entry.get_text()

    def set_command(self, command):
        """Set a command entry"""
        self.command_entry.set_text(command)

    command = property(get_command, set_command)


class ScanToolbar(HIGHBox):
    """
    This function regards the Scanning Toolbar, which includes
    the Target and Profile editable fields/dropdown boxes, as well as
    the Scan button and assigns events and and actions associated with
    each.
    """
    def __init__(self):
        """Initialize Scan Toolbar, including Events, and packing all
        of the GUI elements in layout"""
        HIGHBox.__init__(self)

        self._create_target()
        self._create_profile()

        self.scan_button = Gtk.Button.new_with_label(_("Scan"))
        self.cancel_button = Gtk.Button.new_with_label(_("Cancel"))

        self._pack_noexpand_nofill(self.target_label)
        self._pack_expand_fill(self.target_entry)

        self._pack_noexpand_nofill(self.profile_label)
        self._pack_expand_fill(self.profile_entry)

        self._pack_noexpand_nofill(self.scan_button)
        self._pack_noexpand_nofill(self.cancel_button)

        # Skip over the dropdown arrow so you can tab to the profile entry.
        self.target_entry.set_focus_chain((self.target_entry.get_child(),))

        self.target_entry.get_child().connect('activate',
                        lambda x: self.profile_entry.grab_focus())
        self.profile_entry.get_child().connect('activate',
                        lambda x: self.scan_button.clicked())

    def _create_target(self):
        """Create a target and update the list"""
        self.target_label = HIGEntryLabel(_("Target:"))
        self.target_entry = TargetCombo()

        self.update_target_list()

    def _create_profile(self):
        """Create new profile and update list"""
        self.profile_label = HIGEntryLabel(_('Profile:'))
        self.profile_entry = ProfileCombo()

        self.update()

    def update_target_list(self):
        self.target_entry.update()

    def add_new_target(self, target):
        self.target_entry.add_new_target(target)

    def get_selected_target(self):
        """Return currently selected target"""
        return self.target_entry.selected_target

    def set_selected_target(self, target):
        """Modify currently selected target"""
        self.target_entry.selected_target = target

    def update(self):
        self.profile_entry.update()

    def set_profiles(self, profiles):
        """Modify profile"""
        self.profile_entry.set_profiles(profiles)

    def get_selected_profile(self):
        """Return currently selected profile"""
        return self.profile_entry.selected_profile

    def set_selected_profile(self, profile):
        """Modify currently selected profile"""
        self.profile_entry.selected_profile = profile

    selected_profile = property(get_selected_profile, set_selected_profile)
    selected_target = property(get_selected_target, set_selected_target)

if __name__ == "__main__":
    w = Gtk.Window()
    box = Gtk.Box.new(Gtk.Orientation.VERTICAL, 0)
    w.add(box)

    stool = ScanToolbar()
    sctool = ScanCommandToolbar()

    box.pack_start(stool, True, True, 0)
    box.pack_start(sctool, True, True, 0)

    w.connect("delete-event", lambda x, y: Gtk.main_quit())
    w.show_all()
    Gtk.main()
