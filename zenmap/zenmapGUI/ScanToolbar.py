#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import gtk

from zenmapGUI.higwidgets.higboxes import HIGHBox
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel

import zenmapCore.I18N

from zenmapGUI.ProfileCombo import ProfileCombo
from zenmapGUI.TargetCombo import TargetCombo


class ScanCommandToolbar(HIGHBox):
    """This class builds the toolbar devoted to Command entry. It allows you to retrieve and edit the current command entered."""
    def __init__(self):
        """Initialize command toolbar"""
        HIGHBox.__init__(self)

        self.command_label = HIGEntryLabel(_("Command:"))
        self.command_entry = gtk.Entry()

        self._pack_noexpand_nofill(self.command_label)
        self._pack_expand_fill(self.command_entry)

    def get_command(self):
        """Retrieve command entry"""
        return self.command_entry.get_text().decode("UTF-8")

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

        self.scan_button = gtk.Button(_("Scan"))
        #self.scan_button = HIGButton(_("Scan "), gtk.STOCK_MEDIA_PLAY)
        self.cancel_button = gtk.Button(_("Cancel"))
        #self.cancel_button = HIGButton(_("Cancel "), gtk.STOCK_CANCEL)

        self._pack_noexpand_nofill(self.target_label)
        self._pack_expand_fill(self.target_entry)

        self._pack_noexpand_nofill(self.profile_label)
        self._pack_expand_fill(self.profile_entry)

        self._pack_noexpand_nofill(self.scan_button)
        self._pack_noexpand_nofill(self.cancel_button)

        # Skip over the dropdown arrow so you can tab to the profile entry.
        self.target_entry.set_focus_chain((self.target_entry.child,))

        self.target_entry.child.connect('activate',
                        lambda x: self.profile_entry.grab_focus())
        self.profile_entry.child.connect('activate',
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
        return self.target_entry.selected_target.decode("UTF-8")

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
    w = gtk.Window()
    box = gtk.VBox()
    w.add(box)

    stool = ScanToolbar()
    sctool = ScanCommandToolbar()

    box.pack_start(stool)
    box.pack_start(sctool)

    w.connect("delete-event", lambda x,y: gtk.main_quit())
    w.show_all()
    gtk.main()
