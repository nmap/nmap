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

from zenmapGUI.higwidgets.higboxes import HIGHBox
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel

import zenmapCore.I18N

from zenmapGUI.ProfileCombo import ProfileCombo
from zenmapGUI.TargetCombo import TargetCombo


class ScanCommandToolbar(HIGHBox):
    """This class builds the toolbar devoted to Command entry. It allows you to
    retrieve and edit the current command entered."""
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

    w.connect("delete-event", lambda x, y: gtk.main_quit())
    w.show_all()
    gtk.main()
