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
import pango

from zenmapGUI.higwidgets.higboxes import HIGHBox, HIGVBox
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapGUI.higwidgets.higscrollers import HIGScrolledWindow
import zenmapCore.I18N

def status_data_func(widget, cell_renderer, model, iter):
    entry = model.get_value(iter, 0)
    if entry.running:
        status = _("Running")
    elif entry.finished:
        if entry.parsed is not None and entry.parsed.unsaved:
            status = _("Unsaved")
        else:
            status = ""
    elif entry.failed:
        status = _("Failed")
    elif entry.canceled:
        status = _("Canceled")
    cell_renderer.set_property("text", status)

def command_data_func(widget, cell_renderer, model, iter):
    entry = model.get_value(iter, 0)
    cell_renderer.set_property("ellipsize", pango.ELLIPSIZE_END)
    cell_renderer.set_property("text", entry.get_command_string())

class ScanScanListPage(HIGVBox):
    """This is the "Scans" scan results tab. It the list of running and finished
    scans contained in the ScansListStore passed to the constructor."""
    def __init__(self, scans_store):
        HIGVBox.__init__(self)

        self.set_spacing(4)

        scans_store.connect("row-changed", self._row_changed)

        self.scans_list = gtk.TreeView(scans_store)
        self.scans_list.get_selection().connect("changed", self._selection_changed)

        status_col = gtk.TreeViewColumn(_("Status"))
        cell = gtk.CellRendererText()
        status_col.pack_start(cell)
        status_col.set_cell_data_func(cell, status_data_func)
        self.scans_list.append_column(status_col)

        command_col = gtk.TreeViewColumn(_("Command"))
        cell = gtk.CellRendererText()
        command_col.pack_start(cell)
        command_col.set_cell_data_func(cell, command_data_func)
        self.scans_list.append_column(command_col)

        scrolled_window = HIGScrolledWindow()
        scrolled_window.set_border_width(0)
        scrolled_window.add(self.scans_list)

        self.pack_start(scrolled_window, True, True)

        hbox = HIGHBox()
        buttonbox = gtk.HButtonBox()
        buttonbox.set_layout(gtk.BUTTONBOX_START)
        buttonbox.set_spacing(4)

        self.append_button = HIGButton(_("Append Scan"), gtk.STOCK_ADD)
        buttonbox.pack_start(self.append_button, False)

        self.remove_button = HIGButton(_("Remove Scan"), gtk.STOCK_REMOVE)
        buttonbox.pack_start(self.remove_button, False)

        self.cancel_button = HIGButton(_("Cancel Scan"), gtk.STOCK_CANCEL)
        buttonbox.pack_start(self.cancel_button, False)

        hbox.pack_start(buttonbox, padding = 4)

        self.pack_start(hbox, False, padding = 4)

        self._update()

    def _row_changed(self, model, path, i):
        self._update()

    def _selection_changed(self, selection):
        self._update()

    def _update(self):
        # Make the Cancel button sensitive or not depending on whether a running
        # scan is selected.
        tree_selection = self.scans_list.get_selection()
        if tree_selection is None:
            # I can't find anything in the PyGTK documentation that suggests
            # this is possible, but we received many crash reports that indicate
            # it is.
            model, selection = None, []
        else:
            model, selection = tree_selection.get_selected_rows()

        for path in selection:
            entry = model.get_value(model.get_iter(path), 0)
            if entry.running:
                self.cancel_button.set_sensitive(True)
                break
        else:
            self.cancel_button.set_sensitive(False)

        if len(selection) == 0:
            self.remove_button.set_sensitive(False)
        else:
            self.remove_button.set_sensitive(True)
