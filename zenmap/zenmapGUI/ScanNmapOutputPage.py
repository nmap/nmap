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
import gobject
import pango
import os

from zenmapGUI.higwidgets.higboxes import HIGHBox, HIGVBox

from zenmapGUI.NmapOutputViewer import NmapOutputViewer
from zenmapGUI.ScanRunDetailsPage import ScanRunDetailsPage
from zenmapGUI.ScansListStore import ScansListStore
from zenmapCore.Paths import Path
from zenmapCore.UmitLogging import log
import zenmapCore.I18N

def scan_entry_data_func(widget, cell_renderer, model, iter):
    """Set the properties of a cell renderer for a scan entry."""
    cell_renderer.set_property("ellipsize", pango.ELLIPSIZE_END)
    cell_renderer.set_property("style", pango.STYLE_NORMAL)
    cell_renderer.set_property("strikethrough", False)
    entry = model.get_value(iter, 0)
    if entry is None:
        return
    if entry.running:
        cell_renderer.set_property("style", pango.STYLE_ITALIC)
    elif entry.finished:
        pass
    elif entry.failed or entry.canceled:
        cell_renderer.set_property("strikethrough", True)
    cell_renderer.set_property("text", entry.get_command_string())

class Throbber(gtk.Image):
    """This is a little progress indicator that animates while a scan is
    running."""
    try:
        still = gtk.gdk.pixbuf_new_from_file(os.path.join(Path.pixmaps_dir, "throbber.png"))
        anim = gtk.gdk.PixbufAnimation(os.path.join(Path.pixmaps_dir, "throbber.gif"))
    except Exception, e:
        log.debug("Error loading throbber images: %s." % str(e))
        still = None
        anim = None

    def __init__(self):
        gtk.Image.__init__(self)
        self.set_from_pixbuf(self.still)
        self.animating = False

    def go(self):
        # Don't change anything if we're already animating.
        if not self.animating and self.anim is not None:
            self.set_from_animation(self.anim)
        self.animating = True

    def stop(self):
        if self.animating and self.still is not None:
            self.set_from_pixbuf(self.still)
        self.animating = False

class ScanNmapOutputPage(HIGVBox):
    """This is the "Nmap Output" scan results tab. It holds a text view of Nmap
    output. The constructor takes a ScansListStore, the contents of which are
    made selectable through a combo box. Details for completed scans are
    available and shown in separate windows. It emits the "changed" signal when
    the combo box selection changes."""

    __gsignals__ = {
        "changed": (gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE, ())
    }

    def __init__(self, scans_store):
        HIGVBox.__init__(self)

        # This is a cache of details windows we have open.
        self._details_windows = {}

        self.set_spacing(0)

        hbox = HIGHBox()

        self.scans_list = gtk.ComboBox(scans_store)
        cell = gtk.CellRendererText()
        self.scans_list.pack_start(cell, True)
        self.scans_list.set_cell_data_func(cell, scan_entry_data_func)
        hbox._pack_expand_fill(self.scans_list)

        self.scans_list.connect("changed", self._selection_changed)
        scans_store.connect("row-changed", self._row_changed)
        scans_store.connect("row-deleted", self._row_deleted)

        self.throbber = Throbber()
        hbox._pack_noexpand_nofill(self.throbber)

        self.details_button = gtk.Button(_("Details"))
        self.details_button.connect("clicked", self._show_details)
        hbox._pack_noexpand_nofill(self.details_button)

        self._pack_noexpand_nofill(hbox)

        self.nmap_output = NmapOutputViewer()
        self._pack_expand_fill(self.nmap_output)

        self._update()

    def set_active_iter(self, i):
        """Set the active entry to an interator into the ScansListStore referred
        to by this object."""
        self.scans_list.set_active_iter(i)

    def get_active_entry(self):
        iter = self.scans_list.get_active_iter()
        if iter is None:
            return None
        return self.scans_list.get_model().get_value(iter, 0)

    def _selection_changed(self, widget):
        """This callback is called when a scan in the list of scans is
        selected."""
        self._update()
        self.emit("changed")

    def _row_changed(self, model, path, i):
        """This callback is called when a row in the underlying scans store is
        changed."""
        # If the currently selected entry was changed, update the interface.
        if path[0] == self.scans_list.get_active():
            self._update()

    def _row_deleted(self, model, path):
        """This callback is called when a row in the underlying scans store is
        deleted."""
        self._update()

    def _update(self):
        """Update the interface based on the currently selected entry."""
        entry = self.get_active_entry()
        if entry is None:
            self.nmap_output.show_nmap_output("")
            self.details_button.set_sensitive(False)
            self.throbber.stop()
            return

        if entry.parsed is not None:
            self.nmap_output.set_command_execution(None)
            nmap_output = entry.parsed.get_nmap_output()
            if nmap_output is not None:
                self.nmap_output.show_nmap_output(nmap_output)
            self.details_button.set_sensitive(True)
        elif entry.command is not None:
            self.nmap_output.set_command_execution(entry.command)
            self.nmap_output.refresh_output()
            self.details_button.set_sensitive(False)

        if entry.running:
            self.throbber.go()
        else:
            self.throbber.stop()

    def _show_details(self, button):
        """Show a details window for the currently selected scan, if it is
        finished."""
        entry = self.get_active_entry()
        if entry is None:
            return
        if not entry.finished:
            return
        if self._details_windows.get(entry) is None:
            window = gtk.Window()
            window.add(ScanRunDetailsPage(entry.parsed))
            def close_details(details, event, entry):
                details.destroy()
                del self._details_windows[entry]
            window.connect("delete-event", close_details, entry)
            window.show_all()
            self._details_windows[entry] = window
        self._details_windows[entry].present()
