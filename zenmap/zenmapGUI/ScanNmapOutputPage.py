#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2017 Insecure.Com LLC ("The Nmap  *
# * Project"). Nmap is also a registered trademark of the Nmap Project.     *
# * This program is free software; you may redistribute and/or modify it    *
# * under the terms of the GNU General Public License as published by the   *
# * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
# * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
# * right to use, modify, and redistribute this software under certain      *
# * conditions.  If you wish to embed Nmap technology into proprietary      *
# * software, we sell alternative licenses (contact sales@nmap.com).        *
# * Dozens of software vendors already license Nmap technology such as      *
# * host discovery, port scanning, OS detection, version detection, and     *
# * the Nmap Scripting Engine.                                              *
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
# * As another special exception to the GPL terms, the Nmap Project grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * The Nmap Project has permission to redistribute Npcap, a packet         *
# * capturing driver and library for the Microsoft Windows platform.        *
# * Npcap is a separate work with it's own license rather than this Nmap    *
# * license.  Since the Npcap license does not permit redistribution        *
# * without special permission, our Nmap Windows binary packages which      *
# * contain Npcap may not be redistributed without special permission.      *
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
# * source code repository, it is understood (unless you specify            *
# * otherwise) that you are offering the Nmap Project the unlimited,        *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because     *
# * the inability to relicense code has caused devastating problems for     *
# * other Free Software projects (such as KDE and NASM).  We also           *
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
        still = gtk.gdk.pixbuf_new_from_file(
                os.path.join(Path.pixmaps_dir, "throbber.png"))
        anim = gtk.gdk.PixbufAnimation(
                os.path.join(Path.pixmaps_dir, "throbber.gif"))
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
        """Set the active entry to an iterator into the ScansListStore
        referred to by this object."""
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
            if nmap_output:
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
