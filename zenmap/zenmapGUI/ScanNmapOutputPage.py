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
from gi.repository import Gtk, GObject, GdkPixbuf, Pango

import os

from zenmapGUI.higwidgets.higboxes import HIGHBox, HIGVBox

from zenmapGUI.NmapOutputViewer import NmapOutputViewer
from zenmapGUI.ScanRunDetailsPage import ScanRunDetailsPage
from zenmapCore.Paths import Path
from zenmapCore.UmitLogging import log
import zenmapCore.I18N  # lgtm[py/unused-import]


def scan_entry_data_func(widget, cell_renderer, model, iter):
    """Set the properties of a cell renderer for a scan entry."""
    cell_renderer.set_property("ellipsize", Pango.EllipsizeMode.END)
    cell_renderer.set_property("style", Pango.Style.NORMAL)
    cell_renderer.set_property("strikethrough", False)
    entry = model.get_value(iter, 0)
    if entry is None:
        return
    if entry.running:
        cell_renderer.set_property("style", Pango.Style.ITALIC)
    elif entry.finished:
        pass
    elif entry.failed or entry.canceled:
        cell_renderer.set_property("strikethrough", True)
    cell_renderer.set_property("text", entry.get_command_string())


class Throbber(Gtk.Image):
    """This is a little progress indicator that animates while a scan is
    running."""
    try:
        still = GdkPixbuf.Pixbuf.new_from_file(
                os.path.join(Path.pixmaps_dir, "throbber.png"))
        anim = GdkPixbuf.PixbufAnimation(
                os.path.join(Path.pixmaps_dir, "throbber.gif"))
    except Exception as e:
        log.debug("Error loading throbber images: %s." % str(e))
        still = None
        anim = None

    def __init__(self):
        Gtk.Image.__init__(self)
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
        "changed": (GObject.SignalFlags.RUN_FIRST, GObject.TYPE_NONE, ())
    }

    def __init__(self, scans_store):
        HIGVBox.__init__(self)

        # This is a cache of details windows we have open.
        self._details_windows = {}

        self.set_spacing(0)

        hbox = HIGHBox()

        self.scans_list = Gtk.ComboBox.new_with_model(scans_store)
        cell = Gtk.CellRendererText()
        self.scans_list.pack_start(cell, True)
        self.scans_list.set_cell_data_func(cell, scan_entry_data_func)
        hbox._pack_expand_fill(self.scans_list)

        self.scans_list.connect("changed", self._selection_changed)
        scans_store.connect("row-changed", self._row_changed)
        scans_store.connect("row-deleted", self._row_deleted)

        self.throbber = Throbber()
        hbox._pack_noexpand_nofill(self.throbber)

        self.details_button = Gtk.Button.new_with_label(_("Details"))
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
            window = Gtk.Window()
            window.add(ScanRunDetailsPage(entry.parsed))

            def close_details(details, event, entry):
                details.destroy()
                del self._details_windows[entry]

            window.connect("delete-event", close_details, entry)
            window.show_all()
            self._details_windows[entry] = window
        self._details_windows[entry].present()
