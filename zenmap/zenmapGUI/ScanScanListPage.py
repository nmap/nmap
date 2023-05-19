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
from gi.repository import Gtk, Pango

from zenmapGUI.higwidgets.higboxes import HIGHBox, HIGVBox
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapGUI.higwidgets.higscrollers import HIGScrolledWindow
import zenmapCore.I18N  # lgtm[py/unused-import]


def status_data_func(widget, cell_renderer, model, iter, data):
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


def command_data_func(widget, cell_renderer, model, iter, data):
    entry = model.get_value(iter, 0)
    cell_renderer.set_property("ellipsize", Pango.EllipsizeMode.END)
    cell_renderer.set_property("text", entry.get_command_string())


class ScanScanListPage(HIGVBox):
    """This is the "Scans" scan results tab. It the list of running and
    finished scans contained in the ScansListStore passed to the
    constructor."""
    def __init__(self, scans_store):
        HIGVBox.__init__(self)

        self.set_spacing(4)

        scans_store.connect("row-changed", self._row_changed)

        self.scans_list = Gtk.TreeView.new_with_model(scans_store)
        self.scans_list.get_selection().connect(
                "changed", self._selection_changed)

        status_col = Gtk.TreeViewColumn(title=_("Status"))
        cell = Gtk.CellRendererText()
        status_col.pack_start(cell, True)
        status_col.set_cell_data_func(cell, status_data_func)
        self.scans_list.append_column(status_col)

        command_col = Gtk.TreeViewColumn(title=_("Command"))
        cell = Gtk.CellRendererText()
        command_col.pack_start(cell, True)
        command_col.set_cell_data_func(cell, command_data_func)
        self.scans_list.append_column(command_col)

        scrolled_window = HIGScrolledWindow()
        scrolled_window.set_border_width(0)
        scrolled_window.add(self.scans_list)

        self.pack_start(scrolled_window, True, True, 0)

        hbox = HIGHBox()
        buttonbox = Gtk.ButtonBox.new(Gtk.Orientation.HORIZONTAL)
        buttonbox.set_layout(Gtk.ButtonBoxStyle.START)
        buttonbox.set_spacing(4)

        self.append_button = HIGButton(_("Append Scan"), Gtk.STOCK_ADD)
        buttonbox.pack_start(self.append_button, False, True, 0)

        self.remove_button = HIGButton(_("Remove Scan"), Gtk.STOCK_REMOVE)
        buttonbox.pack_start(self.remove_button, False, True, 0)

        self.cancel_button = HIGButton(_("Cancel Scan"), Gtk.STOCK_CANCEL)
        buttonbox.pack_start(self.cancel_button, False, True, 0)

        hbox.pack_start(buttonbox, True, True, 4)

        self.pack_start(hbox, False, True, 4)

        self._update()

    def _row_changed(self, model, path, i):
        self._update()

    def _selection_changed(self, selection):
        self._update()

    def _update(self):
        # Make the Cancel button sensitive or not depending on whether a
        # running scan is selected.
        tree_selection = self.scans_list.get_selection()
        if tree_selection is None:
            # I can't find anything in the PyGTK documentation that suggests
            # this is possible, but we received many crash reports that
            # indicate it is.
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
