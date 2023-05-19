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

from zenmapGUI.SearchGUI import SearchGUI

import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapCore.UmitConf import is_maemo

from zenmapGUI.higwidgets.higboxes import HIGVBox
from zenmapGUI.higwidgets.higbuttons import HIGButton

BaseSearchWindow = None
hildon = None

if is_maemo():
    import hildon

    class BaseSearchWindow(hildon.Window):
        def __init__(self):
            hildon.Window.__init__(self)

        def _pack_widgets(self):
            pass
else:
    class BaseSearchWindow(Gtk.Window):
        def __init__(self):
            Gtk.Window.__init__(self)
            self.set_title(_("Search Scans"))
            self.set_position(Gtk.WindowPosition.CENTER)

        def _pack_widgets(self):
            self.vbox.set_border_width(4)


class SearchWindow(BaseSearchWindow):
    def __init__(self, load_method, append_method):
        BaseSearchWindow.__init__(self)

        self.set_default_size(600, 400)

        self.load_method = load_method
        self.append_method = append_method

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

    def _create_widgets(self):
        self.vbox = HIGVBox()

        self.bottom_hbox = Gtk.Box.new(Gtk.Orientation.HORIZONTAL, 4)
        self.bottom_label = Gtk.Label()
        self.btn_box = Gtk.ButtonBox.new(Gtk.Orientation.HORIZONTAL)
        self.btn_open = HIGButton(stock=Gtk.STOCK_OPEN)
        self.btn_append = HIGButton(_("Append"), Gtk.STOCK_ADD)
        self.btn_close = HIGButton(stock=Gtk.STOCK_CLOSE)

        self.search_gui = SearchGUI(self)

    def _pack_widgets(self):
        BaseSearchWindow._pack_widgets(self)

        self.btn_box.set_layout(Gtk.ButtonBoxStyle.END)
        self.btn_box.set_spacing(4)
        self.btn_box.pack_start(self.btn_close, True, True, 0)
        self.btn_box.pack_start(self.btn_append, True, True, 0)
        self.btn_box.pack_start(self.btn_open, True, True, 0)

        self.bottom_label.set_alignment(0.0, 0.5)
        self.bottom_label.set_use_markup(True)

        self.bottom_hbox.pack_start(self.bottom_label, True, True, 0)
        self.bottom_hbox.pack_start(self.btn_box, False, True, 0)

        self.vbox.set_spacing(4)
        self.vbox.pack_start(self.search_gui, True, True, 0)
        self.vbox.pack_start(self.bottom_hbox, False, True, 0)

        self.add(self.vbox)

    def _connect_widgets(self):
        # Double click on result, opens it
        self.search_gui.result_view.connect(
                "row-activated", self.open_selected)

        self.btn_open.connect("clicked", self.open_selected)
        self.btn_append.connect("clicked", self.append_selected)
        self.btn_close.connect("clicked", self.close)
        self.connect("delete-event", self.close)

    def close(self, widget=None, event=None):
        self.search_gui.close()
        self.destroy()

    def set_label_text(self, text):
        self.bottom_label.set_label(text)

    def open_selected(self, widget=None, path=None, view_column=None,
            extra=None):
        # Open selected results
        self.load_method(self.results)

        # Close Search Window
        self.close()

    def append_selected(self, widget=None, path=None, view_column=None,
            extra=None):
        # Append selected results
        self.append_method(self.results)

        # Close Search Window
        self.close()

    def get_results(self):
        # Return list with parsed objects from result list store
        return self.search_gui.selected_results

    results = property(get_results)


if __name__ == "__main__":
    search = SearchWindow(lambda x: Gtk.main_quit(), lambda x: Gtk.main_quit())
    search.show_all()
    Gtk.main()
