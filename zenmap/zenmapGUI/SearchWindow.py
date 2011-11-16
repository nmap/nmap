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

from zenmapGUI.SearchGUI import SearchGUI

import zenmapCore.I18N
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
    class BaseSearchWindow(gtk.Window):
        def __init__(self):
            gtk.Window.__init__(self)
            self.set_title(_("Search Scans"))
            self.set_position(gtk.WIN_POS_CENTER)

        def _pack_widgets(self):
            self.vbox.set_border_width(4)

class SearchWindow(BaseSearchWindow, object):
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

        self.bottom_hbox = gtk.HBox()
        self.bottom_label = gtk.Label()
        self.btn_box = gtk.HButtonBox()
        self.btn_open = HIGButton(stock=gtk.STOCK_OPEN)
        self.btn_append = HIGButton(_("Append"), gtk.STOCK_ADD)
        self.btn_close = HIGButton(stock=gtk.STOCK_CLOSE)

        self.search_gui = SearchGUI(self)

    def _pack_widgets(self):
        BaseSearchWindow._pack_widgets(self)

        self.btn_box.set_layout(gtk.BUTTONBOX_END)
        self.btn_box.set_spacing(4)
        self.btn_box.pack_start(self.btn_close)
        self.btn_box.pack_start(self.btn_append)
        self.btn_box.pack_start(self.btn_open)

        self.bottom_label.set_alignment(0.0, 0.5)
        self.bottom_label.set_use_markup(True)

        self.bottom_hbox.set_spacing(4)
        self.bottom_hbox.pack_start(self.bottom_label, True)
        self.bottom_hbox.pack_start(self.btn_box, False)

        self.vbox.set_spacing(4)
        self.vbox.pack_start(self.search_gui, True, True)
        self.vbox.pack_start(self.bottom_hbox, False)

        self.add(self.vbox)

    def _connect_widgets(self):
        # Double click on result, opens it
        self.search_gui.result_view.connect("row-activated", self.open_selected)

        self.btn_open.connect("clicked", self.open_selected)
        self.btn_append.connect("clicked", self.append_selected)
        self.btn_close.connect("clicked", self.close)
        self.connect("delete-event", self.close)

    def close(self, widget=None, event=None):
        self.search_gui.close()
        self.destroy()

    def set_label_text(self, text):
        self.bottom_label.set_label(text)

    def open_selected(self, widget=None, path=None, view_column=None, extra=None):
        # Open selected results
        self.load_method(self.results)

        # Close Search Window
        self.close()

    def append_selected(self, widget=None, path=None, view_column=None, extra=None):
        # Append selected results
        self.append_method(self.results)

        # Close Search Window
        self.close()

    def get_results(self):
        # Return list with parsed objects from result list store
        return self.search_gui.selected_results

    results = property(get_results)


if __name__ == "__main__":
    search = SearchWindow(lambda x: gtk.main_quit())
    search.show_all()
    gtk.main()
