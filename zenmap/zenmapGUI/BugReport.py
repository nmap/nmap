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

from zenmapGUI.higwidgets.higboxes import HIGVBox

from zenmapCore.Name import APP_DISPLAY_NAME, NMAP_DISPLAY_NAME, NMAP_WEB_SITE
import zenmapCore.I18N  # lgtm[py/unused-import]


# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

# For escaping text in marked-up labels.
from xml.sax.saxutils import escape


class BugReport(Gtk.Window, object):
    def __init__(self):
        Gtk.Window.__init__(self)
        self.set_title(_('How to Report a Bug'))
        self.set_position(Gtk.WindowPosition.CENTER_ALWAYS)
        self.set_resizable(False)

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

    def _create_widgets(self):
        self.vbox = HIGVBox()
        self.button_box = Gtk.ButtonBox.new(Gtk.Orientation.HORIZONTAL)

        self.text = Gtk.Label()

        self.btn_ok = Gtk.Button.new_from_stock(Gtk.STOCK_OK)

    def _pack_widgets(self):
        self.vbox.set_border_width(6)

        self.text.set_line_wrap(True)
        self.text.set_max_width_chars(50)
        self.text.set_markup(_("""\
<big><b>How to report a bug</b></big>

Like their author, %(nmap)s and %(app)s aren't perfect. But you can help \
make it better by sending bug reports or even writing patches. If \
%(nmap)s doesn't behave the way you expect, first upgrade to the latest \
version available from <b>%(nmap_web)s</b>. If the problem persists, do \
some research to determine whether it has already been discovered and \
addressed. Try Googling the error message or browsing the nmap-dev \
archives at http://seclists.org/. Read the full manual page as well. If \
nothing comes of this, mail a bug report to \
<b>&lt;dev@nmap.org&gt;</b>. Please include everything you have \
learned about the problem, as well as what version of Nmap you are \
running and what operating system version it is running on. Problem \
reports and %(nmap)s usage questions sent to dev@nmap.org are \
far more likely to be answered than those sent to Fyodor directly.

Code patches to fix bugs are even better than bug reports. Basic \
instructions for creating patch files with your changes are available at \
https://nmap.org/data/HACKING. Patches may be sent to nmap-dev \
(recommended) or to Fyodor directly.
""") % {
            "app": escape(APP_DISPLAY_NAME),
            "nmap": escape(NMAP_DISPLAY_NAME),
            "nmap_web": escape(NMAP_WEB_SITE)
            })
        self.vbox.add(self.text)

        self.button_box.set_layout(Gtk.ButtonBoxStyle.END)
        self.button_box.pack_start(self.btn_ok, True, True, 0)

        self.vbox._pack_noexpand_nofill(self.button_box)
        self.add(self.vbox)

    def _connect_widgets(self):
        self.btn_ok.connect("clicked", self.close)
        self.connect("delete-event", self.close)

    def close(self, widget=None, event=None):
        self.destroy()

if __name__ == "__main__":
    w = BugReport()
    w.show_all()
    w.connect("delete-event", lambda x, y: Gtk.main_quit())

    Gtk.main()
