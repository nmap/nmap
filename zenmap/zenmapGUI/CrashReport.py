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
from gi.repository import Gtk, Gdk

import sys
import traceback

from zenmapGUI.higwidgets.higdialogs import HIGDialog
from zenmapGUI.higwidgets.higboxes import HIGHBox

from zenmapCore.Name import APP_DISPLAY_NAME
from zenmapCore.Version import VERSION
import zenmapCore.I18N  # lgtm[py/unused-import]


# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

# For escaping text in marked-up labels.
from xml.sax.saxutils import escape


class CrashReport(HIGDialog):
    def __init__(self, type, value, tb):
        HIGDialog.__init__(self)
        Gtk.Window.__init__(self)
        self.set_title(_('Crash Report'))
        self.set_position(Gtk.WindowPosition.CENTER_ALWAYS)

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

        trace = "".join(traceback.format_exception(type, value, tb))
        text = "Version: " + VERSION + "\n" + trace
        self.description_text.get_buffer().set_text(text)

    def _create_widgets(self):
        self.button_box = Gtk.ButtonBox.new(Gtk.Orientation.HORIZONTAL)
        self.button_box_ok = Gtk.ButtonBox.new(Gtk.Orientation.HORIZONTAL)

        self.description_scrolled = Gtk.ScrolledWindow()
        self.description_text = Gtk.TextView()
        self.description_text.set_editable(False)

        self.bug_text = Gtk.Label()
        self.bug_text.set_markup(_('An unexpected error has crashed '
            '%(app_name)s. Please copy the stack trace below and send it to '
            'the <a href="mailto:dev@nmap.org">dev@nmap.org</a> mailing list. '
            '(<a href="http://seclists.org/nmap-dev/">More about the list.</a>'
            ') The developers will see your report and try to fix the problem.'
            ) % {"app_name": escape(APP_DISPLAY_NAME)})
        self.email_frame = Gtk.Frame()
        self.email_label = Gtk.Label()
        self.email_label.set_markup(_('<b>Copy and email to '
            '<a href="mailto:dev@nmap.org">dev@nmap.org</a>:</b>'))
        self.btn_copy = Gtk.Button.new_from_stock(Gtk.STOCK_COPY)
        self.btn_ok = Gtk.Button.new_from_stock(Gtk.STOCK_OK)

        self.hbox = HIGHBox()

    def _pack_widgets(self):
        self.description_scrolled.add(self.description_text)
        self.description_scrolled.set_policy(
                Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.description_scrolled.set_size_request(400, 150)
        self.description_text.set_wrap_mode(Gtk.WrapMode.WORD)

        self.bug_text.set_max_width_chars(60)
        self.bug_text.set_line_wrap(True)
        self.email_label.set_line_wrap(True)

        self.email_frame.set_label_widget(self.email_label)
        self.email_frame.set_shadow_type(Gtk.ShadowType.NONE)

        self.hbox.set_border_width(6)
        self.vbox.set_border_width(6)

        self.hbox._pack_expand_fill(self.bug_text)

        self.button_box.set_layout(Gtk.ButtonBoxStyle.START)
        self.button_box_ok.set_layout(Gtk.ButtonBoxStyle.END)

        self.button_box.pack_start(self.btn_copy, True, True, 0)
        self.button_box_ok.pack_start(self.btn_ok, True, True, 0)

        self.vbox.pack_start(self.hbox, True, True, 0)
        self.vbox.pack_start(self.email_frame, True, True, 0)
        self.vbox.pack_start(self.description_scrolled, True, True, 0)
        self.vbox.pack_start(self.button_box, True, True, 0)
        self.action_area.pack_start(self.button_box_ok, True, True, 0)

    def _connect_widgets(self):
        self.btn_ok.connect("clicked", self.close)
        self.btn_copy.connect("clicked", self.copy)
        self.connect("delete-event", self.close)

    def get_description(self):
        buff = self.description_text.get_buffer()
        return buff.get_text(buff.get_start_iter(), buff.get_end_iter(), include_hidden_chars=True)

    def copy(self, widget=None, event=None):
        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        clipboard.set_text(self.get_description(), -1)
        clipboard.store()

    def close(self, widget=None, event=None):
        self.destroy()
        Gtk.main_quit()
        sys.exit(0)

if __name__ == "__main__":
    c = CrashReport(None, None, None)
    c.show_all()
    c.connect("delete-event", lambda x, y: Gtk.main_quit())

    Gtk.main()
