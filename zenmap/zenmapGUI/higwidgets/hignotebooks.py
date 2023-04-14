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
from gi.repository import Gtk, GObject

from .higboxes import HIGHBox
from .higbuttons import HIGButton


class HIGNotebook(Gtk.Notebook):
    def __init__(self):
        Gtk.Notebook.__init__(self)
        self.popup_enable()


class HIGClosableTabLabel(HIGHBox):
    __gsignals__ = {
            'close-clicked': (GObject.SignalFlags.RUN_LAST, GObject.TYPE_NONE, ())
            }

    def __init__(self, label_text=""):
        GObject.GObject.__init__(self)
        #HIGHBox.__init__(self, spacing=4)

        self.label_text = label_text
        self.__create_widgets()

        #self.property_map = {"label_text" : self.label.get_label}

    def __create_widgets(self):
        self.label = Gtk.Label.new(self.label_text)
        self.close_image = Gtk.Image()
        self.close_image.set_from_stock(Gtk.STOCK_CLOSE, Gtk.IconSize.BUTTON)
        self.close_button = HIGButton()
        self.close_button.set_size_request(20, 20)
        self.close_button.set_relief(Gtk.ReliefStyle.NONE)
        self.close_button.set_focus_on_click(False)
        self.close_button.add(self.close_image)

        self.close_button.connect('clicked', self.__close_button_clicked)

        for w in (self.label, self.close_button):
            self.pack_start(w, False, False, 0)

        self.show_all()

        #     def do_get_property(self, property):
        #         func = self.property_map.get(property, None)
        #         if func:
        #             return func()
        #         else:
        #             raise

    def __close_button_clicked(self, data):
        self.emit('close-clicked')

    def get_text(self):
        return self.label.get_text()

    def set_text(self, text):
        self.label.set_text(text)

    def get_label(self):
        return self.label.get_label()

    def set_label(self, label):
        self.label.set_text(label)

GObject.type_register(HIGClosableTabLabel)

HIGAnimatedTabLabel = HIGClosableTabLabel
