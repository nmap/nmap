# vim: set fileencoding=utf-8 :

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
from radialnet.bestwidgets.boxes import *


class BWTextView(BWScrolledWindow):
    """
    """
    def __init__(self):
        """
        """
        BWScrolledWindow.__init__(self)

        self.__auto_scroll = False

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__textbuffer = Gtk.TextBuffer()
        self.__textview = Gtk.TextView.new_with_buffer(self.__textbuffer)

        self.add_with_viewport(self.__textview)

    def bw_set_auto_scroll(self, value):
        """
        """
        self.__auto_scroll = value

    def bw_set_editable(self, editable):
        """
        """
        self.__textview.set_editable(False)

    def bw_modify_font(self, font):
        """
        """
        self.__textview.modify_font(font)

    def bw_set_text(self, text):
        """
        """
        self.__textbuffer.set_text(text)

        if self.__auto_scroll:
            self.bw_set_scroll_down()

    def bw_get_text(self):
        """
        """
        return self.__textbuffer.get_text(self.__textbuffer.get_start_iter(),
                                          self.__textbuffer.get_end_iter())

    def bw_set_scroll_down(self):
        """
        """
        self.get_vadjustment().set_value(self.get_vadjustment().upper)

    def bw_get_textbuffer(self):
        """
        """
        return self.__textbuffer


class BWTextEditor(BWScrolledWindow):
    """
    """
    def __init__(self):
        """
        """
        BWScrolledWindow.__init__(self)
        self.connect('draw', self.__draw)

        self.__auto_scroll = False

        self.__create_widgets()

    def __create_widgets(self):
        """
        """
        self.__hbox = BWHBox(spacing=6)

        self.__textbuffer = Gtk.TextBuffer()
        self.__textview = Gtk.TextView.new_with_buffer(self.__textbuffer)

        self.__linebuffer = Gtk.TextBuffer()
        self.__lineview = Gtk.TextView.new_with_buffer(self.__linebuffer)
        self.__lineview.set_justification(Gtk.Justification.RIGHT)
        self.__lineview.set_editable(False)
        self.__lineview.set_sensitive(False)

        self.__hbox.bw_pack_start_noexpand_nofill(self.__lineview)
        self.__hbox.bw_pack_start_expand_fill(self.__textview)

        self.add_with_viewport(self.__hbox)

    def __draw(self, widget, event):
        """
        """
        # code to fix a gtk issue that don't show text correctly
        self.__hbox.check_resize()

    def bw_set_auto_scroll(self, value):
        """
        """
        self.__auto_scroll = value

    def bw_set_editable(self, editable):
        """
        """
        self.__textview.set_editable(False)

    def bw_modify_font(self, font):
        """
        """
        self.__textview.modify_font(font)
        self.__lineview.modify_font(font)

    def bw_set_text(self, text):
        """
        """
        if text != "":

            count = text.count('\n') + text.count('\r')

            lines = range(1, count + 2)
            lines = [str(i).strip() for i in lines]

            self.__textbuffer.set_text(text)
            self.__linebuffer.set_text('\n'.join(lines))

            if self.__auto_scroll:
                self.bw_set_scroll_down()

        else:

            self.__textbuffer.set_text("")
            self.__linebuffer.set_text("")

    def bw_get_text(self):
        """
        """
        return self.__textbuffer.get_text(self.__textbuffer.get_start_iter(),
                                          self.__textbuffer.get_end_iter())

    def bw_set_scroll_down(self):
        """
        """
        self.get_vadjustment().set_value(self.get_vadjustment().upper)
