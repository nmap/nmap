#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2020 Insecure.Com LLC ("The Nmap  *
# * Project"). Nmap is also a registered trademark of the Nmap Project.     *
# *                                                                         *
# * This program is distributed under the terms of the Nmap Public Source   *
# * License (NPSL). The exact license text applying to a particular Nmap    *
# * release or source code control revision is contained in the LICENSE     *
# * file distributed with that version of Nmap or source code control       *
# * revision. More Nmap copyright/legal information is available from       *
# * https://nmap.org/book/man-legal.html, and further information on the    *
# * NPSL license itself can be found at https://nmap.org/npsl. This header  *
# * summarizes some key points from the Nmap license, but is no substitute  *
# * for the actual license text.                                            *
# *                                                                         *
# * Nmap is generally free for end users to download and use themselves,    *
# * including commercial use. It is available from https://nmap.org.        *
# *                                                                         *
# * The Nmap license generally prohibits companies from using and           *
# * redistributing Nmap in commercial products, but we sell a special Nmap  *
# * OEM Edition with a more permissive license and special features for     *
# * this purpose. See https://nmap.org/oem                                  *
# *                                                                         *
# * If you have received a written Nmap license agreement or contract       *
# * stating terms other than these (such as an Nmap OEM license), you may   *
# * choose to use and redistribute Nmap under those terms instead.          *
# *                                                                         *
# * The official Nmap Windows builds include the Npcap software             *
# * (https://npcap.org) for packet capture and transmission. It is under    *
# * separate license terms which forbid redistribution without special      *
# * permission. So the official Nmap Windows builds may not be              *
# * redistributed without special permission (such as an Nmap OEM           *
# * license).                                                               *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes.          *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to submit your         *
# * changes as a Github PR or by email to the dev@nmap.org mailing list     *
# * for possible incorporation into the main distribution. Unless you       *
# * specify otherwise, it is understood that you are offering us very       *
# * broad rights to use your submissions as described in the Nmap Public    *
# * Source License Contributor Agreement. This is important because we      *
# * fund the project by selling licenses with various terms, and also       *
# * because the inability to relicense code has caused devastating          *
# * problems for other Free Software projects (such as KDE and NASM).       *
# *                                                                         *
# * The free version of Nmap is distributed in the hope that it will be     *
# * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,        *
# * indemnification and commercial support are all available through the    *
# * Npcap OEM program--see https://nmap.org/oem.                            *
# *                                                                         *
# ***************************************************************************/

"""
higwidgets/higlabels.py

   labels related classes
"""

__all__ = [
    'HIGSectionLabel', 'HIGHintSectionLabel', 'HIGEntryLabel', 'HIGDialogLabel'
    ]

import gtk


class HIGSectionLabel(gtk.Label):
    """
    Bold label, used to define sections
    """
    def __init__(self, text=None):
        gtk.Label.__init__(self)
        if text:
            self.set_markup("<b>%s</b>" % (text))
            self.set_justify(gtk.JUSTIFY_LEFT)
            self.set_alignment(0, 0.50)
            self.set_line_wrap(True)


class HIGHintSectionLabel(gtk.HBox, object):
    """
    Bold label used to define sections, with a little icon that shows up a hint
    when mouse is over it.
    """
    def __init__(self, text=None, hint=None):
        gtk.HBox.__init__(self)

        self.label = HIGSectionLabel(text)
        self.hint = Hint(hint)

        self.pack_start(self.label, False, False)
        self.pack_start(self.hint, False, False, 5)


class Hint(gtk.EventBox, object):
    def __init__(self, hint):
        gtk.EventBox.__init__(self)
        self.hint = hint

        self.hint_image = gtk.Image()
        self.hint_image.set_from_stock(
                gtk.STOCK_DIALOG_INFO, gtk.ICON_SIZE_SMALL_TOOLBAR)

        self.add(self.hint_image)

        self.connect("button-press-event", self.show_hint)

    def show_hint(self, widget, event=None):
        hint_window = HintWindow(self.hint)
        hint_window.show_all()


class HintWindow(gtk.Window):
    def __init__(self, hint):
        gtk.Window.__init__(self, gtk.WINDOW_POPUP)
        self.set_position(gtk.WIN_POS_MOUSE)
        bg_color = gtk.gdk.color_parse("#fbff99")

        self.modify_bg(gtk.STATE_NORMAL, bg_color)

        self.event = gtk.EventBox()
        self.event.modify_bg(gtk.STATE_NORMAL, bg_color)
        self.event.set_border_width(10)
        self.event.connect("button-press-event", self.close)

        self.hint_label = gtk.Label(hint)
        self.hint_label.set_use_markup(True)
        self.hint_label.set_line_wrap(True)
        self.hint_label.set_alignment(0.0, 0.5)

        self.event.add(self.hint_label)
        self.add(self.event)

    def close(self, widget, event=None):
        self.destroy()


class HIGEntryLabel(gtk.Label):
    """
    Simple label, like the ones used to label entries
    """
    def __init__(self, text=None):
        gtk.Label.__init__(self, text)
        self.set_justify(gtk.JUSTIFY_LEFT)
        self.set_alignment(0, 0.50)
        self.set_use_markup(True)
        self.set_line_wrap(True)


class HIGDialogLabel(gtk.Label):
    """
    Centered, line-wrappable label, usually used on dialogs.
    """
    def __init__(self, text=None):
        gtk.Label.__init__(self, text)
        self.set_justify(gtk.JUSTIFY_CENTER)
        self.set_use_markup(True)
        self.set_line_wrap(True)

if __name__ == "__main__":
    w = gtk.Window()
    h = HIGHintSectionLabel("Label", "Hint")
    w.add(h)
    w.connect("delete-event", lambda x, y: gtk.main_quit())
    w.show_all()

    gtk.main()
