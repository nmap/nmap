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

"""
higwidgets/higdialogs.py

   dialog related classes
"""

__all__ = ['HIGDialog', 'HIGAlertDialog']

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk


class HIGDialog(Gtk.Dialog):
    """
    HIGFied Dialog
    """
    def __init__(self, title='', parent=None, flags=0, buttons=()):
        Gtk.Dialog.__init__(self, title=title, parent=parent, flags=flags)
        self.set_border_width(5)
        self.vbox.set_border_width(2)
        self.vbox.set_spacing(6)

        if buttons:
            self.add_buttons(*buttons)


class HIGAlertDialog(Gtk.MessageDialog):
    """
    HIGfied Alert Dialog.

    Implements the suggestions documented in:
    http://developer.gnome.org/projects/gup/hig/2.0/windows-alert.html
    """

    def __init__(self, parent=None, flags=0, type=Gtk.MessageType.INFO,
                 # HIG mandates that every Alert should have an "affirmative
                 # button that dismisses the alert and performs the action
                 # suggested"
                 buttons=Gtk.ButtonsType.OK,
                 message_format=None,
                 secondary_text=None):

        Gtk.MessageDialog.__init__(self, parent=parent, flags=flags,
                                   message_type=type, buttons=buttons)

        self.set_resizable(False)

        # HIG mandates that Message Dialogs should have no title:
        # "Alert windows have no titles, as the title would usually
        # unnecessarily duplicate the alert's primary text"
        self.set_title("")
        self.set_markup(
                "<span weight='bold'size='larger'>%s</span>" % message_format)
        if secondary_text:
            self.format_secondary_text(secondary_text)


if __name__ == '__main__':

    from higlabels import HIGEntryLabel, HIGDialogLabel

    # HIGDialog
    d = HIGDialog(title='HIGDialog',
                  buttons=(Gtk.STOCK_OK, Gtk.ResponseType.ACCEPT))
    dialog_label = HIGDialogLabel('A HIGDialogLabel on a HIGDialog')
    dialog_label.show()
    d.vbox.pack_start(dialog_label, True, True, 0)

    entry_label = HIGEntryLabel('A HIGEntryLabel on a HIGDialog')
    entry_label.show()
    d.vbox.pack_start(entry_label, True, True, 0)

    d.run()
    d.destroy()

    # HIGAlertDialog
    d = HIGAlertDialog(message_format="You Have and Appointment in 15 minutes",
                       secondary_text="You shouldn't be late this time. "
                       "Oh, and there's a huge traffic jam on your way!")
    d.run()
    d.destroy()
