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

"""
higwidgets/higdialogs.py

   dialog related classes
"""

__all__ = ['HIGDialog', 'HIGAlertDialog']

import gtk

from gtkutils import gtk_version_minor

class HIGDialog(gtk.Dialog):
    """
    HIGFied Dialog
    """
    def __init__(self, title='', parent=None, flags=0, buttons=()):
        gtk.Dialog.__init__(self, title, parent, flags, buttons)
        self.set_border_width(5)
        self.vbox.set_border_width(2)
        self.vbox.set_spacing(6)

class HIGAlertDialog(gtk.MessageDialog):
    """
    HIGfied Alert Dialog.

    Implements the sugestions documented on:
    http://developer.gnome.org/projects/gup/hig/2.0/windows-alert.html
    """

    def __init__(self, parent=None, flags=0, type=gtk.MESSAGE_INFO,
                 # HIG mandates that every Alert should have an "affirmative
                 # button that dismisses the alert and performs the action
                 # suggested"
                 buttons=gtk.BUTTONS_OK,
                 message_format=None,
                 secondary_text=None):

        gtk.MessageDialog.__init__(self, parent, flags, type, buttons)

        self.set_resizable(False)

        # HIG mandates that Message Dialogs should have no title:
        # "Alert windows have no titles, as the title would usually
        # unnecessarily duplicate the alert's primary text"
        self.set_title("")
        self.set_markup("<span weight='bold'size='larger'>%s</span>" \
                        % message_format)
        if secondary_text:
            # GTK up to version 2.4 does not have secondary_text
            try:
                self.format_secondary_text(secondary_text)
            except:
                pass


if __name__ == '__main__':

    from higlabels import HIGEntryLabel, HIGDialogLabel

    # HIGDialog
    d = HIGDialog(title='HIGDialog',
                  buttons=(gtk.STOCK_OK, gtk.RESPONSE_ACCEPT))
    dialog_label = HIGDialogLabel('A HIGDialogLabel on a HIGDialog')
    dialog_label.show()
    d.vbox.pack_start(dialog_label)

    entry_label = HIGEntryLabel('A HIGEntryLabel on a HIGDialog')
    entry_label.show()
    d.vbox.pack_start(entry_label)

    d.run()
    d.destroy()

    # HIGAlertDialog
    d = HIGAlertDialog(message_format="You Have and Appointment in 15 minutes",
                       secondary_text="You shouldn't be late this time. "
                       "Oh, and there's a huge traffic jam on your way!")
    d.run()
    d.destroy()
