#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
# * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
# * modify, and redistribute this software under certain conditions.  If    *
# * you wish to embed Nmap technology into proprietary software, we sell    *
# * alternative licenses (contact sales@nmap.com).  Dozens of software      *
# * vendors already license Nmap technology such as host discovery, port    *
# * scanning, OS detection, version detection, and the Nmap Scripting       *
# * Engine.                                                                 *
# *                                                                         *
# * Note that the GPL places important restrictions on "derivative works",  *
# * yet it does not provide a detailed definition of that term.  To avoid   *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
# * derivative work for the purpose of this license if it does any of the   *
# * following with any software or content covered by this license          *
# * ("Covered Software"):                                                   *
# *                                                                         *
# * o Integrates source code from Covered Software.                         *
# *                                                                         *
# * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
# * or nmap-service-probes.                                                 *
# *                                                                         *
# * o Is designed specifically to execute Covered Software and parse the    *
# * results (as opposed to typical shell or execution-menu apps, which will *
# * execute anything you tell them to).                                     *
# *                                                                         *
# * o Includes Covered Software in a proprietary executable installer.  The *
# * installers produced by InstallShield are an example of this.  Including *
# * Nmap with other software in compressed or archival form does not        *
# * trigger this provision, provided appropriate open source decompression  *
# * or de-archiving software is widely available for no charge.  For the    *
# * purposes of this license, an installer is considered to include Covered *
# * Software even if it actually retrieves a copy of Covered Software from  *
# * another source during runtime (such as by downloading it from the       *
# * Internet).                                                              *
# *                                                                         *
# * o Links (statically or dynamically) to a library which does any of the  *
# * above.                                                                  *
# *                                                                         *
# * o Executes a helper program, module, or script to do any of the above.  *
# *                                                                         *
# * This list is not exclusive, but is meant to clarify our interpretation  *
# * of derived works with some common examples.  Other people may interpret *
# * the plain GPL differently, so we consider this a special exception to   *
# * the GPL that we apply to Covered Software.  Works which meet any of     *
# * these conditions must conform to all of the terms of this license,      *
# * particularly including the GPL Section 3 requirements of providing      *
# * source code and allowing free redistribution of the work as a whole.    *
# *                                                                         *
# * As another special exception to the GPL terms, Insecure.Com LLC grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * Any redistribution of Covered Software, including any derived works,    *
# * must obey and carry forward all of the terms of this license, including *
# * obeying all GPL rules and restrictions.  For example, source code of    *
# * the whole work must be provided and free redistribution must be         *
# * allowed.  All GPL references to "this License", are to be treated as    *
# * including the terms and conditions of this license text as well.        *
# *                                                                         *
# * Because this license imposes special exceptions to the GPL, Covered     *
# * Work may not be combined (even as part of a larger work) with plain GPL *
# * software.  The terms, conditions, and exceptions of this license must   *
# * be included as well.  This license is incompatible with some other open *
# * source licenses as well.  In some cases we can relicense portions of    *
# * Nmap or grant special permissions to use it in other open source        *
# * software.  Please contact fyodor@nmap.org with any such requests.       *
# * Similarly, we don't incorporate incompatible open source software into  *
# * Covered Software without special permission from the copyright holders. *
# *                                                                         *
# * If you have any questions about the licensing restrictions on using     *
# * Nmap in other works, are happy to help.  As mentioned above, we also    *
# * offer alternative license to integrate Nmap into proprietary            *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@nmap.com for further *
# * information.                                                            *
# *                                                                         *
# * If you have received a written license agreement or contract for        *
# * Covered Software stating terms other than these, you may choose to use  *
# * and redistribute Covered Software under those terms instead of these.   *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes.          *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to the dev@nmap.org mailing list for possible incorporation into the    *
# * main distribution.  By sending these changes to Fyodor or one of the    *
# * Insecure.Org development mailing lists, or checking them into the Nmap  *
# * source code repository, it is understood (unless you specify otherwise) *
# * that you are offering the Nmap Project (Insecure.Com LLC) the           *
# * unlimited, non-exclusive right to reuse, modify, and relicense the      *
# * code.  Nmap will always be available Open Source, but this is important *
# * because the inability to relicense code has caused devastating problems *
# * for other Free Software projects (such as KDE and NASM).  We also       *
# * occasionally relicense the code to third parties as discussed above.    *
# * If you wish to specify special license conditions of your               *
# * contributions, just say so when you send them.                          *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
# * license file for more details (it's in a COPYING file included with     *
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
# *                                                                         *
# ***************************************************************************/

import sys
import gtk
import traceback

from zenmapGUI.higwidgets.higdialogs import HIGDialog
from zenmapGUI.higwidgets.higboxes import HIGHBox

from zenmapCore.Name import APP_DISPLAY_NAME
from zenmapCore.Version import VERSION
import zenmapCore.I18N


# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

# For escaping text in marked-up labels.
from xml.sax.saxutils import escape


class CrashReport(HIGDialog):
    def __init__(self, type, value, tb):
        HIGDialog.__init__(self)
        gtk.Window.__init__(self)
        self.set_title(_('Crash Report'))
        self.set_position(gtk.WIN_POS_CENTER_ALWAYS)

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

        trace = "".join(traceback.format_exception(type, value, tb))
        text = "Version: " + VERSION + "\n" + trace
        self.description_text.get_buffer().set_text(text)

    def _create_widgets(self):
        self.button_box = gtk.HButtonBox()
        self.button_box_ok = gtk.HButtonBox()

        self.description_scrolled = gtk.ScrolledWindow()
        self.description_text = gtk.TextView()
        self.description_text.set_editable(False)

        self.bug_text = gtk.Label()
        self.bug_text.set_markup(_('An unexpected error has crashed '
            '%(app_name)s. Please copy the stack trace below and send it to '
            'the <a href="mailto:dev@nmap.org">dev@nmap.org</a> mailing list. '
            '(<a href="http://seclists.org/nmap-dev/">More about the list.</a>'
            ') The developers will see your report and try to fix the problem.'
            ) % {"app_name": escape(APP_DISPLAY_NAME)})
        self.email_frame = gtk.Frame()
        self.email_label = gtk.Label()
        self.email_label.set_markup(_('<b>Copy and email to '
            '<a href="mailto:dev@nmap.org">dev@nmap.org</a>:</b>'))
        self.btn_copy = gtk.Button(stock=gtk.STOCK_COPY)
        self.btn_ok = gtk.Button(stock=gtk.STOCK_OK)

        self.hbox = HIGHBox()

    def _pack_widgets(self):
        self.description_scrolled.add(self.description_text)
        self.description_scrolled.set_policy(
                gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.description_scrolled.set_size_request(400, 150)
        self.description_text.set_wrap_mode(gtk.WRAP_WORD)

        self.bug_text.set_line_wrap(True)
        self.email_label.set_line_wrap(True)

        self.email_frame.set_label_widget(self.email_label)
        self.email_frame.set_shadow_type(gtk.SHADOW_NONE)

        self.hbox.set_border_width(6)
        self.vbox.set_border_width(6)

        self.hbox._pack_expand_fill(self.bug_text)

        self.button_box.set_layout(gtk.BUTTONBOX_START)
        self.button_box_ok.set_layout(gtk.BUTTONBOX_END)

        self.button_box.pack_start(self.btn_copy)
        self.button_box_ok.pack_start(self.btn_ok)

        self.vbox.pack_start(self.hbox)
        self.vbox.pack_start(self.email_frame)
        self.vbox.pack_start(self.description_scrolled)
        self.vbox.pack_start(self.button_box)
        self.action_area.pack_start(self.button_box_ok)

    def _connect_widgets(self):
        self.btn_ok.connect("clicked", self.close)
        self.btn_copy.connect("clicked", self.copy)
        self.connect("delete-event", self.close)

    def get_description(self):
        buff = self.description_text.get_buffer()
        return buff.get_text(buff.get_start_iter(), buff.get_end_iter())

    def copy(self, widget=None, event=None):
        clipboard = gtk.clipboard_get()
        clipboard.set_text(self.get_description())
        clipboard.store()

    def close(self, widget=None, event=None):
        self.destroy()
        gtk.main_quit()
        sys.exit(0)

if __name__ == "__main__":
    c = CrashReport(None, None, None)
    c.show_all()
    c.connect("delete-event", lambda x, y: gtk.main_quit())

    gtk.main()
