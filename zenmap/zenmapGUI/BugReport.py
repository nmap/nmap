#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, version detection, and the Nmap Scripting Engine.            *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
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
# * works of Nmap, as well as other software we distribute under this       *
# * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
# * but is meant to clarify our interpretation of derived works with some   *
# * common examples.  Our interpretation applies only to Nmap--we don't     *
# * speak for other people's GPL works.                                     *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@insecure.com for     *
# * further information.                                                    *
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
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
# *                                                                         *
# ***************************************************************************/

import gtk

from zenmapGUI.higwidgets.higboxes import HIGVBox

from zenmapCore.Name import APP_DISPLAY_NAME, NMAP_DISPLAY_NAME, NMAP_WEB_SITE
import zenmapCore.I18N

# For escaping text in marked-up labels.
from xml.sax.saxutils import escape

class BugReport(gtk.Window, object):
    def __init__(self):
        gtk.Window.__init__(self)
        self.set_title(_('How to Report a Bug'))
        self.set_position(gtk.WIN_POS_CENTER_ALWAYS)

        self._create_widgets()
        self._pack_widgets()
        self._connect_widgets()

    def _create_widgets(self):
        self.vbox = HIGVBox()
        self.button_box = gtk.HButtonBox()

        self.text = gtk.Label()

        self.btn_ok = gtk.Button(stock=gtk.STOCK_OK)

    def _pack_widgets(self):
        self.vbox.set_border_width(6)

        self.text.set_line_wrap(True)
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
<b>&lt;nmap-dev@insecure.org&gt;</b>. Please include everything you have \
learned about the problem, as well as what version of Nmap you are \
running and what operating system version it is running on. Problem \
reports and %(nmap)s usage questions sent to nmap-dev@insecure.org are \
far more likely to be answered than those sent to Fyodor directly.

Code patches to fix bugs are even better than bug reports. Basic \
instructions for creating patch files with your changes are available at \
http://nmap.org/data/HACKING. Patches may be sent to nmap-dev \
(recommended) or to Fyodor directly.
""") % {"app": escape(APP_DISPLAY_NAME), "nmap": escape(NMAP_DISPLAY_NAME), "nmap_web": escape(NMAP_WEB_SITE)})
        self.vbox.add(self.text)

        self.button_box.set_layout(gtk.BUTTONBOX_END)
        self.button_box.pack_start(self.btn_ok)

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
    w.connect("delete-event", lambda x, y: gtk.main_quit())

    gtk.main()
