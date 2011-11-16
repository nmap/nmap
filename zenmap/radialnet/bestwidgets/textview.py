# vim: set fileencoding=utf-8 :

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
        self.__textbuffer = gtk.TextBuffer()
        self.__textview = gtk.TextView(self.__textbuffer)

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
        self.connect('expose_event', self.__expose)

        self.__auto_scroll = False

        self.__create_widgets()


    def __create_widgets(self):
        """
        """
        self.__hbox = BWHBox(spacing=6)

        self.__textbuffer = gtk.TextBuffer()
        self.__textview = gtk.TextView(self.__textbuffer)

        self.__linebuffer = gtk.TextBuffer()
        self.__lineview = gtk.TextView(self.__linebuffer)
        self.__lineview.set_justification(gtk.JUSTIFY_RIGHT)
        self.__lineview.set_editable(False)
        self.__lineview.set_sensitive(False)

        self.__hbox.bw_pack_start_noexpand_nofill(self.__lineview)
        self.__hbox.bw_pack_start_expand_fill(self.__textview)

        self.add_with_viewport(self.__hbox)


    def __expose(self, widget, event):
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
