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



class BWBox(gtk.Box):
    """
    """
    def bw_pack_start_expand_fill(self, widget, padding=0):
        """
        """
        self.pack_start(widget, True, True, padding)


    def bw_pack_start_expand_nofill(self, widget, padding=0):
        """
        """
        self.pack_start(widget, True, False, padding)


    def bw_pack_start_noexpand_nofill(self, widget, padding=0):
        """
        """
        self.pack_start(widget, False, False, padding)


    def bw_pack_end_expand_fill(self, widget, padding=0):
        """
        """
        self.pack_end(widget, True, True, padding)


    def bw_pack_end_expand_nofill(self, widget, padding=0):
        """
        """
        self.pack_end(widget, True, False, padding)


    def bw_pack_end_noexpand_nofill(self, widget, padding=0):
        """
        """
        self.pack_end(widget, False, False, padding)



class BWHBox(gtk.HBox, BWBox):
    """
    """
    def __init__(self, homogeneous=False, spacing=12):
        """
        """
        gtk.HBox.__init__(self, homogeneous, spacing)



class BWVBox(gtk.VBox, BWBox):
    """
    """
    def __init__(self, homogeneous=False, spacing=12):
        """
        """
        gtk.VBox.__init__(self, homogeneous, spacing)



class BWStatusbar(gtk.Statusbar, BWBox):
    """
    """
    def __init__(self, homogeneous=False, spacing=12):
        """
        """
        gtk.HBox.__init__(self, homogeneous, spacing)



class BWTable(gtk.Table, BWBox):
    """
    """
    def __init__(self, rows=1, columns=1, homogeneous=False):
        """
        """
        gtk.Table.__init__(self, rows, columns, homogeneous)
        self.bw_set_spacing(12)

        self.__rows = rows
        self.__columns = columns

        self.__last_point = (0, 0)


    def bw_set_spacing(self, spacing):
        """
        """
        self.set_row_spacings(spacing)
        self.set_col_spacings(spacing)


    def bw_resize(self, rows, columns):
        """
        """
        self.__rows = rows
        self.__columns = columns

        self.resize(rows, columns)


    def bw_attach_next(self,
                       child,
                       xoptions=gtk.EXPAND|gtk.FILL,
                       yoptions=gtk.EXPAND|gtk.FILL,
                       xpadding=0,
                       ypadding=0):
        """
        """
        row, column = self.__last_point

        if row != self.__rows:

            self.attach(child,
                        column,
                        column + 1,
                        row,
                        row + 1,
                        xoptions,
                        yoptions,
                        xpadding,
                        ypadding)

            if column + 1 == self.__columns:

                column = 0
                row += 1

            else:
                column += 1

            self.__last_point = (row, column)



class BWScrolledWindow(gtk.ScrolledWindow):
    """
    """
    def __init__(self):
        """
        """
        gtk.ScrolledWindow.__init__(self)
        self.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.set_shadow_type(gtk.SHADOW_NONE)
        self.set_border_width(6)
