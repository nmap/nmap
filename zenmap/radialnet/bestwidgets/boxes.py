# vim: set fileencoding=utf-8 :

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

import gtk

__all__ = ('BWBox', 'BWHBox', 'BWVBox',
        'BWStatusbar', 'BWTable', 'BWScrolledWindow')


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
                       xoptions=gtk.EXPAND | gtk.FILL,
                       yoptions=gtk.EXPAND | gtk.FILL,
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
