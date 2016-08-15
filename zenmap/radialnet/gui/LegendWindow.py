# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2015 Insecure.Com LLC. Nmap is    *
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

import gtk
import pango
import math
import cairo

import zenmapCore.I18N
import radialnet.util.drawing as drawing

from radialnet.bestwidgets.windows import *
from radialnet.bestwidgets.boxes import *
from radialnet.bestwidgets.labels import *
from radialnet.gui.Image import Pixmaps
from radialnet.gui.NodeNotebook import NodeNotebook
from radialnet.util.drawing import *
DIMENSION_NORMAL = (350, 450)


def draw_pixmap(context, x, y, name, label):
    context.set_source_pixbuf(Pixmaps().get_pixbuf(name), x, y)
    context.paint()
    context.move_to(x + 50, y + 10)
    context.set_source_rgb(0, 0, 0)
    context.show_text(label)


def reset_font(context):
    context.select_font_face(
            "Monospace", cairo.FONT_SLANT_NORMAL, cairo.FONT_SLANT_NORMAL)
    context.set_font_size(11)


def draw_heading(context, x, y, label):
    context.select_font_face(
            "Monospace", cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
    context.set_font_size(13)
    context.move_to(x - 15, y)
    context.set_source_rgb(0, 0, 0)
    context.show_text(label)
    reset_font(context)


def draw_circle(context, x, y, size, color, label):
    context.set_source_rgb(0, 0, 0)
    context.move_to(x, y)
    context.arc(x, y, size, 0, 2 * math.pi)
    context.stroke_preserve()
    context.set_source_rgb(*color)
    context.fill()
    context.set_source_rgb(0, 0, 0)
    context.move_to(x + 50, y + 5)
    context.show_text(label)


def draw_square(context, x, y, size, color):
    context.set_source_rgb(0, 0, 0)
    context.rectangle(x, y - size / 2, size, size)
    context.stroke_preserve()
    context.set_source_rgb(*color)
    context.fill()


def draw_line(context, x, y, dash, color, label):
    context.set_source_rgb(*color)
    context.move_to(x - 20, y)
    context.set_dash(dash)
    context.line_to(x + 25, y)
    context.stroke()
    context.set_dash([])
    context.set_source_rgb(0, 0, 0)
    context.move_to(x + 50, y + 5)
    context.show_text(label)


class LegendWindow(gtk.Window):
    """
    """
    def __init__(self):
        """
        """
        gtk.Window.__init__(self, gtk.WINDOW_TOPLEVEL)
        self.set_default_size(DIMENSION_NORMAL[0], DIMENSION_NORMAL[1])
        self.__title_font = pango.FontDescription("Monospace Bold")
        self.set_title(_("Topology Legend"))

        self.vbox = gtk.VBox()
        self.add(self.vbox)

        self.drawing_area = gtk.DrawingArea()
        self.vbox.pack_start(self.drawing_area)
        self.drawing_area.connect("expose-event", self.expose_event_handler)
        self.more_uri = gtk.LinkButton(
                "https://nmap.org/book/zenmap-topology.html#zenmap-topology-legend",
                label=_("View full legend online"))
        self.vbox.pack_start(self.more_uri, False, False)

    def expose_event_handler(self, widget, event):
        """
        """
        self.graphic_context = widget.window.cairo_create()
        w, h = widget.window.get_size()
        x, y = 45, 20
        draw_heading(self.graphic_context, x, y, _("Hosts"))

        # white circle
        y += 20
        draw_circle(self.graphic_context, x, y, 3, (1, 1, 1),
                _("host was not port scanned"))
        # green circle
        y += 20
        draw_circle(self.graphic_context, x, y, 4, (0, 1, 0),
                _("host with fewer than 3 open ports"))
        # yellow circle
        y += 20
        draw_circle(self.graphic_context, x, y, 5, (1, 1, 0),
                _("host with 3 to 6 open ports"))
        # red circle
        y += 20
        draw_circle(self.graphic_context, x, y, 6, (1, 0, 0),
                _("host with more than 6 open ports"))

        # green square
        y += 20
        rx = x - 20
        draw_square(self.graphic_context, rx, y, 10, (0, 1, 0))
        rx += 10 + 5
        # yellow square
        draw_square(self.graphic_context, rx, y, 12, (1, 1, 0))
        rx += 12 + 5
        # red square
        draw_square(self.graphic_context, rx, y, 14, (1, 0, 0))

        self.graphic_context.move_to(x + 50, y + 5)
        self.graphic_context.set_source_rgb(0, 0, 0)
        self.graphic_context.show_text(_("host is a router, switch, or WAP"))

        # connections between hosts
        y += 30
        draw_heading(self.graphic_context, x, y, _("Traceroute connections"))

        y += 20
        self.graphic_context.move_to(x, y)
        self.graphic_context.show_text(_("Thicker line means higher round-trip time"))
        # primary traceroute (blue line)
        y += 20
        draw_line(self.graphic_context, x, y, [], (0, 0, 1),
                _("primary traceroute connection"))
        # Alternate route (orange line)
        y += 20
        draw_line(self.graphic_context, x, y, [], (1, 0.5, 0),
                _("alternate path"))
        # no traceroute
        y += 20
        draw_line(self.graphic_context, x, y, [4.0, 2.0], (0, 0, 0),
                _("no traceroute information"))
        # missing traceroute
        y += 20
        self.graphic_context.set_source_rgb(0.5, 0.7, 0.95)
        self.graphic_context.move_to(x - 15, y)
        self.graphic_context.arc(x - 25, y, 5, 0, 2 * math.pi)
        self.graphic_context.stroke_preserve()
        draw_line(self.graphic_context, x, y, [4.0, 2.0], (0.5, 0.7, 0.95),
                _("missing traceroute hop"))

        # special purpose hosts
        y += 30
        draw_heading(self.graphic_context, x, y, _("Additional host icons"))

        # router image
        y += 20
        draw_pixmap(self.graphic_context, x, y, "router", _("router"))

        # switch image
        y += 20
        draw_pixmap(self.graphic_context, x, y, "switch", _("switch"))

        # wap image
        y += 20
        draw_pixmap(self.graphic_context, x, y, "wireless",
                _("wireless access point"))

        # firewall image
        y += 20
        draw_pixmap(self.graphic_context, x, y, "firewall", _("firewall"))

        # host with filtered ports
        y += 20
        draw_pixmap(self.graphic_context, x, y, "padlock",
                _("host with some filtered ports"))
