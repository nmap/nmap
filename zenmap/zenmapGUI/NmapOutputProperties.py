#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2017 Insecure.Com LLC ("The Nmap  *
# * Project"). Nmap is also a registered trademark of the Nmap Project.     *
# * This program is free software; you may redistribute and/or modify it    *
# * under the terms of the GNU General Public License as published by the   *
# * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
# * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
# * right to use, modify, and redistribute this software under certain      *
# * conditions.  If you wish to embed Nmap technology into proprietary      *
# * software, we sell alternative licenses (contact sales@nmap.com).        *
# * Dozens of software vendors already license Nmap technology such as      *
# * host discovery, port scanning, OS detection, version detection, and     *
# * the Nmap Scripting Engine.                                              *
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
# * As another special exception to the GPL terms, the Nmap Project grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * The Nmap Project has permission to redistribute Npcap, a packet         *
# * capturing driver and library for the Microsoft Windows platform.        *
# * Npcap is a separate work with it's own license rather than this Nmap    *
# * license.  Since the Npcap license does not permit redistribution        *
# * without special permission, our Nmap Windows binary packages which      *
# * contain Npcap may not be redistributed without special permission.      *
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
# * source code repository, it is understood (unless you specify            *
# * otherwise) that you are offering the Nmap Project the unlimited,        *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because     *
# * the inability to relicense code has caused devastating problems for     *
# * other Free Software projects (such as KDE and NASM).  We also           *
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
import gtk.gdk
import pango

import zenmapCore.I18N
from zenmapCore.UmitConf import NmapOutputHighlight

from zenmapGUI.higwidgets.higdialogs import HIGDialog
from zenmapGUI.higwidgets.hignotebooks import HIGNotebook
from zenmapGUI.higwidgets.higboxes import HIGVBox
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.higwidgets.higlabels import HIGEntryLabel
from zenmapGUI.higwidgets.higbuttons import HIGButton, HIGToggleButton


class NmapOutputProperties(HIGDialog):
    def __init__(self, nmap_output_view):
        HIGDialog.__init__(self, _("Nmap Output Properties"),
                           buttons=(gtk.STOCK_CLOSE, gtk.RESPONSE_CLOSE))

        self.nmap_highlight = NmapOutputHighlight()

        self.__create_widgets()
        self.__pack_widgets()
        self.highlight_tab()

        self.vbox.show_all()

    def __create_widgets(self):
        self.properties_notebook = HIGNotebook()

    def __pack_widgets(self):
        self.vbox.pack_start(self.properties_notebook)

    def highlight_tab(self):
        # Creating highlight tab main box
        self.highlight_main_vbox = HIGVBox()

        # Creating highlight tab main table
        self.highlight_main_table = HIGTable()
        self.highlight_main_table.set_border_width(6)

        #############
        # Properties:
        self.property_names = {"details": [_("details"), "MAC Address:"],
                               "port_list": [_("port listing title"),
                                   "PORT   STATE   SERVICE"],
                               "open_port": [_("open port"),
                                   "22/tcp   open   ssh"],
                               "closed_port": [_("closed port"),
                                   "70/tcp   closed   gopher"],
                               "filtered_port": [_("filtered port"),
                                   "80/tcp   filtered   http"],
                               "date": [_("date"), "2006-05-26 11:14 BRT"],
                               "hostname": [_("hostname"), "scanme.nmap.org"],
                               "ip": [_("ip"), "127.0.0.1"]}

        for p in self.property_names:
            settings = self.nmap_highlight.__getattribute__(p)

            self.property_names[p].append(settings[0])
            self.property_names[p].append(settings[1])
            self.property_names[p].append(settings[2])
            self.property_names[p].append(gtk.gdk.Color(*settings[3]))
            self.property_names[p].append(gtk.gdk.Color(*settings[4]))
            self.property_names[p].append(settings[5])

        # Creating properties and related widgets and attaching it to main
        # table
        y1 = 0
        y2 = 1
        for p in self.property_names:
            hp = HighlightProperty(p, self.property_names[p])
            self.highlight_main_table.attach(
                    hp.property_name_label, 0, 1, y1, y2)
            self.highlight_main_table.attach(hp.example_label, 1, 2, y1, y2)
            self.highlight_main_table.attach(hp.bold_tg_button, 2, 3, y1, y2)
            self.highlight_main_table.attach(hp.italic_tg_button, 3, 4, y1, y2)
            self.highlight_main_table.attach(
                    hp.underline_tg_button, 4, 5, y1, y2)
            self.highlight_main_table.attach(
                    hp.text_color_button, 5, 6, y1, y2)
            self.highlight_main_table.attach(
                    hp.highlight_color_button, 6, 7, y1, y2)

            # Setting example styles and colors
            hp.update_example()

            self.property_names[p].append(hp)

            y1 += 1
            y2 += 1

        # Packing main table into main vbox
        self.highlight_main_vbox.pack_start(self.highlight_main_table)

        # Adding color tab
        self.properties_notebook.append_page(
                self.highlight_main_vbox,
                gtk.Label(_("Highlight definitions")))


class HighlightProperty(object):
    def __init__(self, property_name, property):
        self.__create_widgets()

        self.property_name = property_name

        self.property_label = property[0].capitalize()
        self.example = property[1]
        self.bold = property[2]
        self.italic = property[3]
        self.underline = property[4]

        self.text_color = property[5]
        self.highlight_color = property[6]

        self.__connect_buttons()

    def __create_widgets(self):
        self.property_name_label = HIGEntryLabel("")
        self.example_label = HIGEntryLabel("")
        self.bold_tg_button = HIGToggleButton("", gtk.STOCK_BOLD)
        self.italic_tg_button = HIGToggleButton("", gtk.STOCK_ITALIC)
        self.underline_tg_button = HIGToggleButton("", gtk.STOCK_UNDERLINE)
        self.text_color_button = HIGButton(
                _("Text"), stock=gtk.STOCK_SELECT_COLOR)
        self.highlight_color_button = HIGButton(
                _("Highlight"), stock=gtk.STOCK_SELECT_COLOR)

    def __connect_buttons(self):
        self.bold_tg_button.connect("toggled", self.update_example)
        self.italic_tg_button.connect("toggled", self.update_example)
        self.underline_tg_button.connect("toggled", self.update_example)

        self.text_color_button.connect("clicked", self.text_color_dialog)
        self.highlight_color_button.connect(
                "clicked", self.highlight_color_dialog)

    ####################################
    # Text color dialog

    def text_color_dialog(self, widget):
        color_dialog = gtk.ColorSelectionDialog(
                "%s %s" % (self.label, _("text color")))
        color_dialog.colorsel.set_current_color(self.text_color)

        color_dialog.ok_button.connect(
                "clicked", self.text_color_dialog_ok, color_dialog)
        color_dialog.cancel_button.connect(
                "clicked", self.text_color_dialog_cancel, color_dialog)
        color_dialog.connect(
                "delete-event", self.text_color_dialog_close, color_dialog)

        color_dialog.run()

    def text_color_dialog_ok(self, widget, color_dialog):
        self.text_color = color_dialog.colorsel.get_current_color()
        color_dialog.destroy()
        self.update_example()

    def text_color_dialog_cancel(self, widget, color_dialog):
        color_dialog.destroy()

    def text_color_dialog_close(self, widget, extra, color_dialog):
        color_dialog.destroy()

    #########################################
    # Highlight color dialog
    def highlight_color_dialog(self, widget):
        color_dialog = gtk.ColorSelectionDialog(
                "%s %s" % (self.property_name, _("highlight color")))
        color_dialog.colorsel.set_current_color(self.highlight_color)

        color_dialog.ok_button.connect(
                "clicked", self.highlight_color_dialog_ok, color_dialog)
        color_dialog.cancel_button.connect(
                "clicked", self.highlight_color_dialog_cancel,
                color_dialog)
        color_dialog.connect(
                "delete-event", self.highlight_color_dialog_close,
                color_dialog)

        color_dialog.run()

    def highlight_color_dialog_ok(self, widget, color_dialog):
        self.highlight_color = color_dialog.colorsel.get_current_color()
        color_dialog.destroy()
        self.update_example()

    def highlight_color_dialog_cancel(self, widget, color_dialog):
        color_dialog.destroy()

    def highlight_color_dialog_close(self, widget, extra, color_dialog):
        color_dialog.destroy()

    def update_example(self, widget=None):
        start = 0
        end = len(self.example)

        attributes = pango.AttrList()

        attributes.insert(
                pango.AttrForeground(self.text_color.red,
                    self.text_color.green, self.text_color.blue, start, end))
        attributes.insert(pango.AttrBackground(self.highlight_color.red,
                                               self.highlight_color.green,
                                               self.highlight_color.blue,
                                               start, end))

        # Bold verification
        if self.bold_tg_button.get_active():
            attributes.insert(pango.AttrWeight(pango.WEIGHT_HEAVY, start, end))
        else:
            attributes.insert(
                    pango.AttrWeight(pango.WEIGHT_NORMAL, start, end))

        # Italic verification
        if self.italic_tg_button.get_active():
            attributes.insert(pango.AttrStyle(pango.STYLE_ITALIC, start, end))
        else:
            attributes.insert(pango.AttrStyle(pango.STYLE_NORMAL, start, end))

        # Underline verification
        if self.underline_tg_button.get_active():
            attributes.insert(
                    pango.AttrUnderline(pango.UNDERLINE_SINGLE, start, end))
        else:
            attributes.insert(
                    pango.AttrUnderline(pango.UNDERLINE_NONE, start, end))

        self.example_label.set_attributes(attributes)

    def show_bold(self, widget):
        self.example_label.set_markup("<>")

    def get_example(self):
        return self.example_label.get_text()

    def set_example(self, example):
        self.example_label.set_text(example)

    def get_bold(self):
        if self.bold_tg_button.get_active():
            return 1
        return 0

    def set_bold(self, bold):
        self.bold_tg_button.set_active(bold)

    def get_italic(self):
        if self.italic_tg_button.get_active():
            return 1
        return 0

    def set_italic(self, italic):
        self.italic_tg_button.set_active(italic)

    def get_underline(self):
        if self.underline_tg_button.get_active():
            return 1
        return 0

    def set_underline(self, underline):
        self.underline_tg_button.set_active(underline)

    def get_label(self):
        return self.property_name_label.get_text()

    def set_label(self, label):
        self.property_name_label.set_text(label)

    label = property(get_label, set_label)
    example = property(get_example, set_example)
    bold = property(get_bold, set_bold)
    italic = property(get_italic, set_italic)
    underline = property(get_underline, set_underline)

if __name__ == "__main__":
    n = NmapOutputProperties(None)
    n.run()
    gtk.main()
