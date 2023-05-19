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

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk

import zenmapCore.I18N  # lgtm[py/unused-import]
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
                           buttons=(Gtk.STOCK_CLOSE, Gtk.ResponseType.CLOSE))

        self.nmap_highlight = NmapOutputHighlight()

        self.__create_widgets()
        self.__pack_widgets()
        self.highlight_tab()

        self.vbox.show_all()

    def __create_widgets(self):
        self.properties_notebook = HIGNotebook()

    def __pack_widgets(self):
        self.vbox.pack_start(self.properties_notebook, True, True, 0)

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
                               "ip": ["ip", "127.0.0.1"]}

        for p in self.property_names:
            settings = self.nmap_highlight.__getattribute__(p)

            self.property_names[p].append(settings[0])
            self.property_names[p].append(settings[1])
            self.property_names[p].append(settings[2])
            self.property_names[p].append(Gdk.Color(*settings[3]))
            self.property_names[p].append(Gdk.Color(*settings[4]))
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
        self.highlight_main_vbox.pack_start(self.highlight_main_table, True, True, 0)

        # Adding color tab
        self.properties_notebook.append_page(
                self.highlight_main_vbox,
                Gtk.Label.new(_("Highlight definitions")))


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
        self.bold_tg_button = HIGToggleButton("", Gtk.STOCK_BOLD)
        self.italic_tg_button = HIGToggleButton("", Gtk.STOCK_ITALIC)
        self.underline_tg_button = HIGToggleButton("", Gtk.STOCK_UNDERLINE)
        self.text_color_button = HIGButton(
                _("Text"), stock=Gtk.STOCK_SELECT_COLOR)
        self.highlight_color_button = HIGButton(
                _("Highlight"), stock=Gtk.STOCK_SELECT_COLOR)

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
        color_dialog = Gtk.ColorSelectionDialog.new(
                "%s %s" % (self.label, _("text color")))
        color_dialog.get_color_selection().set_current_color(self.text_color)

        color_dialog.props.ok_button.connect(
                "clicked", self.text_color_dialog_ok, color_dialog)
        color_dialog.props.cancel_button.connect(
                "clicked", self.text_color_dialog_cancel, color_dialog)
        color_dialog.connect(
                "delete-event", self.text_color_dialog_close, color_dialog)

        color_dialog.run()

    def text_color_dialog_ok(self, widget, color_dialog):
        self.text_color = color_dialog.get_color_selection().get_current_color()
        color_dialog.destroy()
        self.update_example()

    def text_color_dialog_cancel(self, widget, color_dialog):
        color_dialog.destroy()

    def text_color_dialog_close(self, widget, extra, color_dialog):
        color_dialog.destroy()

    #########################################
    # Highlight color dialog
    def highlight_color_dialog(self, widget):
        color_dialog = Gtk.ColorSelectionDialog.new(
                "%s %s" % (self.property_name, _("highlight color")))
        color_dialog.get_color_selection().set_current_color(self.highlight_color)

        color_dialog.props.ok_button.connect(
                "clicked", self.highlight_color_dialog_ok, color_dialog)
        color_dialog.props.cancel_button.connect(
                "clicked", self.highlight_color_dialog_cancel,
                color_dialog)
        color_dialog.connect(
                "delete-event", self.highlight_color_dialog_close,
                color_dialog)

        color_dialog.run()

    def highlight_color_dialog_ok(self, widget, color_dialog):
        self.highlight_color = color_dialog.get_color_selection().get_current_color()
        color_dialog.destroy()
        self.update_example()

    def highlight_color_dialog_cancel(self, widget, color_dialog):
        color_dialog.destroy()

    def highlight_color_dialog_close(self, widget, extra, color_dialog):
        color_dialog.destroy()

    def update_example(self, widget=None):
        label = self.example_label.get_text()

        # Bold verification
        if self.bold_tg_button.get_active():
            label = "<b>" + label + "</b>"

        # Italic verification
        if self.italic_tg_button.get_active():
            label = "<i>" + label + "</i>"

        # Underline verification
        if self.underline_tg_button.get_active():
            label = "<u>" + label + "</u>"

        self.example_label.modify_fg(Gtk.StateType.NORMAL, self.text_color)
        self.example_label.modify_bg(Gtk.StateType.NORMAL, self.highlight_color)
        self.example_label.set_markup(label)

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
    Gtk.main()
