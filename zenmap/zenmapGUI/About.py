#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
import webbrowser

from zenmapGUI.higwidgets.higdialogs import HIGDialog
from zenmapGUI.higwidgets.higwindows import HIGWindow
from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox, \
        hig_box_space_holder
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapGUI.higwidgets.hignotebooks import HIGNotebook
from zenmapGUI.higwidgets.higscrollers import HIGScrolledWindow
from zenmapGUI.higwidgets.higtextviewers import HIGTextView

from zenmapCore.Name import APP_DISPLAY_NAME, APP_WEB_SITE, APP_COPYRIGHT, \
    NMAP_DISPLAY_NAME, NMAP_WEB_SITE, UMIT_DISPLAY_NAME, UMIT_WEB_SITE
from zenmapCore.Version import VERSION
import zenmapCore.I18N  # lgtm[py/unused-import]


# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

# For escaping text in marked-up labels.
from xml.sax.saxutils import escape


class _program_entry(gtk.VBox):
    """A little box containing labels with a program's name and
    description and a clickable link to its web site."""

    # The amount of space to put between the name of a program and its
    # web site button.
    NAME_WEB_SITE_SPACING = 20

    def __init__(self, name=None, web_site=None, description=None):
        gtk.VBox.__init__(self)

        self.hbox = gtk.HBox(False, self.NAME_WEB_SITE_SPACING)
        self.pack_start(self.hbox)

        if name is not None:
            name_label = gtk.Label()
            name_label.set_markup(
                    '<span size="large" weight="bold">%s</span>' % escape(
                        name))
            self.hbox.pack_start(name_label, False)

        if web_site is not None:
            try:
                web_site_button = gtk.LinkButton(web_site)
                web_site_button.connect("clicked", self._link_button_open)
            except AttributeError:
                # LinkButton was only introduced in PyGTK 2.10.
                web_site_button = gtk.Label(web_site)
                web_site_button.set_selectable(True)
            self.hbox.pack_start(web_site_button, False)

        if description is not None:
            description_label = gtk.Label()
            description_label.set_alignment(0.0, 0.0)
            description_label.set_line_wrap(True)
            description_label.set_text(description)
            self.pack_start(description_label)

    def _link_button_open(self, widget):
        webbrowser.open(widget.get_uri())


class About(HIGDialog):
    """An about dialog showing information about the program. It is meant to
    have roughly the same feel as gtk.AboutDialog."""
    def __init__(self):
        HIGDialog.__init__(self)
        self.set_title(_("About %s and %s") % (
            NMAP_DISPLAY_NAME, APP_DISPLAY_NAME))

        self.vbox.set_border_width(12)
        self.vbox.set_spacing(12)

        label = gtk.Label()
        label.set_markup(
                '<span size="xx-large" weight="bold">%s %s</span>' % (
                    escape(APP_DISPLAY_NAME), escape(VERSION)))
        label.set_selectable(True)
        self.vbox.pack_start(label)

        label = gtk.Label()
        label.set_markup(
                '<span size="small">%s</span>' % (escape(APP_COPYRIGHT)))
        self.vbox.pack_start(label)

        entry = _program_entry(NMAP_DISPLAY_NAME, NMAP_WEB_SITE, _(
            "%s is a free and open source utility for network exploration "
            "and security auditing.") % NMAP_DISPLAY_NAME)
        self.vbox.pack_start(entry)

        entry = _program_entry(APP_DISPLAY_NAME, APP_WEB_SITE, _(
            "%s is a multi-platform graphical %s frontend and results viewer. "
            "It was originally derived from %s.") % (
                APP_DISPLAY_NAME, NMAP_DISPLAY_NAME, UMIT_DISPLAY_NAME))
        self.vbox.pack_start(entry)

        entry = _program_entry(UMIT_DISPLAY_NAME, UMIT_WEB_SITE, _(
            "%s is an %s GUI created as part of the Nmap/Google Summer "
            "of Code program.") % (UMIT_DISPLAY_NAME, NMAP_DISPLAY_NAME))
        button = gtk.Button(_("%s credits") % UMIT_DISPLAY_NAME)
        button.connect("clicked", self._show_umit_credits)
        entry.hbox.pack_start(button, False)
        self.vbox.pack_start(entry)

        self.vbox.show_all()

        close_button = self.add_button(gtk.STOCK_CLOSE, gtk.RESPONSE_CANCEL)
        self.set_default_response(gtk.RESPONSE_CANCEL)
        close_button.grab_focus()

        self.set_has_separator(False)
        self.set_resizable(False)

        self._umit_credits_dialog = None

        self.connect("response", self._close)

    def _close(self, widget, response):
        if self._umit_credits_dialog is not None:
            self._umit_credits_dialog.destroy()
            self._umit_credits_dialog = None

        self.hide()

    def _show_umit_credits(self, widget):
        if self._umit_credits_dialog is not None:
            self._umit_credits_dialog.present()
            return

        self._umit_credits_dialog = UmitCredits()

        def credits_destroyed(widget):
            # Mark that the credits dialog has been destroyed.
            self._umit_credits_dialog = None

        self._umit_credits_dialog.connect("destroy", credits_destroyed)
        self._umit_credits_dialog.show_all()


class UmitCredits(HIGWindow):
    def __init__(self):
        HIGWindow.__init__(self)
        self.set_title(_("%s credits") % UMIT_DISPLAY_NAME)
        self.set_size_request(-1, 250)
        self.set_position(gtk.WIN_POS_CENTER)

        self.__create_widgets()
        self.__packing()
        self.set_text()

    def __create_widgets(self):
        self.vbox = HIGVBox()
        self.hbox = HIGHBox()
        self.notebook = HIGNotebook()
        self.btn_close = HIGButton(stock=gtk.STOCK_CLOSE)

        self.written_by_scroll = HIGScrolledWindow()
        self.written_by_text = HIGTextView()

        self.design_scroll = HIGScrolledWindow()
        self.design_text = HIGTextView()

        self.soc2007_scroll = HIGScrolledWindow()
        self.soc2007_text = HIGTextView()

        self.contributors_scroll = HIGScrolledWindow()
        self.contributors_text = HIGTextView()

        self.translation_scroll = HIGScrolledWindow()
        self.translation_text = HIGTextView()

        self.nokia_scroll = HIGScrolledWindow()
        self.nokia_text = HIGTextView()

    def __packing(self):
        self.add(self.vbox)
        self.vbox.set_spacing(12)
        self.vbox._pack_expand_fill(self.notebook)
        self.vbox._pack_noexpand_nofill(self.hbox)

        self.hbox._pack_expand_fill(hig_box_space_holder())
        self.hbox._pack_noexpand_nofill(self.btn_close)

        self.notebook.append_page(
                self.written_by_scroll, gtk.Label(_("Written by")))
        self.notebook.append_page(
                self.design_scroll, gtk.Label(_("Design")))
        self.notebook.append_page(
                self.soc2007_scroll, gtk.Label(_("SoC 2007")))
        self.notebook.append_page(
                self.contributors_scroll, gtk.Label(_("Contributors")))
        self.notebook.append_page(
                self.translation_scroll, gtk.Label(_("Translation")))
        self.notebook.append_page(
                self.nokia_scroll, gtk.Label(_("Maemo")))

        self.written_by_scroll.add(self.written_by_text)
        self.written_by_text.set_wrap_mode(gtk.WRAP_NONE)

        self.design_scroll.add(self.design_text)
        self.design_text.set_wrap_mode(gtk.WRAP_NONE)

        self.soc2007_scroll.add(self.soc2007_text)
        self.soc2007_text.set_wrap_mode(gtk.WRAP_NONE)

        self.contributors_scroll.add(self.contributors_text)
        self.contributors_text.set_wrap_mode(gtk.WRAP_NONE)

        self.translation_scroll.add(self.translation_text)
        self.translation_text.set_wrap_mode(gtk.WRAP_NONE)

        self.nokia_scroll.add(self.nokia_text)
        self.nokia_text.set_wrap_mode(gtk.WRAP_NONE)

        self.btn_close.connect('clicked', lambda x, y=None: self.destroy())

    def set_text(self):
        b = self.written_by_text.get_buffer()
        b.set_text("""Adriano Monteiro Marques <py.adriano@gmail.com>""")

        b = self.design_text.get_buffer()
        b.set_text("""Operating System and Vulnerability Icons:
Takeshi Alexandre Gondo <sinistrofumanchu@yahoo.com.br>

Logo, Application Icons and Splash screen:
Virgílio Carlo de Menezes Vasconcelos <virgiliovasconcelos@gmail.com>

The Umit Project Web Site Design:
Joao Paulo Pacheco <jp.pacheco@gmail.com>""")

        b = self.soc2007_text.get_buffer()
        b.set_text("""Independent Features:
Adriano Monteiro Marques <py.adriano@gmail.com>
Frederico Silva Ribeiro <fredegart@gmail.com>

Network Inventory:
Guilherme Henrique Polo Gonçalves <ggpolo@gmail.com>

Umit Radial Mapper:
João Paulo de Souza Medeiros <ignotus21@gmail.com>

Profile/Wizard interface editor:
Luis Antonio Bastião Silva <luis.kop@gmail.com>

NSE Facilitator:
Maxim I. Gavrilov <lovelymax@gmail.com>

Umit Web:
Rodolfo da Silva Carvalho <rodolfo.ueg@gmail.com>""")

        b = self.contributors_text.get_buffer()
        b.set_text("""Sponsored by (SoC 2005, 2006 and 2007):
Google <code.summer@gmail.com>

Mentor of Umit for Google SoC 2005 and 2006:
Fyodor <fyodor@insecure.org>

Mentor of Umit for Google SoC 2007 Projects:
Adriano Monteiro Marques <py.adriano@gmail.com>

Initial development:
Adriano Monteiro Marques <py.adriano@gmail.com>
Cleber Rodrigues Rosa Junior <cleber.gnu@gmail.com>

Nmap students from Google SoC 2007 that helped Umit:
Eddie Bell <ejlbell@gmail.com>
David Fifield <david@bamsoftware.com>
Kris Katterjohn <katterjohn@gmail.com>

The Umit Project WebSite:
AbraoBarbosa dos Santos Neto <abraobsn@gmail.com>
Adriano Monteiro Marques <py.adriano@gmail.com>
Heitor de Lima Matos <heitordelima@hotmail.com>
Joao Paulo Pacheco <jp.pacheco@gmail.com>
João Paulo de Souza Medeiros <ignotus21@gmail.com>
Luis Antonio Bastião Silva <luis.kop@gmail.com>
Rodolfo da Silva Carvalho <rodolfo.ueg@gmail.com>

Beta testers for 0.9.5RC1:
Drew Miller <securitygeek@fribble.org>
Igor Feghali <ifeghali@php.net>
Joao Paulo Pacheco <jp.pacheco@gmail.com>
Luis Antonio Bastião Silva <luis.kop@gmail.com>
<ray-solomon@excite.com>
<jah@zadkiel.plus.com>
<epatterson@directapps.com>

Initial attempt on Maemo port:
Adriano Monteiro Marques <py.adriano@gmail.com>
Osvaldo Santana Neto <osantana@gmail.com>""")

        b = self.translation_text.get_buffer()
        b.set_text("""Brazilian Portuguese:
Adriano Monteiro Marques <py.adriano@gmail.com>""")

        b = self.nokia_text.get_buffer()
        b.set_text("""Adriano Monteiro Marques <py.adriano@gmail.com>""")

if __name__ == '__main__':
    about = About()
    about.show()
    about.connect("response", lambda widget, response: gtk.main_quit())

    gtk.main()
