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

import gtk
import os.path
import webbrowser

from zenmapGUI.higwidgets.higdialogs import HIGDialog
from zenmapGUI.higwidgets.higwindows import HIGWindow
from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox, hig_box_space_holder
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapGUI.higwidgets.hignotebooks import HIGNotebook
from zenmapGUI.higwidgets.higscrollers import HIGScrolledWindow
from zenmapGUI.higwidgets.higtextviewers import HIGTextView

from zenmapCore.Name import APP_DISPLAY_NAME, APP_WEB_SITE, APP_COPYRIGHT, \
    NMAP_DISPLAY_NAME, NMAP_WEB_SITE, UMIT_DISPLAY_NAME, UMIT_WEB_SITE
from zenmapCore.Version import VERSION
from zenmapCore.Paths import Path
import zenmapCore.I18N

# For escaping text in marked-up labels.
from xml.sax.saxutils import escape

class _program_entry(gtk.VBox):
    """A little box containing labels with a program's name and
    description and a clickable link to its web site."""

    # The amount of space to put between the name of a program and its
    # web site button.
    NAME_WEB_SITE_SPACING = 20

    def __init__(self, name = None, web_site = None, description = None):
        gtk.VBox.__init__(self)

        self.hbox = gtk.HBox(False, self.NAME_WEB_SITE_SPACING)
        self.pack_start(self.hbox)

        if name is not None:
            name_label = gtk.Label()
            name_label.set_markup("<span size=\"large\" weight=\"bold\">%s</span>" % escape(name))
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
        self.set_title(_("About %s and %s") % (NMAP_DISPLAY_NAME, APP_DISPLAY_NAME))

        self.vbox.set_border_width(12)
        self.vbox.set_spacing(12)

        label = gtk.Label()
        label.set_markup("<span size=\"xx-large\" weight=\"bold\">%s %s</span>" \
% (escape(APP_DISPLAY_NAME), escape(VERSION)))
        label.set_selectable(True)
        self.vbox.pack_start(label)

        label = gtk.Label()
        label.set_markup("<span size=\"small\">%s</span>" \
% (escape(APP_COPYRIGHT)))
        self.vbox.pack_start(label)

        entry = _program_entry(NMAP_DISPLAY_NAME, NMAP_WEB_SITE, _("""\
%s is a free and open source utility for network exploration and security \
auditing.""") % NMAP_DISPLAY_NAME)
        self.vbox.pack_start(entry)

        entry = _program_entry(APP_DISPLAY_NAME, APP_WEB_SITE, _("""\
%s is a multi-platform graphical %s frontend and results viewer. It was \
originally derived from %s.""") \
% (APP_DISPLAY_NAME, NMAP_DISPLAY_NAME, UMIT_DISPLAY_NAME))
        self.vbox.pack_start(entry)

        entry = _program_entry(UMIT_DISPLAY_NAME, UMIT_WEB_SITE, _("""\
%s is an %s GUI created as part of the Nmap/Google Summer of Code program.""") \
% (UMIT_DISPLAY_NAME, NMAP_DISPLAY_NAME))
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
        self.set_size_request(-1,250)
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

        self.notebook.append_page(self.written_by_scroll, gtk.Label(_("Written by")))
        self.notebook.append_page(self.design_scroll, gtk.Label(_("Design")))
        self.notebook.append_page(self.soc2007_scroll, gtk.Label(_("SoC 2007")))
        self.notebook.append_page(self.contributors_scroll, gtk.Label(_("Contributors")))
        self.notebook.append_page(self.translation_scroll, gtk.Label(_("Translation")))
        self.notebook.append_page(self.nokia_scroll, gtk.Label(_("Maemo")))

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

        self.btn_close.connect('clicked', lambda x,y=None:self.destroy())

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
