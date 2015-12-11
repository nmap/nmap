#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
import os.path
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
from zenmapCore.Paths import Path
import zenmapCore.I18N


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
