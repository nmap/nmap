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

from zenmapGUI.higwidgets.higwindows import HIGWindow
from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox, HIGSpacer, \
        hig_box_space_holder
from zenmapGUI.higwidgets.higlabels import HIGSectionLabel, HIGEntryLabel
from zenmapGUI.higwidgets.higscrollers import HIGScrolledWindow
from zenmapGUI.higwidgets.higtextviewers import HIGTextView
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog, HIGDialog
from zenmapGUI.OptionBuilder import *
from zenmapCore.Paths import Path
from zenmapCore.UmitConf import Profile, CommandProfile
from zenmapCore.UmitLogging import log
import zenmapCore.I18N
from zenmapCore.NmapOptions import NmapOptions


class ProfileEditor(HIGWindow):
    def __init__(self, command=None, profile_name=None,
            deletable=True, overwrite=False):
        HIGWindow.__init__(self)
        self.connect("delete_event", self.exit)
        self.set_title(_('Profile Editor'))
        self.set_position(gtk.WIN_POS_CENTER)

        self.deletable = deletable
        self.profile_name = profile_name
        self.overwrite = overwrite

        # Used to block recursive updating of the command entry when the
        # command entry causes the OptionBuilder widgets to change.
        self.inhibit_command_update = False

        self.__create_widgets()
        self.__pack_widgets()

        self.profile = CommandProfile()

        self.ops = NmapOptions()
        if profile_name:
            log.debug("Showing profile %s" % profile_name)
            prof = self.profile.get_profile(profile_name)

            # Interface settings
            self.profile_name_entry.set_text(profile_name)
            self.profile_description_text.get_buffer().set_text(
                    prof['description'])

            command_string = prof['command']
            self.ops.parse_string(command_string)
        if command:
            self.ops.parse_string(command)

        self.option_builder = OptionBuilder(
                Path.profile_editor, self.ops,
                self.update_command, self.help_field.get_buffer())
        log.debug("Option groups: %s" % str(self.option_builder.groups))
        log.debug("Option section names: %s" % str(
            self.option_builder.section_names))
        #log.debug("Option tabs: %s" % str(self.option_builder.tabs))

        for tab in self.option_builder.groups:
            self.__create_tab(
                    _(tab),
                    _(self.option_builder.section_names[tab]),
                    self.option_builder.tabs[tab])

        self.update_command()

    def command_entry_changed_cb(self, widget):
        command_string = self.command_entry.get_text().decode("UTF-8")
        self.ops.parse_string(command_string)
        self.inhibit_command_update = True
        self.option_builder.update()
        self.inhibit_command_update = False

    def update_command(self):
        """Regenerate and display the command."""
        if not self.inhibit_command_update:
            # Block recursive updating of the OptionBuilder widgets when they
            # cause a change in the command entry.
            self.command_entry.handler_block(self.command_entry_changed_cb_id)
            self.command_entry.set_text(self.ops.render_string())
            self.command_entry.handler_unblock(
                    self.command_entry_changed_cb_id)

    def update_help_name(self, widget, extra):
        self.help_field.get_buffer().set_text(
                "Profile name\n\nThis is how the profile will be identified "
                "in the drop-down combo box in the scan tab.")

    def update_help_desc(self, widget, extra):
        self.help_field.get_buffer().set_text(
                "Description\n\nThe description is a full description of what "
                "the scan does, which may be long.")

    def __create_widgets(self):

        ###
        # Vertical box to keep 3 boxes
        self.main_whole_box = HIGVBox()

        self.upper_box = HIGHBox()
        self.middle_box = HIGHBox()
        self.lower_box = HIGHBox()

        #self.main_vbox = HIGVBox()
        self.command_entry = gtk.Entry()
        self.command_entry_changed_cb_id = self.command_entry.connect(
                "changed", self.command_entry_changed_cb)

        self.scan_button = HIGButton(_("Scan"))
        self.scan_button.connect("clicked", self.run_scan)

        self.notebook = gtk.Notebook()

        # Profile info page
        self.profile_info_vbox = HIGVBox()
        self.profile_info_label = HIGSectionLabel(_('Profile Information'))
        self.profile_name_label = HIGEntryLabel(_('Profile name'))
        self.profile_name_entry = gtk.Entry()
        self.profile_name_entry.connect(
                'enter-notify-event', self.update_help_name)
        self.profile_description_label = HIGEntryLabel(_('Description'))
        self.profile_description_scroll = HIGScrolledWindow()
        self.profile_description_scroll.set_border_width(0)
        self.profile_description_text = HIGTextView()
        self.profile_description_text.connect(
                'motion-notify-event', self.update_help_desc)

        # Buttons
        self.buttons_hbox = HIGHBox()

        self.cancel_button = HIGButton(stock=gtk.STOCK_CANCEL)
        self.cancel_button.connect('clicked', self.exit)

        self.delete_button = HIGButton(stock=gtk.STOCK_DELETE)
        self.delete_button.connect('clicked', self.delete_profile)

        self.save_button = HIGButton(_("Save Changes"), stock=gtk.STOCK_SAVE)
        self.save_button.connect('clicked', self.save_profile)

        ###
        self.help_vbox = HIGVBox()
        self.help_label = HIGSectionLabel(_('Help'))
        self.help_scroll = HIGScrolledWindow()
        self.help_scroll.set_border_width(0)
        self.help_field = HIGTextView()
        self.help_field.set_cursor_visible(False)
        self.help_field.set_left_margin(5)
        self.help_field.set_editable(False)
        self.help_vbox.set_size_request(200, -1)
        ###

    def __pack_widgets(self):

        ###
        self.add(self.main_whole_box)

        # Packing command entry to upper box
        self.upper_box._pack_expand_fill(self.command_entry)
        self.upper_box._pack_noexpand_nofill(self.scan_button)

        # Packing notebook (left) and help box (right) to middle box
        self.middle_box._pack_expand_fill(self.notebook)
        self.middle_box._pack_expand_fill(self.help_vbox)

        # Packing buttons to lower box
        self.lower_box.pack_end(self.buttons_hbox)

        # Packing the three vertical boxes to the main box
        self.main_whole_box._pack_noexpand_nofill(self.upper_box)
        self.main_whole_box._pack_expand_fill(self.middle_box)
        self.main_whole_box._pack_noexpand_nofill(self.lower_box)
        ###

        # Packing profile information tab on notebook
        self.notebook.append_page(
                self.profile_info_vbox, gtk.Label(_('Profile')))
        self.profile_info_vbox.set_border_width(5)
        table = HIGTable()
        self.profile_info_vbox._pack_noexpand_nofill(self.profile_info_label)
        self.profile_info_vbox._pack_expand_fill(HIGSpacer(table))

        self.profile_description_scroll.add(self.profile_description_text)

        vbox_desc = HIGVBox()
        vbox_desc._pack_noexpand_nofill(self.profile_description_label)
        vbox_desc._pack_expand_fill(hig_box_space_holder())

        vbox_ann = HIGVBox()
        vbox_ann._pack_expand_fill(hig_box_space_holder())

        table.attach(
                self.profile_name_label, 0, 1, 0, 1, xoptions=0, yoptions=0)
        table.attach(self.profile_name_entry, 1, 2, 0, 1, yoptions=0)
        table.attach(vbox_desc, 0, 1, 1, 2, xoptions=0)
        table.attach(self.profile_description_scroll, 1, 2, 1, 2)

        # Packing buttons on button_hbox
        self.buttons_hbox._pack_expand_fill(hig_box_space_holder())
        if self.deletable:
            self.buttons_hbox._pack_noexpand_nofill(self.delete_button)
        self.buttons_hbox._pack_noexpand_nofill(self.cancel_button)
        self.buttons_hbox._pack_noexpand_nofill(self.save_button)

        self.buttons_hbox.set_border_width(5)
        self.buttons_hbox.set_spacing(6)

        ###
        self.help_vbox._pack_noexpand_nofill(self.help_label)
        self.help_vbox._pack_expand_fill(self.help_scroll)
        self.help_scroll.add(self.help_field)
        self.help_vbox.set_border_width(1)
        self.help_vbox.set_spacing(1)
        ###

    def __create_tab(self, tab_name, section_name, tab):
        log.debug(">>> Tab name: %s" % tab_name)
        log.debug(">>>Creating profile editor section: %s" % section_name)
        vbox = HIGVBox()
        if tab.notscripttab:  # if notscripttab is set
            table = HIGTable()
            table.set_row_spacings(2)
            section = HIGSectionLabel(section_name)
            vbox._pack_noexpand_nofill(section)
            vbox._pack_noexpand_nofill(HIGSpacer(table))
            vbox.set_border_width(5)
            tab.fill_table(table, True)
        else:
            hbox = tab.get_hmain_box()
            vbox.pack_start(hbox, True, True, 0)
        self.notebook.append_page(vbox, gtk.Label(tab_name))

    def save_profile(self, widget):
        if self.overwrite:
            self.profile.remove_profile(self.profile_name)
        profile_name = self.profile_name_entry.get_text()
        if profile_name == '':
            alert = HIGAlertDialog(
                    message_format=_('Unnamed profile'),
                    secondary_text=_(
                        'You must provide a name for this profile.'))
            alert.run()
            alert.destroy()

            self.profile_name_entry.grab_focus()

            return None

        command = self.ops.render_string()

        buf = self.profile_description_text.get_buffer()
        description = buf.get_text(
                buf.get_start_iter(), buf.get_end_iter())

        try:
            self.profile.add_profile(
                    profile_name,
                    command=command,
                    description=description)
        except ValueError:
            alert = HIGAlertDialog(
                    message_format=_('Disallowed profile name'),
                    secondary_text=_('Sorry, the name "%s" is not allowed due '
                        'to technical limitations. (The underlying '
                        'ConfigParser used to store profiles does not allow '
                        'it.) Choose a different name.' % profile_name))
            alert.run()
            alert.destroy()
            return

        self.scan_interface.toolbar.profile_entry.update()
        self.destroy()

    def clean_profile_info(self):
        self.profile_name_entry.set_text('')
        self.profile_description_text.get_buffer().set_text('')

    def set_scan_interface(self, interface):
        self.scan_interface = interface

    def exit(self, *args):
        self.destroy()

    def delete_profile(self, widget=None, extra=None):
        if self.deletable:
            dialog = HIGDialog(buttons=(gtk.STOCK_OK, gtk.RESPONSE_OK,
                                        gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
            alert = HIGEntryLabel('<b>' + _("Deleting Profile") + '</b>')
            text = HIGEntryLabel(_(
                'Your profile is going to be deleted! ClickOk to continue, '
                'or Cancel to go back to Profile Editor.'))
            hbox = HIGHBox()
            hbox.set_border_width(5)
            hbox.set_spacing(12)

            vbox = HIGVBox()
            vbox.set_border_width(5)
            vbox.set_spacing(12)

            image = gtk.Image()
            image.set_from_stock(
                    gtk.STOCK_DIALOG_WARNING, gtk.ICON_SIZE_DIALOG)

            vbox.pack_start(alert)
            vbox.pack_start(text)
            hbox.pack_start(image)
            hbox.pack_start(vbox)

            dialog.vbox.pack_start(hbox)
            dialog.vbox.show_all()

            response = dialog.run()
            dialog.destroy()
            if response == gtk.RESPONSE_CANCEL:
                return True
            self.profile.remove_profile(self.profile_name)

        self.update_profile_entry()
        self.destroy()

    def run_scan(self, widget=None):
        command_string = self.command_entry.get_text().decode("UTF-8")
        self.scan_interface.command_toolbar.command = command_string
        self.scan_interface.start_scan_cb()
        self.exit()

    def update_profile_entry(self, widget=None, extra=None):
        self.scan_interface.toolbar.profile_entry.update()
        list = self.scan_interface.toolbar.profile_entry.get_model()
        length = len(list)
        if length > 0:
            self.scan_interface.toolbar.profile_entry.set_active(0)


if __name__ == '__main__':
    p = ProfileEditor()
    p.show_all()
    gtk.main()
