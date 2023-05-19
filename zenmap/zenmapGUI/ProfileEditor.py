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
from gi.repository import Gtk

from zenmapGUI.higwidgets.higwindows import HIGWindow
from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox, HIGSpacer, \
        hig_box_space_holder
from zenmapGUI.higwidgets.higlabels import HIGSectionLabel, HIGEntryLabel
from zenmapGUI.higwidgets.higscrollers import HIGScrolledWindow
from zenmapGUI.higwidgets.higtextviewers import HIGTextView
from zenmapGUI.higwidgets.higbuttons import HIGButton
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog, HIGDialog
from zenmapGUI.OptionBuilder import OptionBuilder
from zenmapCore.Paths import Path
from zenmapCore.UmitConf import CommandProfile
from zenmapCore.UmitLogging import log
import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapCore.NmapOptions import NmapOptions


class ProfileEditor(HIGWindow):
    def __init__(self, command=None, profile_name=None,
            deletable=True, overwrite=False):
        HIGWindow.__init__(self)
        self.connect("delete_event", self.exit)
        self.set_title(_('Profile Editor'))
        self.set_position(Gtk.WindowPosition.CENTER)

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
        command_string = self.command_entry.get_text()
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
        self.command_entry = Gtk.Entry()
        self.command_entry_changed_cb_id = self.command_entry.connect(
                "changed", self.command_entry_changed_cb)

        self.scan_button = HIGButton(_("Scan"))
        self.scan_button.connect("clicked", self.run_scan)

        self.notebook = Gtk.Notebook()

        # Profile info page
        self.profile_info_vbox = HIGVBox()
        self.profile_info_label = HIGSectionLabel(_('Profile Information'))
        self.profile_name_label = HIGEntryLabel(_('Profile name'))
        self.profile_name_label.set_line_wrap(False)
        self.profile_name_entry = Gtk.Entry()
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

        self.cancel_button = HIGButton(stock=Gtk.STOCK_CANCEL)
        self.cancel_button.connect('clicked', self.exit)

        self.delete_button = HIGButton(stock=Gtk.STOCK_DELETE)
        self.delete_button.connect('clicked', self.delete_profile)

        self.save_button = HIGButton(_("Save Changes"), stock=Gtk.STOCK_SAVE)
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
        self.lower_box.pack_end(self.buttons_hbox, True, True, 0)

        # Packing the three vertical boxes to the main box
        self.main_whole_box._pack_noexpand_nofill(self.upper_box)
        self.main_whole_box._pack_expand_fill(self.middle_box)
        self.main_whole_box._pack_noexpand_nofill(self.lower_box)
        ###

        # Packing profile information tab on notebook
        self.notebook.append_page(
                self.profile_info_vbox, Gtk.Label.new(_('Profile')))
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
        self.notebook.append_page(vbox, Gtk.Label.new(tab_name))

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
                buf.get_start_iter(), buf.get_end_iter(), include_hidden_chars=True)

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
            dialog = HIGDialog(buttons=(Gtk.STOCK_OK, Gtk.ResponseType.OK,
                                        Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))
            alert = HIGEntryLabel('<b>' + _("Deleting Profile") + '</b>')
            text = HIGEntryLabel(_(
                'Your profile is going to be deleted! Click Ok to continue, '
                'or Cancel to go back to Profile Editor.'))
            hbox = HIGHBox()
            hbox.set_border_width(5)
            hbox.set_spacing(12)

            vbox = HIGVBox()
            vbox.set_border_width(5)
            vbox.set_spacing(12)

            image = Gtk.Image()
            image.set_from_stock(
                    Gtk.STOCK_DIALOG_WARNING, Gtk.IconSize.DIALOG)

            vbox.pack_start(alert, True, True, 0)
            vbox.pack_start(text, True, True, 0)
            hbox.pack_start(image, True, True, 0)
            hbox.pack_start(vbox, True, True, 0)

            dialog.vbox.pack_start(hbox, True, True, 0)
            dialog.vbox.show_all()

            response = dialog.run()
            dialog.destroy()
            if response == Gtk.ResponseType.CANCEL:
                return True
            self.profile.remove_profile(self.profile_name)

        self.update_profile_entry()
        self.destroy()

    def run_scan(self, widget=None):
        command_string = self.command_entry.get_text()
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
    Gtk.main()
