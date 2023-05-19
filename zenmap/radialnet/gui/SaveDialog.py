# vim: set encoding=utf-8 :

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

import os.path
import radialnet.gui.RadialNet as RadialNet
import zenmapGUI.FileChoosers

from zenmapGUI.higwidgets.higboxes import HIGHBox
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog


TYPES = ((_("By extension"), None, None),
         ("PDF", RadialNet.FILE_TYPE_PDF, ".pdf"),
         ("PNG", RadialNet.FILE_TYPE_PNG, ".png"),
         ("PostScript", RadialNet.FILE_TYPE_PS, ".ps"),
         ("SVG", RadialNet.FILE_TYPE_SVG, ".svg"))
# Build a reverse index of extensions to file types, for the "By extension"
# file type.
EXTENSIONS = {}
for type in TYPES:
    if type[2] is not None:
        EXTENSIONS[type[2]] = type[1]


class SaveDialog(Gtk.FileChooserDialog):
    def __init__(self):
        """
        """
        super(SaveDialog, self).__init__(title=_("Save Topology"),
                action=Gtk.FileChooserAction.SAVE,
                buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                    Gtk.STOCK_SAVE, Gtk.ResponseType.OK))

        types_store = Gtk.ListStore.new([str, object, str])
        for type in TYPES:
            types_store.append(type)

        self.__combo = Gtk.ComboBox.new_with_model(types_store)
        cell = Gtk.CellRendererText()
        self.__combo.pack_start(cell, True)
        self.__combo.add_attribute(cell, "text", 0)

        self.__combo.connect("changed", self.__combo_changed_cb)
        self.__combo.set_active(0)

        self.connect("response", self.__response_cb)

        hbox = HIGHBox()
        label = Gtk.Label.new(_("Select File Type:"))
        hbox.pack_end(self.__combo, False, True, 0)
        hbox.pack_end(label, False, True, 0)

        self.set_extra_widget(hbox)
        self.set_do_overwrite_confirmation(True)

        hbox.show_all()

    def __combo_changed_cb(self, widget):
        filename = self.get_filename() or ""
        dir, basename = os.path.split(filename)
        if dir != self.get_current_folder():
            self.set_current_folder(dir)

        # Find the recommended extension.
        new_ext = self.__combo.get_model().get_value(
                self.__combo.get_active_iter(), 2)
        if new_ext is not None:
            # Change the filename to use the recommended extension.
            root, ext = os.path.splitext(basename)
            if len(ext) == 0 and root.startswith("."):
                root = ""
            self.set_current_name(root + new_ext)

    def __response_cb(self, widget, response_id):
        """Intercept the "response" signal to check if someone used the "By
        extension" file type with an unknown extension."""
        if response_id == Gtk.ResponseType.OK and self.get_filetype() is None:
            ext = self.__get_extension()
            if ext == "":
                filename = self.get_filename() or ""
                dir, basename = os.path.split(filename)
                alert = HIGAlertDialog(
                        message_format=_("No filename extension"),
                        secondary_text=_("""\
The filename "%s" does not have an extension, \
and no specific file type was chosen.
Enter a known extension or select the file type from the list.""" % basename))

            else:
                alert = HIGAlertDialog(
                        message_format=_("Unknown filename extension"),
                        secondary_text=_("""\
There is no file type known for the filename extension "%s".
Enter a known extension or select the file type from the list.\
""") % self.__get_extension())
            alert.run()
            alert.destroy()
            # Go back to the dialog.
            self.emit_stop_by_name("response")

    def __get_extension(self):
        return os.path.splitext(self.get_filename())[1]

    def get_filetype(self):
        filetype = self.__combo.get_model().get_value(
                self.__combo.get_active_iter(), 1)
        if filetype is None:
            # Guess based on extension.
            return EXTENSIONS.get(self.__get_extension())
        return filetype
