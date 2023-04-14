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

import os.path
import sys

import zenmapCore.I18N  # lgtm[py/unused-import]

RESPONSE_OPEN_DIRECTORY = 1


class AllFilesFileFilter(Gtk.FileFilter):
    def __init__(self):
        Gtk.FileFilter.__init__(self)

        pattern = "*"
        self.add_pattern(pattern)
        self.set_name(_("All files (%s)") % pattern)


class ResultsFileFilter(Gtk.FileFilter):
    def __init__(self):
        Gtk.FileFilter.__init__(self)

        patterns = ["*.xml"]
        for pattern in patterns:
            self.add_pattern(pattern)
        self.set_name(_("Nmap XML files (%s)") % ", ".join(patterns))


class ScriptFileFilter(Gtk.FileFilter):
    def __init__(self):
        Gtk.FileFilter.__init__(self)

        patterns = ["*.nse"]
        for pattern in patterns:
            self.add_pattern(pattern)
        self.set_name(_("NSE scripts (%s)") % ", ".join(patterns))


class AllFilesFileChooserDialog(Gtk.FileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=Gtk.FileChooserAction.OPEN,
                 buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.OK), backend=None):

        Gtk.FileChooserDialog.__init__(self, title=title, parent=parent,
                                          action=action, buttons=buttons)
        self.set_default_response(Gtk.ResponseType.OK)
        self.add_filter(AllFilesFileFilter())


class ResultsFileSingleChooserDialog(Gtk.FileChooserDialog):
    """This results file choose only allows the selection of single files, not
    directories."""
    def __init__(self, title="", parent=None,
                 action=Gtk.FileChooserAction.OPEN,
                 buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.OK), backend=None):

        Gtk.FileChooserDialog.__init__(self, title=title, parent=parent,
                                          action=action, buttons=buttons)
        self.set_default_response(Gtk.ResponseType.OK)
        for f in (ResultsFileFilter(), AllFilesFileFilter()):
            self.add_filter(f)


class ResultsFileChooserDialog(Gtk.FileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=Gtk.FileChooserAction.OPEN,
                 buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          "Open Directory", RESPONSE_OPEN_DIRECTORY,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.OK), backend=None):

        Gtk.FileChooserDialog.__init__(self, title=title, parent=parent,
                                          action=action, buttons=buttons)
        self.set_default_response(Gtk.ResponseType.OK)
        for f in (ResultsFileFilter(), AllFilesFileFilter()):
            self.add_filter(f)


class ScriptFileChooserDialog(Gtk.FileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=Gtk.FileChooserAction.OPEN,
                 buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.OK), backend=None):

        Gtk.FileChooserDialog.__init__(self, title=title, parent=parent,
                                          action=action, buttons=buttons)
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_select_multiple(True)
        for f in (ScriptFileFilter(), AllFilesFileFilter()):
            self.add_filter(f)


class SaveResultsFileChooserDialog(Gtk.FileChooserDialog):
    TYPES = (
        (_("By extension"), None, None),
        (_("Nmap XML format (.xml)"), "xml", ".xml"),
        (_("Nmap text format (.nmap)"), "text", ".nmap"),
    )
    # For the "By Extension" choice.
    EXTENSIONS = {
        ".xml": "xml",
        ".nmap": "text",
        ".txt": "text",
    }

    def __init__(self, title="", parent=None,
                 action=Gtk.FileChooserAction.SAVE,
                 buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_SAVE, Gtk.ResponseType.OK), backend=None):

        Gtk.FileChooserDialog.__init__(self, title=title, parent=parent,
                                          action=action, buttons=buttons)

        types_store = Gtk.ListStore.new([str, str, str])
        for type in self.TYPES:
            types_store.append(type)

        self.combo = Gtk.ComboBox.new_with_model(types_store)
        cell = Gtk.CellRendererText()
        self.combo.pack_start(cell, True)
        self.combo.add_attribute(cell, "text", 0)
        self.combo.connect("changed", self.combo_changed_cb)
        self.combo.set_active(1)

        hbox = Gtk.Box.new(Gtk.Orientation.HORIZONTAL, 6)
        hbox.pack_end(self.combo, False, True, 0)
        hbox.pack_end(Gtk.Label.new(_("Select File Type:")), False, True, 0)
        hbox.show_all()

        self.set_extra_widget(hbox)
        self.set_do_overwrite_confirmation(True)

        self.set_default_response(Gtk.ResponseType.OK)

    def combo_changed_cb(self, combo):
        filename = self.get_filename() or ""
        dir, basename = os.path.split(filename)
        if dir != self.get_current_folder():
            self.set_current_folder(dir)

        # Find the recommended extension.
        new_ext = combo.get_model().get_value(combo.get_active_iter(), 2)
        if new_ext is not None:
            # Change the filename to use the recommended extension.
            root, ext = os.path.splitext(basename)
            if len(ext) == 0 and root.startswith("."):
                root = ""
            self.set_current_name(root + new_ext)

    def get_extension(self):
        return os.path.splitext(self.get_filename())[1]

    def get_format(self):
        """Get the save format the user has chosen. It is a string, either
        "text" or "xml"."""
        filetype = self.combo.get_model().get_value(
                self.combo.get_active_iter(), 1)
        if filetype is None:
            # Guess based on extension. "xml" is the default if unknown.
            return self.EXTENSIONS.get(self.get_extension(), "xml")
        return filetype


class DirectoryChooserDialog(Gtk.FileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=Gtk.FileChooserAction.SELECT_FOLDER,
                 buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.OK), backend=None):

        Gtk.FileChooserDialog.__init__(self, title=title, parent=parent,
                                          action=action, buttons=buttons)
        self.set_default_response(Gtk.ResponseType.OK)


class SaveToDirectoryChooserDialog(Gtk.FileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=Gtk.FileChooserAction.SELECT_FOLDER,
                 buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_SAVE, Gtk.ResponseType.OK), backend=None):

        Gtk.FileChooserDialog.__init__(self, title=title, parent=parent,
                                          action=action, buttons=buttons)
        self.set_default_response(Gtk.ResponseType.OK)
