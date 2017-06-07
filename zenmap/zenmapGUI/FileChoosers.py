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

import os.path
import sys
import gtk

import zenmapCore.I18N

RESPONSE_OPEN_DIRECTORY = 1


class AllFilesFileFilter(gtk.FileFilter):
    def __init__(self):
        gtk.FileFilter.__init__(self)

        pattern = "*"
        self.add_pattern(pattern)
        self.set_name(_("All files (%s)") % pattern)


class ResultsFileFilter(gtk.FileFilter):
    def __init__(self):
        gtk.FileFilter.__init__(self)

        patterns = ["*.xml"]
        for pattern in patterns:
            self.add_pattern(pattern)
        self.set_name(_("Nmap XML files (%s)") % ", ".join(patterns))


class ScriptFileFilter(gtk.FileFilter):
    def __init__(self):
        gtk.FileFilter.__init__(self)

        patterns = ["*.nse"]
        for pattern in patterns:
            self.add_pattern(pattern)
        self.set_name(_("NSE scripts (%s)") % ", ".join(patterns))


class UnicodeFileChooserDialog(gtk.FileChooserDialog):
    """This is a base class for file choosers. It is designed to ease the
    retrieval of Unicode file names. On most platforms, the file names returned
    are encoded in the encoding given by sys.getfilesystemencoding(). On
    Windows, they are returned in UTF-8, even though using the UTF-8 file name
    results in a file not found error. The get_filename method of this class
    handles the decoding automatically."""
    def get_filename(self):
        filename = gtk.FileChooserDialog.get_filename(self)
        if sys.platform == "win32":
            encoding = "UTF-8"
        else:
            encoding = sys.getfilesystemencoding() or "UTF-8"
        try:
            filename = filename.decode(encoding)
        except:
            pass
        return filename


class AllFilesFileChooserDialog(UnicodeFileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=gtk.FILE_CHOOSER_ACTION_OPEN,
                 buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                          gtk.STOCK_OPEN, gtk.RESPONSE_OK), backend=None):

        gtk.FileChooserDialog.__init__(self, title, parent,
                                       action, buttons)
        self.set_default_response(gtk.RESPONSE_OK)
        self.add_filter(AllFilesFileFilter())


class ResultsFileSingleChooserDialog(UnicodeFileChooserDialog):
    """This results file choose only allows the selection of single files, not
    directories."""
    def __init__(self, title="", parent=None,
                 action=gtk.FILE_CHOOSER_ACTION_OPEN,
                 buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                          gtk.STOCK_OPEN, gtk.RESPONSE_OK), backend=None):

        UnicodeFileChooserDialog.__init__(self, title, parent,
                                       action, buttons)
        self.set_default_response(gtk.RESPONSE_OK)
        for f in (ResultsFileFilter(), AllFilesFileFilter()):
            self.add_filter(f)


class ResultsFileChooserDialog(UnicodeFileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=gtk.FILE_CHOOSER_ACTION_OPEN,
                 buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                          "Open Directory", RESPONSE_OPEN_DIRECTORY,
                          gtk.STOCK_OPEN, gtk.RESPONSE_OK), backend=None):

        UnicodeFileChooserDialog.__init__(self, title, parent,
                                       action, buttons)
        self.set_default_response(gtk.RESPONSE_OK)
        for f in (ResultsFileFilter(), AllFilesFileFilter()):
            self.add_filter(f)


class ScriptFileChooserDialog(UnicodeFileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=gtk.FILE_CHOOSER_ACTION_OPEN,
                 buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                          gtk.STOCK_OPEN, gtk.RESPONSE_OK), backend=None):

        UnicodeFileChooserDialog.__init__(self, title, parent,
                                       action, buttons)
        self.set_default_response(gtk.RESPONSE_OK)
        self.set_select_multiple(True)
        for f in (ScriptFileFilter(), AllFilesFileFilter()):
            self.add_filter(f)


class SaveResultsFileChooserDialog(UnicodeFileChooserDialog):
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
                 action=gtk.FILE_CHOOSER_ACTION_SAVE,
                 buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                          gtk.STOCK_SAVE, gtk.RESPONSE_OK), backend=None):

        UnicodeFileChooserDialog.__init__(self, title, parent, action, buttons)

        types_store = gtk.ListStore(str, str, str)
        for type in self.TYPES:
            types_store.append(type)

        self.combo = gtk.ComboBox(types_store)
        cell = gtk.CellRendererText()
        self.combo.pack_start(cell, True)
        self.combo.add_attribute(cell, "text", 0)
        self.combo.connect("changed", self.combo_changed_cb)
        self.combo.set_active(1)

        hbox = gtk.HBox(False, 6)
        hbox.pack_end(self.combo, False)
        hbox.pack_end(gtk.Label(_("Select File Type:")), False)
        hbox.show_all()

        self.set_extra_widget(hbox)
        self.set_do_overwrite_confirmation(True)

        self.set_default_response(gtk.RESPONSE_OK)

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


class DirectoryChooserDialog(UnicodeFileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=gtk.FILE_CHOOSER_ACTION_SELECT_FOLDER,
                 buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                          gtk.STOCK_OPEN, gtk.RESPONSE_OK), backend=None):

        UnicodeFileChooserDialog.__init__(self, title, parent, action, buttons)
        self.set_default_response(gtk.RESPONSE_OK)


class SaveToDirectoryChooserDialog(UnicodeFileChooserDialog):
    def __init__(self, title="", parent=None,
                 action=gtk.FILE_CHOOSER_ACTION_SELECT_FOLDER,
                 buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                          gtk.STOCK_SAVE, gtk.RESPONSE_OK), backend=None):

        UnicodeFileChooserDialog.__init__(self, title, parent, action, buttons)
        self.set_default_response(gtk.RESPONSE_OK)
