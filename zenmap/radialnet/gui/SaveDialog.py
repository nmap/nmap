# vim: set encoding=utf-8 :

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
import radialnet.gui.RadialNet as RadialNet
import zenmapGUI.FileChoosers

from zenmapGUI.higwidgets.higboxes import HIGHBox
from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog


TYPES = ((_("By extension"), None, None),
         (_("PDF"), RadialNet.FILE_TYPE_PDF, ".pdf"),
         (_("PNG"), RadialNet.FILE_TYPE_PNG, ".png"),
         (_("PostScript"), RadialNet.FILE_TYPE_PS, ".ps"),
         (_("SVG"), RadialNet.FILE_TYPE_SVG, ".svg"))
# Build a reverse index of extensions to file types, for the "By extension"
# file type.
EXTENSIONS = {}
for type in TYPES:
    if type[2] is not None:
        EXTENSIONS[type[2]] = type[1]


class SaveDialog(zenmapGUI.FileChoosers.UnicodeFileChooserDialog):
    def __init__(self):
        """
        """
        super(SaveDialog, self).__init__(title=_("Save Topology"),
                action=gtk.FILE_CHOOSER_ACTION_SAVE,
                buttons=(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                    gtk.STOCK_SAVE, gtk.RESPONSE_OK))

        types_store = gtk.ListStore(str, object, str)
        for type in TYPES:
            types_store.append(type)

        self.__combo = gtk.ComboBox(types_store)
        cell = gtk.CellRendererText()
        self.__combo.pack_start(cell, True)
        self.__combo.add_attribute(cell, "text", 0)

        self.__combo.connect("changed", self.__combo_changed_cb)
        self.__combo.set_active(0)

        self.connect("response", self.__response_cb)

        hbox = HIGHBox()
        label = gtk.Label(_("Select File Type:"))
        hbox.pack_end(self.__combo, False)
        hbox.pack_end(label, False)

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
        if response_id == gtk.RESPONSE_OK and self.get_filetype() is None:
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
