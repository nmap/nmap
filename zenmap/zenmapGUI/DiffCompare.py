#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
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

import gobject
import gtk
import pango
import os
import os.path
import sys

# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

import xml.sax

from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog, HIGDialog
from zenmapGUI.higwidgets.higboxes import HIGVBox, HIGHBox, \
    hig_box_space_holder
from zenmapGUI.higwidgets.higlabels import HIGSectionLabel
from zenmapGUI.higwidgets.higtables import HIGTable
from zenmapGUI.higwidgets.higbuttons import HIGButton

from zenmapCore.NmapParser import NmapParser
from zenmapCore.UmitLogging import log
import zenmapCore.I18N
import zenmapCore.Diff

from zenmapGUI.FileChoosers import ResultsFileSingleChooserDialog

# In milliseconds.
NDIFF_CHECK_TIMEOUT = 200


class ScanChooser(HIGVBox):
    """This class allows the selection of scan results from the list of open
    tabs or from a file. It emits the "changed" signal when the scan selection
    has changed."""

    __gsignals__ = {
        "changed": (gobject.SIGNAL_RUN_FIRST, gobject.TYPE_NONE, ())
    }

    def __init__(self, scans, title):
        self.__gobject_init__()
        self.title = title
        self.scan_dict = {}

        # Setting HIGVBox
        self.set_border_width(5)
        self.set_spacing(6)

        self._create_widgets()
        self._pack_hbox()
        self._attaching_widgets()
        self._set_scrolled()
        self._set_text_view()
        self._set_open_button()

        for scan in scans:
            self.add_scan(scan.scan_name or scan.get_nmap_command(), scan)

        self.combo_scan.connect('changed', self.show_scan)
        self.combo_scan.connect('changed', lambda x: self.emit('changed'))

        self._pack_noexpand_nofill(self.lbl_scan)
        self._pack_expand_fill(self.hbox)

    def _create_widgets(self):
        self.lbl_scan = HIGSectionLabel(self.title)
        self.hbox = HIGHBox()
        self.table = HIGTable()
        self.list_scan = gtk.ListStore(str)
        self.combo_scan = gtk.ComboBoxEntry(self.list_scan, 0)
        self.btn_open_scan = gtk.Button(stock=gtk.STOCK_OPEN)
        self.exp_scan = gtk.Expander(_("Scan Output"))
        self.scrolled = gtk.ScrolledWindow()
        self.txt_scan_result = gtk.TextView()
        self.txg_tag = gtk.TextTag("scan_style")

    def get_buffer(self):
        return self.txt_scan_result.get_buffer()

    def show_scan(self, widget):
        nmap_output = self.get_nmap_output()
        if nmap_output:
            self.txt_scan_result.get_buffer().set_text(nmap_output)

    def normalize_output(self, output):
        return "\n".join(output.split("\\n"))

    def _pack_hbox(self):
        self.hbox._pack_noexpand_nofill(hig_box_space_holder())
        self.hbox._pack_expand_fill(self.table)

    def _attaching_widgets(self):
        self.table.attach(self.combo_scan, 0, 1, 0, 1, yoptions=0)
        self.table.attach(
            self.btn_open_scan, 1, 2, 0, 1, yoptions=0, xoptions=0)
        self.table.attach(self.exp_scan, 0, 2, 1, 2)

    def _set_scrolled(self):
        self.scrolled.set_border_width(5)
        self.scrolled.set_size_request(-1, 130)

        # Packing scrolled window into expander
        self.exp_scan.add(self.scrolled)

        # Packing text view into scrolled window
        self.scrolled.add_with_viewport(self.txt_scan_result)

        # Setting scrolled window
        self.scrolled.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)

    def _set_text_view(self):
        self.txg_table = self.txt_scan_result.get_buffer().get_tag_table()
        self.txg_table.add(self.txg_tag)
        self.txg_tag.set_property("family", "Monospace")

        self.txt_scan_result.set_wrap_mode(gtk.WRAP_WORD)
        self.txt_scan_result.set_editable(False)
        self.txt_scan_result.get_buffer().connect(
            "changed", self._text_changed_cb)

    def _set_open_button(self):
        self.btn_open_scan.connect('clicked', self.open_file)

    def open_file(self, widget):
        file_chooser = ResultsFileSingleChooserDialog(_("Select Scan Result"))

        response = file_chooser.run()
        file_chosen = file_chooser.get_filename()
        file_chooser.destroy()
        if response == gtk.RESPONSE_OK:
            try:
                parser = NmapParser()
                parser.parse_file(file_chosen)
            except xml.sax.SAXParseException as e:
                alert = HIGAlertDialog(
                    message_format='<b>%s</b>' % _('Error parsing file'),
                    secondary_text=_(
                        "The file is not an Nmap XML output file. "
                        "The parsing error that occurred was\n%s") % str(e))
                alert.run()
                alert.destroy()
                return False
            except Exception as e:
                alert = HIGAlertDialog(
                    message_format='<b>%s</b>' % _(
                        'Cannot open selected file'),
                    secondary_text=_("""\
                        This error occurred while trying to open the file:
                        %s""") % str(e))
                alert.run()
                alert.destroy()
                return False

            scan_name = os.path.split(file_chosen)[-1]
            self.add_scan(scan_name, parser)

            self.combo_scan.set_active(len(self.list_scan) - 1)

    def add_scan(self, scan_name, parser):
        scan_id = 1
        new_scan_name = scan_name
        while new_scan_name in self.scan_dict.keys():
            new_scan_name = "%s (%s)" % (scan_name, scan_id)
            scan_id += 1

        self.list_scan.append([new_scan_name])
        self.scan_dict[new_scan_name] = parser

    def _text_changed_cb(self, widget):
        buff = self.txt_scan_result.get_buffer()
        buff.apply_tag(
            self.txg_tag, buff.get_start_iter(), buff.get_end_iter())

    def get_parsed_scan(self):
        """Return the currently selected scan's parsed output as an NmapParser
        object, or None if no valid scan is selected."""
        selected_scan = self.combo_scan.child.get_text()
        return self.scan_dict.get(selected_scan)

    def get_nmap_output(self):
        """Return the currently selected scan's output as a string, or None if
        no valid scan is selected."""
        if self.parsed_scan is not None:
            return self.parsed_scan.get_nmap_output()
        else:
            return None

    nmap_output = property(get_nmap_output)
    parsed_scan = property(get_parsed_scan)


class DiffWindow(gtk.Window):
    def __init__(self, scans):
        gtk.Window.__init__(self)
        self.set_title(_("Compare Results"))
        self.ndiff_process = None
        # We allow the user to start a new diff before the old one has
        # finished.  We have to keep references to old processes until they
        # finish to avoid problems when tearing down the Python interpreter at
        # program exit.
        self.old_processes = []
        self.timer_id = None

        self.main_vbox = HIGVBox()
        self.diff_view = DiffView()
        self.diff_view.set_size_request(-1, 100)
        self.hbox_buttons = HIGHBox()
        self.progress = gtk.ProgressBar()
        self.btn_close = HIGButton(stock=gtk.STOCK_CLOSE)
        self.hbox_selection = HIGHBox()
        self.scan_chooser_a = ScanChooser(scans, _(u"A Scan"))
        self.scan_chooser_b = ScanChooser(scans, _(u"B Scan"))

        self._pack_widgets()
        self._connect_widgets()

        self.set_default_size(-1, 500)

        # Initial Size Request
        self.initial_size = self.get_size()

    def _pack_widgets(self):
        self.main_vbox.set_border_width(6)

        self.hbox_selection.pack_start(self.scan_chooser_a, True, True)
        self.hbox_selection.pack_start(self.scan_chooser_b, True, True)

        self.main_vbox.pack_start(self.hbox_selection, False)

        scroll = gtk.ScrolledWindow()
        scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scroll.add(self.diff_view)
        self.main_vbox.pack_start(scroll, True, True)

        self.progress.hide()
        self.progress.set_no_show_all(True)
        self.hbox_buttons.pack_start(self.progress, False)
        self.hbox_buttons.pack_end(self.btn_close, False)

        self.main_vbox._pack_noexpand_nofill(self.hbox_buttons)

        self.add(self.main_vbox)

    def _connect_widgets(self):
        self.connect("delete-event", self.close)
        self.btn_close.connect("clicked", self.close)
        self.scan_chooser_a.connect('changed', self.refresh_diff)
        self.scan_chooser_b.connect('changed', self.refresh_diff)

    def refresh_diff(self, widget):
        """This method is called whenever the diff output might have changed,
        such as when a different scan was selected in one of the choosers."""
        log.debug("Refresh diff.")

        if (self.ndiff_process is not None and
                self.ndiff_process.poll() is None):
            # Put this in the list of old processes we keep track of.
            self.old_processes.append(self.ndiff_process)
            self.ndiff_process = None

        scan_a = self.scan_chooser_a.parsed_scan
        scan_b = self.scan_chooser_b.parsed_scan

        if scan_a is None or scan_b is None:
            self.diff_view.clear()
        else:
            try:
                self.ndiff_process = zenmapCore.Diff.ndiff(scan_a, scan_b)
            except OSError as e:
                alert = HIGAlertDialog(
                    message_format=_("Error running ndiff"),
                    secondary_text=_(
                        "There was an error running the ndiff program.\n\n"
                        ) + str(e).decode(sys.getdefaultencoding(), "replace"))
                alert.run()
                alert.destroy()
            else:
                self.progress.show()
                if self.timer_id is None:
                    self.timer_id = gobject.timeout_add(
                        NDIFF_CHECK_TIMEOUT, self.check_ndiff_process)

    def check_ndiff_process(self):
        """Check if the ndiff subprocess is done and show the diff if it is.
        Also remove any finished processes from the old process list."""
        # Check if any old background processes have finished.
        for p in self.old_processes[:]:
            if p.poll() is not None:
                p.close()
                self.old_processes.remove(p)

        if self.ndiff_process is not None:
            # We're running the most recent scan. Check if it's done.
            status = self.ndiff_process.poll()

            if status is None:
                # Keep calling this function on a timer until the process
                # finishes.
                self.progress.pulse()
                return True

            if status == 0 or status == 1:
                # Successful completion.
                try:
                    diff = self.ndiff_process.get_scan_diff()
                except zenmapCore.Diff.NdiffParseException as e:
                    alert = HIGAlertDialog(
                        message_format=_("Error parsing ndiff output"),
                        secondary_text=str(e))
                    alert.run()
                    alert.destroy()
                else:
                    self.diff_view.show_diff(diff)
            else:
                # Unsuccessful completion.
                error_text = _(
                    "The ndiff process terminated with status code %d."
                    ) % status
                stderr = self.ndiff_process.stderr.read()
                if len(stderr) > 0:
                    error_text += "\n\n" + stderr
                alert = HIGAlertDialog(
                    message_format=_("Error running ndiff"),
                    secondary_text=error_text)
                alert.run()
                alert.destroy()

            self.progress.hide()
            self.ndiff_process.close()
            self.ndiff_process = None

        if len(self.old_processes) > 0:
            # Keep calling this callback.
            return True
        else:
            # All done.
            self.timer_id = None
            return False

    def close(self, widget=None, extra=None):
        self.destroy()


class DiffView(gtk.TextView):
    REMOVE_COLOR = "#ffaaaa"
    ADD_COLOR = "#ccffcc"

    """A widget displaying a zenmapCore.Diff.ScanDiff."""
    def __init__(self):
        gtk.TextView.__init__(self)
        self.set_editable(False)

        buff = self.get_buffer()
        # Create text markup tags.
        buff.create_tag("=", font="Monospace")
        buff.create_tag(
            "-", font="Monospace", background=self.REMOVE_COLOR)
        buff.create_tag("+", font="Monospace", background=self.ADD_COLOR)

    def clear(self):
        self.get_buffer().set_text(u"")

    def show_diff(self, diff):
        self.clear()
        buff = self.get_buffer()
        for line in diff.splitlines(True):
            if line.startswith("-"):
                tags = ["-"]
            elif line.startswith("+"):
                tags = ["+"]
            else:
                tags = ["="]
            buff.insert_with_tags_by_name(buff.get_end_iter(), line, *tags)

if __name__ == "__main__":
    from zenmapCore.NmapParser import NmapParser

    parsed1 = NmapParser()
    parsed2 = NmapParser()
    parsed3 = NmapParser()
    parsed4 = NmapParser()

    parsed1.parse_file("test/xml_test1.xml")
    parsed2.parse_file("test/xml_test2.xml")
    parsed3.parse_file("test/xml_test3.xml")
    parsed4.parse_file("test/xml_test4.xml")

    dw = DiffWindow({"Parsed 1": parsed1,
                     "Parsed 2": parsed2,
                     "Parsed 3": parsed3,
                     "Parsed 4": parsed4})

    dw.show_all()
    dw.connect("delete-event", lambda x, y: gtk.main_quit())

    gtk.main()
