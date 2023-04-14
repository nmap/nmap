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


class ScansListStoreEntry(object):
    """This class is an abstraction for running and completed scans, which are
    otherwise represented by very different classes."""

    # Possible states for the scan to be in.
    UNINITIALIZED, RUNNING, FINISHED, FAILED, CANCELED = list(range(5))

    def __init__(self):
        self.state = self.UNINITIALIZED
        self.command = None
        self.parsed = None

    def set_running(self, command=None):
        self.state = self.RUNNING
        self.command = command

    def set_finished(self, parsed=None):
        self.state = self.FINISHED
        self.parsed = parsed

    def set_failed(self):
        self.state = self.FAILED

    def set_canceled(self):
        self.state = self.CANCELED

    def get_command_string(self):
        if self.parsed is not None:
            return self.parsed.get_nmap_command()
        elif self.command is not None:
            return self.command.command
        else:
            return None

    running = property(lambda self: self.state == self.RUNNING)
    finished = property(lambda self: self.state == self.FINISHED)
    failed = property(lambda self: self.state == self.FAILED)
    canceled = property(lambda self: self.state == self.CANCELED)


class ScansListStore(Gtk.ListStore):
    """This is a specialization of a Gtk.ListStore that holds running,
    completed, and failed scans."""
    def __init__(self):
        Gtk.ListStore.__init__(self, object)

    def add_running_scan(self, command):
        """Add a running NmapCommand object to the list of scans."""
        entry = ScansListStoreEntry()
        entry.set_running(command)
        return self.append([entry])

    def finish_running_scan(self, command, parsed):
        """Find an existing NmapCommand object and replace it with the given
        parsed representation."""
        i = self._find_running_scan(command)
        if i is not None:
            entry = self.get_value(i, 0)
            entry.set_finished(parsed)
            path = self.get_path(i)
            self.row_changed(path, i)
            return i

    def fail_running_scan(self, command):
        """Mark a running scan as failed."""
        i = self._find_running_scan(command)
        if i is not None:
            entry = self.get_value(i, 0)
            entry.set_failed()
            path = self.get_path(i)
            self.row_changed(path, i)
            return i

    def cancel_running_scan(self, command):
        """Mark a running scan as canceled."""
        i = self._find_running_scan(command)
        if i is not None:
            entry = self.get_value(i, 0)
            entry.set_canceled()
            path = self.get_path(i)
            self.row_changed(path, i)
            return i

    def add_scan(self, parsed):
        """Add a parsed NmapParser object to the list of scans."""
        entry = ScansListStoreEntry()
        entry.set_finished(parsed)
        return self.append([entry])

    def _find_running_scan(self, command):
        """Find the scan entry whose command is command."""
        i = self.get_iter_first()
        while i is not None:
            entry = self.get_value(i, 0)
            if entry.command is command:
                return i
            i = self.iter_next(i)
        return None
