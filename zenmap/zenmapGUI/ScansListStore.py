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

class ScansListStoreEntry(object):
    """This class is an abstraction for running and completed scans, which are
    otherwise represented by very different classes."""

    # Possible states for the scan to be in.
    UNINITIALIZED, RUNNING, FINISHED, FAILED, CANCELED = range(5)

    def __init__(self):
        self.state = self.UNINITIALIZED
        self.command = None
        self.parsed = None

    def set_running(self, command = None):
        self.state = self.RUNNING
        self.command = command

    def set_finished(self, parsed = None):
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

class ScansListStore(gtk.ListStore):
    """This is a specialization of a gtk.ListStore that holds running,
    completed, and failed scans."""
    def __init__(self):
        gtk.ListStore.__init__(self, object)

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
