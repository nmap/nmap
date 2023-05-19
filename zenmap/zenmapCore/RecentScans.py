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

from os import access, R_OK, W_OK
from os.path import dirname
from zenmapCore.Paths import Path


class RecentScans(object):
    def __init__(self):
        self.temp_list = []

        try:
            self.recent_scans_file = Path.recent_scans
        except Exception:
            self.recent_scans_file = False

        if (self.recent_scans_file and
                (access(self.recent_scans_file, R_OK and W_OK) or
                    access(dirname(self.recent_scans_file), R_OK and W_OK))):
            self.using_file = True

            # Recovering saved targets
            recent_file = open(self.recent_scans_file, "r")
            self.temp_list = [
                    t for t in recent_file.read().split(";")
                    if t != "" and t != "\n"]
            recent_file.close()
        else:
            self.using_file = False

    def save(self):
        if self.using_file:
            recent_file = open(self.recent_scans_file, "w")
            recent_file.write(";".join(self.temp_list))
            recent_file.close()

    def add_recent_scan(self, recent_scan):
        if recent_scan in self.temp_list:
            return

        self.temp_list.append(recent_scan)
        self.save()

    def clean_list(self):
        del self.temp_list
        self.temp_list = []
        self.save()

    def get_recent_scans_list(self):
        t = self.temp_list[:]
        t.reverse()
        return t

recent_scans = RecentScans()

if __name__ == "__main__":
    r = RecentScans()
    print(">>> Getting empty list:", r.get_recent_scans_list())
    print(">>> Adding recent scan bla:", r.add_recent_scan("bla"))
    print(">>> Getting recent scan list:", r.get_recent_scans_list())
    del r
