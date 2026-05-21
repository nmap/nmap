#!/usr/bin/env python3

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *
# * The Nmap Security Scanner is (C) 1996-2026 Nmap Software LLC ("The Nmap
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
# * Source code also allows you to port Nmap to new platforms, fix bugs, and
# * add new features. You are highly encouraged to submit your changes as a
# * Github PR or by email to the dev@nmap.org mailing list for possible
# * incorporation into the main distribution. Unless you specify otherwise, it
# * is understood that you are offering us very broad rights to use your
# * submissions as described in the Nmap Public Source License Contributor
# * Agreement. This is important because we fund the project by selling licenses
# * with various terms, and also because the inability to relicense code has
# * caused devastating problems for other Free Software projects (such as KDE
# * and NASM).
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
from gi.repository import Gtk, GLib, GdkPixbuf

import re
import os.path

from zenmapCore.Paths import Path
from zenmapCore.UmitLogging import log

icon_names = (
    # Operating Systems
    'default',
    'freebsd',
    'irix',
    'linux',
    'macosx',
    'openbsd',
    'redhat',
    'solaris',
    'ubuntu',
    'unknown',
    'win',
    # Vulnerability Levels
    'vl_1',
    'vl_2',
    'vl_3',
    'vl_4',
    'vl_5')

ICONS = {}
pixmap_path = Path.pixmaps_dir
if pixmap_path:
    # This is a generator that returns file names for pixmaps in the order they
    # should be tried.
    def get_pixmap_file_names(icon_name, size):
        yield '%s_%s.png' % (icon_name, size)

    for icon_name in icon_names:
        for type, size in (('icon', '32'), ('logo', '75')):
            key = '%s_%s' % (icon_name, type)
            # Look for a usable image file.
            for file_name in get_pixmap_file_names(icon_name, size):
                file_path = os.path.join(pixmap_path, file_name)
                try:
                    pixbuf = GdkPixbuf.Pixbuf.new_from_file(file_path)
                    break
                except GLib.GError:
                    # Try again.
                    pass
            else:
                log.warn('Could not find the icon for %s at '
                        'any of (%s) in %s' % (
                            icon_name,
                            ', '.join(get_pixmap_file_names(icon_name, size)),
                            pixmap_path))
                continue
            ICONS[key] = pixbuf
            log.debug('Register %s icon name for file %s' % (key, file_path))


def get_os_icon(host):
    return ICONS["%s_icon" % get_os(host)]


def get_os_logo(host):
    return ICONS["%s_logo" % get_os(host)]


OSNAMES = {
        'Windows': 'win',
        'OpenBSD': 'openbsd',
        'FreeBSD': 'freebsd',
        'Solaris': 'solaris',
        'OpenSolaris': 'solaris',
        'IRIX': 'irix',
        'Mac OS X': 'macosx',
        'Mac OS': 'macosx',
        'macOS': 'macosx',
        }


def get_os(host):
    osmatch = host.get_best_osmatch()
    try:
        osfamily = osmatch['osclasses'][0]['osfamily']
    except (KeyError, TypeError):
        return 'unknown'

    if osfamily == 'Linux':
        matchname = osmatch['name'].lower()
        if "ubuntu" in matchname:
            # Ubuntu icon
            return 'ubuntu'
        elif "red hat" in matchname:
            # RedHat icon
            return 'redhat'
        else:
            # Generic Linux icon
            return 'linux'
    else:
        return OSNAMES.get(osfamily, 'default')


def get_vulnerability_logo(open_ports):
    ports = min(int(open_ports), 10)
    lvl = (ports // 2) + 1
    return ICONS['vl_%d_logo' % (lvl,)]
