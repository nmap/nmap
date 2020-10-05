#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2020 Insecure.Com LLC ("The Nmap  *
# * Project"). Nmap is also a registered trademark of the Nmap Project.     *
# *                                                                         *
# * This program is distributed under the terms of the Nmap Public Source   *
# * License (NPSL). The exact license text applying to a particular Nmap    *
# * release or source code control revision is contained in the LICENSE     *
# * file distributed with that version of Nmap or source code control       *
# * revision. More Nmap copyright/legal information is available from       *
# * https://nmap.org/book/man-legal.html, and further information on the    *
# * NPSL license itself can be found at https://nmap.org/npsl. This header  *
# * summarizes some key points from the Nmap license, but is no substitute  *
# * for the actual license text.                                            *
# *                                                                         *
# * Nmap is generally free for end users to download and use themselves,    *
# * including commercial use. It is available from https://nmap.org.        *
# *                                                                         *
# * The Nmap license generally prohibits companies from using and           *
# * redistributing Nmap in commercial products, but we sell a special Nmap  *
# * OEM Edition with a more permissive license and special features for     *
# * this purpose. See https://nmap.org/oem                                  *
# *                                                                         *
# * If you have received a written Nmap license agreement or contract       *
# * stating terms other than these (such as an Nmap OEM license), you may   *
# * choose to use and redistribute Nmap under those terms instead.          *
# *                                                                         *
# * The official Nmap Windows builds include the Npcap software             *
# * (https://npcap.org) for packet capture and transmission. It is under    *
# * separate license terms which forbid redistribution without special      *
# * permission. So the official Nmap Windows builds may not be              *
# * redistributed without special permission (such as an Nmap OEM           *
# * license).                                                               *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes.          *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to submit your         *
# * changes as a Github PR or by email to the dev@nmap.org mailing list     *
# * for possible incorporation into the main distribution. Unless you       *
# * specify otherwise, it is understood that you are offering us very       *
# * broad rights to use your submissions as described in the Nmap Public    *
# * Source License Contributor Agreement. This is important because we      *
# * fund the project by selling licenses with various terms, and also       *
# * because the inability to relicense code has caused devastating          *
# * problems for other Free Software projects (such as KDE and NASM).       *
# *                                                                         *
# * The free version of Nmap is distributed in the hope that it will be     *
# * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,        *
# * indemnification and commercial support are all available through the    *
# * Npcap OEM program--see https://nmap.org/oem.                            *
# *                                                                         *
# ***************************************************************************/

"""
higwidgets/gtkutils.py

   gtk related functions
"""

__all__ = ['gtk_version_major', 'gtk_version_minor', 'gtk_version_release',
           'gtk_constant_name', 'gobject_register']

import gtk
import gobject

# version information
gtk_version_major, gtk_version_minor, gtk_version_release = gtk.gtk_version
assert gtk_version_major == 2


def gtk_constant_name(group, value):
    """
    Returns the (py)GTK+ name of a constant, given its group name
    """
    group_response = {-1: 'gtk.RESPONSE_NONE',
                      -2: 'gtk.RESPONSE_REJECT',
                      -3: 'gtk.RESPONSE_ACCEPT',
                      -4: 'gtk.RESPONSE_DELETE_EVENT',
                      -5: 'gtk.RESPONSE_OK',
                      -6: 'gtk.RESPONSE_CANCEL',
                      -7: 'gtk.RESPONSE_CLOSE',
                      -8: 'gtk.RESPONSE_YES',
                      -9: 'gtk.RESPONSE_NO',
                      -10: 'gtk.RESPONSE_APPLY',
                      -11: 'gtk.RESPONSE_HELP'}

    groups = {'response': group_response}

    return groups.get(group, {}).get(value, 'Error: constant value not found')


def gobject_register(klass):
    """
    Register a given object by calling gobject.type_register.

    Actually gobject.type_register is only called if the pygtk version in use
    is not 2.8 at least.
    """
    if gtk_version_minor < 8:
        gobject.type_register(klass)
