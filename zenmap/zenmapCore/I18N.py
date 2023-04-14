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

import locale
import os

from zenmapCore.Name import APP_NAME


def get_locales():
    """Get a list of locales to use based on system configuration."""
    locales = []
    # locale.getdefaultlocales already looks at LANG et al. on Unix but not on
    # Windows. We look at the environment variables first to allow overriding
    # the system-wide setting on Windows.
    for envar in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        val = os.environ.get(envar)
        if val:
            locales = val.split(":")
            break
    try:
        loc, enc = locale.getdefaultlocale()
        if loc is not None:
            locales.append(loc)
    except ValueError:
        # locale.getdefaultlocale can fail with ValueError on certain locale
        # names; it has been seen with at least en_NG.
        # http://bugs.python.org/issue6895
        pass
    return locales


def install_gettext(locale_dir):
    try:
        locale.setlocale(locale.LC_ALL, '')
    except locale.Error:
        # This can happen if the LANG environment variable is set to something
        # invalid, like LANG=nothing or LANG=en_US/utf8 or LANG=us-ascii.
        # Continue without internationalization.
        pass

    try:
        import gettext
    except ImportError:
        pass
    else:
        t = gettext.translation(
                APP_NAME, locale_dir, languages=get_locales(), fallback=True)
        t.install()

# Install a dummy _ function so modules can safely use it after importing this
# module, even if they don't install the gettext version.

import builtins
builtins.__dict__["_"] = lambda s: s
