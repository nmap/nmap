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

# This program updates the version number in all the places it needs to be
# updated. It takes a single command-line argument, which is the new version
# number. For example:
# python install_scripts/utils/version_update.py X.YY

import os
import sys
import re
from datetime import datetime

VERSION = os.path.join("share", "zenmap", "config", "zenmap_version")
VERSION_PY = os.path.join("zenmapCore", "Version.py")
NAME_PY = os.path.join("zenmapCore", "Name.py")


def update_date(base_dir):
    name_file = os.path.join(base_dir, NAME_PY)
    print(">>> Updating %s" % name_file)
    nf = open(name_file, "r")
    ncontent = nf.read()
    nf.close()
    ncontent = re.sub(r'APP_COPYRIGHT *= *"Copyright 2005-....',
            'APP_COPYRIGHT = "Copyright 2005-%d' % (datetime.today().year),
            ncontent)
    # Write the modified file.
    nf = open(name_file, "w")
    nf.write(ncontent)
    nf.close()


def update_version(base_dir, version):
    print(">>> Updating %s" % os.path.join(base_dir, VERSION))
    vf = open(os.path.join(base_dir, VERSION), "w")
    print(version, file=vf)
    vf.close()
    print(">>> Updating %s" % os.path.join(base_dir, VERSION_PY))
    vf = open(os.path.join(base_dir, VERSION_PY), "w")
    print("VERSION = \"%s\"" % version, file=vf)
    vf.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: %s <version>" % sys.argv[0], file=sys.stderr)
        sys.exit(1)

    version = sys.argv[1]
    print(">>> Updating version number to \"%s\"" % version)
    update_version(".", version)
    update_date(".")
