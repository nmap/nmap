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

import os
import subprocess
import sys
import tempfile
# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

import xml.sax

from zenmapCore.Name import APP_NAME
from zenmapCore.NmapParser import NmapParserSAX
from zenmapCore.UmitConf import PathsConfig
from zenmapCore.UmitLogging import log
import zenmapCore.Paths

# The [paths] configuration from zenmap.conf, used to get ndiff_command_path.
paths_config = PathsConfig()


class NdiffParseException(Exception):
    pass


def get_path():
    """Return a value for the PATH environment variable that is appropriate
    for the current platform. It will be the PATH from the environment plus
    possibly some platform-specific directories."""
    path_env = os.getenv("PATH")
    if path_env is None:
        search_paths = []
    else:
        search_paths = path_env.split(os.pathsep)
    for path in zenmapCore.Paths.get_extra_executable_search_paths():
        if path not in search_paths:
            search_paths.append(path)
    return os.pathsep.join(search_paths)


class NdiffCommand(subprocess.Popen):
    def __init__(self, filename_a, filename_b, temporary_filenames=[]):
        self.temporary_filenames = temporary_filenames

        search_paths = get_path()
        env = dict(os.environ)
        env["PATH"] = search_paths
        if "Zenmap.app" in sys.executable:
            # These vars are set by the launcher, but they can interfere with
            # Ndiff because Ndiff is also a Python application. Without
            # removing these, Ndiff will attempt to run using the
            # bundled Python library, and may run into version or
            # architecture mismatches.
            if "PYTHONPATH" in env:
                del env["PYTHONPATH"]
            if "PYTHONHOME" in env:
                del env["PYTHONHOME"]

        command_list = [
                paths_config.ndiff_command_path,
                "--verbose",
                "--",
                filename_a,
                filename_b
                ]
        self.stdout_file = tempfile.TemporaryFile(
                mode="r",
                prefix=APP_NAME + "-ndiff-",
                suffix=".xml"
                )

        log.debug("Running command: %s" % repr(command_list))
        # shell argument explained in zenmapCore.NmapCommand.py
        subprocess.Popen.__init__(
                self,
                command_list,
                universal_newlines=True,
                stdout=self.stdout_file,
                stderr=self.stdout_file,
                env=env,
                shell=(sys.platform == "win32")
                )

    def get_scan_diff(self):
        self.wait()
        self.stdout_file.seek(0)

        return self.stdout_file.read()

    def close(self):
        """Clean up temporary files."""
        self.stdout_file.close()
        for filename in self.temporary_filenames:
            log.debug("Remove temporary diff file %s." % filename)
            os.remove(filename)
        self.temporary_filenames = []

    def kill(self):
        self.close()


def ndiff(scan_a, scan_b):
    """Run Ndiff on two scan results, which may be filenames or NmapParserSAX
    objects, and return a running NdiffCommand object."""
    temporary_filenames = []

    if isinstance(scan_a, NmapParserSAX):
        fd, filename_a = tempfile.mkstemp(
                prefix=APP_NAME + "-diff-",
                suffix=".xml"
                )
        temporary_filenames.append(filename_a)
        f = os.fdopen(fd, "w")
        scan_a.write_xml(f)
        f.close()
    else:
        filename_a = scan_a

    if isinstance(scan_b, NmapParserSAX):
        fd, filename_b = tempfile.mkstemp(
                prefix=APP_NAME + "-diff-",
                suffix=".xml"
                )
        temporary_filenames.append(filename_b)
        f = os.fdopen(fd, "w")
        scan_b.write_xml(f)
        f.close()
    else:
        filename_b = scan_b

    return NdiffCommand(filename_a, filename_b, temporary_filenames)
