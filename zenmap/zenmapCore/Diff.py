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

import datetime
import os
import subprocess
import sys
import tempfile
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
    def __init__(self, filename_a, filename_b, temporary_filenames = []):
        self.temporary_filenames = temporary_filenames

        search_paths = get_path()
        env = dict(os.environ)
        env["PATH"] = search_paths
        if getattr(sys, "frozen", None) == "macosx_app":
            # These variables are set by py2app, but they can interfere with
            # Ndiff because Ndiff is also a Python application. Without removing
            # these, Ndiff will attempt to run using the py2app-bundled Python
            # library, and may run into version or architecture mismatches.
            if env.has_key("PYTHONPATH"):
                del env["PYTHONPATH"]
            if env.has_key("PYTHONHOME"):
                del env["PYTHONHOME"]

        command_list = [paths_config.ndiff_command_path, "--verbose", "--", filename_a, filename_b]
        self.stdout_file = tempfile.TemporaryFile(mode = "rb", prefix = APP_NAME + "-ndiff-", suffix = ".xml")

        log.debug("Running command: %s" % repr(command_list))
        # See zenmapCore.NmapCommand.py for an explanation of the shell argument.
        subprocess.Popen.__init__(self, command_list, stdout = self.stdout_file, stderr = self.stdout_file, env = env, shell = (sys.platform == "win32"))

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
        fd, filename_a = tempfile.mkstemp(prefix = APP_NAME + "-diff-", suffix = ".xml")
        temporary_filenames.append(filename_a)
        f = os.fdopen(fd, "wb")
        scan_a.write_xml(f)
        f.close()
    else:
        filename_a = scan_a

    if isinstance(scan_b, NmapParserSAX):
        fd, filename_b = tempfile.mkstemp(prefix = APP_NAME + "-diff-", suffix = ".xml")
        temporary_filenames.append(filename_b)
        f = os.fdopen(fd, "wb")
        scan_b.write_xml(f)
        f.close()
    else:
        filename_b = scan_b

    return NdiffCommand(filename_a, filename_b, temporary_filenames)
