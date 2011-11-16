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

# This file contains the definitions of the NmapCommand class, which represents
# and runs an Nmap command line.

import codecs
import errno
import locale
import sys
import os
import re
import tempfile
import unittest

import zenmapCore.I18N

from types import StringTypes
try:
    import subprocess
except ImportError, e:
    raise ImportError(str(e) + ".\n" + _("Python 2.4 or later is required."))

import zenmapCore.Paths
from zenmapCore.Paths import Path
from zenmapCore.NmapOptions import NmapOptions
from zenmapCore.UmitLogging import log
from zenmapCore.UmitConf import PathsConfig
from zenmapCore.Name import APP_NAME

# The [paths] configuration from zenmap.conf, used to get nmap_command_path.
paths_config = PathsConfig()

log.debug(">>> Platform: %s" % sys.platform)

def wrap_file_in_preferred_encoding(f):
    """Wrap an open file to automatically decode its contents when reading from
    the encoding given by locale.getpreferredencoding, or just return the file
    if that doesn't work.

    The nmap executable will write its output in whatever the system encoding
    is. Nmap's output is usually all ASCII, but time zone it prints can be in a
    different encoding. If it is not decoded correctly it will be displayed as
    garbage characters. This function assists in reading the Nmap output. We
    don't know for sure what the encoding used is, but we take a best guess and
    decode the output into a proper unicode object so that the screen display
    and XML writer interpret it correctly."""

    try:
        preferredencoding = locale.getpreferredencoding()
    except locale.Error:
        # This can happen if the LANG environment variable is set to something
        # weird.
        preferredencoding = None

    if preferredencoding is not None:
        try:
            reader = codecs.getreader(preferredencoding)
            return reader(f, "replace")
        except LookupError:
            # The lookup failed. This can happen if the preferred encoding is
            # unknown ("X-MAC-KOREAN" has been observed). Ignore it and return
            # the unwrapped file.
            log.debug("Unknown encoding \"%s\"." % preferredencoding)

    return f

def escape_nmap_filename(filename):
    """Escape '%' characters so they are not interpreted as strftime format
    specifiers, which are not supported by Zenmap."""
    return filename.replace("%", "%%")

class NmapCommand(object):
    """This class represents an Nmap command line. It is responsible for
    starting, stopping, and returning the results from a command-line scan. A
    command line is represented as a string but it is split into a list of
    arguments for execution.
    
    The normal output (stdout and stderr) are written to the file object
    self.stdout_file."""

    def __init__(self, command):
        """Initialize an Nmap command. This creates temporary files for
        redirecting the various types of output and sets the backing
        command-line string."""
        self.command = command
        self.command_process = None

        self.stdout_file = None

        self.ops = NmapOptions()
        self.ops.parse_string(command)
        # Replace the executable name with the value of nmap_command_path.
        self.ops.executable = paths_config.nmap_command_path

        # Normally we generate a random temporary filename to save XML output
        # to. If we find -oX or -oA, the user has chosen his own output file.
        # Set self.xml_is_temp to False and don't delete the file when we're
        # done.
        self.xml_is_temp = True
        self.xml_output_filename = None
        if self.ops["-oX"]:
            self.xml_is_temp = False
            self.xml_output_filename = self.ops["-oX"]
        if self.ops["-oA"]:
            self.xml_is_temp = False
            self.xml_output_filename = self.ops["-oA"] + ".xml"

        # Escape '%' to avoid strftime expansion.
        for op in ("-oA", "-oX", "-oG", "-oN", "-oS"):
            if self.ops[op]:
                self.ops[op] = escape_nmap_filename(self.ops[op])

        if self.xml_is_temp:
            self.xml_output_filename = tempfile.mktemp(prefix = APP_NAME + "-", suffix = ".xml")
            self.ops["-oX"] = escape_nmap_filename(self.xml_output_filename)

        log.debug(">>> Temporary files:")
        log.debug(">>> XML OUTPUT: %s" % self.xml_output_filename)

    def close(self):
        """Close and remove temporary output files used by the command."""
        self.stdout_file.close()
        if self.xml_is_temp:
            try:
                os.remove(self.xml_output_filename)
            except OSError, e:
                if e.errno != errno.ENOENT:
                    raise

    def kill(self):
        """Kill the nmap subprocess."""
        log.debug(">>> Killing scan process %s" % self.command_process.pid)

        if sys.platform != "win32":
            try:
                from signal import SIGKILL
                os.kill(self.command_process.pid, SIGKILL)
                self.command_process.wait()
            except:
                pass
        else:
            try:
                import ctypes
                ctypes.windll.kernel32.TerminateProcess(int(self.command_process._handle), -1)
            except:
                pass

    def get_path(self):
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

    def run_scan(self, stderr = None):
        """Run the command represented by this class."""

        # We don't need a file name for stdout output, just a handle. A
        # TemporaryFile is deleted as soon as it is closed, and in Unix is
        # unlinked immediately after creation so it's not even visible.
        f = tempfile.TemporaryFile(mode = "rb", prefix = APP_NAME + "-stdout-")
        self.stdout_file = wrap_file_in_preferred_encoding(f)
        if stderr is None:
            stderr = f

        search_paths = self.get_path()
        env = dict(os.environ)
        env["PATH"] = search_paths
        log.debug("PATH=%s" % env["PATH"])

        command_list = self.ops.render()
        log.debug("Running command: %s" % repr(command_list))

        startupinfo = None
        if sys.platform == "win32":
            # This keeps a terminal window from opening.
            startupinfo = subprocess.STARTUPINFO()
            try:
                startupinfo.dwFlags |= subprocess._subprocess.STARTF_USESHOWWINDOW
            except AttributeError:
                # This name is used before Python 2.6.5.
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        self.command_process = subprocess.Popen(command_list, bufsize=1,
                                     stdin=subprocess.PIPE,
                                     stdout=f,
                                     stderr=stderr,
                                     startupinfo = startupinfo,
                                     env=env)

    def scan_state(self):
        """Return the current state of a running scan. A return value of True
        means the scan is running and a return value of False means the scan
        subprocess completed successfully. If the subprocess terminated with an
        error an exception is raised. The scan must have been started with
        run_scan before calling this method."""
        if self.command_process == None:
            raise Exception("Scan is not running yet!")

        state = self.command_process.poll()

        if state == None:
            return True # True means that the process is still running
        elif state == 0:
            return False # False means that the process had a successful exit
        else:
            log.warning("An error occurred during the scan execution!")
            log.warning("Command that raised the exception: '%s'" % self.ops.render_string())
            log.warning("Scan output:\n%s" % self.get_output())

            raise Exception("An error occurred during the scan execution!\n\n'%s'" % self.get_output())

    def get_output(self):
        """Return the complete contents of the self.stdout_file. This modifies
        the file pointer."""
        self.stdout_file.seek(0)
        return self.stdout_file.read()

    def get_xml_output_filename(self):
        """Return the name of the XML (-oX) output file."""
        return self.xml_output_filename

if __name__ == '__main__':
    unittest.TextTestRunner().run(unittest.TestLoader().loadTestsFromTestCase(SplitQuotedTest))
