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

# This file contains the definitions of the NmapCommand class, which represents
# and runs an Nmap command line.

import codecs
import errno
import locale
import sys
import os
import tempfile
import unittest

import zenmapCore.I18N  # lgtm[py/unused-import]

import subprocess

import zenmapCore.Paths
from zenmapCore.NmapOptions import NmapOptions
from zenmapCore.UmitLogging import log
from zenmapCore.UmitConf import PathsConfig
from zenmapCore.Name import APP_NAME

# The [paths] configuration from zenmap.conf, used to get nmap_command_path.
paths_config = PathsConfig()

log.debug(">>> Platform: %s" % sys.platform)


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
            fh, self.xml_output_filename = tempfile.mkstemp(
                    prefix=APP_NAME + "-", suffix=".xml")
            os.close(fh)
            self.ops["-oX"] = escape_nmap_filename(self.xml_output_filename)

        log.debug(">>> Temporary files:")
        log.debug(">>> XML OUTPUT: %s" % self.xml_output_filename)

    def close(self):
        """Close and remove temporary output files used by the command."""
        self.stdout_file.close()
        if self.xml_is_temp:
            try:
                os.remove(self.xml_output_filename)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise

    def kill(self):
        """Kill the nmap subprocess."""
        from time import sleep

        log.debug(">>> Killing scan process %s" % self.command_process.pid)

        if sys.platform != "win32":
            try:
                from signal import SIGTERM, SIGKILL
                os.kill(self.command_process.pid, SIGTERM)
                for i in range(10):
                    sleep(0.5)
                    if self.command_process.poll() is not None:
                        # Process has been TERMinated
                        break
                else:
                    log.debug(">>> SIGTERM has not worked even after waiting for 5 seconds. Using SIGKILL.")  # noqa
                    os.kill(self.command_process.pid, SIGKILL)
                    self.command_process.wait()
            except Exception:
                pass
        else:
            try:
                import ctypes
                ctypes.windll.kernel32.TerminateProcess(
                        int(self.command_process._handle), -1)
            except Exception:
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

    def run_scan(self, stderr=None):
        """Run the command represented by this class."""

        # We don't need a file name for stdout output, just a handle. A
        # TemporaryFile is deleted as soon as it is closed, and in Unix is
        # unlinked immediately after creation so it's not even visible.
        f = tempfile.TemporaryFile(mode="r", prefix=APP_NAME + "-stdout-")
        self.stdout_file = f
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
                startupinfo.dwFlags |= \
                        subprocess._subprocess.STARTF_USESHOWWINDOW
            except AttributeError:
                # This name is used before Python 2.6.5.
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        self.command_process = subprocess.Popen(command_list, bufsize=1,
                                     universal_newlines=True,
                                     stdin=subprocess.PIPE,
                                     stdout=f,
                                     stderr=stderr,
                                     startupinfo=startupinfo,
                                     env=env)

    def scan_state(self):
        """Return the current state of a running scan. A return value of True
        means the scan is running and a return value of False means the scan
        subprocess completed successfully. If the subprocess terminated with an
        error an exception is raised. The scan must have been started with
        run_scan before calling this method."""
        if self.command_process is None:
            raise Exception("Scan is not running yet!")

        state = self.command_process.poll()

        if state is None:
            return True  # True means that the process is still running
        elif state == 0:
            return False  # False means that the process had a successful exit
        else:
            log.warning("An error occurred during the scan execution!")
            log.warning("Command that raised the exception: '%s'" %
                    self.ops.render_string())
            log.warning("Scan output:\n%s" % self.get_output())

            raise Exception(
                    "An error occurred during the scan execution!\n\n'%s'" %
                    self.get_output())

    def get_output(self):
        """Return the complete contents of the self.stdout_file. This modifies
        the file pointer."""
        self.stdout_file.seek(0)
        return self.stdout_file.read()

    def get_xml_output_filename(self):
        """Return the name of the XML (-oX) output file."""
        return self.xml_output_filename

if __name__ == '__main__':
    unittest.TextTestRunner().run(
            unittest.TestLoader().loadTestsFromTestCase(SplitQuotedTest))
