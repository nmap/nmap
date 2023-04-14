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

from optparse import OptionParser
from zenmapCore.Name import NMAP_DISPLAY_NAME
from zenmapCore.Version import VERSION
import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapCore.BasePaths import base_paths
from zenmapCore.DelayedObject import DelayedObject


class UmitOptionParser(OptionParser):
    def __init__(self, args=False):
        OptionParser.__init__(self, version="%%prog %s" % VERSION)

        self.set_usage("%prog [options] [result files]")

        self.add_option("--confdir",
            default=base_paths["user_config_dir"],
            dest="confdir",
            metavar="DIR",
            help=_("\
Use DIR as the user configuration directory. Default: %default"))

        ## Open Scan Results (GUI)
        ### Run, opening the specified scan result file, which should be
        ### a nmap XML output file.
        ### This option should be verified if there is no options, and user
        ### specified some positional arguments, which should be considered as
        ### scan result files.
        self.add_option("-f", "--file",
                        default=[],
                        action="append",
                        type="string",
                        dest="result_files",
                        help=_("Specify a scan result file in Nmap XML output \
format. Can be used more than once to specify several \
scan result files."))

        ## Run nmap with args (GUI)
        ### Open and run nmap with specified args. The positional
        ### args should be used to feed the nmap command
        self.add_option("-n", "--nmap",
                        default=[],
                        action="callback",
                        callback=self.__nmap_callback,
                        help=_("Run %s with the specified args."
                            ) % NMAP_DISPLAY_NAME)

        ## Execute a profile against a target (GUI)
        ### Positional args should be taken as targets to feed this scan
        self.add_option("-p", "--profile",
                        default="",
                        action="store",
                        help=_("Begin with the specified profile \
selected. If combined with the -t (--target) option, \
automatically run the profile against the specified target."))

        ## Targets (GUI)
        ### Specify a target to be used along with other command line option
        ### or simply opens with the first tab target field filled with
        ### the target specified with this option
        self.add_option("-t", "--target",
                        default=False,
                        action="store",
                    help=_("Specify a target to be used along with other \
options. If specified alone, open with the target field filled with the \
specified target"))

        ## Verbosity
        self.add_option("-v", "--verbose",
                        default=0,
                        action="count",
                        help=_("Increase verbosity of the output. May be \
used more than once to get even more verbosity"))

        # Parsing options and arguments
        if args:
            self.options, self.args = self.parse_args(args)
        else:
            self.options, self.args = self.parse_args()

    def __nmap_callback(self, option, opt_str, value, parser):
        nmap_args = []
        # Iterate over next arguments that were passed at the command line
        # that wasn't parsed yet.
        while parser.rargs:
            # Store the next argument in a specific list
            nmap_args.append(parser.rargs[0])

            # Remove the added argument from rargs to avoid its later
            # parsing by optparse
            del parser.rargs[0]

        # Set the variable nmap at parser.values, so you may call option.nmap
        # and have the nmap_args as result
        setattr(parser.values, "nmap", nmap_args)

    def get_confdir(self):
        return self.options.confdir

    def get_nmap(self):
        """Return a list of nmap arguments or False if this option was not
        called by the user"""

        try:
            nmap = self.options.nmap
            if nmap:
                return nmap
        except AttributeError:
            return False

    def get_profile(self):
        """Return a string with the profile name, or False if no profile
        option was specified by the user"""
        if self.options.profile != "":
            return self.options.profile
        return False

    def get_target(self):
        """Returns a string with the target specified, or False if this option
        was not called by the user"""
        return self.options.target

    def get_open_results(self):
        """Returns a list of strings with the name of the files specified with
        the -f (--file) option and every positional argument."""
        files = []
        # Add arguments given with -f.
        if self.options.result_files:
            files = self.options.result_files[:]
        # Add any other arguments.
        files += self.args
        return files

    def get_verbose(self):
        """Returns an integer representing the verbosity level of the
        application. Verbosity level starts in 40, which means that only
        messages above the ERROR level are going to be reported at the output.
        As this value gets lower, the verbosity increases.
        """
        return 40 - (self.options.verbose * 10)

option_parser = DelayedObject(UmitOptionParser)

if __name__ == "__main__":
    opt = UmitOptionParser()
    options, args = opt.parse_args()
