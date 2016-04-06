#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
# * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
# * modify, and redistribute this software under certain conditions.  If    *
# * you wish to embed Nmap technology into proprietary software, we sell    *
# * alternative licenses (contact sales@nmap.com).  Dozens of software      *
# * vendors already license Nmap technology such as host discovery, port    *
# * scanning, OS detection, version detection, and the Nmap Scripting       *
# * Engine.                                                                 *
# *                                                                         *
# * Note that the GPL places important restrictions on "derivative works",  *
# * yet it does not provide a detailed definition of that term.  To avoid   *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
# * derivative work for the purpose of this license if it does any of the   *
# * following with any software or content covered by this license          *
# * ("Covered Software"):                                                   *
# *                                                                         *
# * o Integrates source code from Covered Software.                         *
# *                                                                         *
# * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
# * or nmap-service-probes.                                                 *
# *                                                                         *
# * o Is designed specifically to execute Covered Software and parse the    *
# * results (as opposed to typical shell or execution-menu apps, which will *
# * execute anything you tell them to).                                     *
# *                                                                         *
# * o Includes Covered Software in a proprietary executable installer.  The *
# * installers produced by InstallShield are an example of this.  Including *
# * Nmap with other software in compressed or archival form does not        *
# * trigger this provision, provided appropriate open source decompression  *
# * or de-archiving software is widely available for no charge.  For the    *
# * purposes of this license, an installer is considered to include Covered *
# * Software even if it actually retrieves a copy of Covered Software from  *
# * another source during runtime (such as by downloading it from the       *
# * Internet).                                                              *
# *                                                                         *
# * o Links (statically or dynamically) to a library which does any of the  *
# * above.                                                                  *
# *                                                                         *
# * o Executes a helper program, module, or script to do any of the above.  *
# *                                                                         *
# * This list is not exclusive, but is meant to clarify our interpretation  *
# * of derived works with some common examples.  Other people may interpret *
# * the plain GPL differently, so we consider this a special exception to   *
# * the GPL that we apply to Covered Software.  Works which meet any of     *
# * these conditions must conform to all of the terms of this license,      *
# * particularly including the GPL Section 3 requirements of providing      *
# * source code and allowing free redistribution of the work as a whole.    *
# *                                                                         *
# * As another special exception to the GPL terms, Insecure.Com LLC grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * Any redistribution of Covered Software, including any derived works,    *
# * must obey and carry forward all of the terms of this license, including *
# * obeying all GPL rules and restrictions.  For example, source code of    *
# * the whole work must be provided and free redistribution must be         *
# * allowed.  All GPL references to "this License", are to be treated as    *
# * including the terms and conditions of this license text as well.        *
# *                                                                         *
# * Because this license imposes special exceptions to the GPL, Covered     *
# * Work may not be combined (even as part of a larger work) with plain GPL *
# * software.  The terms, conditions, and exceptions of this license must   *
# * be included as well.  This license is incompatible with some other open *
# * source licenses as well.  In some cases we can relicense portions of    *
# * Nmap or grant special permissions to use it in other open source        *
# * software.  Please contact fyodor@nmap.org with any such requests.       *
# * Similarly, we don't incorporate incompatible open source software into  *
# * Covered Software without special permission from the copyright holders. *
# *                                                                         *
# * If you have any questions about the licensing restrictions on using     *
# * Nmap in other works, are happy to help.  As mentioned above, we also    *
# * offer alternative license to integrate Nmap into proprietary            *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@nmap.com for further *
# * information.                                                            *
# *                                                                         *
# * If you have received a written license agreement or contract for        *
# * Covered Software stating terms other than these, you may choose to use  *
# * and redistribute Covered Software under those terms instead of these.   *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes.          *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to the dev@nmap.org mailing list for possible incorporation into the    *
# * main distribution.  By sending these changes to Fyodor or one of the    *
# * Insecure.Org development mailing lists, or checking them into the Nmap  *
# * source code repository, it is understood (unless you specify otherwise) *
# * that you are offering the Nmap Project (Insecure.Com LLC) the           *
# * unlimited, non-exclusive right to reuse, modify, and relicense the      *
# * code.  Nmap will always be available Open Source, but this is important *
# * because the inability to relicense code has caused devastating problems *
# * for other Free Software projects (such as KDE and NASM).  We also       *
# * occasionally relicense the code to third parties as discussed above.    *
# * If you wish to specify special license conditions of your               *
# * contributions, just say so when you send them.                          *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
# * license file for more details (it's in a COPYING file included with     *
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
# *                                                                         *
# ***************************************************************************/

from optparse import OptionParser
from zenmapCore.Name import APP_NAME, NMAP_DISPLAY_NAME
from zenmapCore.Version import VERSION
import zenmapCore.I18N
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
