#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, version detection, and the Nmap Scripting Engine.            *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
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
# * works of Nmap, as well as other software we distribute under this       *
# * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
# * but is meant to clarify our interpretation of derived works with some   *
# * common examples.  Our interpretation applies only to Nmap--we don't     *
# * speak for other people's GPL works.                                     *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@insecure.com for     *
# * further information.                                                    *
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
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
# *                                                                         *
# ***************************************************************************/

import imp
import os
import signal
import sys
import ConfigParser

# Cause an exception if PyGTK can't open a display. Normally this just
# produces a warning, but the lack of a display eventually causes a
# segmentation fault. See http://live.gnome.org/PyGTK/WhatsNew210.
# 'append = "True"' is to work around an error when using PyGTK with
# Python 2.7 that otherwise causes an assertion failure. See
# https://bugzilla.redhat.com/show_bug.cgi?id=620216#c10.
import warnings
warnings.filterwarnings("error", module = "gtk", append = "True")
try:
    import gtk
except Exception:
    # On Mac OS X 10.5, X11 is supposed to be automatically launched on demand.
    # It works by setting the DISPLAY environment variable to something like
    # "/tmp/launch-XXXXXX/:0" and intercepting traffic on that socket; see
    # http://homepage.mac.com/sao1/X11/#four. However this breaks in a strange
    # way if DISPLAY is set in one of the shell startup files like .profile.
    # Those files only have an effect on the shell, not the graphical
    # environment, so X11 starts up as expected, but in doing so it reads the
    # startup scripts, and for some reason the first connection (the one that
    # caused the launch) is rejected. But somehow subsequent connections work
    # fine! So if the import fails, try one more time.
    import gtk
warnings.resetwarnings()

from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog

import zenmapCore.UmitConf
import zenmapCore.Paths
from zenmapCore.UmitConf import is_maemo
from zenmapCore.UmitLogging import log
from zenmapCore.UmitOptionParser import option_parser
from zenmapCore.Name import APP_NAME, APP_DISPLAY_NAME, NMAP_DISPLAY_NAME
from zenmapCore.UmitConf import SearchConfig
import zenmapCore.I18N
from zenmapCore.Paths import Path
from zenmapCore.Name import APP_DISPLAY_NAME

from zenmapGUI.MainWindow import ScanWindow

from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog

# A global list of open scan windows. When the last one is destroyed, we call
# gtk.main_quit.
open_windows = []

def _destroy_callback(window):
    open_windows.remove(window)
    if len(open_windows) == 0:
        gtk.main_quit()
    try:
        from zenmapCore.UmitDB import UmitDB
    except ImportError, e:
        log.debug(">>> Not cleaning up database: %s." % str(e))
    else:
        # Cleaning up data base
        UmitDB().cleanup(SearchConfig().converted_save_time)

def new_window():
    w = ScanWindow()
    w.connect("destroy", _destroy_callback)
    if is_maemo():
        import hildon
        hildon_app = hildon.Program()
        hildon_app.add_window(w)
    open_windows.append(w)
    return w

# Script found at http://www.py2exe.org/index.cgi/HowToDetermineIfRunningFromExe
def main_is_frozen():
    return (hasattr(sys, "frozen") # new py2exe
            or hasattr(sys, "importers") # old py2exe
            or imp.is_frozen("__main__")) # tools/freeze

def is_root():
    return sys.platform == "win32" or os.getuid() == 0 or is_maemo()

def install_excepthook():
    # This will catch exceptions and send them to bugzilla
    def excepthook(type, value, tb):
        import traceback

        traceback.print_exception(type, value, tb)

        # Cause an exception if PyGTK can't open a display. Normally this just
        # produces a warning, but the lack of a display eventually causes a
        # segmentation fault. See http://live.gnome.org/PyGTK/WhatsNew210.
        import warnings
        warnings.filterwarnings("error", module = "gtk")
        import gtk
        warnings.resetwarnings()

        gtk.gdk.threads_enter()

        from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog
        from zenmapGUI.CrashReport import CrashReport
        if type == ImportError:
            d = HIGAlertDialog(type=gtk.MESSAGE_ERROR,
                message_format=_("Import error"),
                secondary_text=_("""\
A required module was not found.

""" + value.message))
            d.run()
            d.destroy()
        else:
            c = CrashReport(type, value, tb)
            c.show_all()
            gtk.main()

        gtk.gdk.threads_leave()

        gtk.main_quit()

    sys.excepthook = excepthook

def safe_shutdown(signum, stack):
    """Kills any active scans/tabs and shuts down the application."""
    log.debug("\n\n%s\nSAFE SHUTDOWN!\n%s\n" % ("#" * 30, "#" * 30))
    log.debug("SIGNUM: %s" % signum)

    for window in open_windows:
        window.scan_interface.kill_all_scans()

    sys.exit(signum)

def run():
    if os.name == "posix":
        signal.signal(signal.SIGHUP, safe_shutdown)
    signal.signal(signal.SIGTERM, safe_shutdown)
    signal.signal(signal.SIGINT, safe_shutdown)

    DEVELOPMENT = os.environ.get(APP_NAME.upper() + "_DEVELOPMENT", False)
    if not DEVELOPMENT:
        install_excepthook()

    zenmapCore.I18N.install_gettext(Path.locale_dir)

    try:
        # Create the ~/.zenmap directory by copying from the system-wide
        # template directory.
        zenmapCore.Paths.create_user_config_dir(Path.user_config_dir, Path.config_dir)
    except (IOError, OSError), e:
        error_dialog = HIGAlertDialog(message_format = _("Error creating the per-user configuration directory"),
            secondary_text = _("""\
There was an error creating the directory %s or one of the files in it. \
The directory is created by copying the contents of %s. \
The specific error was\n\
\n\
%s\n\
\n\
%s needs to create this directory to store information such as the list of \
scan profiles. Check for access to the directory and try again.\
""") % (repr(Path.user_config_dir), repr(Path.config_dir), repr(str(e)), APP_DISPLAY_NAME))
        error_dialog.run()
        error_dialog.destroy()
        sys.exit(1)

    try:
        # Read the ~/.zenmap/zenmap.conf configuration file.
        zenmapCore.UmitConf.config_parser.read(Path.user_config_file)
    except ConfigParser.ParsingError, e:
        error_dialog = HIGAlertDialog(message_format = _("Error parsing the configuration file"),
            secondary_text = _("""\
There was an error parsing the configuration file %s. \
The specific error was\n\
\n\
%s\n\
\n\
%s can continue without this file but any information in it will be ignored \
until it is repaired.\
""") % (Path.user_config_file, str(e), APP_DISPLAY_NAME))
        error_dialog.run()
        error_dialog.destroy()

    # Display a "you're not root" warning if appropriate.
    if not is_root():
        non_root = NonRootWarning()
        non_root.run()
        non_root.destroy()

    # Load files given as command-line arguments.
    filenames = option_parser.get_open_results()
    if len(filenames) == 0:
        # Open up a blank window.
        window = new_window()
        window.show_all()
    else:
        for filename in filenames:
            window = new_window()
            if os.path.isdir(filename):
                window._load_directory(window.scan_interface, filename)
            else:
                window._load(window.scan_interface, filename)
            window.show_all()

    nmap = option_parser.get_nmap()
    target = option_parser.get_target()
    profile = option_parser.get_profile()

    if nmap:
        # Start running a scan if given by the -n option.
        page = window.get_empty_interface()
        page.command_toolbar.command = " ".join(nmap)
        page.start_scan_cb()
    elif target or profile:
        # Set up target and profile according to the -t and -p options.
        page = window.get_empty_interface()
        if target:
            page.toolbar.selected_target = target
        if profile:
            page.toolbar.selected_profile = profile
        if target and profile:
            page.start_scan_cb()

    if main_is_frozen():
        # This is needed by py2exe
        gtk.gdk.threads_init()
        gtk.gdk.threads_enter()

    gtk.main()

    if main_is_frozen():
        gtk.gdk.threads_leave()

class NonRootWarning (HIGAlertDialog):
    def __init__(self):
        warning_text = _('''You are trying to run %s with a non-root user!\n
Some %s options need root privileges to work.''') % (APP_DISPLAY_NAME, NMAP_DISPLAY_NAME)

        HIGAlertDialog.__init__(self, message_format=_('Non-root user'),
                                secondary_text=warning_text)
