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
import signal
import sys
import configparser
import shutil

# Cause an exception if PyGTK can't open a display. Normally this just
# produces a warning, but the lack of a display eventually causes a
# segmentation fault. See http://live.gnome.org/PyGTK/WhatsNew210.
# 'append = "True"' is to work around an error when using PyGTK with
# Python 2.7 that otherwise causes an assertion failure. See
# https://bugzilla.redhat.com/show_bug.cgi?id=620216#c10.
import warnings
warnings.filterwarnings("error", module="gtk", append="True")
try:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, Gdk
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
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk, Gdk
warnings.resetwarnings()

from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog

from zenmapCore.UmitConf import is_maemo, SearchConfig
import zenmapCore.UmitConf
from zenmapCore.UmitLogging import log
from zenmapCore.UmitOptionParser import option_parser
from zenmapCore.Name import APP_NAME, APP_DISPLAY_NAME, NMAP_DISPLAY_NAME
import zenmapCore.I18N  # lgtm[py/unused-import]
from zenmapCore.Paths import Path, create_user_config_dir
from zenmapCore.Name import APP_DISPLAY_NAME

from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog

# A global list of open scan windows. When the last one is destroyed, we call
# Gtk.main_quit.
open_windows = []


def _destroy_callback(window):
    open_windows.remove(window)
    if len(open_windows) == 0:
        Gtk.main_quit()
    try:
        from zenmapCore.UmitDB import UmitDB
    except ImportError as e:
        log.debug(">>> Not cleaning up database: %s." % str(e))
    else:
        # Cleaning up data base
        UmitDB().cleanup(SearchConfig().converted_save_time)


def new_window():
    from zenmapGUI.MainWindow import ScanWindow
    w = ScanWindow()
    w.connect("destroy", _destroy_callback)
    if is_maemo():
        import hildon
        hildon_app = hildon.Program()
        hildon_app.add_window(w)
    open_windows.append(w)
    return w


def is_root():
    if 'NMAP_PRIVILEGED' in os.environ:
        return True
    elif 'NMAP_UNPRIVILEGED' in os.environ:
        return False
    else:
        return sys.platform == "win32" or os.getuid() == 0 or is_maemo()


def install_excepthook():
    # This will catch exceptions and send them to bugzilla
    def excepthook(type, value, tb):
        import traceback

        traceback.print_exception(type, value, tb)

        # Cause an exception if PyGTK can't open a display. Normally this just
        # produces a warning, but the lack of a display eventually causes a
        # segmentation fault. See http://live.gnome.org/PyGTK/WhatsNew210.
        warnings.filterwarnings("error", module="gtk")
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk, Gdk
        warnings.resetwarnings()

        Gdk.threads_enter()

        from zenmapGUI.higwidgets.higdialogs import HIGAlertDialog
        from zenmapGUI.CrashReport import CrashReport
        if type == ImportError:
            d = HIGAlertDialog(type=Gtk.MessageType.ERROR,
                message_format=_("Import error"),
                secondary_text=_("""A required module was not found.

""" + str(value)))
            d.run()
            d.destroy()
        else:
            c = CrashReport(type, value, tb)
            c.show_all()
            Gtk.main()

        Gdk.threads_leave()

        Gtk.main_quit()

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
        create_user_config_dir(
                Path.user_config_dir, Path.config_dir)
    except (IOError, OSError) as e:
        error_dialog = HIGAlertDialog(
                message_format=_(
                    "Error creating the per-user configuration directory"),
                secondary_text=_("""\
There was an error creating the directory %s or one of the files in it. \
The directory is created by copying the contents of %s. \
The specific error was

%s

%s needs to create this directory to store information such as the list of \
scan profiles. Check for access to the directory and try again.""") % (
                    repr(Path.user_config_dir), repr(Path.config_dir),
                    repr(str(e)), APP_DISPLAY_NAME
                    )
                )
        error_dialog.run()
        error_dialog.destroy()
        sys.exit(1)

    try:
        # Read the ~/.zenmap/zenmap.conf configuration file.
        zenmapCore.UmitConf.config_parser.read(Path.user_config_file)
    except configparser.ParsingError as e:
        # ParsingError can leave some values as lists instead of strings. Just
        # blow it all away if we have this problem.
        zenmapCore.UmitConf.config_parser = zenmapCore.UmitConf.config_parser.__class__()
        error_dialog = HIGAlertDialog(
                message_format=_("Error parsing the configuration file"),
                secondary_text=_("""\
There was an error parsing the configuration file %s. \
The specific error was

%s

%s can continue without this file but any information in it will be ignored \
until it is repaired.""") % (Path.user_config_file, str(e), APP_DISPLAY_NAME)
                )
        error_dialog.run()
        error_dialog.destroy()
        global_config_path = os.path.join(Path.config_dir, APP_NAME + '.conf')
        repair_dialog = HIGAlertDialog(
                type=Gtk.MessageType.QUESTION,
                message_format=_("Restore default configuration?"),
                secondary_text=_("""\
To avoid further errors parsing the configuration file %s, \
you can copy the default configuration from %s.

Do this now? \
""") % (Path.user_config_file, global_config_path),
                )
        repair_dialog.add_button(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL)
        repair_dialog.set_default_response(Gtk.ResponseType.CANCEL)
        if repair_dialog.run() == Gtk.ResponseType.OK:
            shutil.copyfile(global_config_path, Path.user_config_file)
            log.debug(">>> Copy %s to %s." % (global_config_path, Path.user_config_file))
        repair_dialog.destroy()

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

    Gtk.main()


class NonRootWarning (HIGAlertDialog):
    def __init__(self):
        warning_text = _('''You are trying to run %s with a non-root user!

Some %s options need root privileges to work.''') % (
            APP_DISPLAY_NAME, NMAP_DISPLAY_NAME)

        HIGAlertDialog.__init__(self, message_format=_('Non-root user'),
                                secondary_text=warning_text)

if __name__ == "__main__":
    run()
