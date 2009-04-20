#!/usr/bin/env python

import distutils.command
import distutils.command.install
import distutils.core
import distutils.cmd
import distutils.errors

class null_command(distutils.cmd.Command):
    """This is a dummy distutils command that does nothing. We use it to replace
    the install_egg_info and avoid installing a .egg-info file, because there's
    no option to disable that."""
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        pass

class checked_install(distutils.command.install.install):
    """This is a wrapper around the install command that checks for an error
    caused by not having the python-dev package installed. By default, distutils
    gives a misleading error message: "invalid Python installation." """
    def finalize_options(self):
        try:
            distutils.command.install.install.finalize_options(self)
        except distutils.errors.DistutilsPlatformError, e:
            raise distutils.errors.DistutilsPlatformError(str(e) + "\n"
                + "Installing your distribution's python-dev package may solve this problem.")

distutils.core.setup(name = u"ndiff", scripts = [u"ndiff"],
    data_files = [(u"share/man/man1", [u"docs/ndiff.1"])],
    cmdclass = {"install_egg_info": null_command, "install": checked_install})
