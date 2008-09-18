#!/usr/bin/env python

from distutils.core import setup
from distutils.cmd import Command

class null_command(Command):
    """This is a dummy distutils command that does nothing. We use it to replace
    the install_egg_info and avoid installing a .egg-info file, because there's
    no option to disable that."""
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        pass

setup(name = u"ndiff", scripts = [u"ndiff"],
      data_files = [(u"share/man/man1", [u"docs/ndiff.1"])],
      cmdclass = {"install_egg_info": null_command})
