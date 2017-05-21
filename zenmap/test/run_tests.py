#!/usr/bin/env python

from __future__ import print_function
import unittest
import gtk

if __name__ == "__main__":
    import sys
    import glob
    import os
    if not hasattr(unittest.defaultTestLoader, "discover"):
        print("Python unittest discovery missing. Requires Python 2.7 or newer.")  # noqa
        sys.exit(0)

    os.chdir("../build/lib")
    suite = unittest.defaultTestLoader.discover(
        start_dir=glob.glob("*")[0],
        pattern="*.py"
        )
    unittest.TextTestRunner().run(suite)
