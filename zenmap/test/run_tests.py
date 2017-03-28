#!/usr/bin/env python

import unittest

if __name__ == "__main__":
    import sys
    import glob
    import os
    if not hasattr(unittest.defaultTestLoader, "discover"):
        print("Python unittest discovery missing. Requires Python 2.7 or newer.")  # noqa
        sys.exit(0)

    test_dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(os.path.join(test_dir, os.pardir))
    suite = unittest.defaultTestLoader.discover(
        start_dir=glob.glob("build/lib*")[0],
        pattern="*.py"
        )
    unittest.TextTestRunner().run(suite)
