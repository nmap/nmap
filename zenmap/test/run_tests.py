#!/usr/bin/env python3

import unittest

if __name__ == "__main__":
    import sys
    import glob
    import os
    if not hasattr(unittest.defaultTestLoader, "discover"):
        print("Python unittest discovery missing. Requires Python 3.0 or newer.")  # noqa
        sys.exit(0)

    os.chdir("..")
    suite = unittest.defaultTestLoader.discover(
        start_dir=glob.glob("build/lib*")[0],
        pattern="*.py"
        )
    unittest.TextTestRunner().run(suite)
