#!/usr/bin/env python3

import unittest

if __name__ == "__main__":
    import sys
    import os
    if not hasattr(unittest.defaultTestLoader, "discover"):
        print("Python unittest discovery missing. Requires Python 3.0 or newer.")  # noqa
        sys.exit(1)

    os.chdir("..")
    suite = unittest.defaultTestLoader.discover(
        start_dir=".",
        pattern="*.py"
        )
    result = unittest.TextTestRunner().run(suite)
    sys.exit(not result.wasSuccessful())
