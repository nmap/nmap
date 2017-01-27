# Custom py2exe boot script

# This runs after py2exe's boot_common.py. That file overrides sys.stderr and
# sys.stdout to write to a logfile and a black hole, respectively. The location
# for the stderr logfile is sys.executable + '.log', though, which is not
# usually writable. We'll change it here to write to some other writable path.


import sys
import os
import os.path


#sys.stderr.write("Enter boot_script\n")
# Only do this if py2exe installed its Stderr object
if sys.stderr.__class__.__name__ == "Stderr":
    logdir = os.environ.get("LOCALAPPDATA",
            os.environ.get("APPDATA",
                os.environ.get("TEMP", "")))

    if sys.stderr._file is not None:
        sys.stderr._file.close()
    sys.stderr._file = open(os.path.join(logdir, "zenmap.exe.log"), 'a')


del os
del sys
