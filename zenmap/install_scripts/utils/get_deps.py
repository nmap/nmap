#!/usr/bin/env python3

import modulefinder
import configparser
import sys
import os.path
import site
import encodings

site_package_deps = ("gi", "cairo")

# These items are unneeded, large, and on macOS _ssl causes dependency problems.
pyd_remove = ("_decimal", "_ssl", "_testcapi", "_hashlib")

def module_paths(mods):
    for m in mods:
        if m.__name__ in pyd_remove:
            continue
        elif getattr(m, "__file__", None) and m.__file__.startswith(sys.prefix):
            yield m.__file__

def get_deps():
    # Start with pygobject and zenmap itself
    sitedirs = site.getsitepackages()
    files = set(os.path.join(sitedirs[0], name) for name in site_package_deps)

    # These items are missed by modulefinder
    files.add(encodings.__path__[0]) # All encodings just in case
    for path in module_paths((site, site._sitebuiltins)):
        files.add(path)

    # Now use modulefinder to get the rest
    mfind = modulefinder.ModuleFinder()
    mfind.run_script(os.path.normpath(__file__ + '/../../../zenmapGUI/App.py'))
    for path in module_paths(mfind.modules.values()):
        parent = os.path.dirname(path)
        found_parent = False
        # If a parent dir is already included, don't bother listing the file.
        while parent not in sys.path and len(parent) > 2:
            if parent in files:
                found_parent = True
                break
            parent = os.path.dirname(parent)
        if not found_parent:
            files.add(path)
    return files

def read_cfg(filename):
    cfg = configparser.ConfigParser()
    cfg.read(filename)
    return cfg

def write_cfg(cfg, filename):
    with open(filename, "w") as f:
        cfg.write(f)

def update_cfg(cfg, files):
    filestr = "\nmingw*".join((f.removeprefix(sys.prefix) for f in files))
    oldvalue = cfg.get('bundle', 'nodelete')
    cfg.set('bundle', 'nodelete', oldvalue + "\nmingw*" + filestr)

def write_xml(filename, files):
    with open(filename, "w") as f:
        for file in files:
            fname = r"${prefix}" + file.removeprefix(sys.prefix)
            fmt = "<data>{}</data>"
            if file.endswith(".so"):
                fmt = "<binary>{}</binary>"
            print(fmt.format(fname), file=f)

if __name__ == "__main__":
    files = get_deps()
    if sys.platform == "win32":
        cfg = read_cfg(sys.argv[2])
        update_cfg(cfg, files)
        write_cfg(cfg, sys.argv[1])
    elif sys.platform == "darwin":
        write_xml(sys.argv[1], files)
    else:
        raise NotImplementedError
