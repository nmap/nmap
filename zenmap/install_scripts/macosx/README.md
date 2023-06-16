## Directory Description

This directory contains various files related to packaging on Mac OS X. These files are primarily intended for individuals interested in building binary distributions of Zenmap for Mac OS X. Below is a brief description of each file:

- **Info.plist**: A properties list file template that is populated by the `make-bundle.sh` script.

- **make-bundle.sh**: This script is responsible for building a `.app` bundle. It should be executed from the root of the Zenmap source tree. The resulting bundle is placed in the `dist/Zenmap.app` directory.

- **zenmap.icns**: An icon file specifically designed for the bundle. It was created using the "Icon Composer" utility, accessible via `open -a "Icon Composer"`.

- **zenmap_auth.c**: A simple wrapper program that attempts to execute `launcher.sh` with elevated privileges.

- **launcher.sh**: A launcher script that sets up the environment for Zenmap, Python, and GTK before launching the main Zenmap script file.

- **zenmap.bundle**: An XML configuration file used by `gtk-mac-bundler`. It specifies the necessary files and metadata for the application bundle. Additional information can be found at: [GTK+ OSX Building](https://wiki.gnome.org/Projects/GTK%2B/OSX/Building)

Please note that these files are specifically relevant to the process of creating binary distributions of Zenmap for macOS and may not be directly applicable for other purposes.
