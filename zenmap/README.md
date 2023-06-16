# Zenmap - Multi-platform Graphical Nmap Frontend and Results Viewer

## Abstract

Zenmap is a high-quality, multi-platform graphical frontend and results viewer for Nmap, the popular network scanner. Developed using the Python programming language, Zenmap leverages the GTK Toolkit to deliver a user-friendly interface. Zenmap's initial conception was a derivative of Umit, a Nmap GUI born from the Google Summer of Code initiative.

## Objective

The Zenmap project aims to deliver a Nmap frontend that caters to advanced and beginner users. Zenmap can create and save specific scan profiles for seasoned network administrators, leading to more efficient network scanning. Furthermore, it provides tools for comparing scan results to identify network changes effectively. Zenmap's profile editor simplifies the construction of powerful network scans for beginners.

## Installation

Zenmap's multi-platform compatibility has been verified on a variety of platforms, including:

- Ubuntu
- Red Hat Enterprise Linux
- OpenBSD
- Microsoft Windows
- Apple macOS

Please note that installation instructions may differ slightly based on the platform.

## Default Installation (From Source)

Zenmap is bundled as part of the Nmap package. If Zenmap's dependencies are installed, and Nmap has not been configured with `--without-zenmap`, Zenmap will install alongside Nmap.

Zenmap requires the following software:

- [Python 3.0](https://www.python.org) or higher
- [GTK 3.0](https://www.gtk.org) or higher
- [PyGObject 3.0](https://pygobject.readthedocs.io/en/latest/index.html) or higher
- [Nmap](https://nmap.org) itself and its requirements

Zenmap's source package is crafted to run 'out-of-the-tarball' if all required software is installed. After unpacking the source distribution, Zenmap can be run in one of two ways:

- By double-clicking the Zenmap file.
- By invoking the Python interpreter on the Zenmap file.

Zenmap utilizes Python's distutils for packaging. To install Zenmap independently of Nmap, navigate to the Zenmap subdirectory and execute the following command:

```bash
python setup.py install
```

# References

- [Python 3.0](https://www.python.org)
- [GTK 3.0](https://www.gtk.org)
- [PyGObject 3.0](https://pygobject.readthedocs.io/en/latest/index.html)
- [Nmap](https://nmap.org)
- [Umit: Nmap GUI](https://seclists.org/nmap-dev/2007/q4/35)
