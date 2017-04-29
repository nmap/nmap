Nmap
===
[![Version](https://img.shields.io/badge/version-7.40SVN-blue.svg)](https:svn.nmap.org)
[![Build Status](https://travis-ci.org/nmap/nmap.svg?branch=master)](https://travis-ci.org/nmap/nmap)
[![License](https://img.shields.io/badge/License-GPL--Modified-orange.svg)](COPYING)

Version
----------
The latest version of Nmap is <b>7.40 SVN</b> which is available as a binary installer for Windows, macOS add Linux(RPM) at https://nmap.org

Getting Started
----------
You can download the [official installer](https://nmap.org/) or proceed to clone the GitHub repo and follow the instructions detailed below

Installing
----------
Ideally, you should be able to just type:

    ./configure
    make
    make install

In case you have an earlier version which you've already configured, `make distclean` and then proceed to `./configure`, `make` and `make install`.

For far more in-depth compilation, installation, and removal notes, read the
[Nmap Install Guide](https://nmap.org/book/install.html) on Nmap.org.

Documentation
----------
Detailed documentation is available
[on the Nmap.org website](https://nmap.org/docs.html) or can be accessed through `man nmap` on compatible systems.

Using Nmap
----------
Nmap has a lot of features, but getting started is as easy as running `nmap
scanme.nmap.org`. Running `nmap` without any parameters  or `nmap -h` will give
a helpful list of the most common options, which are discussed in depth in
[the man page](https://nmap.org/book/man.html).

Nmap also provides a graphical interface Zenmap, which can be downloaded from
[here](https://nmap.org/zenmap/).

Issues and Suggestions
-----------
Any queries, issues or suggestiosn are most welcome and may be sent to
[the Nmap-dev mailing list](https://nmap.org/mailman/listinfo/dev) or opened as an
issue on the issue tracker page [here](https://github.com/nmap/nmap).

Contributing
------------
Information about filing bug reports and contributing to the Nmap project can
be found in the [HACKING](HACKING) and [CONTRIBUTING.md](CONTRIBUTING.md)
files.

License
-----------
Nmap is released under a GPL-style license, the full text of which is available
in [the COPYING file](COPYING).
