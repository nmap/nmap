# Table of Contents
---
   
 * [Introduction](#intro)
 * [Requirements](#requ)
 * [Installation](#install)
 * [Files in this directory](#files)
 * [Zenmap](#zenmap)
 * [Repositories and Troubleshooting](#repo)
 * [The CONTRIBUTING file](#contributing)

## <a name="intro"></a>Introduction

 * **Nmap** is a free and open source utility for network exploration and security auditing. 
 * **Zenmap** is a multi-platform graphical frontend and results viewer for Nmap. 
 * **Ncat** is a general-purpose network sending and receiving utility, a reimplementation of Netcat. 
 * **Ndiff** is a an Nmap scan comparison utility. 
 * **Nping** is a tool for packet generation and sending.

This package contains Nmap, Zenmap, Ncat, Ndiff, and Nping. It is intended to work on Intel Macs running **Mac OS X 10.8 or later**.

Installation of all packages is optional. Unselect Zenmap to get just the command-line tool. Unselect Nmap if you prefer to use a copy of Nmap that is already installed. Zenmap will not work without Nmap.

The nmap, ncat, ndiff, and nping command-line binaries will be installed in `/usr/local/bin`, and additional support files will be installed in `/usr/local/share`. The Zenmap application bundle will be installed in `/Applications/Zenmap.app`.

For a full description of Nmap's installation on Mac OS, visit the page:
[https://nmap.org/book/inst-macosx.html](https://nmap.org/book/inst-macosx.html) 

## <a name="requ"></a>Requirements

In order to compile, build and run Nmap on Mac OS, you will require the following:

1.	**Jhbuild** for bundling and dependencies (see the [BUNDLING file](../BUNDLING.md))
2. **Xcode** for Mac OS 10.8 or later ([https://developer.apple.com/xcode](https://developer.apple.com/xcode/))
3. **Xcode Command-line Tools** for Mac OS 10.8 or later ([https://developer.apple.com/downloads](https://developer.apple.com/downloads/)  then download the latest version compatible with your OS version)

## <a name="install"></a>Installation

Ideally, you should be able to just type:

	./configure
	make
	make install
	
from `nmap/` directory (the root folder).

For far more in-depth compilation, installation, and removal notes, read the **Nmap Install Guide** at [https://nmap.org/book/install.html](https://nmap.org/book/install.html).

## <a name="files"></a>Files in this directory

* [openssl.modules](openssl.modules): This is a Jhbuild moduleset that can be used to build dependencies (openssl) as required for building Nmap, Ncat, and Nping. Use it like this:

	~~~~
	$ jhbuild -m openssl.modules build nmap-deps
	~~~~
	
* [Makefile](Makefile): The Mac OS X Makefile used to build everything specific to this OS.
* [BUNDLING.md](BUNDLING.md): A manual on how to setup and use Jhbuild on Mac OS X.

## <a name="zenmap"></a>Zenmap

The native macOS Zenmap app is built by the Xcode project in the repository root. Its SwiftUI source lives in `zenmap/macos/native/`, while macOS packaging and release helper scripts live in this `macosx/` directory.

Useful release and packaging scripts include:

* [package-zenmap-macos.sh](package-zenmap-macos.sh): Bundles Homebrew OpenSSL and libssh2 dylibs into a built `Zenmap.app`, adjusts library install names, and performs development ad-hoc signing.
* [release-zenmap-macos.sh](release-zenmap-macos.sh): Builds the native `Zenmap` target, packages bundled dylibs, copies the app into `dist/`, and creates a development zip archive.
* [release-nmap-cli-macos.sh](release-nmap-cli-macos.sh): Builds the command-line Nmap tools used by the macOS installer staging flow.
* [stage-nmap-replacement-root-macos.sh](stage-nmap-replacement-root-macos.sh): Stages replacement-root contents for the macOS installer package.
* [pkg-nmap-macos.sh](pkg-nmap-macos.sh): Builds the local macOS installer package from the staged files.

The Xcode build-phase helper scripts remain under `xcode/scripts/` because they are invoked directly by `NmapMac.xcodeproj`.

## <a name="repo"></a>Repositories and Troubleshooting

Nmap uses a read-only repository on **Github** for issues tracking and pull requests. You can contribute at the following address: [https://github.com/nmap/nmap](https://github.com/nmap/nmap).

The read-write repository is managed with **Subversion**. Although, all actual commits are made to our Subversion repository on [https://svn.nmap.org](https://svn.nmap.org/).

In order to be always up to date, you can consult the Changelog here: [https://nmap.org/changelog.html](https://nmap.org/changelog.html).

## <a name="contributing"></a>The CONTRIBUTING file

General information about contributing to Nmap can be found in the [CONTRIBUTING file](../CONTRIBUTING.md). It contains information specifically about Nmap's use of Github and how contributors can use Github services to participate in **Nmap development**.
