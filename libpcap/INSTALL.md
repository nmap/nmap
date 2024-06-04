# libpcap installation notes
Libpcap can be built either with the configure script and `make`, or
with CMake and any build system supported by CMake.

To build libpcap with the configure script and `make`:

* Run `./configure` (a shell script).  The configure script will
determine your system attributes and generate an appropriate `Makefile`
from `Makefile.in`.  The configure script has a number of options to
control the configuration of libpcap; `./configure --help`` will show
them.

* Next, run `make`.  If everything goes well, you can
`su` to root and run `make install`.  However, you need not install
libpcap if you just want to build tcpdump; just make sure the tcpdump
and libpcap directory trees have the same parent directory.

To build libpcap with CMake and the build system of your choice, from
the command line:

* Create a build directory into which CMake will put the build files it
generates; CMake does not work as well with builds done in the source
code directory as does the configure script.  The build directory may be
created as a subdirectory of the source directory or as a directory
outside the source directory.

* Change to the build directory and run CMake with the path from the
build directory to the source directory as an argument.  The `-G` flag
can be used to select the CMake "generator" appropriate for the build
system you're using; various `-D` flags can be used to control the
configuration of libpcap.

* Run the build tool.  If everything goes well, you can `su` to root and
run the build tool with the `install` target.  Building tcpdump from a
libpcap in a build directory is not supported.

An `uninstall` target is supported with both `./configure` and CMake.

***DO NOT*** run the build as root; there is no need to do so, running
anything as root that doesn't need to be run as root increases the risk
of damaging your system, and running the build as root will put files in
the build directory that are owned by root and that probably cannot be
overwritten, removed, or replaced except by root, which could cause
permission errors in subsequent builds.

If configure says:

    configure: warning: cannot determine packet capture interface
    configure: warning: (see INSTALL.md file for more info)

or CMake says:

    cannot determine packet capture interface

    (see the INSTALL.md file for more info)

then your system either does not support packet capture or your system
does support packet capture but libpcap does not support that
particular type. (If you have HP-UX, see below.) If your system uses a
packet capture not supported by libpcap, please send us patches; don't
forget to include an autoconf fragment suitable for use in
`configure.ac`.

It is possible to override the default packet capture type with the
`--with-pcap`` option to `./configure` or the `-DPCAP_TYPE` option to
CMake, although the circumstances where this works are limited.  One
possible reason to do that would be to force a supported packet capture
type in the case where the configure or CMake scripts fails to detect
it.

You will need a C99 compiler to build libpcap. The configure script
will abort if your compiler is not C99 compliant. If this happens, use
the generally available GNU C compiler (GCC) or Clang.

You will need either Flex 2.5.31 or later, or a version of Lex
compatible with it (if any exist), to build libpcap.  The configure
script will abort if there isn't any such program; CMake fails if Flex
or Lex cannot be found, but doesn't ensure that it's compatible with
Flex 2.5.31 or later.  If you have an older version of Flex, or don't
have a compatible version of Lex, the current version of Flex is
available [here](https://github.com/westes/flex).

You will need either Bison, Berkeley YACC, or a version of YACC
compatible with them (if any exist), to build libpcap.  The configure
script will abort if there isn't any such program; CMake fails if Bison
or some form of YACC cannot be found, but doesn't ensure that it's
compatible with Bison or Berkeley YACC.  If you don't have any such
program, the current version of Bison can be found
[here](https://ftp.gnu.org/gnu/bison/) and the current version of
Berkeley YACC can be found [here](https://invisible-island.net/byacc/).

Sometimes the stock C compiler does not interact well with Flex and
Bison. The list of problems includes undefined references for alloca(3).
You can get around this by installing GCC.

## Linux specifics
On Linux, libpcap will not work if the kernel does not have the packet
socket option enabled; see [this file](doc/README.linux) for more
information.

## Solaris specifics
If you use the SPARCompiler, you must be careful to not use the
`/usr/ucb/cc` interface. If you do, you will get bogus warnings and
perhaps errors. Either make sure your path has `/opt/SUNWspro/bin`
before `/usr/ucb` or else:

    setenv CC /opt/SUNWspro/bin/cc

before running configure. (You might have to do a `make distclean`
if you already ran `configure` once).

See [this file](doc/README.solaris.md) for more up to date
Solaris-related information.

## HP-UX specifics
If you use HP-UX, you must have at least version 9 and either the
version of `cc` that supports C99 (`cc -AC99`) or else use the GNU C
compiler. You must also buy the optional streams package. If you don't
have:

    /usr/include/sys/dlpi.h
    /usr/include/sys/dlpi_ext.h

then you don't have the streams package. In addition, we believe you
need to install the "9.X LAN and DLPI drivers cumulative" patch
(PHNE_6855) to make the version 9 DLPI work with libpcap.

The DLPI streams package is standard starting with HP-UX 10.

The HP implementation of DLPI is a little bit eccentric. Unlike
Solaris, you must attach `/dev/dlpi` instead of the specific `/dev/*`
network pseudo device entry in order to capture packets. The PPA is
based on the ifnet "index" number. Under HP-UX 9, it is necessary to
read `/dev/kmem` and the kernel symbol file (`/hp-ux`). Under HP-UX 10,
DLPI can provide information for determining the PPA. It does not seem
to be possible to trace the loopback interface. Unlike other DLPI
implementations, PHYS implies MULTI and SAP and you get an error if you
try to enable more than one promiscuous mode at a time.

It is impossible to capture outbound packets on HP-UX 9.  To do so on
HP-UX 10, you will, apparently, need a late "LAN products cumulative
patch" (at one point, it was claimed that this would be PHNE_18173 for
s700/10.20; at another point, it was claimed that the required patches
were PHNE_20892, PHNE_20725 and PHCO_10947, or newer patches), and to do
so on HP-UX 11 you will, apparently, need the latest lancommon/DLPI
patches and the latest driver patch for the interface(s) in use on HP-UX
11 (at one point, it was claimed that patches PHNE_19766, PHNE_19826,
PHNE_20008, and PHNE_20735 did the trick).

Furthermore, on HP-UX 10, you will need to turn on a kernel switch by
doing

	echo 'lanc_outbound_promisc_flag/W 1' | adb -w /stand/vmunix /dev/mem

You would have to arrange that this happens on reboots; the right way to
do that would probably be to put it into an executable script file
`/sbin/init.d/outbound_promisc` and making
`/sbin/rc2.d/S350outbound_promisc` a symbolic link to that script.

Finally, testing shows that there can't be more than one simultaneous
DLPI user per network interface.

See [this file](doc/README.hpux) for more information specific to HP-UX.

## AIX specifics
See [this file](doc/README.aix) for information on installing libpcap and
configuring your system to be able to support libpcap.

## other specifics
If you are trying to do packet capture with a FORE ATM card, you may or
may not be able to. They usually only release their driver in object
code so unless their driver supports packet capture, there's not much
libpcap can do.

If you get an error like:

    tcpdump: recv_ack: bind error 0x???

when using DLPI, look for the DL_ERROR_ACK error return values, usually
in `/usr/include/sys/dlpi.h`, and find the corresponding value.

## Description of files
	CHANGES		    - description of differences between releases
	ChmodBPF/*	    - macOS startup item to set ownership and permissions on /dev/bpf*
	CMakeLists.txt	    - CMake file
	CONTRIBUTING.md	    - guidelines for contributing
	CREDITS		    - people that have helped libpcap along
	INSTALL.md	    - this file
	LICENSE		    - the license under which tcpdump is distributed
	Makefile.in	    - compilation rules (input to the configure script)
	README.md	    - description of distribution
	doc/README.aix	    - notes on using libpcap on AIX
	doc/README.dag	    - notes on using libpcap to capture on Endace DAG devices
	doc/README.hpux	    - notes on using libpcap on HP-UX
	doc/README.linux    - notes on using libpcap on Linux
	doc/README.macos    - notes on using libpcap on macOS
	doc/README.septel   - notes on using libpcap to capture on Intel/Septel devices
	doc/README.sita	    - notes on using libpcap to capture on SITA devices
	doc/README.solaris.md - notes on using libpcap on Solaris
	doc/README.Win32.md - notes on using libpcap on Win32 systems (with Npcap)
	VERSION		    - version of this release
	aclocal.m4	    - autoconf macros
	arcnet.h	    - ARCNET definitions
	atmuni31.h	    - ATM Q.2931 definitions
	bpf_dump.c	    - BPF program printing routines
	bpf_filter.c	    - BPF filtering routines
	bpf_image.c	    - BPF disassembly routine
	config.guess	    - autoconf support
	config.h.in	    - autoconf input
	config.sub	    - autoconf support
	configure	    - configure script (run this first)
	configure.ac	    - configure script source
	dlpisubs.c	    - DLPI-related functions for pcap-dlpi.c and pcap-libdlpi.c
	dlpisubs.h	    - DLPI-related function declarations
	etherent.c	    - /etc/ethers support routines
	ethertype.h	    - Ethernet protocol types and names definitions
	fad-getad.c	    - pcap_findalldevs() for systems with getifaddrs()
	fad-gifc.c	    - pcap_findalldevs() for systems with only SIOCGIFLIST
	fad-glifc.c	    - pcap_findalldevs() for systems with SIOCGLIFCONF
	testprogs/filtertest.c      - test program for BPF compiler
	testprogs/findalldevstest.c - test program for pcap_findalldevs()
	gencode.c	    - BPF code generation routines
	gencode.h	    - BPF code generation definitions
	grammar.y	    - filter string grammar
	ieee80211.h	    - 802.11 definitions
	install-sh	    - BSD style install script
	lbl/os-*.h	    - OS-dependent defines and prototypes
	llc.h		    - 802.2 LLC SAP definitions
	missing/*	    - replacements for missing library functions
	mkdep		    - construct Makefile dependency list
	msdos/*		    - drivers for MS-DOS capture support
	nametoaddr.c	    - hostname to address routines
	nlpid.h		    - OSI network layer protocol identifier definitions
	optimize.c	    - BPF optimization routines
	pcap/bluetooth.h    - public definition of DLT_BLUETOOTH_HCI_H4_WITH_PHDR header
	pcap/bpf.h	    - BPF definitions
	pcap/namedb.h	    - public libpcap name database definitions
	pcap/pcap.h	    - public libpcap definitions
	pcap/sll.h	    - public definitions of DLT_LINUX_SLL and DLT_LINUX_SLL2 headers
	pcap/usb.h	    - public definition of DLT_USB header
	pcap-bpf.c	    - BSD Packet Filter support
	pcap-bpf.h	    - header for backwards compatibility
	pcap-bt-linux.c	    - Bluetooth capture support for Linux
	pcap-bt-linux.h	    - Bluetooth capture support for Linux
	pcap-dag.c	    - Endace DAG device capture support
	pcap-dag.h	    - Endace DAG device capture support
	pcap-dlpi.c	    - Data Link Provider Interface support
	pcap-dos.c	    - MS-DOS capture support
	pcap-dos.h	    - headers for MS-DOS capture support
	pcap-enet.c	    - enet support
	pcap-int.h	    - internal libpcap definitions
	pcap-libdlpi.c	    - Data Link Provider Interface support for systems with libdlpi
	pcap-linux.c	    - Linux packet socket support
	pcap-namedb.h	    - header for backwards compatibility
	pcap-nit.c	    - SunOS Network Interface Tap support
	pcap-npf.c	    - Npcap capture support
	pcap-null.c	    - dummy monitor support (allows offline use of libpcap)
	pcap-pf.c	    - Ultrix and Digital/Tru64 UNIX Packet Filter support
	pcap-septel.c       - Intel/Septel device capture support
	pcap-septel.h       - Intel/Septel device capture support
	pcap-sita.c	    - SITA device capture support
	pcap-sita.h	    - SITA device capture support
	pcap-sita.html	    - SITA device capture documentation
	pcap-snit.c	    - SunOS 4.x STREAMS-based Network Interface Tap support
	pcap-snoop.c	    - IRIX Snoop network monitoring support
	pcap-usb-linux.c    - USB capture support for Linux
	pcap-usb-linux.h    - USB capture support for Linux
	pcap.3pcap	    - manual entry for the library
	pcap.c		    - pcap utility routines
	pcap.h		    - header for backwards compatibility
	pcap_*.3pcap	    - manual entries for library functions
	pcap-filter.manmisc.in   - manual entry for filter syntax
	pcap-linktype.manmisc.in - manual entry for link-layer header types
	ppp.h		    - Point to Point Protocol definitions
	savefile.c	    - offline support
	scanner.l	    - filter string scanner
	sunatmpos.h	    - definitions for SunATM capturing
