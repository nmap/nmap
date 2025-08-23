# Product Overview

Nmap (Network Mapper) is a free and open-source network discovery and security auditing utility. It's designed to rapidly scan large networks and determine what hosts are available, what services they're offering, what operating systems they're running, what type of packet filters/firewalls are in use, and dozens of other characteristics.

## Key Components

- **Nmap Core**: The main network scanning engine written in C++
- **NSE (Nmap Scripting Engine)**: Lua-based scripting framework for advanced detection and vulnerability assessment
- **Zenmap**: Python-based graphical user interface for Nmap
- **Ncat**: Feature-packed networking utility (netcat replacement)
- **Ndiff**: Utility for comparing Nmap scan results
- **Nping**: Network packet generation tool and ping utility

## License

Nmap is distributed under the Nmap Public Source License (NPSL), which is based on but not compatible with GPLv2. The license allows free usage by end users while restricting commercial redistribution without special permission.

## Target Platforms

- Linux (primary development platform)
- Windows (with Npcap for packet capture)
- macOS
- Various Unix systems (FreeBSD, OpenBSD, NetBSD, Solaris, etc.)