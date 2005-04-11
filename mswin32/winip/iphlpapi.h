/*

iphlpapi.h: declares the subset of iphlpapi needed to compile
Copyright (C) 2000  Andy Lutomirski

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License, version 2.1, as published by the Free Software
Foundation, with the exception that if this copy of the library
is distributed under the Lesser GNU Public License (as opposed
to the ordinary GPL), you may ignore section 6b, and that all
copies distributed without exercising section 3 must retain this
paragraph in its entirety.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#ifndef __IPHLPAPI_H__
#ifndef __IPHLPAPI_FAKE_H__
#define __IPHLPAPI_FAKE_H__

#include <windows.h>
#include <iprtrmib.h>
#include <ipexport.h>
#include <iptypes.h>

#ifdef __cplusplus
extern "C" {
#endif

DWORD __declspec(dllimport) __stdcall GetIfTable(PMIB_IFTABLE, DWORD*, BOOL);
DWORD __declspec(dllimport) __stdcall GetIpAddrTable(PMIB_IPADDRTABLE, DWORD*, BOOL);
DWORD __declspec(dllimport) __stdcall GetIpNetTable(PMIB_IPNETTABLE, DWORD*, BOOL);
DWORD __declspec(dllimport) __stdcall GetIpForwardTable(PMIB_IPFORWARDTABLE, DWORD*, BOOL);
DWORD __declspec(dllimport) __stdcall GetIfEntry(PMIB_IFROW);
DWORD __declspec(dllimport) __stdcall SendARP( int, int, PULONG, PULONG );

#ifdef __cplusplus
}
#endif

#endif
#endif
