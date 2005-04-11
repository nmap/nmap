/*

snmp95.c: win95-safe versions of IpHlpApi calls
Copyright (C) 2001  Andy Lutomirski

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

These functions are equivalent to the IpHlpApi calls of the same name
except that they work on windows 95.


*/

//	Side note: on GCC, this code is pointless :)

#include "..\tcpip.h"
#include "winip.h"
#include "iphlpapi.h"
#include "MibAccess.h"

#ifdef _MSC_VER
#include "delayimp.h"
#endif

#define MakeAOI(name) {sizeof(name) / sizeof(UINT), name}


//	This is ridiculous...
#undef errno	//	safe for now
#undef read		//	for GCC
#include <memory>

#define DLI_ERROR VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)

#ifndef _MSC_VER
//	sigh
#define min(x, y) ( (x) < (y) ? (x) : (y) )
#endif


//	MIB descriptors

//	ifTable
UINT OID_ifNumber[] = {1, 3, 6, 1, 2, 1, 2, 1, 0};	//	includes instance
UINT OID_ifIndex[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 1};
UINT OID_ifType[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 3};
UINT OID_ifPhysAddress[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 6};
UINT OID_ifOperStatus[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 8};

AsnObjectIdentifier AOI_ifNumber = MakeAOI(OID_ifNumber);

AsnObjectIdentifier ifTable[] =
{
	MakeAOI(OID_ifIndex),		// 0
	MakeAOI(OID_ifType),		// 1
	MakeAOI(OID_ifPhysAddress),	// 2
	MakeAOI(OID_ifOperStatus)	// 3
};

//	ipAddrTable
UINT OID_ipAdEntAddr[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 1};
UINT OID_ipAdEntIfIndex[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 2};
UINT OID_ipAdEntNetMask[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 3};
UINT OID_ipAdEntBcastAddr[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 4};
UINT OID_ipAdEntReasmMaxSize[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 5};

AsnObjectIdentifier ipAddrTable[] =
{
	MakeAOI(OID_ipAdEntAddr),			// 0
	MakeAOI(OID_ipAdEntIfIndex),		// 1
	MakeAOI(OID_ipAdEntNetMask),		// 2
	MakeAOI(OID_ipAdEntBcastAddr),		// 3 (int)
	MakeAOI(OID_ipAdEntReasmMaxSize)	// 4
};

//	ipRouteTable
UINT OID_ipRouteDest[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 1};
UINT OID_ipRouteIfIndex[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 2};
UINT OID_ipRouteMetric1[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 3};
UINT OID_ipRouteNextHop[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 7};
UINT OID_ipRouteType[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 8};
UINT OID_ipRouteMask[] = {1, 3, 6, 1, 2, 1, 4, 21, 1, 11};

AsnObjectIdentifier ipRouteTable[] =
{
	MakeAOI(OID_ipRouteDest),		// 0
	MakeAOI(OID_ipRouteIfIndex),	// 1
	MakeAOI(OID_ipRouteMetric1),	// 2
	MakeAOI(OID_ipRouteNextHop),	// 3
	MakeAOI(OID_ipRouteType),		// 4
	MakeAOI(OID_ipRouteMask)		// 5
};

//	ipNetTable
UINT OID_ipNetToMediaIfIndex[] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 1};
UINT OID_ipNetToMediaPhysAddress[] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 2};
UINT OID_ipNetToMediaNetAddress[] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 3};
UINT OID_ipNetToMediaType[] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 4};

AsnObjectIdentifier ipNetToMediaTable[] =
{
	MakeAOI(OID_ipNetToMediaIfIndex),		// 0
	MakeAOI(OID_ipNetToMediaPhysAddress),	// 1
	MakeAOI(OID_ipNetToMediaNetAddress),	// 2
	MakeAOI(OID_ipNetToMediaType)			// 3
};

static std::auto_ptr<MibII> m;

static bool populated = false;

static PMIB_IPADDRTABLE pAddrtable = 0;
static DWORD szAddrtable = 0;

static PMIB_IPFORWARDTABLE pRoutetable = 0;
static DWORD szRoutetable = 0;

int iphlp_avail = 1;	//	Is the iphlpapi dll present?
int net_avail = 1;	//	Is some method of access present?

static int __cdecl compip(const void *e1, const void *e2)
{
	return ((const MIB_IPADDRROW*)(e1))->dwAddr - ((const MIB_IPADDRROW*)(e2))->dwAddr;
}

static bool Populate()
{
#if defined(_MSC_VER) || defined(__MINGW32__)
	if(populated) return szAddrtable != 0;
	populated = true;

	if(wo.trace) printf("***WinIP***  initializing inetmib1 tables...");

	//	Allocate
	m = std::auto_ptr<MibII>(new MibII);
	MIBTraverser::m = m.get();

	m->Init();
	if(!m->GetDLLStatus())
	{
		if(wo.trace) printf("\n***WinIP***  no inetmib1.dll\n");
		net_avail = 0;
		return false;
	}

	MIBTraverser mt;

	//	Populate the address table
	mt.Init(ipAddrTable, sizeof(ipAddrTable) / sizeof(ipAddrTable[0]));

	szAddrtable = sizeof(UINT) + 10 * sizeof(MIB_IPADDRROW);
	pAddrtable = (PMIB_IPADDRTABLE)malloc(szAddrtable);
	pAddrtable->dwNumEntries = 0;

	while(mt.Next())
	{
		if(sizeof(UINT) + (pAddrtable->dwNumEntries + 1) * sizeof(MIB_IPADDRROW)
			> szAddrtable)
		{
			szAddrtable += 10 * sizeof(MIB_IPADDRROW);
			pAddrtable = (PMIB_IPADDRTABLE)realloc(pAddrtable, szAddrtable);
		}

		MIB_IPADDRROW *r = pAddrtable->table + pAddrtable->dwNumEntries;
		pAddrtable->dwNumEntries++;
		ZeroMemory(r, sizeof(MIB_IPADDRROW));
		r->dwAddr = ASN_IP(mt[0].value.asnValue);
		r->dwIndex = mt[1].value.asnValue.unsigned32;
		r->dwMask = ASN_IP(mt[2].value.asnValue);
		r->dwBCastAddr = (r->dwAddr & r->dwMask)
			| ( (mt[3].value.asnValue.unsigned32 & 1) * ~r->dwMask );
		r->dwReasmSize = mt[4].value.asnValue.unsigned32;
	}

	szAddrtable = sizeof(UINT) * pAddrtable->dwNumEntries * sizeof(MIB_IPADDRROW);

	//	Populate the route table
	mt.Init(ipRouteTable, sizeof(ipRouteTable) / sizeof(ipRouteTable[0]));

	szRoutetable = sizeof(UINT) + 10 * sizeof(MIB_IPFORWARDROW);
	pRoutetable = (PMIB_IPFORWARDTABLE)malloc(szRoutetable);
	pRoutetable->dwNumEntries = 0;

	while(mt.Next())
	{
		if(sizeof(UINT) + (pRoutetable->dwNumEntries + 1) * sizeof(MIB_IPFORWARDROW)
			> szRoutetable)
		{
			szRoutetable += 10 * sizeof(MIB_IPFORWARDROW);
			pRoutetable = (PMIB_IPFORWARDTABLE)realloc(pRoutetable, szRoutetable);
		}

		MIB_IPFORWARDROW *r = pRoutetable->table + pRoutetable->dwNumEntries;
		pRoutetable->dwNumEntries++;
		ZeroMemory(r, sizeof(MIB_IPFORWARDROW));
		r->dwForwardIfIndex = mt[1].value.asnValue.unsigned32;
		r->dwForwardDest = ASN_IP(mt[0].value.asnValue);
		r->dwForwardMetric1 = mt[2].value.asnValue.unsigned32;
		r->dwForwardNextHop = ASN_IP(mt[3].value.asnValue);
		r->dwForwardType = mt[4].value.asnValue.unsigned32;
		r->dwForwardMask = ASN_IP(mt[5].value.asnValue);
	}

	szRoutetable = sizeof(UINT) * pRoutetable->dwNumEntries * sizeof(MIB_IPFORWARDROW);

	if(wo.trace) printf(" Done\n");

	return true;
#else
	return false;	//	won't get here anyway
#endif
}

//	we can ignore the sort option because the table is pre-sorted
extern "C" DWORD GetIfTableSafe(PMIB_IFTABLE pOut, DWORD* size, BOOL bSort)
{
	if(wo.noiphlpapi) iphlp_avail = 0;

	if(iphlp_avail)
	{
#ifdef _MSC_VER
		__try {
#endif
			return GetIfTable(pOut, size, bSort);
#ifdef _MSC_VER
		}
		__except(GetExceptionCode() == DLI_ERROR)
		{
			iphlp_avail = 0;
		}
#endif
	}

	if(!Populate()) return -1;

	MIBTraverser mt;

	//	Initialize for single-object read
	mt.Init(&AOI_ifNumber, 1);

	if(!mt.Get())
		return 0xFFFFFFFF;

	UINT numnic = mt[0].value.asnValue.unsigned32;
	DWORD sz = sizeof(UINT) + numnic * sizeof(MIB_IFROW);

	if(!pOut)
	{
		*size = sz;
		return 0;
	}
	else
	{
		if(*size < sz)
		{
			*size = sz;
			return ERROR_INSUFFICIENT_BUFFER;
		}

		//	Populate the table
		mt.Init(ifTable, sizeof(ifTable) / sizeof(ifTable[0]));
		pOut->dwNumEntries = 0;
		while(mt.Next())
		{
			MIB_IFROW *r = &pOut->table[pOut->dwNumEntries];
			pOut->dwNumEntries++;

			ZeroMemory(r, sizeof(MIB_IFROW));
			r->dwIndex = mt[0].value.asnValue.unsigned32;
			r->dwType = mt[1].value.asnValue.unsigned32;
			r->dwPhysAddrLen = min(MAXLEN_PHYSADDR,
				mt[2].value.asnValue.string.length);
			memcpy(r->bPhysAddr, mt[2].value.asnValue.string.stream,
				r->dwPhysAddrLen);
			r->dwOperStatus = mt[3].value.asnValue.unsigned32;
		}

		return 0;
	}
}


extern "C" DWORD GetIpAddrTableSafe(PMIB_IPADDRTABLE pOut, DWORD* size, BOOL bSort)
{
	if(wo.noiphlpapi) iphlp_avail = 0;

	if(iphlp_avail)
	{
#ifdef _MSC_VER
		__try {
#endif
			return GetIpAddrTable(pOut, size, bSort);
#ifdef _MSC_VER
		}
		__except(GetExceptionCode() == DLI_ERROR)
		{
			iphlp_avail = 0;
		}
#endif
	}

	if(!Populate()) return 0xFFFFFFFF;

	if(!pOut)
	{
		*size = szAddrtable;
		return 0;
	}
	else
	{
		if(*size < szAddrtable)
		{
			*size = szAddrtable;
			return ERROR_INSUFFICIENT_BUFFER;
		}

		memcpy(pOut, pAddrtable, szAddrtable);
		return 0;
	}
}


extern "C" DWORD GetIpNetTableSafe(PMIB_IPNETTABLE pOut, DWORD* size, BOOL bSort)
{
	if(wo.noiphlpapi) iphlp_avail = 0;

	if(iphlp_avail)
	{
#ifdef _MSC_VER
		__try {
#endif
			return GetIpNetTable(pOut, size, bSort);
#ifdef _MSC_VER
		}
		__except(GetExceptionCode() == DLI_ERROR)
		{
			iphlp_avail = 0;
		}
#endif
	}

	if(!Populate()) return -1;

	int sz = sizeof(UINT);	//	Space used so far

	DWORD temp;
	if(*size < 4) pOut = (PMIB_IPNETTABLE)&temp;
	pOut->dwNumEntries = 0;

	//	Initialize the traverser
	MIBTraverser mt;
	mt.Init(ipNetToMediaTable,
		sizeof(ipNetToMediaTable) / sizeof(ipNetToMediaTable[0]));

	//	Begin the traversal
	while(mt.Next())
	{
		sz += sizeof(MIB_IPNETROW);
		if(sz <= *size)
		{
			//	Fill in the row
			MIB_IPNETROW *r = pOut->table + pOut->dwNumEntries;
			pOut->dwNumEntries++;
			r->dwIndex = mt[0].value.asnValue.unsigned32;
			r->dwPhysAddrLen = mt[1].value.asnValue.string.length;
			memcpy(r->bPhysAddr, mt[1].value.asnValue.string.stream,
				r->dwPhysAddrLen);
			r->dwAddr = ASN_IP(mt[2].value.asnValue);
			r->dwType = mt[3].value.asnValue.unsigned32;
		}
	}

	if(sz > *size)
	{
		*size = sz;
		return ERROR_INSUFFICIENT_BUFFER;
	}
	else return 0;
}

extern "C" DWORD GetIpForwardTableSafe(PMIB_IPFORWARDTABLE pOut, DWORD* size, BOOL bSort)
{
	if(wo.noiphlpapi) iphlp_avail = 0;

	if(iphlp_avail)
	{
#ifdef _MSC_VER
		__try {
#endif
			return GetIpForwardTable(pOut, size, bSort);
#ifdef _MSC_VER
		}
		__except(GetExceptionCode() == DLI_ERROR)
		{
			iphlp_avail = 0;
		}
#endif
	}

	if(!Populate()) return -1;

	if(!pOut)
	{
		*size = szRoutetable;
		return 0;
	}
	else
	{
		if(*size < szRoutetable)
		{
			*size = szRoutetable;
			return ERROR_INSUFFICIENT_BUFFER;
		}

		memcpy(pOut, pRoutetable, szRoutetable);
		return 0;
	}
}
