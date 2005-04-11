/************************************************************************/
/*      Copyright (C) Stas Khirman 1998.  All rights reserved.          */
/*      Written by Stas Khirman (staskh@rocketmail.com).                */
/*					  and											    */
/*                 Raz Galili (razgalili@hotmail.com)				    */
/*                                                                      */
/*      Free software: no warranty; use anywhere is ok; spread the      */
/*      sources; note any modifications; share variations and           */
/*      derivatives (including sending to staskh@rocketmail.com).       */
/*                                                                      */
/************************************************************************/

//	Modified by Andy Lutomirski (AMLuto@hotmail.com) on Sept 8, 2001
//	Changes: added the MIBACCESS_SIMPLE flag to turn it
//	into a simple wrapper

//	Also added the MIBTraverser class


//	This file is _not_ LGPL -- see above license


#include "..\tcpip.h"
#include "winip.h"
#include <winsock2.h>
#include "MibAccess.h"

MibII *MIBTraverser::m = 0;


/*
o http://members.tripod.com/~staskh to find example code for reading your Windows PC's MIB.
o http://www.cyberport.com/~tangent/programming/winsock/examples/getmac-snmp.html for example code.
o Read the following keys for more information:

1.3.6.1.2.1.2.1			- # of NIC Entries
1.3.6.1.2.1.4.20.1.1	- IP Address (one per address)
1.3.6.1.2.1.4.20.1.2	- Interface Index (one per interface, cross references to Interface Entry Number)
1.3.6.1.2.1.4.20.1.3	- Subnet Mask (one per address)
1.3.6.1.2.1.2.2.1.1		- Interface Entry Number (one per interface)
1.3.6.1.2.1.2.2.1.2		- Description (one per interface)
1.3.6.1.2.1.2.2.1.3		- Type (one per interface, 6 = Ethernet or DUN, 24 = Loopback)
1.3.6.1.2.1.2.2.1.6		- MAC Address (one per interface, also use to rule out DUNs)
1.3.6.1.2.1.4.21.1		- IP routing table (I assume that this holds the gateway information, but have not needed it and therefore
						  have not looked at it with more detail).

For a complete description of the MIB, see RFCs 1155 (SMI), 1156 (MIB), 1157 (SNMP), and 1213 (MIB-II). After reviewing RFC 1155 (SMI)
and RFC 1156 (MIB) briefly, I use RFC 1213 (MIB-II) almost exclusively.
*/


MibExtLoad::MibExtLoad(LPSTR MibDllName)
{
	m_Init = NULL;	
	m_InitEx = NULL;
	m_Query = NULL;	
	m_Trap = NULL;
	
	m_hInst = LoadLibrary(MibDllName);
	if (m_hInst < (HINSTANCE) HINSTANCE_ERROR)
	{
		m_hInst = NULL;
		return;
	}		

	m_Init	 = (pSnmpExtensionInit) GetProcAddress(m_hInst ,"SnmpExtensionInit");
	m_InitEx = (pSnmpExtensionInitEx) GetProcAddress(m_hInst ,"SnmpExtensionInitEx");
	m_Query	 = (pSnmpExtensionQuery) GetProcAddress(m_hInst ,"SnmpExtensionQuery");
	m_Trap	 = (pSnmpExtensionTrap) GetProcAddress(m_hInst ,"SnmpExtensionTrap");
}


MibExtLoad::~MibExtLoad()
{
	if (m_hInst)
		FreeLibrary(m_hInst);

	m_hInst = NULL;
}


BOOL MibExtLoad::Init(DWORD dwTimeZeroReference, HANDLE *hPollForTrapEvent,
					  AsnObjectIdentifier *supportedView)
{
	if (m_hInst && m_Init)
		return m_Init(dwTimeZeroReference, hPollForTrapEvent, supportedView);

	return FALSE;
}


BOOL MibExtLoad::InitEx(AsnObjectIdentifier *supportedView)
{
	if (m_hInst && m_InitEx)
		return m_InitEx(supportedView);
	
	return FALSE;
}


BOOL MibExtLoad::Query(BYTE requestType, OUT RFC1157VarBindList *variableBindings, 
					   AsnInteger *errorStatus, AsnInteger *errorIndex)
{
	if (m_hInst && m_Query)
		return m_Query(requestType, variableBindings, errorStatus, errorIndex);
	
	return FALSE;
}


BOOL MibExtLoad::Trap(AsnObjectIdentifier *enterprise, AsnInteger *genericTrap,
					  AsnInteger *specificTrap, AsnTimeticks *timeStamp, 
					  RFC1157VarBindList  *variableBindings)
{
	if (m_hInst && m_Trap)
		return m_Trap(enterprise, genericTrap, specificTrap, timeStamp, variableBindings);
	
	return FALSE;
}


BOOL MibExtLoad::GetDLLStatus()
{
	if (m_hInst == NULL)
		return FALSE;
	else
		return TRUE;
}


MibII::MibII() : MibExtLoad("inetmib1.dll")
#ifndef MIBACCESS_SIMPLE
 ,m_pNICInfo(0), m_ifIndex(0), m_ifEntryNum(0)
#endif
{
#ifndef MIBACCESS_SIMPLE
	WSADATA		wsa;

	m_rvWSA = WSAStartup(MAKEWORD(1, 1), &wsa);
#endif
}


MibII::~MibII()
{
#ifndef MIBACCESS_SIMPLE
	WSACleanup();

	if (m_ifCount > 0)
	{
		delete m_pNICInfo;
		delete m_ifIndex;
		delete m_ifEntryNum;
	}
#endif
}


int MibII::Init()
{
// If there was an error when accessing INETMIB1.DLL ...
	if (!GetDLLStatus())
		return ERROR_MIB_DLL;

// If there was an error when starting Winsock ...
#ifndef MIBACCESS_SIMPLE
	if (m_rvWSA)
		return ERROR_MIB_WINSOCK;
#endif

	HANDLE PollForTrapEvent;
	AsnObjectIdentifier SupportedView;

	if (!MibExtLoad::Init(GetTickCount(), &PollForTrapEvent, &SupportedView))
		return ERROR_MIB_INIT;

	return 0;
}

#ifndef MIBACCESS_SIMPLE
UINT MibII::GetNICCount(BOOL bDialup, BOOL bLoopback)
{
#define			NUM_VARBIND_LIST			7

// SNMP interface for # of NIC Entries.
	UINT				OID_ifNumEntries[] = {1, 3, 6, 1, 2, 1, 2, 1};
	AsnObjectIdentifier MIB_ifNumEntries = {sizeof(OID_ifNumEntries) / sizeof(UINT), OID_ifNumEntries};

// SNMP interface for Entry Type.
	UINT				OID_ifEntryType[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 3};
	AsnObjectIdentifier MIB_ifEntryType = {sizeof(OID_ifEntryType) / sizeof(UINT), OID_ifEntryType};

// SNMP interface for MAC Address.
	UINT				OID_ifMAC[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 6};
	AsnObjectIdentifier MIB_ifMAC = {sizeof(OID_ifMAC) / sizeof(UINT), OID_ifMAC};

// SNMP interface for IP Address.
	UINT				OID_ifIPAddr[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 1};
	AsnObjectIdentifier MIB_ifIPAddr = {sizeof(OID_ifIPAddr) / sizeof(UINT), OID_ifIPAddr};

// SNMP interface for Subnet Mask.
	UINT				OID_ifSubnetMask[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 3};
	AsnObjectIdentifier MIB_ifSubnetMask = {sizeof(OID_ifSubnetMask) / sizeof(UINT), OID_ifSubnetMask};
	
// SNMP interface for Description.
	UINT				OID_ifDesc[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 2};
	AsnObjectIdentifier MIB_ifDesc = {sizeof(OID_ifDesc) / sizeof(UINT), OID_ifDesc};
	
// SNMP interface for Interface Index
	UINT				OID_ifIndex[] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 2};
	AsnObjectIdentifier MIB_ifIndex = {sizeof(OID_ifIndex) / sizeof(UINT), OID_ifIndex};

// SNMP interface for IP Routing Table
	UINT				OID_ifIPRouteTable[] = {1, 3, 6, 1, 2, 1, 4, 21, 1};
	AsnObjectIdentifier MIB_ifIPRouteTable = {sizeof(OID_ifIPRouteTable) / sizeof(UINT), OID_ifIPRouteTable};

// SNMP interface for Interface Entry Number
	UINT				OID_ifEntryNum[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 1};
	AsnObjectIdentifier MIB_ifEntryNum = {sizeof(OID_ifEntryNum) / sizeof(UINT), OID_ifEntryNum};

	RFC1157VarBindList	varBindList;
	RFC1157VarBind		varBind[NUM_VARBIND_LIST];
	AsnInteger			errorStatus;
	AsnInteger			errorIndex;
	AsnObjectIdentifier MIB_NULL = {0, 0};
	int					ret;
	UINT				NICCount = 0, ifIndex = 0, i;

	// Initialize the variable list to be retrieved by Query
	varBindList.list = varBind;
//	varBind[0].name = MIB_NULL;

// If the user wants to get the # of NICs in the system, then use only Num Entries.
	// Copy in the OID to find the # of entries in the Interface table
	varBindList.len = 1;
	SNMP_oidcpy(&varBind[0].name, &MIB_ifNumEntries);
	ret = Query(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex);
	m_ifCount = varBind[0].value.asnValue.number;
	if (m_ifCount > 0)
	{
		m_pNICInfo = new tSTRUCTNICINFO [m_ifCount];
		m_ifIndex = new DWORD [m_ifCount];
		m_ifEntryNum = new DWORD [m_ifCount];
		m_bDialup = bDialup;
		m_bLoopback = bLoopback;
	}
	else
		return 0;

	// Copy in the OID for the type of interface
	SNMP_oidcpy(&varBind[0].name, &MIB_ifEntryType);

	// Copy in the OID for MAC Address
	SNMP_oidcpy(&varBind[1].name, &MIB_ifMAC);

	// If the user wants to get the # of NICs in the system, then use only Entry Type and MAC Address,
	// otherwise also retrieve IP Address, Subnet Mask, Description, Interface Index, and Interface Entry Number.
	varBindList.len = NUM_VARBIND_LIST;

	// Copy in the OID for IP Address
	SNMP_oidcpy(&varBind[2].name, &MIB_ifIPAddr);

	// Copy in the OID for Subnet Mask
	SNMP_oidcpy(&varBind[3].name, &MIB_ifSubnetMask);

	// Copy in the OID for Description
	SNMP_oidcpy(&varBind[4].name, &MIB_ifDesc);

	// Copy in the OID for Interface Index
	SNMP_oidcpy(&varBind[5].name, &MIB_ifIndex);

	// Copy in the OID for Interface Entry Number
	SNMP_oidcpy(&varBind[6].name, &MIB_ifEntryNum);

	memset(m_pNICInfo, 0, sizeof(tSTRUCTNICINFO) * m_ifCount);

	do
	{
		// Submit the query.  Responses will be loaded into varBindList.  We can expect this call to
		// succeed a # of times corresponding to the # of adapters reported to be in the system.
		ret = Query(ASN_RFC1157_GETNEXTREQUEST, &varBindList, &errorStatus, &errorIndex); 
		if (!ret)
			ret = 1;
		else
            // Confirm that the proper type has been returned
			ret = SNMP_oidncmp(&varBind[0].name, &MIB_ifEntryType, MIB_ifEntryType.idLength);
		
		if (!ret)
		{
			// Confirm that we have an address here
			ret = SNMP_oidncmp(&varBind[1].name, &MIB_ifMAC, MIB_ifMAC.idLength);
			if (!ret)
			{
				NICCount++;

				// Ignore Loopback devices
				if ((varBind[1].value.asnValue.address.length == 0 && !m_bLoopback) ||
				// Ignore Dial-Up Networking adapters
					(varBind[1].value.asnValue.address.length > 0 &&
					 varBind[1].value.asnValue.address.stream[0] == 0x44 &&
					 varBind[1].value.asnValue.address.stream[1] == 0x45 &&
					 varBind[1].value.asnValue.address.stream[2] == 0x53 &&
					 varBind[1].value.asnValue.address.stream[3] == 0x54 && !m_bDialup) ||
				// Ignore NULL addresses returned by other network interfaces
					(varBind[1].value.asnValue.address.length > 0 &&
					 varBind[1].value.asnValue.address.stream[0] == 0x00 &&
					 varBind[1].value.asnValue.address.stream[1] == 0x00 &&
					 varBind[1].value.asnValue.address.stream[2] == 0x00 &&
					 varBind[1].value.asnValue.address.stream[3] == 0x00 &&
					 varBind[1].value.asnValue.address.stream[4] == 0x00 &&
					 varBind[1].value.asnValue.address.stream[5] == 0x00))
					NICCount--;

				// Store Interface Index and Entry Numbers so we can match up the data later.
				m_ifIndex[ifIndex] = varBind[5].value.asnValue.number;
				m_ifEntryNum[ifIndex] = varBind[6].value.asnValue.number;

				// Store data and increment counter.
				m_pNICInfo[ifIndex].type = varBind[0].value.asnValue.number;
				m_pNICInfo[ifIndex].MACLength = varBind[1].value.asnValue.address.length;
				for (i = 0; i < varBind[1].value.asnValue.address.length; i++)
					m_pNICInfo[ifIndex].MAC[i] = varBind[1].value.asnValue.address.stream[i];

				if (!SNMP_oidncmp(&varBind[2].name, &MIB_ifIPAddr, MIB_ifIPAddr.idLength))
				{					
					for (i = 0; i < 4; i++)
						m_pNICInfo[ifIndex].IP[i] = varBind[2].value.asnValue.address.stream[i];
				}

				if (!SNMP_oidncmp(&varBind[3].name, &MIB_ifSubnetMask, MIB_ifSubnetMask.idLength))
				{				
					for (i = 0; i < 4; i++)
						m_pNICInfo[ifIndex].SubnetMask[i] = varBind[3].value.asnValue.address.stream[i];
				}
				
				// Leave the last byte as a NULL terminator
				i = sizeof(m_pNICInfo[ifIndex].Description) - 1;
				if (varBind[4].value.asnValue.address.length < i)
					i = varBind[4].value.asnValue.address.length;
				memcpy(m_pNICInfo[ifIndex].Description, varBind[4].value.asnValue.address.stream, i);
				ifIndex++;
			}
		}
	} 
	while (!ret);
	// Stop only on an error.  An error will occur when the list of interfaces is exhausted.

	// Free the bindings
	for (i = 0; i < varBindList.len; i++)
		SNMP_FreeVarBind(&varBind[i]);

	return NICCount;
}

/*
Because IP Address, Interface Index, and Subnet Mask are in the same OID (4.20.1.x), and Interface Entry Number, Description,
Type, and MAC Address are in another OID (2.2.1.x), you have to cross reference the Interface Index with the Interface Entry
Number.  All IP Address and Subnet Mask values belong together, but you have to find the matching Interface Entry Number to get
the corresponding Description, Type, and MAC Address.
*/
void MibII::GetNICInfo(tSTRUCTNICINFO *pNICInfo)
{
	tSTRUCTNICINFO		tempStruct;
	UINT				i, j, k, validNICIndex = 0;

	for (i = 0; i < m_ifCount; i++)
	{
		memcpy(tempStruct.IP, m_pNICInfo[i].IP, sizeof(tempStruct.IP));
		memcpy(tempStruct.SubnetMask, m_pNICInfo[i].SubnetMask, sizeof(tempStruct.SubnetMask));
		// Find the Interface Entry Number that matches the Interface Index.
		for (j = 0; j < m_ifCount; j++)
		{
			if (m_ifIndex[i] == m_ifEntryNum[j])
				break;
		}
		tempStruct.type = m_pNICInfo[j].type;
		memcpy(tempStruct.Description, m_pNICInfo[j].Description, sizeof(tempStruct.Description));
		tempStruct.MACLength = m_pNICInfo[j].MACLength;
		memcpy(tempStruct.MAC, m_pNICInfo[j].MAC, tempStruct.MACLength);

		// Ignore Loopback devices
		if ((tempStruct.MACLength == 0 && !m_bLoopback) ||
		// Ignore Dial-Up Networking adapters
			(tempStruct.MAC[0] == 0x44 &&
			 tempStruct.MAC[1] == 0x45 &&
			 tempStruct.MAC[2] == 0x53 &&
			 tempStruct.MAC[3] == 0x54 && !m_bDialup) ||
		// Ignore NULL addresses returned by other network interfaces
			(tempStruct.MAC[0] == 0x00 &&
			 tempStruct.MAC[1] == 0x00 &&
			 tempStruct.MAC[2] == 0x00 &&
			 tempStruct.MAC[3] == 0x00 &&
			 tempStruct.MAC[4] == 0x00 &&
			 tempStruct.MAC[5] == 0x00))
		{
		}
		else
		{
			memcpy(&pNICInfo[validNICIndex], &tempStruct, sizeof(tSTRUCTNICINFO));
			validNICIndex++;
		}
	}
}

#endif // MIBACCESS_SIMPLE
