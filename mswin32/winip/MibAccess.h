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

//	Modified the include statements in the cpp files

//	Also added the MIBTraverser class


//	This file is _not_ LGPL -- see above license

//////////////////////////////////////////////////////
// FILE  : MibAccess.h
//
//

#ifndef _SNMP_ACCESS_H_
#define _SNMP_ACCESS_H_

#include <snmp.h>

#define MIBACCESS_SIMPLE

//////////////////////////////////////////////////////////////
// Definition of pointers to the four functions in the Mib Dll
//
typedef BOOL (WINAPI *pSnmpExtensionInit)(IN  DWORD               dwTimeZeroReference,
										  OUT HANDLE              *hPollForTrapEvent,
										  OUT AsnObjectIdentifier *supportedView);

typedef BOOL (WINAPI *pSnmpExtensionTrap)(OUT AsnObjectIdentifier *enterprise,
										  OUT AsnInteger          *genericTrap,
										  OUT AsnInteger          *specificTrap,
										  OUT AsnTimeticks        *timeStamp,
										  OUT RFC1157VarBindList  *variableBindings);

typedef BOOL (WINAPI *pSnmpExtensionQuery)(IN BYTE                   requestType,
										   IN OUT RFC1157VarBindList *variableBindings,
										   OUT AsnInteger            *errorStatus,
										   OUT AsnInteger            *errorIndex);

typedef BOOL (WINAPI *pSnmpExtensionInitEx)(OUT AsnObjectIdentifier *supportedView);


#ifndef MIBACCESS_SIMPLE
typedef struct
{
	long		type;
	BYTE		MACLength;
	BYTE		MAC[14];
	BYTE		IP[4];
	BYTE		SubnetMask[4];
	BYTE		Description[64];
} tSTRUCTNICINFO;
#endif


#define		ERROR_MIB_DLL			-1
#define		ERROR_MIB_WINSOCK		-2
#define		ERROR_MIB_INIT			-3
	

class MibExtLoad
{
public:
	MibExtLoad(LPSTR MibDllName);
	~MibExtLoad();
	
	BOOL	Init(DWORD dwTimeZeroReference, HANDLE *hPollForTrapEvent, AsnObjectIdentifier *supportedView);
	BOOL	InitEx(AsnObjectIdentifier *supportedView);
	BOOL	Query(BYTE requestType, OUT RFC1157VarBindList *variableBindings,
			AsnInteger *errorStatus, AsnInteger *errorIndex);
	BOOL	Trap(AsnObjectIdentifier *enterprise, AsnInteger *genericTrap, 
			AsnInteger *specificTrap, AsnTimeticks *timeStamp, RFC1157VarBindList  *variableBindings);

	BOOL	GetDLLStatus();

private:	
	HINSTANCE				m_hInst;
	pSnmpExtensionInit		m_Init;
	pSnmpExtensionInitEx	m_InitEx;
	pSnmpExtensionQuery		m_Query;
	pSnmpExtensionTrap		m_Trap;
};


class MibII: public MibExtLoad
{
public:
	MibII();
	~MibII();

	int						Init();

#ifndef MIBACCESS_SIMPLE
	UINT					GetNICCount(BOOL bDialup, BOOL bLoopback);
	void					GetNICInfo(tSTRUCTNICINFO *pNICInfo);
#endif

private:

#ifndef MIBACCESS_SIMPLE
	int						m_rvWSA;
	UINT					m_ifCount;
	DWORD					*m_ifIndex;
	DWORD					*m_ifEntryNum;
	tSTRUCTNICINFO			*m_pNICInfo;
	BOOL					m_bDialup;
	BOOL					m_bLoopback;

	void					MatchNICEntries(UINT NICCount, tSTRUCTNICINFO *pNICInfo);
#endif
};

//	This is cheap, but it works courtesy of the big-endianness of IP's
#define ASN_IP(x) ( * reinterpret_cast<DWORD*>(x.string.stream) )

class MIBTraverser
{
private:
	AsnObjectIdentifier *desc;
	UINT len;	//	number of elements in desc

	SnmpVarBindList vbl;
	SnmpVarBind *vb;

public:
	MIBTraverser() : desc(0), len(0), vb(0) {}
	~MIBTraverser() { clean(); }

	static MibII *m;	//	set this before using

	void Init(AsnObjectIdentifier *list, UINT sz)
	{
		clean();

		desc = list;
		len = sz;
		vb = new SnmpVarBind[len];
		vbl.list = vb;
		vbl.len = len;

		ZeroMemory(vb, len * sizeof(vb));
		int i;
		for(i = 0; i < len; i++)
			SNMP_oidcpy(&vb[i].name, &desc[i]);
	}

	void clean()
	{
		int i;
		for(i = 0; i < len; i++)
			SnmpUtilVarBindFree(vb + i);

		delete[] vb;
		vb = 0;
	}

	inline UINT length() {return len;}
	inline SnmpVarBind &operator [] (UINT index) {return vb[index];}

	bool Next(AsnInteger32 *stat = 0, AsnInteger32 *errindex = 0)
	{
		AsnInteger32 mystat, myind;
		if(!stat) stat = &mystat;
		if(!errindex) errindex = &myind;

		if(!m->Query(ASN_RFC1157_GETNEXTREQUEST, &vbl, stat, errindex))
			return false;

		if(*stat != SNMP_ERRORSTATUS_NOERROR) return false;

		if(SnmpUtilOidNCmp(&vb[0].name, &desc[0], desc[0].idLength))
			return false;	//	passed end

		return true;
	}

	bool Get(AsnInteger32 *stat = 0, AsnInteger32 *errindex = 0)
	{
		AsnInteger32 mystat, myind;
		if(!stat) stat = &mystat;
		if(!errindex) errindex = &myind;

		if(!m->Query(ASN_RFC1157_GETREQUEST, &vbl, stat, errindex))
			return false;

		if(*stat != SNMP_ERRORSTATUS_NOERROR) return false;

		return true;
	}
};

#endif