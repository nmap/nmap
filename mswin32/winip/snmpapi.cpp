/******************************************************************
*
*      Copyright (C) Stas Khirman 1998.  All rights reserved.         
*                                                                     
*       This program is distributed WITHOUT ANY WARRANTY
*
*******************************************************************/

/*************************************************
*     
*       Reproduction of SNMP.LIB and SNMPAPI.LIB base
*           functions
*
* Author: Stas Khirman (staskh@rocketmail.com)
*
*
* Free software: no warranty; use anywhere is ok; spread the      
* sources; note any modifications; share variations and           
* derivatives (including sending to staskh@rocketmail.com).       
*                                                                     
*
*************************************************/

//	This file is _not_ LGPL -- see above license

#include "..\tcpip.h"
#include "winip.h"
#include <snmp.h>
#include <string.h>

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOidCpy(
    OUT AsnObjectIdentifier *DstObjId,
    IN  AsnObjectIdentifier *SrcObjId
    )
{
  DstObjId->ids = (UINT *)GlobalAlloc(GMEM_ZEROINIT,SrcObjId->idLength * 
          sizeof(UINT));
  if(!DstObjId->ids){
    SetLastError(1);
    return 0;
  }

  memcpy(DstObjId->ids,SrcObjId->ids,SrcObjId->idLength*sizeof(UINT));
  DstObjId->idLength = SrcObjId->idLength;

  return 1;
}


VOID
SNMP_FUNC_TYPE
SnmpUtilOidFree(
    IN OUT AsnObjectIdentifier *ObjId
    )
{
  GlobalFree(ObjId->ids);
  ObjId->ids = 0;
  ObjId->idLength = 0;
}

SNMPAPI
SNMP_FUNC_TYPE
SnmpUtilOidNCmp(
    IN AsnObjectIdentifier *ObjIdA,
    IN AsnObjectIdentifier *ObjIdB,
    IN UINT                 Len
    )
{
  UINT CmpLen;
  UINT i;
  int  res;

  CmpLen = Len;
  if(ObjIdA->idLength < CmpLen)
    CmpLen = ObjIdA->idLength;
  if(ObjIdB->idLength < CmpLen)
    CmpLen = ObjIdB->idLength;

  for(i=0;i<CmpLen;i++){
    res = ObjIdA->ids[i] - ObjIdB->ids[i];
    if(res!=0)
      return res;
  }
  return 0;
}

VOID
SNMP_FUNC_TYPE
SnmpUtilVarBindFree(
    IN OUT RFC1157VarBind *VarBind
    )
{
  BYTE asnType;
  // free object name
  SnmpUtilOidFree(&VarBind->name);

  asnType = VarBind->value.asnType;

  if(asnType==ASN_OBJECTIDENTIFIER){
    SnmpUtilOidFree(&VarBind->value.asnValue.object);
  }
  else if(
        (asnType==ASN_OCTETSTRING) ||
        (asnType==ASN_RFC1155_IPADDRESS) ||
        (asnType==ASN_RFC1155_OPAQUE) ||
        (asnType==ASN_SEQUENCE)){
    if(VarBind->value.asnValue.string.dynamic){
      GlobalFree(VarBind->value.asnValue.string.stream);
    }
  }

  VarBind->value.asnType = ASN_NULL;

}
