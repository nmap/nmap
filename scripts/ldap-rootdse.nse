local comm = require "comm"
local ldap = require "ldap"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Retrieves the LDAP root DSA-specific Entry (DSE)
]]

---
--
-- @usage
-- nmap -p 389 --script ldap-rootdse <host>
--
-- @output
-- PORT    STATE SERVICE
-- 389/tcp open  ldap
-- | ldap-rootdse:
-- |     currentTime: 20100112092616.0Z
-- |     subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=cqure,DC=net
-- |     dsServiceName: CN=NTDS Settings,CN=LDAPTEST001,CN=Servers,CN=Default-First-Site,CN=Sites,CN=Configuration,DC=cqure,DC=net
-- |     namingContexts: DC=cqure,DC=net
-- |     namingContexts: CN=Configuration,DC=cqure,DC=net
-- |     namingContexts: CN=Schema,CN=Configuration,DC=cqure,DC=net
-- |     namingContexts: DC=DomainDnsZones,DC=cqure,DC=net
-- |     namingContexts: DC=ForestDnsZones,DC=cqure,DC=net
-- |     namingContexts: DC=TAPI3Directory,DC=cqure,DC=net
-- |     defaultNamingContext: DC=cqure,DC=net
-- |     schemaNamingContext: CN=Schema,CN=Configuration,DC=cqure,DC=net
-- |     configurationNamingContext: CN=Configuration,DC=cqure,DC=net
-- |     rootDomainNamingContext: DC=cqure,DC=net
-- |     supportedControl: 1.2.840.113556.1.4.319
-- |     .
-- |     .
-- |     supportedControl: 1.2.840.113556.1.4.1948
-- |     supportedLDAPVersion: 3
-- |     supportedLDAPVersion: 2
-- |     supportedLDAPPolicies: MaxPoolThreads
-- |     supportedLDAPPolicies: MaxDatagramRecv
-- |     supportedLDAPPolicies: MaxReceiveBuffer
-- |     supportedLDAPPolicies: InitRecvTimeout
-- |     supportedLDAPPolicies: MaxConnections
-- |     supportedLDAPPolicies: MaxConnIdleTime
-- |     supportedLDAPPolicies: MaxPageSize
-- |     supportedLDAPPolicies: MaxQueryDuration
-- |     supportedLDAPPolicies: MaxTempTableSize
-- |     supportedLDAPPolicies: MaxResultSetSize
-- |     supportedLDAPPolicies: MaxNotificationPerConn
-- |     supportedLDAPPolicies: MaxValRange
-- |     highestCommittedUSN: 126991
-- |     supportedSASLMechanisms: GSSAPI
-- |     supportedSASLMechanisms: GSS-SPNEGO
-- |     supportedSASLMechanisms: EXTERNAL
-- |     supportedSASLMechanisms: DIGEST-MD5
-- |     dnsHostName: EDUSRV011.cqure.local
-- |     ldapServiceName: cqure.net:edusrv011$@CQURE.NET
-- |     serverName: CN=EDUSRV011,CN=Servers,CN=Default-First-Site,CN=Sites,CN=Configuration,DC=cqure,DC=net
-- |     supportedCapabilities: 1.2.840.113556.1.4.800
-- |     supportedCapabilities: 1.2.840.113556.1.4.1670
-- |     supportedCapabilities: 1.2.840.113556.1.4.1791
-- |     isSynchronized: TRUE
-- |     isGlobalCatalogReady: TRUE
-- |     domainFunctionality: 0
-- |     forestFunctionality: 0
-- |_    domainControllerFunctionality: 2
--
--
-- The root DSE object may contain a number of different attributes as described in RFC 2251 section 3.4:
-- * namingContexts: naming contexts held in the server
-- * subschemaSubentry: subschema entries (or subentries) known by this server
-- * altServer: alternative servers in case this one is later unavailable.
-- * supportedExtension: list of supported extended operations.
-- * supportedControl: list of supported controls.
-- * supportedSASLMechanisms: list of supported SASL security features.
-- * supportedLDAPVersion: LDAP versions implemented by the server.
--
-- The above example, which contains a lot more information is from Windows 2003 accessible without authentication.
-- The same request against OpenLDAP will result in significantly less information.
--
-- The ldap-search script queries the root DSE for the namingContexts and/or defaultNamingContexts, which it sets as base
-- if no base object was specified
--
-- Credit goes out to Martin Swende who provided me with the initial code that got me started writing this.
--

-- Version 0.3
-- Created 01/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/20/2010 - v0.2 - added SSL support
-- Revised 04/09/2016 - v0.3 - added support for LDAP over UDP - Tom Sellers

author = "Patrik Karlsson"
copyright = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"ldap-brute"}

-- Map domainControllerFunctionality to OS - https://msdn.microsoft.com/en-us/library/cc223272.aspx
-- Tested to be valid even when Active Directory functional level is lower than target ADC's OS version
DC_FUNCT_ID = {}
DC_FUNCT_ID["0"] = "Windows 2000"
DC_FUNCT_ID["2"] = "Windows 2003"
DC_FUNCT_ID["3"] = "Windows 2008"
DC_FUNCT_ID["4"] = "Windows 2008 R2"
DC_FUNCT_ID["5"] = "Windows 2012"
DC_FUNCT_ID["6"] = "Windows 2012 R2"

portrule = shortport.port_or_service({389,636}, {"ldap","ldapssl"},{'tcp','udp'})

function action(host,port)
  local status, searchResEntries, req, result, opt

  if port.protocol == 'tcp' then

    local socket = nmap.new_socket()

    -- In order to discover what protocol to use (SSL/TCP) we need to send a few bytes to the server
    -- An anonymous bind should do it
    local ldap_anonymous_bind = "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
    local _
    socket, _, opt = comm.tryssl( host, port, ldap_anonymous_bind, nil )

    if not socket then
      return
    end

    -- We close and re-open the socket so that the anonymous bind does not distract us
    socket:close()
    status = socket:connect(host, port, opt)
    socket:set_timeout(10000)

    -- Searching for an empty argument list against LDAP on W2K3 returns all attributes
    -- This is not the case for OpenLDAP, so we do a search for an empty attribute list
    -- Then we compare the results against some known and expected returned attributes
    req = { baseObject = "", scope = ldap.SCOPE.base, derefPolicy = ldap.DEREFPOLICY.default }
    status, searchResEntries = ldap.searchRequest( socket, req )

    if not status then
      socket:close()
      return stdnse.format_output(false, searchResEntries)
    end

    -- Check if we were served all the results or not?
    if not ldap.extractAttribute( searchResEntries, "namingContexts" ) and
        not ldap.extractAttribute( searchResEntries, "supportedLDAPVersion" ) then

      -- The namingContexts was not there, try to query all attributes instead
      -- Attributes extracted from Windows 2003 and complemented from RFC
      local attribs = {"_domainControllerFunctionality","configurationNamingContext","currentTime","defaultNamingContext",
        "dnsHostName","domainFunctionality","dsServiceName","forestFunctionality","highestCommittedUSN",
        "isGlobalCatalogReady","isSynchronized","ldap-get-baseobject","ldapServiceName","namingContexts",
        "rootDomainNamingContext","schemaNamingContext","serverName","subschemaSubentry",
        "supportedCapabilities","supportedControl","supportedLDAPPolicies","supportedLDAPVersion",
        "supportedSASLMechanisms", "altServer", "supportedExtension"}

      req = { baseObject = "", scope = ldap.SCOPE.base, derefPolicy = ldap.DEREFPOLICY.default, attributes = attribs }
      status, searchResEntries = ldap.searchRequest( socket, req )
    end

    socket:close()
  else
    -- Port protocol is UDP, indicating that this is an Active Directory Controller LDAP service
    req = { baseObject = "", scope = ldap.SCOPE.base, derefPolicy = ldap.DEREFPOLICY.default}
    status, searchResEntries = ldap.udpSearchRequest( host, port, req )
  end

  if not status or not searchResEntries then return stdnse.format_output(false, searchResEntries) end
  result = ldap.searchResultToTable( searchResEntries )

  -- if taken a way and ldap returns a single result, it ain't shown....
  result.name = "LDAP Results"
  local scriptResult = stdnse.format_output(true, result )

  -- Start extracting target information
  -- The following works on Windows AD LDAP as well as VMware's LDAP, VMware uses lower case cn vs AD ucase CN
  local serverName = scriptResult:match("serverName: [cC][nN]=([^,]+),[cC][nN]=Servers,[cC][nN]=")
  if serverName then port.version.hostname = serverName end

  -- Check to see if this is Active Directory vs some other product or ADAM
  -- https://msdn.microsoft.com/en-us/library/cc223359.aspx
  if string.match(scriptResult,"1.2.840.113556.1.4.800") then
    port.version.product = 'Microsoft Windows Active Directory LDAP'
    port.version.name_confidence = 10

    -- Determine Windows version
    if not port.version.ostype or port.version.ostype == 'Windows' then
      local DC_Func = string.match(scriptResult,"domainControllerFunctionality: (%d)")
      if DC_FUNCT_ID[DC_Func] then
        port.version.ostype = DC_FUNCT_ID[DC_Func]
      else
        port.version.ostype = 'Windows'
        stdnse.debug(1,"Unmatched OS lookup for domainControllerFunctionality: %d", DC_Func)
      end
    end

    local siteName = string.match(scriptResult,"serverName: CN=[^,]+,CN=Servers,CN=([^,]+),CN=Sites,")
    local domainName = string.match(scriptResult,"rootDomainNamingContext: ([^\n]*)")
    domainName = string.gsub(domainName,",DC=",".")
    domainName = string.gsub(domainName,"DC=","")
    if domainName and siteName then
      port.version.extrainfo = string.format("Domain: %s, Site: %s", domainName, siteName)
    end
  end

  -- Set port information
  port.version.name = "ldap"
  nmap.set_port_version(host, port, "hardmatched")
  nmap.set_port_state(host, port, "open")

  return scriptResult
end
