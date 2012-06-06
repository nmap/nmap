local comm = require "comm"
local ldap = require "ldap"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to perform an LDAP search and returns all matches.

If no username and password is supplied to the script the Nmap registry
is consulted. If the <code>ldap-brute</code> script has been selected
and it found a valid account, this account will be used. If not
anonymous bind will be used as a last attempt.
]]

---
-- @args ldap.username If set, the script will attempt to perform an LDAP bind using the username and password
-- @args ldap.password If set, used together with the username to authenticate to the LDAP server
-- @args ldap.qfilter If set, specifies a quick filter. The library does not support parsing real LDAP filters.
--       The following values are valid for the filter parameter: computer, users, ad_dcs, custom or all. If no value is specified it defaults to all.
-- @args ldap.searchattrib When used with the 'custom' qfilter, this parameter works in conjunction with ldap.searchvalue to allow the user to specify a custom attribute and value as search criteria.
-- @args ldap.searchvalue When used with the 'custom' qfilter, this parameter works in conjunction with ldap.searchattrib to allow the user to specify a custom attribute and value as search criteria.
--       This parameter DOES PERMIT the use of the asterisk '*' as a wildcard.
-- @args ldap.base If set, the script will use it as a base for the search. By default the defaultNamingContext is retrieved and used.
--       If no defaultNamingContext is available the script iterates over the available namingContexts
-- @args ldap.attrib If set, the search will include only the attributes specified. For a single attribute a string value can be used, if
--       multiple attributes need to be supplied a table should be used instead.
-- @args ldap.maxobjects If set, overrides the number of objects returned by the script (default 20). 
--       The value -1 removes the limit completely.
-- @args ldap.savesearch If set, the script will save the output to a file beginning with the specified path and name.  The file suffix 
--       of .CSV as well as the hostname and port will automatically be added based on the output type selected.
--
-- @usage
-- nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=ldaptest,cn=users,dc=cqure,dc=net",ldap.password=ldaptest,
-- ldap.qfilter=users,ldap.attrib=sAMAccountName' <host>
--
-- nmap -p 389 --script ldap-search --script-args 'ldap.username="cn=ldaptest,cn=users,dc=cqure,dc=net",ldap.password=ldaptest,
-- ldap.qfilter=custom,ldap.searchattrib="operatingSystem",ldap.searchvalue="Windows *Server*",ldap.attrib={operatingSystem,whencreated,OperatingSystemServicePack}' <host>
--
-- @output
-- PORT    STATE SERVICE REASON
-- 389/tcp open  ldap    syn-ack
-- | ldap-search:  
-- |   DC=cqure,DC=net
-- |     dn: CN=Administrator,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: Administrator
-- |     dn: CN=Guest,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: Guest
-- |     dn: CN=SUPPORT_388945a0,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: SUPPORT_388945a0
-- |     dn: CN=EDUSRV011,OU=Domain Controllers,DC=cqure,DC=net
-- |         sAMAccountName: EDUSRV011$
-- |     dn: CN=krbtgt,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: krbtgt
-- |     dn: CN=Patrik Karlsson,CN=Users,DC=cqure,DC=net
-- |         sAMAccountName: patrik
-- |     dn: CN=VMABUSEXP008,CN=Computers,DC=cqure,DC=net
-- |         sAMAccountName: VMABUSEXP008$
-- |     dn: CN=ldaptest,CN=Users,DC=cqure,DC=net
-- |_        sAMAccountName: ldaptest
-- 
--
-- PORT    STATE SERVICE REASON
-- 389/tcp open  ldap    syn-ack
-- | ldap-search:
-- |   Context: DC=cqure,DC=net; QFilter: custom; Attributes: operatingSystem,whencreated,OperatingSystemServicePack
-- |     dn: CN=USDC01,OU=Domain Controllers,DC=cqure,DC=net
-- |         whenCreated: 2010/08/27 17:30:16 UTC
-- |         operatingSystem: Windows Server 2008 R2 Datacenter
-- |         operatingSystemServicePack: Service Pack 1
-- |     dn: CN=TESTBOX,OU=Test Servers,DC=cqure,DC=net
-- |         whenCreated: 2010/09/04 00:33:02 UTC
-- |         operatingSystem: Windows Server 2008 R2 Standard
-- |_        operatingSystemServicePack: Service Pack 1


-- Credit 
-- ------
-- o Martin Swende who provided me with the initial code that got me started writing this.

-- Version 0.8
-- Created 01/12/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/20/2010 - v0.2 - added SSL support
-- Revised 01/26/2010 - v0.3 - Changed SSL support to comm.tryssl, prefixed arguments with ldap, changes in determination of namingContexts
-- Revised 02/17/2010 - v0.4 - Added dependencie to ldap-brute and the abilitity to check for ldap accounts (credentials) stored in nmap registry
--                             Capped output to 20 entries, use ldap.maxObjects to override
-- Revised 07/16/2010 - v0.5 - Fixed bug with empty contexts, added objectClass person to qfilter users, add error msg for invalid credentials
-- Revised 09/05/2011 - v0.6 - Added support for saving searches to a file via argument ldap.savesearch
-- Revised 10/29/2011 - v0.7 - Added support for custom searches and the ability to leverage LDAP substring search functionality added to LDAP.lua
-- Revised 10/30/2011 - v0.8 - Added support for ad_dcs (AD domain controller ) searches and the ability to leverage LDAP extensibleMatch filter added to LDAP.lua


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


dependencies = {"ldap-brute"}

portrule = shortport.port_or_service({389,636}, {"ldap","ldapssl"})

function action(host,port)

	local status
	local socket, opt	
	local args = nmap.registry.args
	local username = stdnse.get_script_args('ldap.username')
	local password = stdnse.get_script_args('ldap.password')
	local qfilter = stdnse.get_script_args('ldap.qfilter')
	local searchAttrib = stdnse.get_script_args('ldap.searchattrib')
	local searchValue = stdnse.get_script_args('ldap.searchvalue')
	local base = stdnse.get_script_args('ldap.base')
	local attribs = stdnse.get_script_args('ldap.attrib')
	local saveFile = stdnse.get_script_args('ldap.savesearch')
	local accounts
	local objCount = 0
	local maxObjects = stdnse.get_script_args('ldap.maxobjects') and tonumber(stdnse.get_script_args('ldap.maxobjects')) or 20

	-- In order to discover what protocol to use (SSL/TCP) we need to send a few bytes to the server
	-- An anonymous bind should do it
	local ldap_anonymous_bind = string.char( 0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00 )
	local _
	socket, _, opt = comm.tryssl( host, port, ldap_anonymous_bind, nil )
	
	if not socket then
		return
	end
	
	-- Check if ldap-brute stored us some credentials
	if ( not(username) and nmap.registry.ldapaccounts~=nil ) then
		accounts = nmap.registry.ldapaccounts
	end

	-- We close and re-open the socket so that the anonymous bind does not distract us
	socket:close()
	status = socket:connect(host, port, opt)
	socket:set_timeout(10000)
	
	local req
	local searchResEntries
	local contexts = {}
	local result = {} 
	local filter

	if base == nil then
		req = { baseObject = "", scope = ldap.SCOPE.base, derefPolicy = ldap.DEREFPOLICY.default, attributes = { "defaultNamingContext", "namingContexts" } }
		status, searchResEntries = ldap.searchRequest( socket, req )
		
		if not status then
			socket:close()
			return
		end

		contexts = ldap.extractAttribute( searchResEntries, "defaultNamingContext" )

		-- OpenLDAP does not have a defaultNamingContext
		if not contexts then
			contexts = ldap.extractAttribute( searchResEntries, "namingContexts" )
		end
	else
		table.insert(contexts, base)
	end

	if ( not(contexts) or #contexts == 0 ) then
		stdnse.print_debug( "Failed to retrieve namingContexts" )
		contexts = {""}
	end

	-- perform a bind only if we have valid credentials
	if ( username ) then
		local bindParam = { version=3, ['username']=username, ['password']=password}
		local status, errmsg = ldap.bindRequest( socket, bindParam )
		
		if not status then
			stdnse.print_debug( string.format("ldap-search failed to bind: %s", errmsg) )
			return "  \n  ERROR: Authentication failed"
		end
	-- or if ldap-brute found us something
	elseif ( accounts ) then
		for username, password in pairs(accounts) do
			local bindParam = { version=3, ['username']=username, ['password']=password}
			local status, errmsg = ldap.bindRequest( socket, bindParam )
		
			if status then
				break
			end
		end
	end
	
	if qfilter == "users" then
		filter = { op=ldap.FILTER._or, val= 
						{ 
							{ op=ldap.FILTER.equalityMatch, obj='objectClass', val='user' }, 
							{ op=ldap.FILTER.equalityMatch, obj='objectClass', val='posixAccount' },
							{ op=ldap.FILTER.equalityMatch, obj='objectClass', val='person' } 
						}
				   }
	elseif qfilter == "computers" or qfilter == "computer" then
		filter = { op=ldap.FILTER.equalityMatch, obj='objectClass', val='computer' }
	
	elseif qfilter == "ad_dcs" then
		filter = { op=ldap.FILTER.extensibleMatch, obj='userAccountControl', val='1.2.840.113556.1.4.803:=8192' }
		
	elseif qfilter == "custom" then
		if searchAttrib == nil or searchValue == nil then
			return "\n\nERROR: Please specify both ldap.searchAttrib and ldap.searchValue using using the custom qfilter."
		end
		if string.find(searchValue, '*') == nil then
			filter = { op=ldap.FILTER.equalityMatch, obj=searchAttrib, val=searchValue }
		else
			filter = { op=ldap.FILTER.substrings, obj=searchAttrib, val=searchValue }
		end
	
	elseif qfilter == "all" or qfilter == nil then
		filter = nil -- { op=ldap.FILTER}
	else
		return "  \n\nERROR: Unsupported Quick Filter: " .. qfilter
	end
	
	if type(attribs) == 'string' then
		local tmp = attribs
		attribs = {}
		table.insert(attribs, tmp)
	end	
	
	for _, context in ipairs(contexts) do
	
		req = { 
			baseObject = context, 
			scope = ldap.SCOPE.sub, 
			derefPolicy = ldap.DEREFPOLICY.default, 
			filter = filter, 
			attributes = attribs,
			['maxObjects'] = maxObjects }
		status, searchResEntries = ldap.searchRequest( socket, req )
		
		if not status then
			if ( searchResEntries:match("DSID[-]0C090627") and not(username) ) then
				return "ERROR: Failed to bind as the anonymous user"
			else
				stdnse.print_debug( string.format( "ldap.searchRequest returned: %s", searchResEntries ) )
				return
			end
		end
				
		local result_part = ldap.searchResultToTable( searchResEntries )

		if saveFile then
			local output_file = saveFile .. "_" .. host.ip .. "_" .. port.number .. ".csv"
			local save_status, save_err = ldap.searchResultToFile(searchResEntries,output_file)
			if not save_status then
				stdnse.print_debug(save_err)
			end
		end
		
		objCount = objCount + (result_part and #result_part or 0)
		result_part.name = ""

		if ( context ) then
			result_part.name = ("Context: %s"):format(#context > 0 and context or "<empty>")
		end
		if ( qfilter ) then
			result_part.name = result_part.name .. ("; QFilter: %s"):format(qfilter)
		end
		if ( attribs ) then
			result_part.name = result_part.name .. ("; Attributes: %s"):format(stdnse.strjoin(",", attribs))			
		end

		table.insert( result, result_part )

		-- catch any softerrors
		if searchResEntries.resultCode ~= 0 then
			local output = stdnse.format_output(true, result )
			output = output .. string.format("\n\n\n=========== %s ===========", searchResEntries.errorMessage )
			
			return output
		end

	end
		
	-- perform a unbind only if we have valid credentials
	if ( username ) then
		status = ldap.unbindRequest( socket )
	end
	
	socket:close()
	
	-- if taken a way and ldap returns a single result, it ain't shown....
	--result.name = "LDAP Results"
	
	local output = stdnse.format_output(true, result )
	
	if ( maxObjects ~= -1 and objCount == maxObjects ) then
		output = output .. ("\n\nResult limited to %d objects (see ldap.maxobjects)"):format(maxObjects)
	end
	
	return output
end
