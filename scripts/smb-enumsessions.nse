id = "MSRPC: NetSessEnum()"
description = [[
Enumerates the users logged into a system either locally, through a remote desktop client (terminal
services), or through a SMB share.

Enumerating the local and terminal services users is done by reading the remote registry. Keys under
<code>HKEY_USERS</code> are SIDs that represent the currently logged in users, and those SIDs can be converted
to proper names by using the <code>LsaLookupSids()</code> function. Doing this requires any access higher than
anonymous (guests, users, or administrators are all able to perform this request on the operating
systems I tested). 

Enumerating SMB connections is done using the <code>srvsvc.netsessenum()</code> function, which returns who's
logged in, when they logged in, and how long they've been idle for. Unfortunately, I couldn't find
a way to get the user's domain with this function, so the domain isn't printed. The level of access
required for this varies between Windows versions, but in Windows 2000 anybody (including the 
anonymous account) can access this, and in Windows 2003 a user or administrator account is 
required.

Since both of these are related to users being logged into the server, it seemed logical to combine
them into a single script. 

I learned the idea and technique for this from sysinternals' tool, PsLoggedOn.exe. I use similar
function calls to what they use, so thanks go out to them. Thanks also to Matt, for giving me the 
idea to write this one. 
]]

---
--@usage
-- nmap --script smb-enumsessions.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enumsessions.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- |  MSRPC: NetSessEnum():
-- |  Users logged in:
-- |  |_ TESTBOX\Administrator since 2008-10-21 08:17:14
-- |  |_ DOMAIN\rbowes since 2008-10-20 09:03:23
-- |  Active SMB Sessions:
-- |_ |_ ADMINISTRATOR is connected from 10.100.254.138 for [just logged in, it's probably you], idle for [not idle]
-- 
-- @args smb* This script supports the <code>smbusername</code>,
-- <code>smbpassword</code>, <code>smbhash</code>, <code>smbguest</code>, and
-- <code>smbtype</code> script arguments of the <code>smb</code> module.
-----------------------------------------------------------------------

id = "MSRPC: NetSessEnum()"
author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

require 'msrpc'
require 'smb'
require 'stdnse'

hostrule = function(host)

	local port = smb.get_port(host)

	if(port == nil) then
		return false
	else
		return true
	end

end

---Attempts to enumerate the sessions on a remote system using MSRPC calls. This will likely fail 
-- against a modern system, but will succeed against Windows 2000. 
--
--@param host The host object. 
--@return Status (true or false).
--@return List of sessions (if status is true) or an an error string (if status is false).
local function srvsvc_enum_sessions(host)
	local i
	local status, smbstate
	local bind_result, netsessenum_result

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.SRVSVC_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Call netsessenum
	status, netsessenum_result = msrpc.srvsvc_netsessenum(smbstate, host.ip)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, netsessenum_result
	end

	-- Stop the SMB session
	msrpc.stop_smb(smbstate)

	return true, netsessenum_result['sessions']
end

---Enumerates the users logged in locally (or through terminal services) by using functions
-- that access the registry. To perform this check, guest access or higher is required. 
--
--@param host The host object. 
--@return An array of user tables, each with the keys <code>name</code>, <code>domain</code>, and <code>changed_date</code> (representing
--        when they logged in). 
local function winreg_enum_rids(host)
	local i, j
	local elements = {}

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.WINREG_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to WINREG service
	status, bind_result = msrpc.bind(smbstate, msrpc.WINREG_UUID, msrpc.WINREG_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	status, openhku_result = msrpc.winreg_openhku(smbstate)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, openhku_result
	end

	-- Loop through the keys under HKEY_USERS and grab the names
	i = 0
	repeat 
		status, enumkey_result = msrpc.winreg_enumkey(smbstate, openhku_result['handle'], i)

		if(status == true) then
			local status, openkey_result

			local element = {}
			element['name']         = enumkey_result['name']
			element['sid']          = msrpc.string_to_sid(enumkey_result['name'])

			-- To get the time the user logged in, we check the 'Volatile Environment' key
			status, openkey_result = msrpc.winreg_openkey(smbstate, openhku_result['handle'], element['name'] .. "\\Volatile Environment")
			if(status ~= false) then
				local queryinfokey_result, closekey_result

				-- Query the info about this key. The response will tell us when the user logged into the server. 
				status, queryinfokey_result = msrpc.winreg_queryinfokey(smbstate, openkey_result['handle'])
				if(status == false) then
					msrpc.stop_smb(smbstate)
					return false, queryinfokey_result
				end

				status, closekey_result = msrpc.winreg_closekey(smbstate, openkey_result['handle'])
				if(status == false) then
					msrpc.stop_smb(smbstate)
					return false, closekey_result
				end

				element['changed_date'] = queryinfokey_result['last_changed_date']
				elements[#elements + 1] = element
			end
		end

		i = i + 1
	until status ~= true

	status, closekey_result = msrpc.winreg_closekey(smbstate, openhku_result['handle'])
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, closekey_result
	end

	msrpc.stop_smb(smbstate)

	-- Start a new SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.LSA_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to LSA service
	status, bind_result = msrpc.bind(smbstate, msrpc.LSA_UUID, msrpc.LSA_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Get a policy handle
	status, openpolicy2_result = msrpc.lsa_openpolicy2(smbstate, host.ip)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, openpolicy2_result
	end

	-- Convert the RIDs to names
	local results = {}
	stdnse.print_debug(3, "MSRPC: Found %d SIDs that might be logged in", #elements)
	for i = 1, #elements, 1 do
		if(elements[i]['sid'] ~= nil) then
			-- The RID is the last subauthority
			local rid = elements[i]['sid']['subauthorities'][elements[i]['sid']['count']]
			stdnse.print_debug(3, "MSRPC: Found an actual RID: %d", rid)

			-- The server is the rest of the SID, so remove the last subauthority
			elements[i]['sid']['subauthorities'][elements[i]['sid']['count']] = nil
			elements[i]['sid']['count'] = elements[i]['sid']['count'] - 1

			-- Look up the RID
			stdnse.print_debug(3, "MSRPC: Looking up RID %s in SID %s", rid, msrpc.sid_to_string(elements[i]['sid']))
			status, lookupsids2_result = msrpc.lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], elements[i]['sid'], {rid})
			if(status == false) then
				-- It may not succeed, if it doesn't that's ok
				stdnse.print_debug(3, "MSRPC: Lookup failed")
			else
				-- Create the result array
				local result = {}
				result['rid'] = rid
				result['changed_date'] = elements[i]['changed_date']
	
				-- Fill in the result from the response
				if(lookupsids2_result['details'][1] == nil) then
					result['name'] = "<unknown>"
					result['domain'] = ""
				else
					result['name'] = lookupsids2_result['details'][1]['name']
					result['type'] = lookupsids2_result['details'][1]['type']
					result['domain'] = lookupsids2_result['domains'][1]['name']
				end

				if(result['type'] ~= 5) then -- Don't show "well known" accounts
					-- Add it to the results
					results[#results + 1] = result
				end
			end
		end
	end

	-- Close the policy
	msrpc.lsa_close(smbstate, openpolicy2_result['policy_handle'])

	-- Stop the session
	msrpc.stop_smb(smbstate)

	return true, results
end

action = function(host)
	local response = " \n"

	local status1, status2

	-- Enumerate the logged in users
	status1, users = winreg_enum_rids(host)
	if(status1 == false) then
		response = response .. "ERROR: Couldn't enumerate login sessions: " .. users .. "\n"
	else
		response = response .. "Users logged in:\n"
		if(#users == 0) then
			response = response .. "|_ <nobody>\n"
		else
			for i = 1, #users, 1 do
				response = response .. string.format("|_ %s\\%s since %s\n", users[i]['domain'], users[i]['name'], users[i]['changed_date'])
			end
		end
	end

	-- Get the connected sessions
	status2, sessions = srvsvc_enum_sessions(host)
	if(status2 == false) then
		response = response .. "ERROR: Couldn't enumerate network sessions: " .. sessions .. "\n"
	else
		response = response .. "Active SMB Sessions:\n"
		if(#sessions == 0) then
			response = response .. "|_ <none>\n"
		else
			-- Format the result
			for i = 1, #sessions, 1 do
		
				local active = sessions[i]['active']
				if(active == 0) then
					active = "[just logged in, it's probably you]"
				elseif(active > 60 * 60 * 24) then
					active = string.format("%dd%dh%02dm%02ds", active / (60*60*24), (active % (60*60*24)) / 3600, (active % 3600) / 60, active % 60)
				elseif(active > 60 * 60) then
					active = string.format("%dh%02dm%02ds", active / 3600, (active % 3600) / 60, active % 60)
				else
					active = string.format("%02dm%02ds", active / 60, active % 60)
				end
		
				local idle = sessions[i]['idle']
				if(idle == 0) then
					idle = "[not idle]"
				elseif(idle > 60 * 60 * 24) then
					idle = string.format("%dd%dh%02dm%02ds", idle / (60*60*24), (idle % (60*60*24)) / 3600, (idle % 3600) / 60, idle % 60)
				elseif(idle > 60 * 60) then
					idle = string.format("%dh%02dm%02ds", idle / 3600, (idle % 3600) / 60, idle % 60)
				else
					idle = string.format("%02dm%02ds", idle / 60, idle % 60)
				end
	
				response = response .. string.format("|_ %s is connected from %s for %s, idle for %s\n", sessions[i]['user'], sessions[i]['client'], active, idle)
			end
		end
	end

	if(status1 == false and status2 == false) then
		if(nmap.debugging() > 0) then
			return response
		else
			return nil
		end
	else
		return response
	end
end



