id = "MSRPC: List of user accounts"
description = [[
Attempts to enumerate the users on a remote Windows system, with as much
information as possible, through a variety of techniques (over SMB + MSRPC,
which uses port 445 or 139). Some functions in SAMR are used to enumerate
users, and some bruteforce guessing using LSA functions is attempted. 

One technique used is calling the QueryDisplayInfo() function in the SAMR library. 
If this succeeds, it will return a detailed list of users. This can be done
anonymously against Windows 2000, and with a user-level account on other Windows
versions (but not with a guest-level account). 

To perform this test, the following functions are used:

	* Bind() -- bind to the SAMR service
	* Connect4() -- get a connect_handle
	* EnumDomains() -- get a list of the domains
	* QueryDomain() -- get the sid for the domain
	* OpenDomain() -- get a handle for each domain
	* QueryDisplayInfo() -- get the list of users in the domain
	* Close() -- Close the domain handle
	* Close() -- Close the connect handle

The advantage of this technique is that a lot of details are returned, including
the full name and description; the disadvantage is that it requires a user-level
account on every system except for Windows 2000. Additionally, it only pulls actual
user accounts, not groups or aliasts. 

Regardless of whether or not this succeeds, a second technique is used to pull
user accounts, called LSA bruteforcing. LSA bruteforcing can be done anonymously
against Windows 2000, and requires a guest account or better on other systems. 
It has the advantage of running with less permissions, and will also find more 
account types (ie, groups, aliases, etc). The disadvantages is that it returns 
less information, and that, because it's a bruteforce, it's possible to miss
accounts. 
\n\n
This isn't a bruteforce in the common sense, however; it's a bruteforce of users' 
RIDs. A user's RID is a value (generally 500, 501, or 1000+) that uniquely identifies
a user on a domain or system. An LSA function is exposed which lets us convert the RID
(say, '1000') to the username (say, 'Ron'). So, the bruteforce will essentially try
converting 1000 to a name, 1001, 1002, etc., until we think we're done. 
\n\n
I break the users into 5-RID groups, and check them individually (checking too many
at once causes problems). I continue checking until I reach 1100, and get an empty
group. This probably isn't the most effective way, but it seems to work. 
It might be a good idea to modify this, in the future, with some more
intelligence.  I performed a test on an old server with a lot of accounts, 
and I got these results: 500, 501, 1000, 1030, 1031, 1053, 1054, 1055, 
1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1070, 
1075, 1081, 1088, 1090. The jump from 1000 to 1030 is quite large and can easily 
result in missing accounts, in an automated check. 
\n\n
Before attempting this conversion, the SID of the server has to be determined. 
The SID is determined by doing the reverse operation -- converting a name into 
a RID. The name is determined by looking up any name present on the system. 
In this script, I try looking up:
\n\n
<ul>
	<li>The computer name / domain name, returned in SMB_COM_NEGOTIATE
	<li>An nbstat query to get the server name and the currently loggeed in user
	<li>Some common names ("administrator", "guest", and "test")
</ul>
\n\n
In theory, the computer name should be sufficient for this to always work, and
so far has in my tests, but I included the rest of the names for good measure. 
\n\n
The names and details from both of these techniques are merged and displayed.
If the output is verbose, then extra details. The output is ordered alphabetically. 
\n\n
Credit goes out to the enum.exe, sid2user.exe, and user2sid.exe programs, 
the code I wrote for this is largely based on the techniques used by them.
]]
---
-- @usage
-- nmap --script smb-enumusers.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enumusers.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  MSRPC: List of user accounts:
-- |_ TESTBOX\Administrator, EXTERNAL\DnsAdmins, TESTBOX\Guest, EXTERNAL\HelpServicesGroup, EXTERNAL\PARTNERS$, TESTBOX\SUPPORT_388945a0
-- 
-- Host script results:
-- |  MSRPC: List of user accounts:
-- |  Administrator
-- |    |_ Type: User
-- |    |_ Domain: LOCALSYSTEM
-- |    |_ Full name: Built-in account for administering the computer/domain
-- |    |_ Flags: Normal account, Password doesn't expire
-- |  DnsAdmins
-- |    |_ Type: Alias
-- |    |_ Domain: EXTRANET
-- |  EventViewer
-- |    |_ Type: User
-- |    |_ Domain: SHARED
-- |  ProxyUsers
-- |    |_ Type: Group
-- |    |_ Domain: EXTRANET
-- |  ComputerAccounts
-- |    |_ Type: Group
-- |    |_ Domain: EXTRANET
-- |  Helpdesk
-- |    |_ Type: Group
-- |    |_ Domain: EXTRANET
-- |  Guest
-- |    |_ Type: User
-- |    |_ Domain: LOCALSYSTEM
-- |    |_ Full name: Built-in account for guest access to the computer/domain
-- |    |_ Flags: Normal account, Disabled, Password not required, Password doesn't expire
-- |  Staff
-- |    |_ Type: Alias
-- |    |_ Domain: LOCALSYSTEM
-- |  Students
-- |    |_ Type: Alias
-- |_   |_ Domain: LOCALSYSTEM
-- 
--
--@args  smbusername The SMB username to log in with. The form DOMAIN\username and username@DOMAIN
--                   are NOT understood. To set a domain, use the smbdomain argument. 
--@args  smbdomain   The domain to log in with. If you aren't in a domained environment, then anything
--                   will (should?) be accepted by the server. 
--@args  smbpassword The password to connect with. Be cautious with this, since some servers will lock
--                   accounts if the incorrect password is given (although it's rare for the 
--                   'administrator' account to be lockoutable, in the off chance that it is, you could
--                   get yourself in trouble). 
--@args  smbhash     A password hash to use when logging in. This is given as a single hex string (32
--                   characters) or a pair of hex strings (2 x 32 characters, optionally separated by a 
--                   single character). These hashes are the Lanman or NTLM hash of the user's password,
--                   and are stored by systems, on the harddrive or memory. They can be retrived from memory
--                   using the fgdump or pwdump tools. 
--@args  smbguest    If this is set to 'true' or '1', a 'guest' login will be attempted if the normal one 
--                   fails. This should be harmless, but I thought I would disable it by default anyway
--                   because I'm not entirely sure of any possible consequences. 
--@args  smbtype     The type of SMB authentication to use. By default, NTLMv1 is used, which is a pretty
--                   decent compromise between security and compatibility. If you are paranoid, you might 
--                   want to use 'v2' or 'lmv2' for this (actually, if you're paranoid, you should be 
--                   avoiding this protocol altogether :P). If you're using an extremely old system, you 
--                   might need to set this to 'v1' or 'lm', which are less secure but more compatible. 
--
--                   If you want finer grained control, these are the possible options:
--                       * v1 -- Sends LMv1 and NTLMv1
--                       * LMv1 -- Sends LMv1 only
--                       * NTLMv1 -- Sends NTLMv1 only (default)
--                       * v2 -- Sends LMv2 and NTLMv2
--                       * LMv2 -- Sends LMv2 only
--
-----------------------------------------------------------------------

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

---Attempt to enumerate users through SAMR methods. See the file description for more information. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is an
--        array of tables. Each table contains a 'name', 'domain', 'fullname', 'rid', and 'description'. 
local function enum_samr(host)

	stdnse.print_debug(3, "Entering enum_samr()")

	local smbstate
	local bind_result, connect4_result, enumdomains_result
	local connect_handle
	local status, smbstate
	local response = {}

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.SAMR_PATH)

	if(status == false) then
		return false, smbstate
	end

	-- Bind to SAMR service
	status, bind_result = msrpc.bind(smbstate, msrpc.SAMR_UUID, msrpc.SAMR_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Call connect4()
	status, connect4_result = msrpc.samr_connect4(smbstate, host.ip)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, connect4_result
	end

	-- Save the connect_handle
	connect_handle = connect4_result['connect_handle']

	-- Call EnumDomains()
	status, enumdomains_result = msrpc.samr_enumdomains(smbstate, connect_handle)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, enumdomains_result
	end

	-- If no domains were returned, go back with an error
	if(#enumdomains_result['domains'] == 0) then
		msrpc.stop_smb(smbstate)
		return false, "Couldn't find any domains"
	end

	-- Now, loop through the domains and find the users
	for i = 1, #enumdomains_result['domains'], 1 do

		local domain = enumdomains_result['domains'][i]
		-- We don't care about the 'builtin' domain, in all my tests it's empty
		if(domain ~= 'Builtin') then
			local sid
			local domain_handle
			local opendomain_result, querydisplayinfo_result

			-- Call LookupDomain()
			status, lookupdomain_result = msrpc.samr_lookupdomain(smbstate, connect_handle, domain)
			if(status == false) then
				msrpc.stop_smb(smbstate)
				return false, lookupdomain_result
			end

			-- Save the sid
			sid = lookupdomain_result['sid']
	
			-- Call OpenDomain()
			status, opendomain_result = msrpc.samr_opendomain(smbstate, connect_handle, sid)
			if(status == false) then
				msrpc.stop_smb(smbstate)
				return false, opendomain_result
			end

			-- Save the domain handle
			domain_handle = opendomain_result['domain_handle']
	
			-- Call QueryDisplayInfo()
			status, querydisplayinfo_result = msrpc.samr_querydisplayinfo(smbstate, domain_handle)
			if(status == false) then
				msrpc.stop_smb(smbstate)
				return false, querydisplayinfo_result
			end

			-- Close the domain handle
			msrpc.samr_close(smbstate, domain_handle)

			-- Finally, fill in the response!
			for i = 1, #querydisplayinfo_result['details'], 1 do
				querydisplayinfo_result['details'][i]['domain'] = domain
				-- All we get from this is users
				querydisplayinfo_result['details'][i]['typestr'] = "User"
				querydisplayinfo_result['details'][i]['source']  = "SAMR Enumeration"
				response[#response + 1] = querydisplayinfo_result['details'][i]
			end
		end -- Checking for 'builtin'
	end -- Domain loop

	-- Close the connect handle
	msrpc.samr_close(smbstate, connect_handle)

	-- Stop the SAMR SMB
	msrpc.stop_smb(smbstate)

	stdnse.print_debug(3, "Leaving enum_samr()")

	return true, response
end

---Attempt to enumerate users through LSA methods. See the file description for more information. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is an
--        array of tables. Each table contains a 'name', 'domain', and 'rid'. 
local function enum_lsa(host)

	local smbstate
	local status
	local response = {}

	stdnse.print_debug(3, "Entering enum_lsa()")

	-- Create the SMB session
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

	-- Open the LSA policy
	status, openpolicy2_result = msrpc.lsa_openpolicy2(smbstate, host.ip)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, openpolicy2_result
	end

	-- Start with some common names, as well as the name returned by the negotiate call
	-- Vista doesn't like a 'null' after the server name, so fix that (TODO: the way I strip the null here feels hackish, is there a better way?)
	names = {"administrator", "guest", "test", smbstate['domain'], string.sub(smbstate['server'], 1, #smbstate['server'] - 1) }

	-- Get the server's name from nbstat
	local result, server_name = netbios.get_server_name(host.ip)
	if(result == true) then
		names[#names + 1] = server_name
	end

	-- Get the logged in user from nbstat
	local result, user_name = netbios.get_user_name(host.ip)
	if(result == true) then
		names[#names + 1] = user_name
	end

	-- Look up the names, if any are valid than the server's SID will be returned
	status, lookupnames2_result = msrpc.lsa_lookupnames2(smbstate, openpolicy2_result['policy_handle'], names)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, lookupnames2_result
	end

	-- Loop through the domains returned and find the users in each
	for i = 1, #lookupnames2_result['domains'], 1 do
		local domain = lookupnames2_result['domains'][i]['name']
		local sid	= lookupnames2_result['domains'][i]['sid']
		local rids   = { }
		local start  = 1000

		-- Start by looking up 500 - 505 (will likely be Administrator + guest)
		for j = 500, 505, 1 do 
			rids[#rids + 1] = j 
		end

		status, lookupsids2_result = msrpc.lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], sid, rids)
		if(status == false) then
			stdnse.print_debug(1, string.format("Error looking up RIDs: %s", lookupsids2_result))
		else
			-- Put the details for each name into an array
			for j = 1, #lookupsids2_result['details'], 1 do
				if(lookupsids2_result['details'][j]['type'] ~= 8) then -- 8 = user not found
					local result = {}
					result['name']   = lookupsids2_result['details'][j]['name']
					result['rid']	= 500 + j - 1
					result['domain'] = domain
					result['typestr'] = lookupsids2_result['details'][j]['typestr']
					result['source']  = "LSA Bruteforce"
					response[#response + 1] = result
				end
			end
		end

		-- Now do groups of 5 users, until we get past 1100 and have an empty group
		repeat
			local used_names = 0
			local rids = {}
			for j = start, start + 4, 1 do 
				rids[#rids + 1] = j 
			end

			-- Try converting this group of RIDs into names
			status, lookupsids2_result = msrpc.lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], sid, rids)
			if(status == false) then
				stdnse.print_debug(1, string.format("Error looking up RIDs: %s", lookupsids2_result))
			else
				-- Put the details for each name into an array
				for j = 1, #lookupsids2_result['details'], 1 do
					if(lookupsids2_result['details'][j]['type'] ~= 8) then -- 8 = user not found
						local result = {}
						result['name']   = lookupsids2_result['details'][j]['name']
						result['rid']	= start + j - 1
						result['domain'] = domain
						result['typestr'] = lookupsids2_result['details'][j]['typestr']
						result['source']  = "LSA Bruteforce"
						response[#response + 1] = result

						-- Increment the number of used names we have
						used_names = used_names + 1
					end
				end
			end

			-- Go to the next set of RIDs
			start = start + 5
		until status == false or (used_names == 0 and start > 1100)
	end

	-- Close the handle
	msrpc.lsa_close(smbstate, openpolicy2_result['policy_handle'])

	msrpc.stop_smb(smbstate)

	stdnse.print_debug(3, "Leaving enum_lsa()")

	return true, response
end



action = function(host)
	local i, j
	local samr_status, lsa_status
	local samr_result, lsa_result
	local names = {}
	local name_strings = {}
	local response = " \n"

	-- Try enumerating through LSA first. Since LSA provides less information, we want the
	-- SAMR result to overwrite it. 
	lsa_status, lsa_result  = enum_lsa(host)
	if(lsa_status == false) then
		if(nmap.debugging() > 0) then
			response = response .. "ERROR: couldn't enum through LSA: " .. lsa_result .. "\n"
		end
	else
		-- Copy the returned array into the names[] table, using the name as the key
		stdnse.print_debug(2, "EnumUsers: Received %d names from LSA", #lsa_result)
		for i = 1, #lsa_result, 1 do
			names[string.upper(lsa_result[i]['name'])] = lsa_result[i]
		end
	end

	-- Try enumerating through SAMR
	samr_status, samr_result = enum_samr(host)
	if(samr_status == false) then
		if(nmap.debugging() > 0) then
			response = response .. "ERROR: couldn't enumerate through SAMR: " .. samr_result .. "\n"
		end
	else
		-- Copy the returned array into the names[] table, using the name as the key
		stdnse.print_debug(2, "EnumUsers: Received %d names from SAMR", #samr_result)
		for i = 1, #samr_result, 1 do
			names[string.upper(samr_result[i]['name'])] = samr_result[i]
		end
	end

	-- Check if both failed
	if(samr_status == false and lsa_status == false) then
		if(nmap.debugging() > 0) then
			return response
		else
			return nil
		end
	end

	-- Put the names into an array of strings, so we can sort them
	for name, details in pairs(names) do
		name_strings[#name_strings + 1] = names[name]['name']
	end
	-- Sort them
	table.sort(name_strings, function (a, b) return string.lower(a) < string.lower(b) end)

	-- Check if we actually got any names back
	if(#name_strings == 0) then
		response = response .. "Sorry, couldn't find any account names anonymously!"
	else
		-- If we're not verbose, just print out the names. Otherwise, print out everything we can
		if(nmap.verbosity() < 1) then
			local response_array = {}
			for i = 1, #name_strings, 1 do
				local name = string.upper(name_strings[i])
				response_array[#response_array + 1] = (names[name]['domain'] .. "\\" .. names[name]['name'])
			end
				
			response = response .. stdnse.strjoin(", ", response_array)
		else
			for i = 1, #name_strings, 1 do
				local name = string.upper(name_strings[i])
				response = response .. string.format("%s\n", names[name]['name'])

				if(names[name]['typestr'] ~= nil)     then response = response .. string.format("  |_ Type: %s\n",        names[name]['typestr'])     end
				if(names[name]['domain'] ~= nil)      then response = response .. string.format("  |_ Domain: %s\n",      names[name]['domain'])      end
				if(nmap.verbosity() > 1) then
					if(names[name]['rid'] ~= nil)         then response = response .. string.format("  |_ RID: %s\n",         names[name]['rid'])         end
				end
				if(names[name]['fullname'] ~= nil)    then response = response .. string.format("  |_ Full name: %s\n",   names[name]['fullname'])    end
				if(names[name]['description'] ~= nil) then response = response .. string.format("  |_ Description: %s\n", names[name]['description']) end
				if(names[name]['flags'] ~= nil)       then response = response .. string.format("  |_ Flags: %s\n",       stdnse.strjoin(", ", names[name]['flags_list'])) end

				if(nmap.verbosity() > 1) then
					if(names[name]['source'] ~= nil)      then response = response .. string.format("  |_ Source: %s\n",      names[name]['source']) end
				end
			end
		end
	end

	return response
end

--real_action = action
--
-- function action (...)
-- 	local t = {n = select("#", ...), ...};
-- 	local status, ret = xpcall(function() return real_action(unpack(t, 1, t.n)) end, debug.traceback)
-- 
-- 	if not status then 
-- 		error(ret) 
-- 	end
-- 
-- 	return ret
-- end

