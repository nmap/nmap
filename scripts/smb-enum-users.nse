description = [[
Attempts to enumerate the users on a remote Windows system, with as much
information as possible, through two different techniques (both over MSRPC,
which uses port 445 or 139). Some SAMR functions are used to enumerate users, 
and bruteforce LSA guessing is attempted. 

By default, both SAMR enumeration and LSA bruteforcing are used; however, these
can be fine tuned using Nmap parameters. For the most possible information, 
leave the defaults; however, there are advantages to using them individually. 

Advantages of using SAMR enumeration:
* Stealthier (requires one packet/user account, whereas LSA uses at least 20
  packets; additionally, LSA makes a lot of noise in the Windows event log (LSA
  enumeration is the only script I (Ron Bowes) have been called on by the 
  administrator of a box I was testing against). 
* More information is returned (more than just the username).
* Every account will be found, since they're being enumerated with a function 
  that's designed to enumerate users.

Advantages of using LSA bruteforcing:
* More accounts are returned (system accounts, groups, and aliases are returned,
  not just users).
* Requires a lower-level account to run on Windows XP and higher (a 'guest' account
  can be used, whereas SAMR enumeration requires a 'user' account; especially useful
  when only guest access is allowed, or when an account has a blank password (which 
  effectively gives it guest access)). 

SAMR enumeration is done with the  <code>QueryDisplayInfo</code> function. 
If this succeeds, it will return a detailed list of users, along with descriptions,
types, and full names. This can be done anonymously against Windows 2000, and 
with a user-level account on other Windows versions (but not with a guest-level account). 

To perform this test, the following functions are used:
* <code>Bind</code>: bind to the SAMR service.
* <code>Connect4</code>: get a connect_handle.
* <code>EnumDomains</code>: get a list of the domains.
* <code>QueryDomain</code>: get the sid for the domain.
* <code>OpenDomain</code>: get a handle for each domain.
* <code>QueryDisplayInfo</code>: get the list of users in the domain.
* <code>Close</code>: Close the domain handle.
* <code>Close</code>: Close the connect handle.
The advantage of this technique is that a lot of details are returned, including
the full name and description; the disadvantage is that it requires a user-level
account on every system except for Windows 2000. Additionally, it only pulls actual
user accounts, not groups or aliases. 

Regardless of whether this succeeds, a second technique is used to pull
user accounts, called LSA bruteforcing. LSA bruteforcing can be done anonymously
against Windows 2000, and requires a guest account or better on other systems. 
It has the advantage of running with less permission, and will also find more 
account types (i.e., groups, aliases, etc.). The disadvantages is that it returns 
less information, and that, because it's a brute-force guess, it's possible to miss
accounts. It's also extremely noisy. 

This isn't a brute-force technique in the common sense, however: it's a brute-forcing of users' 
RIDs. A user's RID is a value (generally 500, 501, or 1000+) that uniquely identifies
a user on a domain or system. An LSA function is exposed which lets us convert the RID
(say, 1000) to the username (say, "Ron"). So, the technique will essentially try
converting 1000 to a name, then 1001, 1002, etc., until we think we're done. 

To do this, this script breaks users into groups of five RIDs, then checked individually 
(checking too many at once causes problems). We continue checking until we reach 
1100, and get an empty group of five. This probably isn't the most effective way, but it 
seems to work.  It might be a good idea to modify this, in the future, with some more
intelligence.  I (Ron Bowes) performed a test on an old server with a lot of accounts, 
and these were the active RIDs: 500, 501, 1000, 1030, 1031, 1053, 1054, 1055, 
1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1070, 
1075, 1081, 1088, 1090. The jump from 1000 to 1030 is quite large and can easily 
result in missing accounts, in an automated check. An ideal solution might be to continue
doing groups of 5, but wait until we get 5-10 consecutive empty groups before giving up. 

Before attempting this conversion, the SID of the server has to be determined. 
The SID is determined by doing the reverse operation; that is, by converting a name into 
its RID. The name is determined by looking up any name present on the system. 
We try:
* The computer name and domain name, returned in <code>SMB_COM_NEGOTIATE</code>;
* An nbstat query to get the server name and the user currently logged in; and
* Some common names: "administrator", "guest", and "test".

In theory, the computer name should be sufficient for this to always work, and
it has so far has in my tests, but I included the rest of the names for good measure. It 
doesn't hurt to add more. 

The names and details from both of these techniques are merged and displayed.
If the output is verbose, then extra details are shown. The output is ordered alphabetically. 

Credit goes out to the enum.exe, sid2user.exe, and user2sid.exe programs, 
the code I wrote for this is largely based on the techniques used by them.
]]

---
-- @usage
-- nmap --script smb-enum-users.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  smb-enum-users:
-- |_ TESTBOX\Administrator, EXTERNAL\DnsAdmins, TESTBOX\Guest, EXTERNAL\HelpServicesGroup, EXTERNAL\PARTNERS$, TESTBOX\SUPPORT_388945a0
-- 
-- Host script results:
-- |  smb-enum-users:
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
-- @args smb* This script supports the <code>smbusername</code>,
-- <code>smbpassword</code>, <code>smbhash</code>, and <code>smbtype</code>
-- script arguments of the <code>smb</code> module.
-- @args lsaonly If set, script will only enumerate using an LSA bruteforce (requires less
--       access than samr). Only set if you know what you're doing, you'll get better results
--       by using the default options. 
-- @args samronly If set, script will only query a list of users using a SAMR lookup. This is 
--       much quieter than LSA lookups, so enable this if you want stealth. Generally, however,
--       you'll get better results by using the default options. 
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

require 'msrpc'
require 'smb'
require 'stdnse'

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

---Attempt to enumerate users through SAMR methods. See the file description for more information. 
--
--@param host The host object. 
--@return Status (true or false).
--@return Array of user tables (if status is true) or an an error string (if
--status is false). Each user table contains the fields <code>name</code>,
--<code>domain</code>, <code>fullname</code>, <code>rid</code>, and
--<code>description</code>.
local function enum_samr(host)
	local i, j

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
	if(#enumdomains_result['sam']['entries'] == 0) then
		msrpc.stop_smb(smbstate)
		return false, "Couldn't find any domains"
	end

	-- Now, loop through the domains and find the users
	for i = 1, #enumdomains_result['sam']['entries'], 1 do

		local domain = enumdomains_result['sam']['entries'][i]['name']
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

			-- Loop as long as we're getting valid results	
			j = 0
			repeat
				-- Call QueryDisplayInfo()
				status, querydisplayinfo_result = msrpc.samr_querydisplayinfo(smbstate, domain_handle, j)
				if(status == false) then
					msrpc.stop_smb(smbstate)
					return false, querydisplayinfo_result
				end

				-- Save the response
				if(querydisplayinfo_result['return'] ~= 0 and querydisplayinfo_result['info'] ~= nil and querydisplayinfo_result['info']['entries'] ~= nil and querydisplayinfo_result['info']['entries'][1] ~= nil) then
					local array = {}
					local k

					-- The reason these are all indexed from '1' is because we request names one at a time. 
					array['domain']      = domain
					array['name']        = querydisplayinfo_result['info']['entries'][1]['account_name']
					array['fullname']    = querydisplayinfo_result['info']['entries'][1]['full_name']
					array['description'] = querydisplayinfo_result['info']['entries'][1]['description']
					array['rid']         = querydisplayinfo_result['info']['entries'][1]['rid']
					array['flags']       = querydisplayinfo_result['info']['entries'][1]['acct_flags']
					array['source']      = "SAMR Enumeration"

					-- Clean up the 'flags' array
					for k = 1, #array['flags'], 1 do
						array['flags'][k] = msrpc.samr_AcctFlags_tostr(array['flags'][k])
					end

					-- Add it to the array
					response[#response + 1] = array
				end
				j = j + 1
			until querydisplayinfo_result['return'] == 0

			-- Close the domain handle
			msrpc.samr_close(smbstate, domain_handle)

			-- Finally, fill in the response!
--			for i = 1, #querydisplayinfo_result['details'], 1 do
--				querydisplayinfo_result['details'][i]['domain'] = domain
--				-- All we get from this is users
--				querydisplayinfo_result['details'][i]['typestr'] = "User"
--				querydisplayinfo_result['details'][i]['source']  = "SAMR Enumeration"
--				response[#response + 1] = querydisplayinfo_result['details'][i]
--			end
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
--@return Status (true or false).
--@return Array of user tables (if status is true) or an an error string (if
--status is false). Each user table contains the fields <code>name</code>,
--<code>domain</code>, and <code>rid</code>.
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
	for i = 1, #lookupnames2_result['domains']['domains'], 1 do
		local domain = lookupnames2_result['domains']['domains'][i]['name']
		local sid	= lookupnames2_result['domains']['domains'][i]['sid']
		local sids   = { }
		local start  = 1000

		-- Start by looking up 500 - 505 (will likely be Administrator + guest)
		for j = 500, 505, 1 do 
			sids[#sids + 1] = sid .. "-" .. j 
		end
		status, lookupsids2_result = msrpc.lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], sids)
		if(status == false) then
			stdnse.print_debug(1, string.format("Error looking up RIDs: %s", lookupsids2_result))
		else
			-- Put the details for each name into an array
			-- NOTE: Be sure to mirror any changes here in the next bit! 
			for j = 1, #lookupsids2_result['names']['names'], 1 do
				if(lookupsids2_result['names']['names'][j]['sid_type'] ~= "SID_NAME_UNKNOWN") then
					local result = {}
					result['name']    = lookupsids2_result['names']['names'][j]['name']
					result['rid']	  = 500 + j - 1
					result['domain']  = domain
					result['typestr'] = msrpc.lsa_SidType_tostr(lookupsids2_result['names']['names'][j]['sid_type'])
					result['source']  = "LSA Bruteforce"
					response[#response + 1] = result
				end
			end
		end

		-- Now do groups of 5 users, until we get past 1100 and have an empty group
		repeat
			local used_names = 0
			local sids = {}
			for j = start, start + 4, 1 do 
				sids[#sids + 1] = sid .. "-" .. j
			end

			-- Try converting this group of RIDs into names
			status, lookupsids2_result = msrpc.lsa_lookupsids2(smbstate, openpolicy2_result['policy_handle'], sids)
			if(status == false) then
				stdnse.print_debug(1, string.format("Error looking up RIDs: %s", lookupsids2_result))
			else
				-- Put the details for each name into an array
				for j = 1, #lookupsids2_result['names']['names'], 1 do
					if(lookupsids2_result['names']['names'][j]['sid_type'] ~= "SID_NAME_UNKNOWN") then
						local result = {}
						result['name']    = lookupsids2_result['names']['names'][j]['name']
						result['rid']	  = start + j - 1
						result['domain']  = domain
						result['typestr'] = msrpc.lsa_SidType_tostr(lookupsids2_result['names']['names'][j]['sid_type'])
						result['source']  = "LSA Bruteforce"
						response[#response + 1] = result
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
	local samr_status = false
	local lsa_status  = false
	local samr_result = "Didn't run"
	local lsa_result  = "Didn't run"
	local names = {}
	local name_strings = {}
	local response = " \n"
	local samronly = nmap.registry.args.samronly
	local lsaonly  = nmap.registry.args.lsaonly
	local do_samr  = samronly ~= nil or (samronly == nil and lsaonly == nil)
	local do_lsa   = lsaonly  ~= nil or (samronly == nil and lsaonly == nil)

	-- Try enumerating through LSA first. Since LSA provides less information, we want the
	-- SAMR result to overwrite it. 
	if(do_lsa) then
		lsa_status, lsa_result  = enum_lsa(host)
		if(lsa_status == false) then
			if(nmap.debugging() > 0) then
				response = response .. "ERROR: Couldn't enumerate through LSA: " .. lsa_result .. "\n"
			end
		else
			-- Copy the returned array into the names[] table, using the name as the key
			stdnse.print_debug(2, "EnumUsers: Received %d names from LSA", #lsa_result)
			for i = 1, #lsa_result, 1 do
				if(lsa_result[i]['name'] ~= nil) then
					names[string.upper(lsa_result[i]['name'])] = lsa_result[i]
				end
			end
		end
	end

	-- Try enumerating through SAMR
	if(do_samr) then
		samr_status, samr_result = enum_samr(host)
		if(samr_status == false) then
			if(nmap.debugging() > 0) then
				response = response .. "ERROR: Couldn't enumerate through SAMR: " .. samr_result .. "\n"
			end
		else
			-- Copy the returned array into the names[] table, using the name as the key
			stdnse.print_debug(2, "EnumUsers: Received %d names from SAMR", #samr_result)
			for i = 1, #samr_result, 1 do
				names[string.upper(samr_result[i]['name'])] = samr_result[i]
			end
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
		response = response .. "Couldn't find any account names anonymously, sorry!"
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
				if(names[name]['flags'] ~= nil)       then response = response .. string.format("  |_ Flags: %s\n",       stdnse.strjoin(", ", names[name]['flags'])) end

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

