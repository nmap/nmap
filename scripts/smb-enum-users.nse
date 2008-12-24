description = [[
Attempts to enumerate the users on a remote Windows system, with as much
information as possible, through two different techniques (both over MSRPC,
which uses port 445 or 139). Some SAMR functions are used to enumerate users, 
and bruteforce LSA guessing is attempted. 

By default, both SAMR enumeration and LSA bruteforcing are used; however, these
can be fine tuned using Nmap parameters. For the most possible information, 
leave the defaults; however, there are advantages to using them individually. 

Advantages of using SAMR enumeration:
* Stealthier (requires one packet/user account, whereas LSA uses at least 10
  packets while SAMR uses half that; additionally, LSA makes a lot of noise in 
  the Windows event log (LSA enumeration is the only script I (Ron Bowes) have 
  been called on by the administrator of a box I was testing against). 
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

To do this, the script breaks users into groups of RIDs based on the <code>LSA_GROUPSIZE</code>
constant. All members of this group are checked simultaneously, and the responses recorded. 
When a series of empty groups are found (<code>LSA_MINEMPTY</code> groups, specifically), 
the scan ends. As long as you are getting a few groups with active accounts, the scan will
continue. 

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
		lsa_status, lsa_result  = msrpc.lsa_enum_users(host)
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
		samr_status, samr_result = msrpc.samr_enum_users(host)
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

