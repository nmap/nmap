id = "MSRPC: List of user accounts"
description = [[
Attempts to enumerate the users on a remote Windows system, with as much
information as possible, through a variety of techniques (over SMB + MSRPC,
which uses port 445 or 139).
\n\n
Will first attempt to call the QueryDisplayInfo() MSRPC function. If NULL
sessions are enabled, this will succeed and pull back a detailed list of users.
Unfortunately, this likely won't succeed unless we're scanning Windows 2000.
When this test is performed, the following MSRPC functions are called:\n
Bind() -- bind to the SAMR service\n
Connect4() -- get a connect_handle\n
EnumDomains() -- get a list of the domains\n
QueryDomain() -- get the sid for the domain\n
OpenDomain() -- get a handle for each domain\n
QueryDisplayInfo() -- get the list of users in the domain\n
Close() -- Close the domain handle\n
Close() -- Close the connect handle
\n\n
Credit goes out to the enum.exe program, the code I wrote for this is largely
due to packetlogs I took of its operations.
\n\n
Regardless of whether or not this succeeds, a second technique is used to pull
user accounts. This one is apparently successful against more machines,
although I haven't found a machine that this only works against. However, I did
find that this will turn up more users for certain systems (although I haven't
figured out why).
\n\n
Each user on a Windows system has an RID. The RID of 500 is the Administrator
account (even if it's renamed), 501 is the Guest account, and 1000+ are the
user accounts. This technique, which was originally used in the
sid2user/user2sid programs, will attempt to convert common RID numbers to names
to discover users.
\n\n
First, the SID of the server has to be determined. This is done by looking up
any name present on the server using a technique like user2sid. For this code,
we try and convert as many names as we can find -- all we need is one valid
name for this to succeed. In this code, I use:\n
- The computer name / domain name, returned in SMB_COM_NEGOTIATE\n
- An nbstat query to get the server name and the currently loggeed in user\n
- Some common names ("administrator", "guest", and "test")
\n\n
In theory, the computer name should be sufficient for this to always work, and
the rest of the names are in there for good measure.
\n\n
Once that's completed, the RIDs 500 - 505 are requested, and any responses are
displayed. Then, starting at 1000, we take small groups of RIDs which are
requestd. I break them into smaller groups because if too many are requested at
once, we get a STATUS_BUFFER_OVERFLOW error. We try every RID up to 1100, then,
as soon as we get an empty group (5 RIDs in a row without a result), we stop.
\n\n
It might be a good idea to modify this, in the future, with some more
intelligence. For example, have it run until it get 5 groups in a row with no
results instead of going up to 1100. I performed a test on an old server we
have here with a lot of accounts, and I got these results: 500, 501, 1000,
1030, 1031, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063,
1064, 1065, 1066, 1067, 1070, 1075, 1081, 1088, 1090. The jump from 1000 to
1030 is quite large and can easily result in missing accounts.
\n\n
The disadvantage of using the user2sid/sid2user technique is that less
information is returned about the user.
\n\n
The names and details from both of these techniques are merged and displayed.
If the output is verbose, then as many details as possible are displayed,
otherwise only the list of usernames are displayed. The names are ordered
alphabetically.
]]

---
-- @usage
-- nmap --script smb-enumusers.nse -p445 <host>\n
-- sudo nmap -sU -sS --script smb-enumusers.nse -p U:137,T:139 <host>
--
-- @output
-- TODO
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

	local bind_result, connect4_result, enumdomains_result
	local connect_handle
	local status, socket
	local uid, tid, fid
	local response = {}

	-- Create the SMB session
	status, socket, uid, tid, fid = msrpc.start_smb(host, msrpc.SAMR_PATH)
	if(status == false) then
		return false, socket
	end

	-- Bind to SAMR service
	status, bind_result = msrpc.bind(socket, msrpc.SAMR_UUID, msrpc.SAMR_VERSION, nil, uid, tid, fid)
	if(status == false) then
		msrpc.stop_smb(socket, uid, tid)
		return false, bind_result
	end

	-- Call connect4()
	status, connect4_result = msrpc.samr_connect4(socket, host.ip, uid, tid, fid)
	if(status == false) then
		msrpc.stop_smb(socket, uid, tid)
		return false, connect4_result
	end

	-- Save the connect_handle
	connect_handle = connect4_result['connect_handle']

	-- Call EnumDomains()
	status, enumdomains_result = msrpc.samr_enumdomains(socket, connect_handle, uid, tid, fid)
	if(status == false) then
		msrpc.stop_smb(socket, uid, tid)
		return false, enumdomains_result
	end

	-- If no domains were returned, go back with an error
	if(#enumdomains_result['domains'] == 0) then
		msrpc.stop_smb(socket, uid, tid)
		return false, "Couldn't find any domains"
	end

	for i = 1, #enumdomains_result['domains'], 1 do

		local domain = enumdomains_result['domains'][i]
		-- We don't care about the 'builtin' domain
		if(domain ~= 'Builtin') then
			local sid
			local domain_handle
			local opendomain_result, querydisplayinfo_result

			-- Call LookupDomain()
			status, lookupdomain_result = msrpc.samr_lookupdomain(socket, connect_handle, domain, uid, tid, fid)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return false, lookupdomain_result
			end

			-- Save the sid
			sid = lookupdomain_result['sid']
	
			-- Call OpenDomain()
			status, opendomain_result = msrpc.samr_opendomain(socket, connect_handle, sid, uid, tid, fid)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return false, opendomain_result
			end

			-- Save the domain handle
			domain_handle = opendomain_result['domain_handle']
	
			-- Call QueryDisplayInfo()
			status, querydisplayinfo_result = msrpc.samr_querydisplayinfo(socket, domain_handle, uid, tid, fid)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return false, querydisplayinfo_result
			end

			-- Close the domain handle
			msrpc.samr_close(socket, domain_handle,  uid, tid, fid)

			-- Finally, fill in the response!
			for i = 1, #querydisplayinfo_result['details'], 1 do
				querydisplayinfo_result['details'][i]['domain'] = domain
				response[#response + 1] = querydisplayinfo_result['details'][i]
			end
		end -- Checking for 'builtin'
	end -- Domain loop

	-- Close the connect handle
	msrpc.samr_close(socket, connect_handle, uid, tid, fid)

	-- Stop the SAMR SMB
	msrpc.stop_smb(socket, uid, tid)

	return true, response
end

---Attempt to enumerate users through LSA methods. See the file description for more information. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error message. Otherwise, result is an
--        array of tables. Each table contains a 'name', 'domain', and 'rid'. 
local function enum_lsa(host)

	local status, socket
	local uid, tid, fid
	local response = {}

    -- Create the SMB session
    status, socket, uid, tid, fid, negotiate_result = msrpc.start_smb(host, msrpc.LSA_PATH)
    if(status == false) then
        return false, socket
    end

    -- Bind to LSA service
    status, bind_result = msrpc.bind(socket, msrpc.LSA_UUID, msrpc.LSA_VERSION, nil, uid, tid, fid)
    if(status == false) then
        msrpc.stop_smb(socket, uid, tid)
        return false, bind_result
    end

    -- Open the LSA policy
    status, openpolicy2_result = msrpc.lsa_openpolicy2(socket, host.ip, uid, tid, fid)
    if(status == false) then
        msrpc.stop_smb(socket, uid, tid)
        return false, openpolicy2_result
    end

    -- Start with some common names, as well as the name returned by the negotiate call
    names = {"administrator", "guest", "test", negotiate_result['domain'], negotiate_result['server'] }

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
    status, lookupnames2_result = msrpc.lsa_lookupnames2(socket, openpolicy2_result['policy_handle'], names, uid, tid, fid)
    if(status == false) then
        msrpc.stop_smb(socket, uid, tid)
        return false, lookupnames2_result
    end

    -- Loop through the domains returned and find teh users in each
    for i = 1, #lookupnames2_result['domains'], 1 do
        local domain = lookupnames2_result['domains'][i]['name']
        local sid    = lookupnames2_result['domains'][i]['sid']
        local rids   = { }
        local start  = 1000

        -- Start by looking up 500 - 505 (will likely be Administrator + guest)
        for j = 500, 505, 1 do 
			rids[#rids + 1] = j 
		end

        status, lookupsids2_result = msrpc.lsa_lookupsids2(socket, openpolicy2_result['policy_handle'], sid, rids, uid, tid, fid)
        if(status == false) then
            msrpc.stop_smb(socket, uid, tid)
            return false, lookupsids2_result
        end

		-- Put the details for each name into an array
		for j = 1, #lookupsids2_result['details'], 1 do
			if(lookupsids2_result['details'][j]['name'] ~= nil) then
				local result = {}
				result['name']   = lookupsids2_result['details'][j]['name']
				result['rid']    = 500 + j - 1
				result['domain'] = domain
				response[#response + 1] = result
			end
		end

        -- Now do groups of 5 users, until we get past 1100 and have an empty group
        repeat
            rids = {}
            for j = start, start + 4, 1 do 
				rids[#rids + 1] = j 
			end

			-- Try converting this group of RIDs into names
            status, lookupsids2_result = msrpc.lsa_lookupsids2(socket, openpolicy2_result['policy_handle'], sid, rids, uid, tid, fid)
            if(status == false) then
                msrpc.stop_smb(socket, uid, tid)
                return false, lookupsids2_result
            end

			-- Put the details for each name into an array
			for j = 1, #lookupsids2_result['details'], 1 do
				if(lookupsids2_result['details'][j]['name'] ~= nil) then
					local result = {}
					result['name']   = lookupsids2_result['details'][j]['name']
					result['rid']    = start + j - 1
					result['domain'] = domain
					response[#response + 1] = result
				end
			end

			-- Go to the next set of RIDs
            start = start + 5
        until #lookupsids2_result['names'] == 0 and start > 1100

    end

    -- Close the handle
    msrpc.lsa_close(socket, openpolicy2_result['policy_handle'], uid, tid, fid)

    msrpc.stop_smb(socket, uid, tid)

	return true, response
end



action = function(host)
	local i, j
	local status
	local samr_result, lsa_result
	local names = {}
	local name_strings = {}
	local response = " \n"

	-- Try enumerating through SAMR
	status, samr_result = enum_samr(host)
	if(status == false) then
		response = response .. "Enum via SAMR error: " .. samr_result .. "\n"
	else
		-- Copy the returned array into the names[] table, using the name as the key
		stdnse.print_debug("EnumUsers: Received %d names from SAMR", #samr_result)
		for i = 1, #samr_result, 1 do
			names[string.upper(samr_result[i]['name'])] = samr_result[i]
		end
	end

	-- Try enumerating through LSA
	status, lsa_result  = enum_lsa(host)
	if(status == false) then
		response = response .. "Enum via LSA error: " .. lsa_result .. "\n"
	else
		-- Copy the returned array into the names[] table, using the name as the key
		stdnse.print_debug("EnumUsers: Received %d names from LSA", #samr_result)
		for i = 1, #lsa_result, 1 do
			if(names[lsa_result[i]['name']] == nil) then
				names[string.upper(lsa_result[i]['name'])] = lsa_result[i]
			end
		end
	end

	-- Put the names into an array of strings, so we can sort them
	for name, details in pairs(names) do
		name_strings[#name_strings + 1] = name
	end
	-- Sort them
	table.sort(name_strings, function (a, b) return string.lower(a) < string.lower(b) end)

	-- Check if we actually got any names back
	if(#name_strings == 0) then
		response = response .. "Sorry, couldn't find any account names anonymously!"
	else
		-- If we're not verbose, just print out the names. Otherwise, print out everything we can
		if(nmap.verbosity() < 1) then
			response = response .. stdnse.strjoin(", ", name_strings)
		else
			for i = 1, #name_strings, 1 do
				local name = name_strings[i]
				response = response .. string.format("%s\n", names[name]['name'])
				if(names[name]['domain'] ~= nil)      then response = response .. string.format("  |_ Domain: %s\n",      names[name]['domain'])      end
				if(names[name]['rid'] ~= nil)         then response = response .. string.format("  |_ RID: %s\n",         names[name]['rid'])         end
				if(names[name]['fullname'] ~= nil)    then response = response .. string.format("  |_ Full name: %s\n",   names[name]['fullname'])    end
				if(names[name]['description'] ~= nil) then response = response .. string.format("  |_ Description: %s\n", names[name]['description']) end
				if(names[name]['flags'] ~= nil)       then response = response .. string.format("  |_ Flags: %s\n",       stdnse.strjoin(", ", names[name]['flags_list'])) end
			end
		end
	end

	return response
end


