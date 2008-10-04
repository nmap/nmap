--- Attempts to enumerate domains on a system, along with their policies. This will likely
-- only work without credentials against Windows 2000. \n
-- \n
-- After the initial bind() to SAMR, the sequence of calls is:\n
-- Connect4() -- get a connect_handle\n
-- EnumDomains() -- get a list of the domains (stop here if you just want the names)\n
-- QueryDomain() -- get the sid for the domain\n
-- OpenDomain() -- get a handle for each domain\n
-- QueryDomainInfo2() -- get the domain information\n
--
--@usage
-- nmap --script smb-enumdomains.nse -p445 <host>\n
-- sudo nmap -sU -sS --script smb-enumdomains.nse -p U:137,T:139 <host>\n
--
--@output
-- Host script results:
-- |  MSRPC: List of domains:\n
-- |  Domain: TEST1\n
-- |   |_ SID: S-1-5-21-1060284298-842925246-839522115\n
-- |   |_ Users: Administrator, ASPNET, Guest, Ron, test\n
-- |   |_ Creation time: 2006-10-17 15:35:07\n
-- |   |_ Min password length: 0 characters\n
-- |   |_ Max password age: 10675199 days\n
-- |   |_ Min password age: 0 days\n
-- |   |_ Password history length: 0 passwords\n
-- |   |_ Lockout threshold: 0 login attempts\n
-- |   |_ Lockout duration: 60 minutes\n
-- |   |_ Lockout window: 60 minutes\n
-- |   |_ Password properties: \n
-- |     |_  Password complexity requirements do not exist\n
-- |_    |_  Administrator account cannot be locked out\n

-----------------------------------------------------------------------

id = "MSRPC: List of domains"
description = "Tries calling the EnumDomains() and QueryDomainInfo2() RPC function to obtain a list of domains/policies."
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

action = function(host)
	local response = " \n"
	local status, socket
	local uid, tid, fid

	-- Create the SMB session
	status, socket, uid, tid, fid = msrpc.start_smb(host, msrpc.SAMR_PATH)
	if(status == false) then
		return "ERROR: " .. socket
	end

	-- Bind to SAMR service
	status, bind_result = msrpc.bind(socket, msrpc.SAMR_UUID, msrpc.SAMR_VERSION, nil, uid, tid, fid)
	if(status == false) then
		msrpc.stop_smb(socket, uid, tid)
		return "ERROR: " .. bind_result
	end

	-- Call connect4()
	status, connect4_result = msrpc.samr_connect4(socket, host.ip, uid, tid, fid)
	if(status == false) then
		msrpc.stop_smb(socket, uid, tid)
		return "ERROR: " .. connect4_result
	end

	-- Save the connect_handle
	connect_handle = connect4_result['connect_handle']

	-- Call EnumDomains()
	status, enumdomains_result = msrpc.samr_enumdomains(socket, connect_handle, uid, tid, fid)
	if(status == false) then
		msrpc.stop_smb(socket, uid, tid)
		return "ERROR: " .. enumdomains_result
	end

	-- If no domanis were returned, print an error (I don't expect this will actually happen)
	if(#enumdomains_result['domains'] == 0) then
		return "ERROR: Couldn't find any domains to check"
	end

	for i = 1, #enumdomains_result['domains'], 1 do

		local domain = enumdomains_result['domains'][i]
		-- We don't care about the 'builtin' domain
		if(domain ~= 'Builtin') then
			local sid
			local domain_handle

			-- Call LookupDomain()
			status, lookupdomain_result = msrpc.samr_lookupdomain(socket, connect_handle, domain, uid, tid, fid)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return "ERROR: " .. lookupdomain_result
			end

			-- Save the sid
			sid = lookupdomain_result['sid']
	
			-- Call OpenDomain()
			status, opendomain_result = msrpc.samr_opendomain(socket, connect_handle, sid, uid, tid, fid)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return "ERROR: " .. opendomain_result
			end

			-- Save the domain handle
			domain_handle = opendomain_result['domain_handle']
	
			-- Call QueryDomainInfo2() to get domain properties. We call these for three types == 1, 8, and 12, since those return
			-- the most useful information. 
			status, querydomaininfo2_result = msrpc.samr_querydomaininfo2(socket, domain_handle, 1, uid, tid, fid)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return "ERROR: " .. querydomaininfo2_result
			end
			status, querydomaininfo2_result = msrpc.samr_querydomaininfo2(socket, domain_handle, 8, uid, tid, fid, querydomaininfo2_result)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return "ERROR: " .. querydomaininfo2_result
			end
			status, querydomaininfo2_result = msrpc.samr_querydomaininfo2(socket, domain_handle, 12, uid, tid, fid, querydomaininfo2_result)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return "ERROR: " .. querydomaininfo2_result
			end

			-- Call EnumDomainUsers() to get users
			status, enumdomainusers_result = msrpc.samr_enumdomainusers(socket, domain_handle, uid, tid, fid)
			if(status == false) then
				msrpc.stop_smb(socket, uid, tid)
				return "ERROR: " .. enumdomainusers_result
			end

			-- Close the domain handle
			msrpc.samr_close(socket, domain_handle, uid, tid, fid)

			-- Finally, fill in the response!
			response = response .. string.format("Domain: %s\n", domain)
			response = response .. string.format(" |_ SID: %s\n",                               msrpc.sid_to_string(lookupdomain_result['sid']))
			response = response .. string.format(" |_ Users: %s\n",                             stdnse.strjoin(", ", enumdomainusers_result['names']))
			response = response .. string.format(" |_ Creation time: %s\n",                     querydomaininfo2_result['create_date'])
			response = response .. string.format(" |_ Min password length: %d characters\n",    querydomaininfo2_result['min_password_length'])
			response = response .. string.format(" |_ Max password age: %d days\n",             querydomaininfo2_result['max_password_age'])
			response = response .. string.format(" |_ Min password age: %d days\n",             querydomaininfo2_result['min_password_age'])
			response = response .. string.format(" |_ Password history length: %d passwords\n", querydomaininfo2_result['password_history_length'])
			response = response .. string.format(" |_ Lockout threshold: %d login attempts\n",  querydomaininfo2_result['lockout_threshold'])
			response = response .. string.format(" |_ Lockout duration: %d minutes\n",          querydomaininfo2_result['lockout_duration'])
			response = response .. string.format(" |_ Lockout window: %d minutes\n",            querydomaininfo2_result['lockout_window'])
			if(#querydomaininfo2_result['password_properties_list'] > 0) then
				response = response .. " |_ Password properties: \n   |_  " .. stdnse.strjoin("\n   |_  ", querydomaininfo2_result['password_properties_list']) .. "\n"
			end
		end
	end

	-- Close the connect handle
	msrpc.samr_close(socket, connect_handle, uid, tid, fid)

	-- Close the SMB session
	msrpc.stop_smb(socket, uid, tid)

	return response

end


