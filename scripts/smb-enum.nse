--- Attempts to enumerate users and shares anonymously over SMB. 
--
-- First, it logs in as the anonymous user and tries to connect to IPC$. 
-- If it is successful, it knows that Null sessions are enabled. If it
-- is unsuccessful, it can still check for shares (because Windows is 
-- cool like that). A list of common shares is checked (see the 'shares' 
-- variable) to see what anonymous can access. Either a successful result
-- is returned (has access), STATUS_ACCESS_DENIED is returned (exists but
-- anonymous can't access), or STATUS_BAD_NETWORK_NAME is returned (doesn't
-- exist). 
--
-- Next, the Guest account is attempted with a blank password. If it's
-- enabled, a message is displayed and shares that it has access to are 
-- checked the same as anonymous. 
--
-- Finally, the Administrator account is attempted with a blank password. 
-- Because Administrator can't typically be locked out, this should be
-- safe. That being said, it is possible to configure Administrator to 
-- be lockoutable, so watch out for that caveat. If you do lock yourself
-- out of Administrator, there's a bootdisk that can help. :)
--
-- If Administrator has a blank password, it often doesn't allow remote
-- logins, if this is the case, STATUS_ACCOUNT_RESTRICTION is returned
-- instead of STATUS_ACCESS_DENIED, so we know the account has no password. 
--
--@usage
-- nmap --script smb-enum.nse -p445 127.0.0.1\n
-- sudo nmap -sU -sS --script smb-enum.nse -p U:137,T:139 127.0.0.1\n
--
--@output
-- Host script results:
-- |  SMB Enumeration:  
-- |  Null sessions enabled
-- |  Anonymous shares found:  IPC$ 
-- |  Restricted shares found:  C$ TEST 
-- |  Guest account is enabled
-- |  Guest can access:  IPC$ TEST 
-- |  Administrator account has a blank password
-- |_ Administrator can access:  IPC$ C$ TEST 
-----------------------------------------------------------------------

id = "SMB Enumeration"
description = "Attempts to enumerate users and shares anonymously over SMB"
author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version","intrusive"}

require 'smb'

-- Shares to try connecting to as Null session / GUEST
local shares = {"IPC", "C", "D", "TEST", "SHARE", "HOME", "DFS", "COMCFG" }

hostrule = function(host)

	local port = smb.get_port(host)

	if(port == nil) then
		return false
	else
		return true
	end

end
--- Attempts to connect to a list of shares as the given UID, returning the
--  shares that it has and doesn't have access to. 
--@param socket The socket to use
--@param ip     The ip address of the host
--@param uid    The UserID we're logged in as
--@return (allowed_shares, denied_shares) Lists of shares we can and can't access, 
--        but all of which exist. 
function find_shares(socket, ip, uid)
	local i
	local allowed_shares = {}
	local denied_shares = {}
	

	for i = 1, #shares, 1 do

		local share = string.format("\\\\%s\\%s", ip, shares[i])

		status, tree_result = smb.tree_connect(socket, share, uid)
		if(status == false) then
			if(tree_result == 0xc0000022) then -- STATUS_ACCESS_DENIED
				denied_shares[#denied_shares + 1] = shares[i]
			end
		else
			allowed_shares[#allowed_shares + 1] = shares[i]
		end

		share = share .. "$"
		status, tree_result = smb.tree_connect(socket, share, uid)
		if(status == false) then
			if(tree_result == 0xc0000022) then -- STATUS_ACCESS_DENIED
				denied_shares[#denied_shares + 1] = shares[i] .. "$"
			end
		else
			allowed_shares[#allowed_shares + 1] = shares[i] .. "$"
		end
		
	end

	return allowed_shares, denied_shares
end

--- Join strings together with a space. 
function string_join(table)
	local i
	local response = " "

	for i = 1, #table, 1 do
		response = response .. table[i] .. " "
	end

	return response
end

action = function(host)
	local response = " \n"
	local status, socket, negotiate_result, session_result
	local allowed_shares, restricted_shares

	status, socket = smb.start(host)
	if(status == false) then
		return "ERROR: " .. socket
	end

	status, negotiate_result = smb.negotiate_protocol(socket)
	if(status == false) then
		smb.stop(socket)
		return "ERROR: " .. negotiate_result
	end

	-- Start up a null session
	status, session_result = smb.start_session(socket, "", negotiate_result['session_key'], negotiate_result['capabilities'])
	if(status == false) then
		smb.stop(socket)
		return "ERROR: " .. session_result
	end

	-- Check if null session has access to IPC$
	status, result = smb.tree_connect(socket, "IPC$", session_result['uid'])
	if(status == true) then
		response = response .. "Null sessions enabled\n"
	end

	-- Find shares
	allowed_shares, restricted_shares = find_shares(socket, host.ip, session_result['uid'])

	-- Display shares the Null user had access to
	if(#allowed_shares > 0) then
		response = response .. "Anonymous shares found: " .. string_join(allowed_shares) .. "\n"
	end

	-- Display shares the Null user didn't have access to
	if(#restricted_shares > 0) then
		response = response .. "Restricted shares found: " .. string_join(restricted_shares) .. "\n"
	end

	-- Check if Guest can log in
	status, session_result = smb.start_session(socket, "GUEST", negotiate_result['session_key'], negotiate_result['capabilities'])
	if(status == true) then
		response = response .. "Guest account is enabled\n"

		-- Find shares for Guest
		allowed_shares, restricted_shares = find_shares(socket, host.ip, session_result['uid'])

		-- Display shares Guest had access to
		if(#allowed_shares > 0) then
			response = response .. "Guest can access: " .. string_join(allowed_shares) .. "\n"
		end
	end

	-- Check if Administrator has a blank password
	-- (we check Administrator and not other accounts because Administrator can't generally be locked out)
	status, session_result = smb.start_session(socket, "ADMINISTRATOR", negotiate_result['session_key'], negotiate_result['capabilities'])
	if(status == true) then
		response = response .. "Administrator account has a blank password\n"

		-- Find shares for Administrator
		allowed_shares, restricted_shares = find_shares(socket, host.ip, session_result['uid'])

		-- Display shares administrator had access to
		if(#allowed_shares > 0) then
			response = response .. "Administrator can access: " .. string_join(allowed_shares) .. "\n"
		end
	elseif(session_result == 0xc000006e) then -- STATUS_ACCOUNT_RESTRICTION
		response = response .. "Administrator account has a blank password, but can't use SMB\n"
	end
	
	

	smb.stop(socket)
	return response
end


