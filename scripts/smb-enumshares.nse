--- Attempts to call the srvsvc.NetShareEnumAll() MSRPC function. This will
--  likely only work anonymously against Windows 2000. \n
--\n
-- There isn't a whole lot to say about this one. The sequence of calls after
-- the initial bind() is:\n
-- NetShareEnumAll()\n
--\n
-- Since NetShareEnumAll() only works anonymously, if it fails this will check
-- a handful of common shares. \n
--\n
-- Once it has a list of shares, whether it was pulled over MSRPC or guessed, 
-- we attempt to connect to each of them with a standard smb tree_connect request
-- over a null session. We record which ones succeeded and failed (that is, which
-- shares allowed for anonymous access).\n
--
--@usage
-- nmap --script smb-enumshares.nse -p445 <host>\n
-- sudo nmap -sU -sS --script smb-enumshares.nse -p U:137,T:139 <host>\n
--
--@output
-- Host script results:\n
-- TODO
-----------------------------------------------------------------------

id = "MSRPC: NetShareEnumAll()"
description = "Tries calling the NetShareEnumAll() RPC function, and guessing shares"
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

---Attempts to enumerate the shares on a remote system using MSRPC calls. This will likely fail 
-- against a modern system, but will succeed against Windows 2000. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error string. Otherwise, result is 
--        a list of all shares on a system. 
local function samr_enum_shares(host)

	local status, socket, uid, tid, fid
	local bind_result, netshareenumall_result

	-- Create the SMB session
	status, socket, uid, tid, fid = msrpc.start_smb(host, msrpc.SRVSVC_PATH)
	if(status == false) then
		return false, socket
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(socket, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil, uid, tid, fid)
	if(status == false) then
		smb.stop(socket)
		return false, bind_result
	end

	-- Call netsharenumall
	status, netshareenumall_result = msrpc.srvsvc_netshareenumall(socket, host.ip, uid, tid, fid)
	if(status == false) then
		smb.stop(socket)
		return false, netshareenumall_result
	end

	-- Stop the SMB session
	smb.stop(socket, uid, tid)

	return true, netshareenumall_result['shares']
end

---Attempts to connect to a list of shares as the anonymous user, returning which ones
-- it has and doesn't have access to. 
--
--@param host   The host object
--@param shares An array of shares to check
--@return (allowed_shares, denied_shares) Lists of shares we can and can't access, 
--        but all of which exist. 
function check_shares(host, shares)
    local i
    local allowed_shares = {}
    local denied_shares = {}

	-- Begin the SMB session
	status, socket = smb.start(host)
	if(status == false) then
		return false, socket
	end

	-- Negotiate the protocol
	status, negotiate_result = smb.negotiate_protocol(socket)
	if(status == false) then
		smb.stop(socket)
		return false, negotiate_result
	end

	-- Start up a null session
	status, session_result = smb.start_session(socket, "", negotiate_result['session_key'], negotiate_result['capabilities'])
	if(status == false) then
		smb.stop(socket)
		return false, session_result
	end

	-- Connect to the shares
	stdnse.print_debug(2, "EnumShares: Testing %d shares", #shares)
    for i = 1, #shares, 1 do

		-- Change the share to the '\\ip\share' format
        local share = string.format("\\\\%s\\%s", host.ip, shares[i])

		-- Try connecting to the tree
		stdnse.print_debug(3, "EnumShares: Testing share %s", share)
        status, tree_result = smb.tree_connect(socket, share, session_result['uid'])
		-- If it fails, checkwhy
        if(status == false) then
			-- If the result was ACCESS_DENIED, record it
            if(tree_result == 0xc0000022 or tree_result == 'NT_STATUS_ACCESS_DENIED') then
				stdnse.print_debug(3, "EnumShares: Access was denied")
                denied_shares[#denied_shares + 1] = shares[i]
			else
				stdnse.print_debug(3, "EnumShares: Share didn't pan out: %s", tree_result)
            end
        else
			-- Add it to allowed shares
			stdnse.print_debug(3, "EnumShares: Access was granted")
            allowed_shares[#allowed_shares + 1] = shares[i]
            smb.tree_disconnect(socket, session_result['uid'], tree_result['tid'])
        end
    end

	-- Log off the user
	smb.stop(socket, session_result['uid'])

    return allowed_shares, denied_shares
end


action = function(host)
	local result, shared
	local response = " \n"
	local shares = {}
	local allowed, denied

	-- Try and do this the good way, make a MSRPC call to get the shares
	result, shares = samr_enum_shares(host)

	-- If that failed, try doing it with brute force. This almost certainly won't find everything, but it's the
	-- best we can do. 
	if(result == false) then
		response = response .. string.format("Couldn't enum all shares, checking for common ones (%s)\n", shares)
		-- Take some common share names I've seen
		shares = {"IPC$", "ADMIN$", "TEST", "TEST$", "HOME", "HOME$"}
		-- Try every alphabetic share, with and without a trailing '$'
		for i = string.byte("A", 1), string.byte("Z", 1), 1 do
			shares[#shares + 1] = string.char(i)
			shares[#shares + 1] = string.char(i) .. "$"
		end
	end

	-- Break them into anonymous/authenticated shares
	allowed, denied = check_shares(host, shares)

	return response .. string.format("Anonymous shares: %s\nRestricted shares: %s\n", stdnse.strjoin(", ", allowed), stdnse.strjoin(", ", denied))
end


