description = [[
Attempts to list shares using the <code>srvsvc.NetShareEnumAll</code> MSRPC function and
retrieve more information about them using <code>srvsvc.NetShareGetInfo</code>.

Running <code>NetShareEnumAll</code> will work anonymously against Windows 2000, and 
requires a user-level account on any other Windows version. Calling <code>NetShareGetInfo</code> 
requires an administrator account on every version of Windows I (Ron Bowes) tested. 

Although <code>NetShareEnumAll</code> is restricted on certain systems, making a connection to
a share to check whether or not it exists will always work. So, if <code>NetShareEnumAll</code> 
fails, a list of common shares will be checked. 

After a list of shares is found, we attempt to connect to each of them anonymously, which lets 
us divide them into the classes "anonymous" and "restricted." 

When possible, once the list of shares is determined, <code>NetShareGetInfo</code> is called 
to get additional information on them. Odds are this will fail, unless we're doing an authenticated 
test. 
]]

---
--@usage
-- nmap --script smb-enum-shares.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <host>
--
--@output
-- Standard:
-- |  smb-enum-shares:
-- |  Anonymous shares: IPC$
-- |_ Restricted shares: F$, ADMIN$, C$
--
-- Verbose:
-- Host script results:
-- |  smb-enum-shares: 
-- |  Anonymous shares:
-- |     IPC$
-- |     |_ Type: STYPE_IPC_HIDDEN
-- |     |_ Comment: Remote IPC
-- |     |_ Users: 1, Max: <unlimited>
-- |     |_ Path:
-- |     test
-- |     |_ Type: STYPE_DISKTREE
-- |     |_ Comment: This is a test share, with a maximum of 7 users
-- |     |_ Users: 0, Max: 7
-- |     |_ Path: C:\Documents and Settings\Ron\Desktop\test
-- |  Restricted shares:
-- |     ADMIN$
-- |     |_ Type: STYPE_DISKTREE_HIDDEN
-- |     |_ Comment: Remote Admin
-- |     |_ Users: 0, Max: <unlimited>
-- |     |_ Path: C:\WINNT
-- |     C$
-- |     |_ Type: STYPE_DISKTREE_HIDDEN
-- |     |_ Comment: Default share
-- |     |_ Users: 0, Max: <unlimited>
-- |_    |_ Path: C:\
-- 
-- @args smb* This script supports the <code>smbusername</code>,
-- <code>smbpassword</code>, <code>smbhash</code>, and <code>smbtype</code>
-- script arguments of the <code>smb</code> module.
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

---Attempts to enumerate the shares on a remote system using MSRPC calls. This will likely fail 
-- against a modern system, but will succeed against Windows 2000. 
--
--@param host The host object. 
--@return Status (true or false).
--@return List of shares (if status is true) or an an error string (if status is false).
local function samr_enum_shares(host)

	local status, smbstate
	local bind_result, netshareenumall_result
	local shares
	local i, v

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.SRVSVC_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate)
		return false, bind_result
	end

	-- Call netsharenumall
	status, netshareenumall_result = msrpc.srvsvc_netshareenumall(smbstate, host.ip)
	if(status == false) then
		smb.stop(smbstate)
		return false, netshareenumall_result
	end

	-- Stop the SMB session
	smb.stop(smbstate)

	-- Convert the share list to an array
	shares = {}
	for i, v in pairs(netshareenumall_result['ctr']['array']) do
		shares[#shares + 1] = v['name']
	end

	return true, shares
end

---Attempts to connect to a list of shares as the anonymous user, returning which ones
-- it has and doesn't have access to. 
--
--@param host   The host object.
--@param shares An array of shares to check.
--@return List of shares we're allowed to access.
--@return List of shares that exist but are denied to us.
function check_shares(host, shares)
	local smbstate
	local i
	local allowed_shares = {}
	local denied_shares = {}

	-- Begin the SMB session
	status, smbstate = smb.start(host)
	if(status == false) then
		return false, smbstate
	end

	-- Negotiate the protocol
	status, err = smb.negotiate_protocol(smbstate)
	if(status == false) then
		smb.stop(smbstate)
		return false, err
	end

	-- Start up a null session
	status, err = smb.start_session(smbstate, "", "", "", "", "LM")
	if(status == false) then
		smb.stop(smbstate)
		return false, err
	end

	-- Check for hosts that accept any share by generating a totally random name (we don't use a set
	-- name because then hosts could potentially fool us. Perhaps I'm in a paranoid mood today)
	local set = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
	local share = ""
	math.randomseed(os.time())
	for i = 1, 16, 1 do
		local random = math.random(#set)
		share = share .. string.sub(set, random, random)
	end

	share = string.format("%s", share)
	stdnse.print_debug(2, "EnumShares: Trying a random share to see if server responds properly: %s", share)
	status, err = smb.tree_connect(smbstate, share)
	if(status == false) then
		if(err == 0xc0000022 or err == 'NT_STATUS_ACCESS_DENIED') then
			return false, "Server doesn't return proper value for non-existent shares (returns ACCESS_DENIED)"
		end
	else
		-- If we were actually able to connect to this share, then there's probably a serious issue
		smb.tree_disconnect(smbstate)
		return false, "Server doesn't return proper value for non-existent shares (accepts the connection)"
	end

	-- Connect to the shares
	stdnse.print_debug(2, "EnumShares: Testing %d shares", #shares)
	for i = 1, #shares, 1 do

		-- Change the share to the '\\ip\share' format
		local share = string.format("%s", shares[i])

		-- Try connecting to the tree
		stdnse.print_debug(3, "EnumShares: Testing share %s", share)
		status, err = smb.tree_connect(smbstate, share)
		-- If it fails, checkwhy
		if(status == false) then
			-- If the result was ACCESS_DENIED, record it
			if(err == 0xc0000022 or err == 'NT_STATUS_ACCESS_DENIED') then
				stdnse.print_debug(3, "EnumShares: Access was denied")
				denied_shares[#denied_shares + 1] = shares[i]
			else
				-- If we're here, an error that we weren't prepared for came up. 
--				smb.stop(smbstate)
--				return false, string.format("Error while checking shares: %s", err)
			end
		else
			-- Add it to allowed shares
			stdnse.print_debug(3, "EnumShares: Access was granted")
			allowed_shares[#allowed_shares + 1] = shares[i]
			smb.tree_disconnect(smbstate)
		end
	end

	-- Log off the user
	smb.stop(smbstate)

    return true, allowed_shares, denied_shares
end

---Attempts to retrieve additional information about a share. Will fail unless we have 
-- administrative access. 
--
--@param host The host object. 
--@return Status (true or false).
--@return List of shares (if status is true) or an an error string (if status is false).
local function get_share_info(host, name)
	local status, smbstate
	local response = {}

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.SRVSVC_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate)
		return false, bind_result
	end

	-- Call NetShareGetInfo
	status, netsharegetinfo_result = msrpc.srvsvc_netsharegetinfo(smbstate, host.ip, name, 2)
	if(status == false) then
		smb.stop(smbstate)
		return false, netsharegetinfo_result
	end

	smb.stop(smbstate)

	return true, netsharegetinfo_result

end

action = function(host)

	local enum_result
	local result, shared
	local response = " \n"
	local shares = {}
	local allowed, denied

	-- Try and do this the good way, make a MSRPC call to get the shares
	enum_result, shares = samr_enum_shares(host)

	-- If that failed, try doing it with brute force. This almost certainly won't find everything, but it's the
	-- best we can do. 
	if(enum_result == false) then
		if(nmap.debugging() > 0) then
			response = response .. string.format("ERROR: Couldn't enum all shares, checking for common ones (%s)\n", shares)
		end

		-- Take some common share names I've seen
		shares = {"IPC$", "ADMIN$", "TEST", "TEST$", "HOME", "HOME$", "PORN", "PR0N", "PUBLIC", "PRINT", "PRINT$", "GROUPS", "USERS", "MEDIA", "SOFTWARE", "XSERVE", "NETLOGON", "INFO", "PROGRAMS", "FILES", "WWW", "STMP", "TMP", "DATA", "BACKUP", "DOCS", "HD", "WEBSERVER", "WEB DOCUMENTS", "SHARED"}

		-- Try every alphabetic share, with and without a trailing '$'
		for i = string.byte("A", 1), string.byte("Z", 1), 1 do
			shares[#shares + 1] = string.char(i)
			shares[#shares + 1] = string.char(i) .. "$"
		end
	end

	-- Break them into anonymous/authenticated shares
	status, allowed, denied = check_shares(host, shares)

	if(status == false) then
		if(enum_result == false) then
			-- At this point, we have nothing
			if(nmap.debugging() > 0) then
				return "ERROR: " .. allowed
			else
				return nil
			end
		else
			-- If we're here, we have a valid list of shares, but couldn't check them
			if(nmap.debugging() > 0) then
				return "ERROR: " .. allowed .. "\nShares found: " .. stdnse.strjoin(", ", shares)
			else
				return stdnse.strjoin(", ", shares)
			end
		end
	end

	if(result == false or nmap.verbosity() == 0) then
		return response .. string.format("Anonymous shares: %s\nRestricted shares: %s\n", stdnse.strjoin(", ", allowed), stdnse.strjoin(", ", denied))
	else
		response = response .. string.format("Anonymous shares:\n")
		for i = 1, #allowed, 1 do
			local status, info = get_share_info(host, allowed[i])

			response = response .. string.format("   %s\n", allowed[i])

			if(status == false) then
				stdnse.print_debug(2, "ERROR: Couldn't get information for share %s: %s", allowed[i], info)
			else
				info = info['info']

				if(info['max_users'] == 0xFFFFFFFF) then
					info['max_users'] = "<unlimited>"
				end

				response = response .. string.format("   |_ Type: %s\n",           msrpc.srvsvc_ShareType_tostr(info['sharetype']))
				response = response .. string.format("   |_ Comment: %s\n",        info['comment'])
				response = response .. string.format("   |_ Users: %s, Max: %s\n", info['current_users'], info['max_users'])
				response = response .. string.format("   |_ Path: %s\n",           info['path'])
			end
		end

		response = response .. string.format("Restricted shares:\n")
		for i = 1, #denied, 1 do
			local status, info = get_share_info(host, denied[i])

			response = response .. string.format("   %s\n", denied[i])

			if(status == false) then
				stdnse.print_debug(2, "ERROR: Couldn't get information for share %s: %s", denied[i], info)
			else
				info = info['info']
				if(info['max_users'] == 0xFFFFFFFF) then
					info['max_users'] = "<unlimited>"
				end

				response = response .. string.format("   |_ Type: %s\n",           msrpc.srvsvc_ShareType_tostr(info['sharetype']))
				response = response .. string.format("   |_ Comment: %s\n",        info['comment'])
				response = response .. string.format("   |_ Users: %s, Max: %s\n", info['current_users'], info['max_users'])
				response = response .. string.format("   |_ Path: %s\n",           info['path'])
			end
		end

		return response
	end
end


