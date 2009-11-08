description = [[
Attempts to list shares using the <code>srvsvc.NetShareEnumAll</code> MSRPC function and
retrieve more information about them using <code>srvsvc.NetShareGetInfo</code>. If access
to those functions is denied, a list of common share names are checked. 

Finding open shares is useful to a penetration tester because there may be private files
shared, or, if it's writable, it could be a good place to drop a Trojan or to infect a file
that's already there. Knowing where the share is could make those kinds of tests more useful, 
except that determiing where the share is requires administrative privileges already. 

Running <code>NetShareEnumAll</code> will work anonymously against Windows 2000, and 
requires a user-level account on any other Windows version. Calling <code>NetShareGetInfo</code> 
requires an administrator account on all versions of Windows up to 2003, as well as Windows Vista
and Windows 7, if UAC is turned down. 

Even if <code>NetShareEnumAll</code> is restricted, attempting to connect to a share will always
reveal its existence. So, if <code>NetShareEnumAll</code> fails, a pre-generated list of shares,
based on a large test network, are used. If any of those succeed, they are recorded. 

After a list of shares is found, the script attempts to connect to each of them anonymously, 
which divides them into "anonymous", for shares that the NULL user can connect to, or "restricted",
for shares that require a user account. 
]]

---
--@usage
-- nmap --script smb-enum-shares.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- |  smb-enum-shares:  
-- |  ADMIN$
-- |  |_ Type: STYPE_DISKTREE_HIDDEN
-- |  |_ Comment: Remote Admin
-- |  |_ Users: 0, Max: <unlimited>
-- |  |_ Path: C:\WINNT
-- |  |_ Anonymous access: <none>
-- |  |_ Current user ('test') access: READ/WRITE
-- |  C$
-- |  |_ Type: STYPE_DISKTREE_HIDDEN
-- |  |_ Comment: Default share
-- |  |_ Users: 0, Max: <unlimited>
-- |  |_ Path: C:\
-- |  |_ Anonymous access: <none>
-- |  |_ Current user ('test') access: READ
-- |  IPC$
-- |  |_ Type: STYPE_IPC_HIDDEN
-- |  |_ Comment: Remote IPC
-- |  |_ Users: 1, Max: <unlimited>
-- |  |_ Path: 
-- |  |_ Anonymous access: READ <not a file share>
-- |  |_ Current user ('test') access: READ <not a file share>
-- |  test
-- |  |_ Type: STYPE_DISKTREE
-- |  |_ Comment: This is a test share, with a maximum of 7 users
-- |  |_ Users: 0, Max: 7
-- |  |_ Path: C:\Documents and Settings\Ron\Desktop\test
-- |  |_ Anonymous access: <none>
-- |_ |_ Current user ('test') access: READ/WRITE

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

local function go(host)
	local status, shares, extra
	local response = " \n"

	-- Get the list of shares
	status, shares, extra = smb.share_get_list(host)
	if(status == false) then
		return false, string.format("Couldn't enumerate shares: %s", shares)
	end

	-- Find out who the current user is
	local result, username, domain = smb.get_account(host)
	if(result == false) then
		username = "<unknown>"
		domain = ""
	end

	if(extra ~= nil) then
		response = response .. extra .. "\n"
	end

	for i = 1, #shares, 1 do
		local share = shares[i]

		-- Start generating a human-readable string
		response = response .. share['name'] .. "\n"
	
		if(type(share['details']) ~= 'table') then 
			response = response .. string.format("|_ Couldn't get details for share: %s\n", share['details'])
		else
			local details = share['details']

			response = response .. string.format("|_ Type: %s\n",           details['sharetype'])
			response = response .. string.format("|_ Comment: %s\n",        details['comment'])
			response = response .. string.format("|_ Users: %s, Max: %s\n", details['current_users'], details['max_users'])
			response = response .. string.format("|_ Path: %s\n",           details['path'])
		end
		
	
		-- A share of 'NT_STATUS_OBJECT_NAME_NOT_FOUND' indicates this isn't a fileshare
		if(share['user_can_write'] == "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
			-- Print details for a non-file share
			if(share['anonymous_can_read']) then
				response = response .. "|_ Anonymous access: READ <not a file share>\n"
			else
				response = response .. "|_ Anonymous access: <none> <not a file share>\n"
			end

			-- Don't bother printing this if we're already anonymous
			if(username ~= '') then
				if(share['user_can_read']) then
					response = response .. "|_ Current user ('" .. username .. "') access: READ <not a file share>\n"
				else
					response = response .. "|_ Current user ('" .. username .. "') access: <none> <not a file share>\n"
				end
			end
		else
			-- Print details for a file share
			if(share['anonymous_can_read'] and share['anonymous_can_write']) then
				response = response .. "|_ Anonymous access: READ/WRITE\n"
			elseif(share['anonymous_can_read'] and not(share['anonymous_can_write'])) then
				response = response .. "|_ Anonymous access: READ\n"
			elseif(not(share['anonymous_can_read']) and share['anonymous_can_write']) then
				response = response .. "|_ Anonymous access: WRITE\n"
			else
				response = response .. "|_ Anonymous access: <none>\n"
			end



			if(username ~= '') then
				if(share['user_can_read'] and share['user_can_write']) then
					response = response .. "|_ Current user ('" .. username .. "') access: READ/WRITE\n"
				elseif(share['user_can_read'] and not(share['user_can_write'])) then
					response = response .. "|_ Current user ('" .. username .. "') access: READ\n"
				elseif(not(share['user_can_read']) and share['user_can_write']) then
					response = response .. "|_ Current user ('" .. username .. "') access: WRITE\n"
				else
					response = response .. "|_ Current user ('" .. username .. "') access: <none>\n"
				end
			end
		end
	end

	return true, response
end


action = function(host)
	local status, result

	status, result = go(host)

	if(status == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. result
		end
	else
		return result
	end
end



