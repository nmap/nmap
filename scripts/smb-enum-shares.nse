local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

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
-- |  |  ADMIN$
-- |  |  |  Type: STYPE_DISKTREE_HIDDEN
-- |  |  |  Comment: Remote Admin
-- |  |  |  Users: 0, Max: <unlimited>
-- |  |  |  Path: C:\WINNT
-- |  |  |  Anonymous access: <none>
-- |  |  |_ Current user ('administrator') access: READ/WRITE
-- |  |  C$
-- |  |  |  Type: STYPE_DISKTREE_HIDDEN
-- |  |  |  Comment: Default share
-- |  |  |  Users: 0, Max: <unlimited>
-- |  |  |  Path: C:\
-- |  |  |  Anonymous access: <none>
-- |  |  |_ Current user ('administrator') access: READ
-- |  |  IPC$
-- |  |  |  Type: STYPE_IPC_HIDDEN
-- |  |  |  Comment: Remote IPC
-- |  |  |  Users: 1, Max: <unlimited>
-- |  |  |  Path:
-- |  |  |  Anonymous access: READ <not a file share>
-- |_ |_ |_ Current user ('administrator') access: READ <not a file share>
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}


hostrule = function(host)
	return smb.get_port(host) ~= nil
end

action = function(host)
	local status, shares, extra
	local response = {}

	-- Get the list of shares
	status, shares, extra = smb.share_get_list(host)
	if(status == false) then
		return stdnse.format_output(false, string.format("Couldn't enumerate shares: %s", shares))
	end

	-- Find out who the current user is
	local result, username, domain = smb.get_account(host)
	if(result == false) then
		username = "<unknown>"
		domain = ""
	end

	if(extra ~= nil and extra ~= '') then
		table.insert(response, extra)
	end

	for i = 1, #shares, 1 do
		local share = shares[i]
		local share_output = {}
		share_output['name'] = share['name']

		if(type(share['details']) ~= 'table') then 
			share_output['warning'] = string.format("Couldn't get details for share: %s", share['details'])
		else
			local details = share['details']

			table.insert(share_output, string.format("Type: %s",           details['sharetype']))
			table.insert(share_output, string.format("Comment: %s",        details['comment']))
			table.insert(share_output, string.format("Users: %s, Max: %s", details['current_users'], details['max_users']))
			table.insert(share_output, string.format("Path: %s",           details['path']))
		end
		
	
		-- A share of 'NT_STATUS_OBJECT_NAME_NOT_FOUND' indicates this isn't a fileshare
		if(share['user_can_write'] == "NT_STATUS_OBJECT_NAME_NOT_FOUND") then
			-- Print details for a non-file share
			if(share['anonymous_can_read']) then
				table.insert(share_output, "Anonymous access: READ <not a file share>")
			else
				table.insert(share_output, "Anonymous access: <none> <not a file share>")
			end

			-- Don't bother printing this if we're already anonymous
			if(username ~= '') then
				if(share['user_can_read']) then
					table.insert(share_output, "Current user ('" .. username .. "') access: READ <not a file share>")
				else
					table.insert(share_output, "Current user ('" .. username .. "') access: <none> <not a file share>")
				end
			end
		else
			-- Print details for a file share
			if(share['anonymous_can_read'] and share['anonymous_can_write']) then
				table.insert(share_output, "Anonymous access: READ/WRITE")
			elseif(share['anonymous_can_read'] and not(share['anonymous_can_write'])) then
				table.insert(share_output, "Anonymous access: READ")
			elseif(not(share['anonymous_can_read']) and share['anonymous_can_write']) then
				table.insert(share_output, "Anonymous access: WRITE")
			else
				table.insert(share_output, "Anonymous access: <none>")
			end

			if(username ~= '') then
				if(share['user_can_read'] and share['user_can_write']) then
					table.insert(share_output, "Current user ('" .. username .. "') access: READ/WRITE")
				elseif(share['user_can_read'] and not(share['user_can_write'])) then
					table.insert(share_output, "Current user ('" .. username .. "') access: READ")
				elseif(not(share['user_can_read']) and share['user_can_write']) then
					table.insert(share_output, "Current user ('" .. username .. "') access: WRITE")
				else
					table.insert(share_output, "Current user ('" .. username .. "') access: <none>")
				end
			end
		end

		table.insert(response, share_output)
	end

	return stdnse.format_output(true, response)
end

