local afp = require "afp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Shows AFP shares and ACLs.
]]

---
--
--@output
-- PORT    STATE SERVICE
-- 548/tcp open  afp
-- | afp-showmount:  
-- |   Yoda's Public Folder
-- |     Owner: Search,Read,Write
-- |     Group: Search,Read
-- |     Everyone: Search,Read
-- |     User: Search,Read
-- |   Vader's Public Folder
-- |     Owner: Search,Read,Write
-- |     Group: Search,Read
-- |     Everyone: Search,Read
-- |     User: Search,Read
-- |_    Options: IsOwner

-- Version 0.4
-- Created 01/03/2010 - v0.1 - created by Patrik Karlsson
-- Revised 01/13/2010 - v0.2 - Fixed a bug where a single share wouldn't show due to formatting issues
-- Revised 01/20/2010 - v0.3 - removed superflous functions
-- Revised 05/03/2010 - v0.4 - cleaned up and added dependency to afp-brute and added support for credentials
--                             by argument or registry


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


dependencies = {"afp-brute"}

portrule = shortport.portnumber(548, "tcp")

action = function(host, port)

	local status, response, shares
	local result = {}
	local afpHelper = afp.Helper:new()
	local args = nmap.registry.args
	local users = nmap.registry.afp or { ['nil'] = 'nil' }

	if ( args['afp.username'] ) then
		users = {}
		users[args['afp.username']] = args['afp.password']
	end	

	for username, password in pairs(users) do

		status, response = afpHelper:OpenSession(host, port)
		if ( not status ) then
			stdnse.print_debug(response)
			return
		end

		-- if we have a username attempt to authenticate as the user
		-- Attempt to use No User Authentication?
		if ( username ~= 'nil' ) then
			status, response = afpHelper:Login(username, password)
		else
			status, response = afpHelper:Login()
		end

		if ( not status ) then
			stdnse.print_debug("afp-showmount: Login failed", response)
			stdnse.print_debug(3, "afp-showmount: Login error: %s", response)
			return
		end

		status, shares = afpHelper:ListShares()

		if status then
			for _, vol in ipairs( shares ) do
				local status, response = afpHelper:GetSharePermissions( vol )
				if status then
					response.name = vol
					table.insert(result, response)
				end
			end
		end

		status, response = afpHelper:Logout()
		status, response = afpHelper:CloseSession()

		if ( result ) then
			return stdnse.format_output(true, result)
		end
	end
	return
end
