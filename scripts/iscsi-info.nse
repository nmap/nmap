local iscsi = require "iscsi"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Collects and displays information from remote iSCSI targets.
]]

---
-- @output
-- PORT     STATE SERVICE
-- 3260/tcp open  iscsi
-- | iscsi-info: 
-- |   iqn.2006-01.com.openfiler:tsn.c8c08cad469d
-- |     Target address: 192.168.56.5:3260,1
-- |     Authentication: NOT required
-- |   iqn.2006-01.com.openfiler:tsn.6aea7e052952
-- |     Target address: 192.168.56.5:3260,1
-- |_    Authentication: required
-- 

-- Version 0.2
-- Created 2010/11/18 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 2010/11/28 - v0.2 - improved error handling <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe", "discovery"}


portrule = shortport.portnumber(3260, "tcp", {"open", "open|filtered"})

-- Attempts to determine whether authentication is required or not
--
-- @return status true on success false on failure
-- @return result true if auth is required false if not
--         err string containing error message
local function requiresAuth( host, port, target )
	local helper = iscsi.Helper:new( host, port )
	local errors = iscsi.Packet.LoginResponse.Errors
	
	local status, err = helper:connect()
	if ( not(status) ) then return false, "Failed to connect" end

	local response
	status, response = helper:login( target )
	if ( not(status) ) then return false, response:getErrorMessage() end

	if ( status and response:getErrorCode() == errors.SUCCESS) then
		-- try to logout
		status = helper:logout()
	end
	
	status = helper:close()

	return true, "Authentication successful"
end

action = function( host, port )

	local helper = iscsi.Helper:new( host, port )
	
	local status = helper:connect()
	if ( not(status) ) then
		stdnse.print_debug("%s: failed to connect to server", SCRIPT_NAME )
		return
	end

	local records
	status, records = helper:discoverTargets()
	if ( not(status) ) then
		stdnse.print_debug("%s: failed to discover targets", SCRIPT_NAME )
		return
	end
	status = helper:logout()
	status = helper:close()
	
	local result = {}
	for _, record in ipairs(records) do
		local result_part = {}
		result_part.name = ("Target: %s"):format(record.name)
		for _, addr in ipairs( record.addr ) do
			table.insert(result_part, ("Address: %s"):format(addr) )
		end
		
		local status, err = requiresAuth( host, port, record.name )
		if ( not(status) ) then
			table.insert(result_part, "Authentication: " .. err )
		else
			table.insert(result_part, "Authentication: No authentication required")
		end
		table.insert(result, result_part)
	end	
	return stdnse.format_output( true, result )
end
