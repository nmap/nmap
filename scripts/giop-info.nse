local giop = require "giop"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Queries a CORBA naming server for a list of objects.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @output
-- PORT     STATE SERVICE              REASON
-- 1050/tcp open  java-or-OTGfileshare syn-ack
-- | giop-info:  
-- |   Object: Hello
-- |   Context: Test
-- |_  Object: GoodBye


-- Version 0.1

-- Created 07/08/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>


portrule = shortport.port_or_service( {2809,1050,1049} , "giop", "tcp", "open")

action = function(host, port)

	local helper = giop.Helper:new( host, port )
	local ctx, objs, status, err
	local result = {}
	
	status, err = helper:Connect()
	if ( not(status) ) then return err end

	status, ctx = helper:GetNamingContext()
	if ( not(status) ) then return "  \n  ERROR: " .. ctx end
	
	status, objs = helper:ListObjects(ctx)
	if ( not(status) ) then return "  \n  ERROR: " .. objs end
	
	for _, obj in ipairs( objs ) do 
		local tmp = ""
		
		if ( obj.enum == 0 ) then
			tmp = "Object: "
		elseif( obj.enum == 1 ) then
			tmp = "Context: "
		else
			tmp = "Unknown: "
		end
		
		table.insert(result, tmp .. obj.id ) 
	end
	
	return stdnse.format_output(true, result)
end
