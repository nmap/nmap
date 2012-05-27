local ncp = require "ncp"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Retrieves a list of all eDirectory users from the Novell NetWare Core Protocol (NCP) service.
]]

---
--
--@output
-- PORT    STATE SERVICE REASON
-- 524/tcp open  ncp     syn-ack
-- | ncp-enum-users: 
-- |   CN=admin.O=cqure
-- |   CN=cawi.OU=finance.O=cqure
-- |   CN=linux-l84tadmin.O=cqure
-- |   CN=nist.OU=hr.O=cqure
-- |   CN=novlxregd.O=cqure
-- |   CN=novlxsrvd.O=cqure
-- |   CN=OESCommonProxy_linux-l84t.O=cqure
-- |   CN=sasi.OU=hr.O=cqure
-- |_  CN=wwwrun.O=cqure
--

-- Version 0.1
-- Created 04/26/2011 - v0.1 - created by Patrik Karlsson

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth", "safe"}


portrule = shortport.port_or_service(524, "ncp", "tcp")

action = function(host, port)
	local helper = ncp.Helper:new(host,port)

	local status, resp = helper:connect()
	if ( not(status) ) then	return stdnse.format_output(false, resp) end

	status, resp = helper:search("[Root]", "User", "*")
	if ( not(status) ) then	return stdnse.format_output(false, resp) end
	
	local output = {}
	
	for _, entry in ipairs(resp) do
		table.insert(output, entry.name)
	end

	return stdnse.format_output(true, output)
end

