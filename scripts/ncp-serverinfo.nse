local ncp = require "ncp"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Retrieves eDirectory server information (OS version, server name,
mounts, etc.) from the Novell NetWare Core Protocol (NCP) service.
]]

---
--
--@output
-- PORT    STATE SERVICE
-- 524/tcp open  ncp
-- | ncp-serverinfo: 
-- |   Server name: LINUX-L84T
-- |   Tree Name: IIT-LABTREE
-- |   OS Version: 5.70 (rev 7)
-- |   Product version: 6.50 (rev 7)
-- |   OS Language ID: 4
-- |   Addresses
-- |     10.0.200.33 524/udp
-- |     10.0.200.33 524/tcp
-- |   Mounts
-- |     SYS
-- |     ADMIN
-- |_    _ADMIN

-- Version 0.1
-- Created 04/26/2011 - v0.1 - created by Patrik Karlsson

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.port_or_service(524, "ncp", "tcp")

action = function(host, port)
	local helper = ncp.Helper:new(host,port)

	local status, resp = helper:connect()
	if ( not(status) ) then	return stdnse.format_output(false, resp) end

	status, resp = helper:getServerInfo()
	if ( not(status) ) then	return stdnse.format_output(false, resp) end
	
	helper:close()

	return stdnse.format_output(true, resp)
end
