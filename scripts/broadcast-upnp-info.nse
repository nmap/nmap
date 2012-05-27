local stdnse = require "stdnse"
local upnp = require "upnp"

description = [[
Attempts to extract system information from the UPnP service by sending a multicast query, then collecting, parsing, and displaying all responses.
]]

---
-- @output
-- | broadcast-upnp-info: 
-- |   1.2.3.50
-- |       Debian/4.0 DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.0
-- |       Location:  http://1.2.3.50:8200/rootDesc.xml
-- |       Webserver:  Debian/4.0 DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.0
-- |       Name: BUBBA|TWO DLNA Server
-- |       Manufacturer: Justin Maggard
-- |       Model Descr: MiniDLNA on Debian
-- |       Model Name: Windows Media Connect compatible (MiniDLNA)
-- |       Model Version: 1
-- |   1.2.3.114
-- |       Linux/2.6 UPnP/1.0 KDL-32EX701/1.7
-- |       Location:  http://1.2.3.114:52323/dmr.xml
-- |       Webserver:  Linux/2.6 UPnP/1.0 KDL-32EX701/1.7
-- |       Name: BRAVIA KDL-32EX701
-- |       Manufacturer: Sony Corporation
-- |_      Model Name: KDL-32EX701

-- Version 0.1

-- Created 10/29/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

---
-- Sends UPnP discovery packet to host, 
-- and extracts service information from results
action = function()
	local helper = upnp.Helper:new()
	helper:setMulticast(true)
	local status, result = helper:queryServices()
	
	if ( status ) then
		return stdnse.format_output(true, result)
	end
end

