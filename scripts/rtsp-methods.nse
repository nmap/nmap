local rtsp = require "rtsp"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Determines which methods are supported by the RTSP (real time streaming protocol) server.
]]

---
-- @usage
-- nmap -p 554 --script rtsp-methods <ip>
--
-- @output
-- PORT    STATE SERVICE
-- 554/tcp open  rtsp
-- | rtsp-methods: 
-- |_  DESCRIBE, SETUP, PLAY, TEARDOWN, OPTIONS
--
-- @args rtsp-methods.path the path to query, defaults to "*" which queries
--       the server itself, rather than a specific url.
--

--
-- Version 0.1
-- Created 23/10/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--
author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}


portrule = shortport.port_or_service(554, "rtsp", "tcp", "open")

action = function(host, port)
	local path = stdnse.get_script_args('rtsp-methods.path') or '*'
	local helper = rtsp.Helper:new(host, port)
	local status = helper:connect()
	if ( not(status) ) then
		stdnse.print_debug(2, "ERROR: Failed to connect to RTSP server")
		return
	end

	local response
	status, response = helper:options(path)
	helper:close()
	if ( status ) then
		return stdnse.format_output(true, response.headers['Public'])
	end
end
