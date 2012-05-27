local shortport = require "shortport"
local socks = require "socks"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Determines the supported authentication mechanisms of a remote SOCKS
proxy server.  Starting with SOCKS version 5 socks servers may support
authentication.  The script checks for the following authentication
types:
  0 - No authentication
  1 - GSSAPI
  2 - Username and password
]]

---
-- @usage
-- nmap -p 1080 <ip> --script socks-auth-info
--
-- @output
-- PORT     STATE SERVICE
-- 1080/tcp open  socks
-- | socks-auth-info:
-- |   No authentication 
-- |_  Username and password
--


author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}

portrule = shortport.port_or_service({1080, 9050}, {"socks", "socks5", "tor-socks"})

action = function(host, port)

	local helper = socks.Helper:new(host, port)
	local auth_methods = {}

	-- iterate over all authentication methods as the server only responds with
	-- a single supported one if we send a list.
	for _, method in pairs(socks.AuthMethod) do
		local status, response = helper:connect( method )
		if ( status ) then
			table.insert(auth_methods, helper:authNameByNumber(response.method))
		end
	end
	
	helper:close()
	if ( 0 == #auth_methods ) then return end
	return stdnse.format_output(true, auth_methods)
end
