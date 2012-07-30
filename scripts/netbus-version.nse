local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extends version detection to detect NetBuster, a honeypot service
that mimes NetBus.
]]

---
-- @usage
-- nmap -sV -p 12345 --script netbus-version <target>
--
-- @output
-- 12345/tcp open  netbus  Netbuster (honeypot)

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"version"}


portrule = shortport.version_port_or_service ({}, "netbus", {"tcp"})

action = function( host, port )

	local socket = nmap.new_socket()
	socket:set_timeout(5000)
	local status, err = socket:connect(host.ip, port.number)
	if not status then
		return
	end
	local buffer, _ = stdnse.make_buffer(socket, "\r")
	buffer() --discard banner
	socket:send("Password;0;\r")

	--NetBus answers to auth
	if buffer() ~= nil then
		return
	end

	--NetBuster does not
	port.version.name = "netbus"
	port.version.product = "NetBuster"
	port.version.extrainfo = "honeypot"
	port.version.version = nil
	nmap.set_port_version(host, port)
	return
end


