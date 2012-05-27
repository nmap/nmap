local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"

description = [[
Attempts to retrieve a list of usernames using the finger service.
]]

author = "Eddie Bell"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

---
-- @output
-- PORT   STATE SERVICE
-- 79/tcp open  finger
-- | finger:
-- | Welcome to Linux version 2.6.31.12-0.2-default at linux-pb94.site !
-- |  01:14am  up  18:54,  4 users,  load average: 0.14, 0.08, 0.01
-- |
-- | Login      Name                  Tty      Idle  Login Time   Where
-- | Gutek      Ange Gutek           *:0          -     Wed 06:19 console
-- | Gutek      Ange Gutek            pts/1   18:54     Wed 06:20
-- | Gutek      Ange Gutek           *pts/0       -     Thu 00:41
-- |_Gutek      Ange Gutek           *pts/4       3     Thu 01:06


portrule = shortport.port_or_service(79, "finger")

action = function(host, port)
	local try = nmap.new_try()

	return try(comm.exchange(host, port, "\r\n",
        	{lines=100, proto=port.protocol, timeout=5000}))
end
