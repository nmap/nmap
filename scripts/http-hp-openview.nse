local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

-- install this script in the /usr/share/nmap/scripts folder and then run
-- nmap -script-update as root
-- should auto-run when it detects ports 383,3013 or 3565 open
-- atm it pukes up a bunch of HTML which is horrible :(
-- version 0.01


description = [[
Attempts to retrieve the details from a HP Openview BBC web server.
]]

---
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-HP-Openview BBC: ton of junk atm
-- | 
-- |_need to do some tidying up cause its just html crazy


author = "freakyclown"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.portnumber({383,3013,3565}, "tcp")

action = function(host, port)
	local response
 	response = http.get(host, port, "/Hewlett-Packard/OpenView/BBC/version?html")
	return response
end
