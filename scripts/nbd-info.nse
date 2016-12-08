local nbd = require "nbd"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
]]

---
-- @usage nmap -p 10809 --script nbd-info.nse <target>
--

author = "Mak Kolybabi <mak@kolybabi.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

portrule = shortport.version_port_or_service(10809, "nbd", "tcp")

action = function(host, port)
  return nbd.connect(host, port)
end
