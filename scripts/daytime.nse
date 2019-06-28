local comm = require "comm"
local shortport = require "shortport"
local oops = require "oops"

description = [[
Retrieves the day and time from the Daytime service.
]]

---
-- @output
-- PORT   STATE SERVICE
-- 13/tcp open  daytime
-- |_daytime: Wed Mar 31 14:48:58 MDT 2010

author = "Diman Todorov"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}


portrule = shortport.port_or_service(13, "daytime", {"tcp", "udp"})

action = function(host, port)
  return oops.output(comm.exchange(host, port, "dummy", {lines=1}))
end
