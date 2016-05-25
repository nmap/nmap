local comm = require "comm"
local shortport = require "shortport"

description = [[
Checks for an identd (auth) server which is spoofing its replies.

Tests whether an identd (auth) server responds with an answer before
we even send the query.  This sort of identd spoofing can be a sign of
malware infection, though it can also be used for legitimate privacy
reasons.
]]

---
-- @output
-- PORT    STATE SERVICE REASON
-- 113/tcp open  auth    syn-ack
-- |_auth-spoof: Spoofed reply: 0, 0 : USERID : UNIX : OGJdvM

author = "Diman Todorov"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"malware", "safe"}


portrule = shortport.port_or_service(113, "auth")

action = function(host, port)
  local status, owner = comm.get_banner(host, port, {lines=1})

  if not status then
    return
  end

  return "Spoofed reply: " .. owner
end

