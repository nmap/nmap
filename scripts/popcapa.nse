id = "POP3 Capabilites"
description = [[
Retrieves POP3 server capabilities.
]]

---
-- @output
-- 110/tcp open  pop3
-- |_ POP3 Capabilites:  USER CAPA RESP-CODES UIDL PIPELINING STLS TOP SASL(PLAIN)

author = "Philip Pickering <pgpickering@gmail.com>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default"}

require 'pop3'
require 'shortport'

portrule = shortport.port_or_service({110}, "pop3")

action = function(host, port)
  local capa = pop3.capabilities(host, port)
  if capa then 
     local capstr = ""
     local cap, args
     for cap, args in pairs(capa) do
	capstr = capstr .. " " .. cap
	if type(args) == "string" then capstr = capstr .. "(" .. args .. ")" end
	if type(args) == "table" then
	   local arg
	   capstr = capstr .. "("
	   for i, arg in ipairs(args) do
	      capstr = capstr .. arg .. " "
	   end
	   capstr = string.sub(capstr, 1, #capstr - 1) .. ")"
	end
     end
     return capstr
  else
     return "server doesn't support CAPA"
  end
end
