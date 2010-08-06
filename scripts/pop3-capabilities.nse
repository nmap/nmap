description = [[
Retrieves POP3 email server capabilities.

POP3 capabilities are defined in RFC 2449. The CAPA command allows a client to
ask a server what commands it supports and possibly any site-specific policy.
Besides the list of supported commands, the IMPLEMENTATION string giving the
server version may be available.
]]

---
-- @output
-- 110/tcp open  pop3
-- |_ pop3-capabilities: USER CAPA RESP-CODES UIDL PIPELINING STLS TOP SASL(PLAIN)

author = "Philip Pickering"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default","discovery","safe"}

require 'pop3'
require 'shortport'
require 'stdnse'

portrule = shortport.port_or_service({110,995},{"pop3","pop3s"})

action = function(host, port)
  local capa, err = pop3.capabilities(host, port)
  if type(capa) == "table" then
     -- Convert the capabilities table into an array of strings.
     local capstrings = {}
     local cap, args
     for cap, args in pairs(capa) do
	local capstr = cap
	if type(args) == "string" then capstr = capstr .. "(" .. args .. ")" end
	if type(args) == "table" then
	   local arg
	   capstr = capstr .. "("
	   for i, arg in ipairs(args) do
	      capstr = capstr .. arg .. " "
	   end
	   capstr = string.sub(capstr, 1, #capstr - 1) .. ")"
	end
	table.insert(capstrings, capstr)
     end
     return stdnse.strjoin(" ", capstrings)
  elseif type(err) == "string" then
     stdnse.print_debug(1, "%s: '%s' for %s", SCRIPT_NAME, err, host.ip)
     return
  else
     return "server doesn't support CAPA"
  end
end
