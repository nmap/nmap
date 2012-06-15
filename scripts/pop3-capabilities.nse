local pop3 = require "pop3"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

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


portrule = shortport.port_or_service({110,995},{"pop3","pop3s"})

action = function(host, port)
	local capa, err = pop3.capabilities(host, port)
	if type(capa) == "table" then
 		-- Convert the capabilities table into an array of strings.
		local capstrings = {}
		for cap, args in pairs(capa) do
			if ( #args > 0 ) then
				table.insert(capstrings, ("%s(%s)"):format(cap, stdnse.strjoin(" ", args)))
			else
				table.insert(capstrings, cap)
			end
     	end
		return stdnse.strjoin(" ", capstrings)
	elseif type(err) == "string" then
		stdnse.print_debug(1, "%s: '%s' for %s", SCRIPT_NAME, err, host.ip)
		return
	else
		return "server doesn't support CAPA"
	end
end
