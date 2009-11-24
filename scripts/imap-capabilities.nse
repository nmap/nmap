description = [[
Retrieves IMAP email server capabilities.

IMAP4rev1 capabilities are defined in RFC 3501. The CAPABILITY command
allows a client to ask a server what commands it supports and possibly
any site-specific policy.
]]

---
-- @output
-- 143/tcp open  imap
-- |_ imap-capabilities: LOGINDISABLED IDLE IMAP4 LITERAL+ STARTTLS NAMESPACE IMAP4rev1


author = "Brandon Enright"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "safe"}

require 'imap'
require 'shortport'
require 'stdnse'

portrule = shortport.port_or_service({143}, "imap")

action = function(host, port)
  local capa, err = imap.capabilities(host, port)
  if type(capa) == "table" then
     -- Convert the capabilities table into an array of strings.
     local capstrings = {}
     local cap, args
     for cap, args in pairs(capa) do
	table.insert(capstrings, cap)
     end
     return stdnse.strjoin(" ", capstrings)
  elseif type(err) == "string" then
     stdnse.print_debug(1, "%s: '%s' for %s", filename, err, host.ip)
     return
  else
     return "server doesn't support CAPABILITIES"
  end
end
