local imap = require "imap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

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


portrule = shortport.port_or_service({143}, "imap")

action = function(host, port)
  local helper = imap.Helper:new(host, port)
  local status = helper:connect()
  if ( not(status) ) then return "\n  ERROR: Failed to connect to server" end

  local status, capa = helper:capabilities(host, port)
  if( not(status) ) then return "\n  ERROR: Failed to retrieve capabilities" end
  helper:close()

  if type(capa) == "table" then
     -- Convert the capabilities table into an array of strings.
     local capstrings = {}
     local cap, args
     for cap, args in pairs(capa) do
	table.insert(capstrings, cap)
     end
     return stdnse.strjoin(" ", capstrings)
  elseif type(capa) == "string" then
     stdnse.print_debug(1, "%s: '%s' for %s", SCRIPT_NAME, capa, host.ip)
     return
  else
     return "server doesn't support CAPABILITIES"
  end
end
