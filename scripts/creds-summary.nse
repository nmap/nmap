local creds = require "creds"

description = [[
Lists all discovered credentials (e.g. from brute force and default password checking scripts) at end of scan.
]]

---
--@output
-- | creds-summary:
-- |   10.10.10.10
-- |     22/ssh
-- |       lisbon:jane - Account is valid
-- |   10.10.10.20
-- |     21/ftp
-- |       jane:redjohn - Account is locked
-- |     22/ssh
-- |       cho:secret11 - Account is valid
-- |     23/telnet
-- |       rigsby:pelt - Account is valid
-- |       pelt:rigsby - Password needs to be changed at next logon
-- |     80/http
-- |       lisbon:jane - Account is valid
-- |       jane:redjohn - Account is locked
-- |_      cho:secret11 - Account is valid


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "default", "safe"}


postrule = function()
  local all = creds.Credentials:new(creds.ALL_DATA)
  local tab = all:getTable()
  if ( tab and next(tab) ) then return true end
end

action = function()
  local all = creds.Credentials:new(creds.ALL_DATA)
  return all:getTable()
end
