local math = require "math"
local msrpc = require "msrpc"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Attempts to enumerate domains on a system, along with their policies. This generally requires
credentials, except against Windows 2000. In addition to the actual domain, the "Builtin"
domain is generally displayed. Windows returns this in the list of domains, but its policies
don't appear to be used anywhere.

Much of the information provided is useful to a penetration tester, because it tells the
tester what types of policies to expect. For example, if passwords have a minimum length of 8,
the tester can trim his database to match; if the minimum length is 14, the tester will
probably start looking for sticky notes on people's monitors.

Another useful piece of information is the password lockouts. A penetration tester often wants
to know whether or not there's a risk of negatively impacting a network, and this will
indicate it. The SID is displayed, which may be useful in other tools; the users are listed,
which uses different functions than <code>smb-enum-users.nse</code> (though likely won't
get different results), and the date and time the domain was created may give some insight into
its history.

After the initial <code>bind</code> to SAMR, the sequence of calls is:
* <code>Connect4</code>: get a connect_handle
* <code>EnumDomains</code>: get a list of the domains (stop here if you just want the names).
* <code>QueryDomain</code>: get the SID for the domain.
* <code>OpenDomain</code>: get a handle for each domain.
* <code>QueryDomainInfo2</code>: get the domain information.
* <code>QueryDomainUsers</code>: get a list of the users in the domain.
]]

---
-- @usage
-- nmap --script smb-enum-domains.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- | smb-enum-domains:
-- |   WINDOWS2000
-- |     Groups: n/a
-- |     Users: Administrator, blah, Guest, testpass, ron, test, user
-- |     Creation time: 2009-10-17 12:45:47
-- |     Passwords: min length: n/a; min age: 5 days; max age: 100 days; history: 10 passwords
-- |     Properties: Complexity requirements exist
-- |     Account lockout: 5 attempts in 30 minutes will lock out the account for 30 minutes
-- |   Builtin
-- |     Groups: Administrators, Backup Operators, Guests, Power Users, Replicator, Users
-- |     Users: n/a
-- |     Creation time: 2009-10-17 12:45:46
-- |     Passwords: min length: n/a; min age: n/a days; max age: 42 days; history: n/a passwords
-- |_    Account lockout disabled
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}
dependencies = {"smb-brute"}


-- TODO: This script needs some love...

hostrule = function(host)
  return smb.get_port(host) ~= nil
end

action = function(host)

  local status, result = msrpc.get_domains(host)

  if(not(status)) then
    return stdnse.format_output(false, result)
  else
    local response = {}

    for domain, data in pairs(result) do
      local piece = {}
      piece['name'] = domain

      if(#data.groups > 0) then
        table.insert(piece, string.format("Groups: %s", table.concat(data.groups, ", ")))
      else
        table.insert(piece, "Groups: n/a")
      end

      if(#data.users > 0) then
        table.insert(piece, string.format("Users: %s", table.concat(data.users, ", ")))
      else
        table.insert(piece, "Users: n/a")
      end

      -- Floor data.max_password_age, if possible
      if(data.max_password_age) then
        data.max_password_age = math.floor(data.max_password_age)
      end

      table.insert(piece, string.format("Creation time: %s", data.created))
      table.insert(piece, string.format("Passwords: min length: %s; min age: %s days; max age: %s days; history: %s passwords",
        data.min_password_length or "n/a",
        data.min_password_age or "n/a",
        data.max_password_age or "n/a",
        data.password_history or "n/a"))
      if(data.password_properties and #data.password_properties) then
        table.insert(piece, string.format("Properties: %s", table.concat(data.password_properties, ", ")))
      end

      if(data.lockout_threshold) then
        table.insert(piece, string.format("Account lockout: %s attempts in %s minutes will lock out the account for %s minutes", data.lockout_threshold, data.lockout_window or "unlimited", data.lockout_duration or "unlimited"))
      else
        table.insert(piece, "Account lockout disabled")
      end

      table.insert(response, piece)
    end

    return stdnse.format_output(true, response)
  end
end

