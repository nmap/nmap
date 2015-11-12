description = [[
Attempts to retrieve information about the domain name of the target
]]

---
-- @usage nmap --script whois-domain.nse <target>
--
-- This script starts by querying the whois.iana.org (which is the root of the
-- whois servers). Using some patterns the script can determine if the response
-- represents a referral to a record hosted elsewhere. If that's the case it will
-- query that referral. The script keeps repeating this until the response don't
-- match with any of the patterns, meaning that there are no other referrals and
-- prints the output.
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | whois-domain:
-- | whois3: Record found at whois.arin.net
-- | netrange: 199.19.112.0 - 199.19.119.255
-- | netname: WEBRULON-NETWORK
-- | orgname: webRulon, LLC
-- | orgid: WL-1
-- | country: US stateprov: NY
-- |
-- | orgtechname: webRulon Support
-- | orgtechemail: support@webrulon.com
-- |
-- | Domain name record found at whois.enom.com
-- |
-- | Registration Service Provided By: Namecheap.com
-- | Contact: support@namecheap.com
-- | Visit: http://namecheap.com
-- | Registered through: eNom, Inc.
-- |
-- | Domain name: random-foo-example.com
-- |
-- | Registrant Contact:
-- |    Example
-- |    John Foo ()
-- |
-- |    Fax:
-- |    Dimosthenous 215
-- |    Athens, Attiki 17673
-- |    GR
-- |
-- | Administrative Contact:
-- |    Example
-- |    John Foo (john@gmail.com)
-- |    +30.69425555555
-- |    Fax: +1.5555555555
-- |    Dimosthenous 215
-- |    Athens, Attiki 17673
-- |    GR
-- |
-- | Technical Contact:
-- |    Example
-- |    John Foo (john@gmail.com)
-- |    +30.69425555555
-- |    Fax: +1.5555555555
-- |    Dimosthenous 215
-- |    Athens, Attiki 17673
-- |    GR
-- |
-- | Status: Active
-- |
-- | Name Servers:
-- |    dns1.registrar-servers.com
-- |    dns2.registrar-servers.com
-- |    dns3.registrar-servers.com
-- |    dns4.registrar-servers.com
-- |    dns5.registrar-servers.com
-- |
-- | Creation date: 14 Oct 2011 13:41:00
-- | Expiration date: 14 Oct 2013 05:41:00
---

author = "George Chatzisofroniou"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "external", "safe"}

local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

hostrule = function( host )
  local is_private, err = ipOps.isPrivate( host.ip )
  if is_private == nil then
    stdnse.debug1("Error in Hostrule: %s.", err )
    return false
  end

  return not is_private
end


action = function( host )

  local mutexes = {}

  -- If the user has provided a domain name.
  if host.targetname then

    local referral_patterns = {"refer:%s*(.-)\n", "Whois%sServer:%s*(.-)\n"}

    -- Remove www prefix and add a newline.
    local query_data = string.gsub(host.targetname, "^www%.", "") .. "\n"

    local result

    -- First server to query is iana's.
    local referral = "whois.iana.org"

    while referral do

      if not mutexes[referral] then
        mutexes[referral] = nmap.mutex(referral)
      end

      mutexes[referral] "lock"

      result = {}
      local socket = nmap.new_socket()
      local catch = function()
        stdnse.debug1( "fail")
        socket:close()
      end

      local status, line = {}
      local try = nmap.new_try( catch )

      socket:set_timeout( 50000 )

      try( socket:connect(referral, 43 ) )
      try( socket:send( query_data ) )

      while true do
        local status, lines = socket:receive_lines(1)
        if not status then
          break
        else
          result[#result+1] = lines
        end
      end

      socket:close()

      mutexes[referral] "done"

      if #result == 0 then
        return nil
      end

      table.insert(result, 1, "\n\nDomain name record found at " .. referral .. "\n")

      -- Do we have a referral?
      referral = false
      for _, p in ipairs(referral_patterns) do
        referral = referral or string.match(table.concat(result), p)
      end

    end

    result = table.concat( result )
    return result
  end
  return "You should provide a domain name."
end

