local nmap = require "nmap"
local stdnse = require "stdnse"
local stringaux = require "stringaux"
local table = require "table"
local target = require "target"

description = [[
Produces a list of IP prefixes for a given routing AS number (ASN).

This script uses a whois server database operated by the Shadowserver
Foundation.  We thank them for granting us permission to use this in
Nmap.

Output is in CIDR notation.

http://www.shadowserver.org/wiki/pmwiki.php/Services/IP-BGP
]]

---
-- @args targets-asn.asn The ASN to search.
-- @args targets-asn.whois_server The whois server to use. Default: asn.shadowserver.org.
-- @args targets-asn.whois_port The whois port to use. Default: 43.
--
-- @usage
-- nmap --script targets-asn --script-args targets-asn.asn=32
--
-- @output
-- Pre-scan script results:
-- | targets-asn:
-- |   32
-- |     128.12.0.0/16
-- |_    171.64.0.0/14

author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "external", "safe"}


prerule = function()
  return true
end

action = function(host, port)
  local asns, whois_server, whois_port, err, status, newtargets
  local results = {}

  asns = stdnse.get_script_args('targets-asn.asn') or stdnse.get_script_args('asn-to-prefix.asn')
  whois_server = stdnse.get_script_args('targets-asn.whois_server') or stdnse.get_script_args('asn-to-prefix.whois_server')
  whois_port = stdnse.get_script_args('targets-asn.whois_port') or stdnse.get_script_args('asn-to-prefix.whois_port')

  if not asns then
    return stdnse.format_output(true, "targets-asn.asn is a mandatory parameter")
  end
  if not whois_server then
    whois_server = "asn.shadowserver.org"
  end
  if not whois_port then
    whois_port = 43
  end
  if type(asns) ~= "table" then
    asns = {asns}
  end

  for _, asn in ipairs(asns) do
    local socket = nmap.new_socket()

    local prefixes = {}
    prefixes['name'] = asn

    status, err = socket:connect(whois_server, whois_port)
    if ( not(status) ) then
      table.insert(prefixes, err)
    else
      status, err = socket:send("prefix " .. asn .. "\n")
      if ( not(status) ) then
        table.insert(prefixes, err)
      else
        while true do
          local status, data = socket:receive_lines(1)
          if ( not(status) ) then
            table.insert(prefixes, err)
            break
          else
            for i, prefix in ipairs(stringaux.strsplit("\n",data)) do
              if ( #prefix > 1 ) then
                table.insert(prefixes,prefix)
                if target.ALLOW_NEW_TARGETS then
                  stdnse.debug1("Added targets: "..prefix)
                  local status,err = target.add(prefix)
                end
              end
            end
          end
        end
      end
    end
    table.insert(results,prefixes)
  end
  return stdnse.format_output(true, results)
end
