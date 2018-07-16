local bin = require "bin"
local dns = require "dns"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Retrieves information from a DNS nameserver by requesting
its nameserver ID (nsid) and asking for its id.server and
version.bind values. This script performs the same queries as the following
two dig commands:
  - dig CH TXT bind.version @target
  - dig +nsid CH TXT id.server @target

References:
[1]http://www.ietf.org/rfc/rfc5001.txt
[2]http://www.ietf.org/rfc/rfc4892.txt
]]

---
-- @usage
-- nmap -sSU -p 53 --script dns-nsid <target>
--
-- @output
-- 53/udp open  domain  udp-response
-- | dns-nsid:
-- |   NSID dns.example.com (646E732E6578616D706C652E636F6D)
-- |   id.server: dns.example.com
-- |_  bind.version: 9.7.3-P3
--
-- @xmloutput
-- <table key="NSID">
--   <elem key="raw">mia01.l.root-servers.org</elem>
--   <elem key="hex">6d696130312e6c2e726f6f742d736572766572732e6f7267</elem>
-- </table>
-- <elem key="id.server">mia01.l.root-servers.org</elem>
-- <elem key="bind.version">NSD 3.2.15</elem>

author = "John R. Bond"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "default", "safe"}


portrule = function (host, port)
  if not shortport.port_or_service(53, "domain", {"tcp", "udp"})(host, port) then
    return false
  end
  -- only check tcp if udp is not open or open|filtered
  if port.protocol == 'tcp' then
    local tmp_port = nmap.get_port_state(host, {number=port.number, protocol="udp"})
    if tmp_port then
      return not string.match(tmp_port.state, '^open')
    end
  end
  return true
end

local function rr_filter(pktRR, label)
  for _, rec in ipairs(pktRR, label) do
    if ( rec[label] and 0 < #rec.data ) then
      if ( dns.types.OPT == rec.dtype ) then
        local pos, _, len = bin.unpack(">SS", rec.data)
        if ( len ~= #rec.data - pos + 1 ) then
          return false, "Failed to decode NSID"
        end
        return true, select(2, bin.unpack("A" .. len, rec.data, pos))
      else
        return true, select(2, bin.unpack("p", rec.data))
      end
    end
  end
end

action = function(host, port)
  local result = stdnse.output_table()
  local flag = false
  local status, resp = dns.query("id.server", {host = host.ip, port=port.number, proto=port.protocol, dtype='TXT', class=dns.CLASS.CH, retAll=true, retPkt=true, nsid=true, dnssec=true})
  if ( status ) then
    local status, nsid = rr_filter(resp.add,'OPT')
    if ( status ) then
      flag = true
      -- RFC 5001 says NSID can be any arbitrary bytes, and should be displayed
      -- as hex, but often it is a readable string. Store both.
      result["NSID"] = { raw = nsid, hex = stdnse.tohex(nsid) }
      setmetatable(result["NSID"], {
        __tostring = function(t)
          return ("%s (%s)"):format(t.raw, t.hex)
        end
      })
    end
    local status, id_server = rr_filter(resp.answers,'TXT')
    if ( status ) then
      flag = true
      result["id.server"] = id_server
    end
  end
  local status, bind_version = dns.query("version.bind", {host = host.ip, port=port.number, proto=port.protocol, dtype='TXT', class=dns.CLASS.CH})
  if ( status ) then
    flag = true
    result["bind.version"] = bind_version
  end
  if flag then
    return result
  end
end
