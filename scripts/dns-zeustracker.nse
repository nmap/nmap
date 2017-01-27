local dns = require "dns"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description = [[
Checks if the target IP range is part of a Zeus botnet by querying ZTDNS @ abuse.ch.
Please review the following information before you start to scan:
* https://zeustracker.abuse.ch/ztdns.php
]]

---
-- @usage
-- nmap -sn -PN --script=dns-zeustracker <ip>
-- @output
-- Host script results:
-- | dns-zeustracker:
-- |   Name                IP        SBL         ASN    Country  Status   Level               Files Online  Date added
-- |   foo.example.com     1.2.3.4   SBL123456   1234   CN       online   Bulletproof hosted  0             2011-06-17
-- |_  bar.example.com     1.2.3.5   SBL123456   1234   CN       online   Bulletproof hosted  0             2011-06-15

author = "Mikael Keri"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "external", "malware"}



hostrule = function(host) return not(ipOps.isPrivate(host.ip)) end

action = function(host)

  local levels = {
    "Bulletproof hosted",
    "Hacked webserver",
    "Free hosting service",
    "Unknown",
    "Hosted on a FastFlux botnet"
  }
  local dname = dns.reverse(host.ip)
  dname = dname:gsub ("%.in%-addr%.arpa",".ipbl.zeustracker.abuse.ch")
  local status, result = dns.query(dname, {dtype='TXT', retAll=true} )

  if ( not(status) and result == "No Such Name" ) then
    return
  elseif ( not(status) ) then
    return stdnse.format_output(false, "DNS Query failed")
  end

  local output = tab.new(9)
  tab.addrow(output, "Name", "IP", "SBL", "ASN", "Country", "Status", "Level",
    "Files Online", "Date added")
  for _, record in ipairs(result) do
    local name, ip, sbl, asn, country, status, level, files_online,
      dateadded = table.unpack(stdnse.strsplit("| ", record))
    level = levels[tonumber(level)] or "Unknown"
    tab.addrow(output, name, ip, sbl, asn, country, status, level, files_online, dateadded)
  end
  return stdnse.format_output(true, tab.dump(output))
end
