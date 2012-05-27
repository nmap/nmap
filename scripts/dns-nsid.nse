local bin = require "bin"
local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

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
---

author = "John Bond"
license = "Simplified (2-clause) BSD license--See http://nmap.org/svn/docs/licenses/BSD-simplified"

categories = {"discovery", "default"}


portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

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
	local result = {}
	local status, resp = dns.query("id.server", {host = host.ip, dtype='TXT', class=dns.CLASS.CH, retAll=true, retPkt=true, nsid=true, dnssec=true})
	if ( status ) then
		local status, nsid = rr_filter(resp.add,'OPT')
		if ( status ) then
			table.insert(result, ("NSID: %s (%s)"):format(nsid, stdnse.tohex(nsid)))
		end
		local status, id_server = rr_filter(resp.answers,'TXT')
		if ( status ) then
			table.insert(result, ("id.server: %s"):format(id_server))
		end
	end
	local status, bind_version = dns.query("version.bind", {host = host.ip, dtype='TXT', class=dns.CLASS.CH})
	if ( status ) then
		table.insert(result, ("bind.version: %s"):format(bind_version))
	end
	return stdnse.format_output(true, result)
end
