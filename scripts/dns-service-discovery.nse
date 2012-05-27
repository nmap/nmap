local dnssd = require "dnssd"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description=[[ 
Attempts to discover target hosts' services using the DNS Service Discovery protocol.

The script first sends a query for _services._dns-sd._udp.local to get a
list of services. It then sends a followup query for each one to try to
get more information.
]]


---
-- @usage
-- nmap --script=dns-service-discovery -p 5353 <target>
--
-- @output
-- PORT     STATE SERVICE  REASON
-- 5353/udp open  zeroconf udp-response
-- | dns-service-discovery:  
-- |   548/tcp afpovertcp
-- |     model=MacBook5,1
-- |     Address=192.168.0.2 fe80:0:0:0:223:6cff:1234:5678
-- |   3689/tcp daap
-- |     txtvers=1
-- |     iTSh Version=196609
-- |     MID=0xFB5338C04123456
-- |     Database ID=6FA9761FE123456
-- |     dmv=131078
-- |     Version=196616
-- |     OSsi=0x1F6
-- |     Machine Name=Patrik Karlsson\xE2\x80\x99s Library
-- |     Media Kinds Shared=1
-- |     Machine ID=8945A7123456
-- |     Password=0
-- |_    Address=192.168.0.2 fe80:0:0:0:223:6cff:1234:5678


-- Version 0.7
-- Created 01/06/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/13/2010 - v0.2 - modified to use existing dns library instead of mdns, changed output to be less DNS like
-- Revised 02/01/2010 - v0.3 - removed incorrect try/catch statements
-- Revised 10/04/2010 - v0.4 - added prerule and add target support <patrik@cqure.net>
-- Revised 10/05/2010 - v0.5 - added ip sort function and
-- Revised 10/10/2010 - v0.6 - multicast queries are now used in parallel to collect service information <patrik@cqure.net>
-- Revised 10/29/2010 - v0.7 - factored out most of the code to dnssd library

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.portnumber(5353, "udp")

action = function(host, port)
	local helper = dnssd.Helper:new( host, port )
	local status, result = helper:queryServices()

	if ( status ) then
		-- set port to open
		nmap.set_port_state(host, port, "open")
		return stdnse.format_output(true, result)
	end
end

