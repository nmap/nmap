description=[[ 
Attempts to discover hosts' services using the DNS Service Discovery protocol.  It sends a multicast DNS-SD query and collects all the responses.

The script first sends a query for _services._dns-sd._udp.local to get a
list of services. It then sends a followup query for each one to try to
get more information.
]]


---
-- @usage
-- nmap --script=broadcast-dns-service-discovery
--
-- @output
-- | broadcast-dns-service-discovery: 
-- |   1.2.3.1
-- |     _ssh._tcp.local
-- |     _http._tcp.local
-- |   1.2.3.50
-- |     22/tcp ssh
-- |       org.freedesktop.Avahi.cookie=2292090182
-- |       Address=1.2.3.50
-- |     80/tcp http
-- |       path=/admin
-- |       org.freedesktop.Avahi.cookie=2292090182
-- |       path=/
-- |       org.freedesktop.Avahi.cookie=2292090182
-- |       path=/pim
-- |       org.freedesktop.Avahi.cookie=2292090182
-- |       Address=1.2.3.50
-- |   1.2.3.116
-- |     80/tcp http
-- |_      Address=1.2.3.116


-- Version 0.1
-- Created 10/29/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}

require 'shortport'
require 'dnssd'

prerule = function() return true end

action = function()
	local helper = dnssd.Helper:new( )
	helper:setMulticast(true)
	
	local status, result = helper:queryServices()
	if ( status ) then 
		return stdnse.format_output(true, result)
	end
end
