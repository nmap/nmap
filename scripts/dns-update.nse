local dns = require "dns"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to perform a dynamic DNS update without authentication.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

---
-- @output
-- PORT   STATE SERVICE
-- 53/udp open  domain
-- | dns-update: 
-- |   Successfully added the record "nmap-test.cqure.net"
-- |_  Successfully deleted the record "nmap-test.cqure.net"
--
-- @args dns-update.hostname the name of the host to add to the zone
-- @args dns-update.ip the ip address of the host to add to the zone
--

--
-- Examples
--
-- Adding different types of records to a server
--   * dns.update( "www.cqure.net", { host=host, port=port, dtype="A", data="10.10.10.10" } )
--	 * dns.update( "alias.cqure.net", { host=host, port=port, dtype="CNAME", data="www.cqure.net" } )
--	 * dns.update( "cqure.net", { host=host, port=port, dtype="MX", data={ pref=10, mx="mail.cqure.net"} })
--	 * dns.update( "_ldap._tcp.cqure.net", { host=host, port=port, dtype="SRV", data={ prio=0, weight=100, port=389, target="ldap.cqure.net" } } )
--
-- Removing the above records by setting an empty data and a ttl of zero
--   * dns.update( "www.cqure.net", { host=host, port=port, dtype="A", data="", ttl=0 } )
--	 * dns.update( "alias.cqure.net", { host=host, port=port, dtype="CNAME", data="", ttl=0 } )
--	 * dns.update( "cqure.net", { host=host, port=port, dtype="MX", data="", ttl=0 } )
--	 * dns.update( "_ldap._tcp.cqure.net", { host=host, port=port, dtype="SRV", data="", ttl=0 } )
--

-- Version 0.2

-- Created 01/09/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/10/2011 - v0.2 - added test function <patrik@cqure.net>


portrule = shortport.port_or_service( 53, "dns", "udp", {"open", "open|filtered"} )

local function test(host, port)
	
	local status, err = dns.update( "www.cqure.net", { host=host, port=port, dtype="A", data="10.10.10.10" } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	status, err = dns.update( "www2", { zone="cqure.net", host=host, port=port, dtype="A", data="10.10.10.10" } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	status, err = dns.update( "alias.cqure.net", { host=host, port=port, dtype="CNAME", data="www.cqure.net" } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	status, err = dns.update( "cqure.net", { host=host, port=port, dtype="MX", data={ pref=10, mx="mail.cqure.net"} })
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	status, err = dns.update( "_ldap._tcp.cqure.net", { host=host, port=port, dtype="SRV", data={ prio=0, weight=100, port=389, target="ldap.cqure.net" } } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	
	status, err = dns.update( "www.cqure.net", { host=host, port=port, dtype="A", data="", ttl=0 } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	status, err = dns.update( "www2.cqure.net", { host=host, port=port, dtype="A", data="", ttl=0 } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	status, err = dns.update( "alias.cqure.net", { host=host, port=port, dtype="CNAME", data="", ttl=0 } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	status, err = dns.update( "cqure.net", { host=host, port=port, dtype="MX", data="", ttl=0 } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	status, err = dns.update( "_ldap._tcp.cqure.net", { host=host, port=port, dtype="SRV", data="", ttl=0 } )
	if ( status ) then stdnse.print_debug("SUCCESS") else stdnse.print_debug("FAIL: " .. (err or "")) end
	
end

action = function(host, port)
	
	local t = stdnse.get_script_args('dns-update.test')
	local name, ip = stdnse.get_script_args('dns-update.hostname', 'dns-update.ip')

	if ( t ) then return test(host, port) end
	if ( not(name) or not(ip) ) then return end

	-- we really need an ip or name to continue
	-- we could attempt a random name, but we need to know at least the name of the zone
	local status, err = dns.update( name, { host=host, port=port, dtype="A", data=ip } )

	if ( status ) then
		local result = {}
		table.insert(result, ("Successfully added the record \"%s\""):format(name))
		local status = dns.update( name, { host=host, port=port, dtype="A", data="", ttl=0 } )
		if ( status ) then
			table.insert(result, ("Successfully deleted the record \"%s\""):format(name))
		else
			table.insert(result, ("Failed to delete the record \"%s\""):format(name))
		end
		nmap.set_port_state(host, port, "open")
		return stdnse.format_output(true, result)
	elseif ( err ) then
		return "\n  ERROR: " .. err 
	end

end
