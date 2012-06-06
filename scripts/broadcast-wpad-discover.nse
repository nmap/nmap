local dhcp = require "dhcp"
local dns = require "dns"
local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Retrieves a list of proxy servers on a LAN using the Web Proxy
Autodiscovery Protocol (WPAD).  It implements both the DHCP and DNS
methods of doing so and starts by querying DHCP to get the address.
DHCP discovery requires nmap to be running in privileged mode and will
be skipped when this is not the case.  DNS discovery relies on the
script being able to resolve the local domain either through a script
argument or by attempting to reverse resolve the local IP.
]]

---
-- @usage
-- nmap --script broadcast-wpad-discover
--
-- @output
-- | broadcast-wpad-discover: 
-- |   1.2.3.4:8080
-- |_  4.5.6.7:3128
-- 
-- @args broadcast-wpad-discover.domain the domain in which the WPAD host should be discovered
-- @args broadcast-wpad-discover.nodns instructs the script to skip discovery using DNS
-- @args broadcast-wpad-discover.nodhcp instructs the script to skip discovery using dhcp
-- @args broadcast-wpad-discover.getwpad instructs the script to retrieve the WPAD file instead of parsing it

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

local arg_domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain")
local arg_nodns  = stdnse.get_script_args(SCRIPT_NAME .. ".nodns")
local arg_nodhcp = stdnse.get_script_args(SCRIPT_NAME .. ".nodhcp")
local arg_getwpad= stdnse.get_script_args(SCRIPT_NAME .. ".getwpad")

local function createRequestList(req_list)
	local output = ""
	for _, v in ipairs(req_list) do
		output = output .. string.char(v)
	end
	return output
end


-- Gets a list of available interfaces based on link and up filters
--
-- @param link string containing the link type to filter
-- @param up string containing the interface status to filter
-- @return result table containing the matching interfaces
local function getInterfaces(link, up)
	if( not(nmap.list_interfaces) ) then return end
	local interfaces, err = nmap.list_interfaces()
	local result
	if ( not(err) ) then
		for _, iface in ipairs(interfaces) do
			if ( iface.link == link and iface.up == up ) then
				result = result or {}
				result[iface.device] = true
			end
		end
	end
	return result
end	


local function parseDHCPResponse(response)
	for _, v in ipairs(response.options) do
		if ( "WPAD" == v.name ) then
			return true, v.value
		end
	end
end

local function getWPAD(u)
	local u_parsed = url.parse(u)
	
	if ( not(u_parsed) ) then
		return false, ("Failed to parse url: %s"):format(u)
	end
	
	local response = http.get(u_parsed.host, u_parsed.port or 80, u_parsed.path)
	if ( response and response.status == 200 ) then
		return true, response.body
	end
	
	return false, ("Failed to retrieve wpad.dat (%s) from server"):format(u)
end

local function parseWPAD(wpad)
	local proxies = {}
	for proxy in wpad:gmatch("PROXY%s*([^\";%s]*)") do
		table.insert(proxies, proxy)
	end
	return proxies
end

local function dnsDiscover()

	-- tries to discover WPAD for all domains and sub-domains
	local function enumWPADNames(domain)
		local d = domain
		-- reduce domain until we only have a single dot left
		-- there is a security problem in querying for wpad.tld like eg
		-- wpad.com as this could be a rougue domain. This loop does not
		-- account for domains with tld's containing two parts e.g. co.uk.
		-- However, as the script just attempts to download and parse the
		-- proxy values in the WPAD there should be no real harm here.
		repeat
			local name = ("wpad.%s"):format(d)
			d = d:match("^[^%.]-%.(.*)$")
			local status, response = dns.query(name, { dtype = 'A', retAll = true })

			-- get the first entry and return
			if ( status and response[1] ) then
				return true, { name = name, ip = response[1] }
			end
		until( not(d) or not(d:match("%.")) )
		
	end
	
	-- first try a domain if it was supplied
	if ( arg_domain ) then
		local status, response = enumWPADNames(arg_domain)
		if ( status ) then
			return status, response
		end
	end
	
	
	-- if no domain was supplied, attempt to reverse lookup every ip on each
	-- interface to find our FQDN hostname, once we do, try to query for WPAD
	for i in pairs(getInterfaces("ethernet", "up") or {}) do
		local iface, err = nmap.get_interface_info(i)
		if ( iface ) then
			local status, response = dns.query( dns.reverse(iface.address), { dtype = 'PTR', retAll = true } )

			-- did we get a name back from dns?
			if ( status ) then
				local domains = {}
				for _, name in ipairs(response) do
					-- first get all unique domain names
					if ( not(name:match("in%-addr.arpa$")) ) then
						local domain = name:match("^[^%.]-%.(.*)$")
						domains[domain] = true
					end
				end
				
				-- attempt to discover the ip for WPAD in all domains
				-- each domain is processed and reduced and ones the first
				-- match is received it returns an IP
				for domain in pairs(domains) do
					status, response = enumWPADNames(domain)
					if ( status ) then
						return true, response
					end
				end
								
			end

		end
	end
	
	return false, "Failed to find WPAD using DNS"

end

local function dhcpDiscover()

	-- send a DHCP discover on all ethernet interfaces that are up
	for i in pairs(getInterfaces("ethernet", "up") or {}) do
		local iface, err = nmap.get_interface_info(i)
		if ( iface ) then
			local req_list = createRequestList( { 1, 15, 3, 6, 44, 46, 47, 31, 33, 249, 43, 252 } )
			local status, response = dhcp.make_request("255.255.255.255", dhcp.request_types["DHCPDISCOVER"], "0.0.0.0", iface.mac, nil, req_list, { flags = 0x8000 } )
			
			-- if we got a response, we're happy and don't need to continue
			if (status) then
				return status, response
			end
		end
	end

end


action = function()

	local status, response, wpad
	
	if ( arg_nodhcp and arg_nodns ) then
		return "\n  ERROR: Both nodns and nodhcp arguments were supplied"
	end
	
	if ( nmap.is_privileged() and not(arg_nodhcp) ) then
		status, response = dhcpDiscover()
		if ( status ) then
			status, wpad = parseDHCPResponse(response)
		end
	end
		
	-- if the DHCP did not get a result, fallback to DNS
	if (not(status) and not(arg_nodns) ) then
		status, response = dnsDiscover()
		if ( not(status) ) then
			local services = "DNS" .. ( nmap.is_privileged() and "/DHCP" or "" )
			return ("\n  ERROR: Could not find WPAD using %s"):format(services)
		end
		wpad = ("http://%s/wpad.dat"):format( response.name )
	end
	
	if ( status ) then
		status, response = getWPAD(wpad)
	end
	
	if ( not(status) ) then
		return status, response
	end
	
	local output = ( arg_getwpad and response or parseWPAD(response) )
	
	return stdnse.format_output(true, output)
end
