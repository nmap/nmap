--- A minimalistic DNS BlackList library implemented to facilitate querying
-- various DNSBL services. The current list of services has been implemented
-- based on the following compilations of services:
-- * http://en.wikipedia.org/wiki/Comparison_of_DNS_blacklists
-- * http://www.robtex.com
-- * http://www.sdsc.edu/~jeff/spam/cbc.html
--
-- The library implements a helper class through which script may access
-- the BL services. A typical script implementation could look like this:
--
-- <code>
-- local helper = dnsbl.Helper:new("SPAM", "short")
-- helper:setFilter('dnsbl.inps.de')
-- local status, result = helper:checkBL(host.ip)
-- ... formatting code ...
-- </code>
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--

module(... or "dnsbl", package.seeall)

require 'bit'

-- The services table contains a list of valid DNSBL providers
-- Providers are categorized in categories that should contain services that
-- do DNS blacklist checks for that particular category.
--
-- Each service should be stored under a key that specifies the service name
-- and should contain:
-- <code>ns_type</code> - A table with a record type as key and mode as value
--   eg: { ["A"] = "short", ["TXT"] = "long" }.
--   If only short queries are supported using A records, this argument may be
--   omitted.
--
-- <code>resp_parser</code> - A function to parse the response received from
--   the DNS query. The function should take two arguments:
--     * <code>response</code> - the DNS response received by the server,
--       typically a code represented by an IP.
--     * <code>mode</code> - a string representing what mode (long|short) that
--       the function should parse. If <code>ns_type</code> does not contain
--       the TXT record, this argument and check can be omitted.
--   When the short mode is used, the function should return a table containing
--   the <code>state</code> field, or nil if the IP wasn't listed. When long
--   mode is used, the function should return additional information using the 
--  <code>details</code> field. Eg:
--     return { state = "SPAM" } -- short mode
--     return { state = "PROXY", details = {
--                           "Proxy is working",
--                           "Proxy was scanned"
--                          } -- long mode
--
-- <code>fmt_query</code> - A function responsible for formatting the DNS
--   query. When the default format is being used <reverse ip>.<servicename>
--   eg: 4.3.2.1.spam.dnsbl.sorbs.net, this function can be omitted.
--                            
SERVICES = {
	
	SPAM = {
		
		["dnsbl.inps.de"] = {
			-- This service supports both long and short <code>mode</code>
			ns_type	= {
				["short"] = "A",
				["long"] = "TXT",
			},
			-- sample fmt_query function, if no function is specified, the library
			-- will assume that the IP should be reversed add suffixed with the
			-- service name.
			fmt_query   = function(ip)
				local rev_ip = dns.reverse(ip):match("^(.*)%.in%-addr%.arpa$")
				return ("%s.spam.dnsbl.sorbs.net"):format(rev_ip)
			end,
			-- This function parses the response and supports borth long and
			-- short mode.
			resp_parser = function(r, mode)
				local responses = {
					["127.0.0.2"] = "SPAM",
				}
				if ( ("short" == mode and r[1]) ) then
					return responses[r[1]]
				else
					return { state = "SPAM", details = { r[1] } }
				end
			end,
		},

		["spam.dnsbl.sorbs.net"] = { 
			ns_type		= {
				["short"] = "A"
			},
			resp_parser = function(r)
				return ( r[1] == "127.0.0.6" and { state = "SPAM" } )
			end,
		},

		["bl.nszones.com"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.2"] = "SPAM",
					["127.0.0.3"] = "DYNAMIC"
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
	
		["all.spamrats.com"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.36"] = "DYNAMIC",
					["127.0.0.38"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
		
		["list.quorum.to"] = {
			resp_parser = function(r)
				return ( ( r[1] and r[1] == "127.0.0.2" ) and { state = "SPAM" } ) 
			end
		},
		
		["sbl.spamhaus.org"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.2"] = "SPAM",
					["127.0.0.3"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,		
		},
		
		["bl.spamcop.net"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.2"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,					
		},
		
		["dnsbl.ahbl.org"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.4"] = "SPAM",
					["127.0.0.5"] = "SPAM",
					["127.0.0.6"] = "SPAM",
					["127.0.0.7"] = "SPAM",
					["127.0.0.8"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,								
		},
		
		["l2.apews.org"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.2"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,					
		},
	
	},

	PROXY = {		
		["dnsbl.tornevall.org"] = {
			resp_parser = function(r, mode)
				if ( "short" == mode and r[1] ) then
					return { state = "PROXY" }
				elseif ( "long" == mode ) then
					local responses = {
						[1]		= "Proxy has been scanned",
						[2]		= "Proxy is working",
						[4]		= "?",
						[8] 	= "Proxy was tested, but timed out on connection",
						[16]	= "Proxy was tested but failed at connection",
						[32]	= "Proxy was tested but the IP was different",
						[64]	= "IP marked as \"abusive host\"",
						[128]	= "Proxy has a different anonymous-state"
					}
					
					local code = tonumber(r[1]:match("%.(%d*)$"))
					local result = {}

					for k, v in pairs(responses) do
						if ( bit.band( code, k ) == k ) then
							table.insert(result, v)
						end
					end					
					return { state = "PROXY", details = result }
				end	
			end,					
		},
		
		["dnsbl.ahbl.org"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.3"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,									
		},
		
		["http.dnsbl.sorbs.net"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.2"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,												
		},
		
		["socks.dnsbl.sorbs.net"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.3"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,												
		},
		
		["misc.dnsbl.sorbs.net"] = {
			resp_parser = function(r)
				local responses = {
					["127.0.0.4"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,												
		}
			
	}
	
}



Helper = {
	
	-- Creates a new Helper instance
	-- @param category string containing a valid DNSBL service category
	-- @param mode string (short|long) specifying whether short or long
	--        results are to be returned
	-- @return o instance of Helper
	new = function(self, category, mode)
		local o = { category = category:upper(), mode = mode }
		assert(category and SERVICES[category:upper()], "Invalid category was supplied, aborting")
		setmetatable(o, self)
		self.__index = self
		return o
	end,
    
	-- Lists all DNSBL services for the category
	-- @return services table of service names
	listServices = function(self)
		local services = {}
		for svc in pairs(SERVICES[self.category]) do
			table.insert(services, svc)
		end
		return services		
	end,
	
	-- Validates the filter set by setFilter to make sure it contains only
	-- valid service names.
	-- @return status boolean, true on success false on failure
	-- @return err string containing an error message on failure
	validateFilter = function(self)
	
		if ( not(self.filterstr) ) then
			return true
		end
	
		local all = SERVICES[self.category]
		self.filter = {}
		for _, f in pairs(stdnse.strsplit(",%s*", self.filterstr)) do
			if ( not(SERVICES[self.category][f]) ) then
				self.filter = nil
				return false, ("Service does not exist '%s'"):format(f)
			end
			self.filter[f] = true
		end
		return true
	end,
	
	-- Sets a new service filter to choose only a limited subset of services
	-- within a category.
	-- @param filter string containing a comma separated list of service names
	setFilter = function(self, filter) self.filterstr = filter end,
	
	-- Gets a list of filtered services, or all services if no filter is in use
	-- @return services table containing a list of services
	getServices = function(self)
		if ( not(self:validateFilter()) ) then
			return nil
		end
		
		if ( self.filter ) then
			local filtered = {}
			for name, svc in pairs(SERVICES[self.category]) do
				if ( self.filter[name] ) then
					filtered[name] = svc
				end
			end
			return filtered
		else
			return SERVICES[self.category]
		end
	end,
	
	-- Runs the DNS blacklist check for the given IP against all non-filtered
	-- services in the given category.
	-- @param ip string containing the IP address to check
	-- @return result table containing the results of the BL checks
	checkBL = function(self, ip)
	
		local result = {}
		
		for name, svc in pairs(self:getServices()) do
			--local ns_type = ( self.mode == "long" and (tabcontains(svc.ns_type or {}, 'TXT') and 'TXT' or 'A') or 'A')
			local ns_type = ( svc.ns_type and svc.ns_type[self.mode] ) and svc.ns_type[self.mode] or "A"
			local query
			
			if ( svc.fmt_query ) then
				query = svc.fmt_query(ip)
			else
				local rev_ip = dns.reverse(ip):match("^(.*)%.in%-addr%.arpa$")
				query = ("%s.%s"):format(rev_ip, name)
			end
			
			local status, answer = dns.query(query, {dtype=ns_type, retAll=true} )
			if ( status ) then
				local svc_result = svc.resp_parser(answer, self.mode)
				
			 	if ( not(svc_result) ) then
					local resp = ( #answer > 0 and ("UNKNOWN (%s)"):format(answer[1]) or "UNKNOWN" )
					stdnse.print_debug(2, ("%s received %s"):format(name, resp))
				end
				
				-- only add a record if the response could be parsed, some
				-- services, such as list.quorum.to, incorrectly return
				-- 127.0.0.0 when all is good.
				if ( svc_result ) then
					table.insert(result, { name = name, result = svc_result })
				end
			-- if status is false, and the response was "No Such Name", it
			-- simply means that the IP isn't listed, we haven't failed at
			-- this point. It would obviously be better to check this against
			-- an error code, or in some other way, but this is what we've got.
			elseif ( answer ~= "No Such Name" ) then
				table.insert(result, { name = name, result = { state = "FAIL" }})
			end
		end
		return result
	end,
	

}



