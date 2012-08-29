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

local bit = require "bit"
local coroutine = require "coroutine"
local dns = require "dns"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("dnsbl", stdnse.seeall)


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
--   eg: 4.3.2.1.spam.dnsbl.sorbs.net, this function can be omitted. But if
--   this function is defined, it must return the query to be executed,
--   otherwise the library will assume that the provider needs configuration
--   that failed to be provided.
--
-- <code>configuration</code> - If the service requires the user to provide
--   configurations, this function will have to return a list with the name
--   and description of the arguments that provide the configuration/options.
--   If this function isn't specified, the library will assume the service
--   doesn't require configuration.
--                            
SERVICES = {
	
	SPAM = {
		
		["dnsbl.inps.de"] = {
			-- This service supports both long and short <code>mode</code>
			ns_type = {
				["short"] = "A",
				["long"] = "TXT",
			},
			-- Creates a new Service instance
			-- @param ip host that needs to be checked
			-- @param mode string (short|long) specifying whether short or long
			--        results are to be returned
			-- @param config service configuration in case this service provider
			--        needs user supplied configuration
			-- @return o instance of Helper
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			-- Sample fmt_query function, if no function is specified, the library
			-- will assume that the IP should be reversed add suffixed with the
			-- service name.
			fmt_query = function(self)
				local rev_ip = dns.reverse(self.ip):match("^(.*)%.in%-addr%.arpa$")
				return ("%s.spam.dnsbl.sorbs.net"):format(rev_ip)
			end,
			-- This function parses the response and supports borth long and
			-- short mode.
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.2"] = "SPAM",
				}
				if ( ("short" == self.mode and r[1]) ) then
					return responses[r[1]]
				else
					return { state = "SPAM", details = { r[1] } }
				end
			end,
		},

		["spam.dnsbl.sorbs.net"] = { 
			ns_type = {
				["short"] = "A"
			},
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				return ( r[1] == "127.0.0.6" and { state = "SPAM" } )
			end,
		},

		["bl.nszones.com"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.2"] = "SPAM",
					["127.0.0.3"] = "DYNAMIC"
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
	
		["all.spamrats.com"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.36"] = "DYNAMIC",
					["127.0.0.38"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
		
		["list.quorum.to"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				-- this service appears to return 127.0.0.0 when the service is
				-- "blocked because it has never been seen to send mail".
				-- This would essentially return every host as SPAM and we
				-- don't want that. 
				return ( ( r[1] and r[1] ~= "127.0.0.0" ) and { state = "SPAM" } ) 
			end
		},
		
		["sbl.spamhaus.org"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.2"] = "SPAM",
					["127.0.0.3"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,		
		},
		
		["bl.spamcop.net"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.2"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
		
		["dnsbl.ahbl.org"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
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
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.2"] = "SPAM",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
	
	},

	PROXY = {
		
		["dnsbl.tornevall.org"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				if ( "short" == self.mode and r[1] ) then
					return { state = "PROXY" }
				elseif ( "long" == self.mode ) then
					local responses = {
						[1]	= "Proxy has been scanned",
						[2]	= "Proxy is working",
						[4]	= "?",
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
		
		["ip-port.exitlist.torproject.org"] = {
			configuration = {
				["port"] = "the port to which the target can relay to",
				["ip"] = "the IP address to which the target can relay to"
			},
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			fmt_query = function(self)
				if ( not(self.config.port) or not(self.config.ip) ) then
					return
				end

				local rev_ip = dns.reverse(self.ip):match("^(.*)%.in%-addr%.arpa$")
				return ("%s.%s.%s.ip-port.exitlist.torproject.org"):format(rev_ip,
						self.config.port, self.config.ip)
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.2"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},

		["tor.dan.me.uk"] = {
			ns_type = {
				["short"] = "A",
				["long"] = "TXT",
			},
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.100"] = "PROXY",
				}
				if ( "short" == self.mode and r[1] ) then
					return { state = responses[r[1]] }
				else
					local flagsinfo = {
						["E"] = "Exit",
						["A"] = "Authority",
						["B"] = "BadExit",
						["D"] = "V2Dir",
						["F"] = "Fast",
						["G"] = "Guard",
						["H"] = "HSDir",
						["N"] = "Named",
						["R"] = "Running",
						["S"] = "Stable",
						["U"] = "Unnamed",
						["V"] = "Valid"
					}

					local name, ports, flagsfound = r[1]:match(
						"N:(.+)/P:([%d,]+)/F:([EABDFGHNRSUV]+)")

					local flags = {}
					flags['name'] = "Flags"

					for k, v in pairs(flagsinfo) do
						if flagsfound:match(k) then
							table.insert(flags, v)
						end
					end

					local result = {
						("Name: %s"):format(name),
						("Ports: %s"):format(ports),
						flags
					}

					return { state = "PROXY", details = result }
				end
			end,
		},
		
		["dnsbl.ahbl.org"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.3"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
		
		["http.dnsbl.sorbs.net"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.2"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
		
		["socks.dnsbl.sorbs.net"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.3"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		},
		
		["misc.dnsbl.sorbs.net"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
				local responses = {
					["127.0.0.4"] = "PROXY",
				}
				return ( r[1] and responses[r[1]] ) and { state = responses[r[1]] }
			end,
		}
			
	},

	ATTACK = {
		["dnsbl.httpbl.org"] = {
			configuration = {
				["apikey"] = "the http:BL API key"
			},
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			fmt_query = function(self)
				if ( not(self.config.apikey) ) then
					return
				end

				local rev_ip = dns.reverse(self.ip):match("^(.*)%.in%-addr%.arpa$")
				return ("%s.%s.dnsbl.httpbl.org"):format(self.config.apikey, rev_ip)
			end,
			resp_parser = function(self, r)
				if ( not(r[1]) ) then
					return
				end

				local parts, err = ipOps.get_parts_as_number(r[1])

				if ( not(parts) or err ) then
					-- TODO Should we return failure in the result?
					stdnse.print_debug("The dnsbl.httpbl.org provider failed to return a valid address")
					return
				end

				local octet1, octet2, octet3, octet4 = table.unpack(parts)

				if ( octet1 ~= 127 ) then
					-- This should'nt happen :P
					stdnse.print_debug(string.format(
						"The request made to dnsbl.httpbl.org was considered invalid (%i)", octet1))
				elseif ( "short" == self.mode ) then
					return { state = "ATTACK" }
				else
					local search = {
						[0] = "Undocumented",
						[1] = "AltaVista",
						[2] = "Ask",
						[3] = "Baidu",
						[4] = "Excite",
						[5] = "Google",
						[6] = "Looksmart",
						[7] = "Lycos",
						[8] = "MSN",
						[9] = "Yahoo",
						[10] = "Cuil",
						[11] = "InfoSeek",
						[12] = "Miscellaneous"
					}

					local result = {}
					
					-- Search engines are a special case.
					if ( octet4 == 0 ) then
						table.insert(result, ("Search engine: %s"):format(
							search[octet3]))
					else
						table.insert(result, ("Last activity: %i days"):format(
							octet2))
						table.insert(result, ("Threat score: %i"):format(
							octet3))
						
						local activity = {}
						activity['name'] = "Activity"
						-- Suspicious activity
						if ( bit.band(octet4, 1) == 1) then
							table.insert(activity, "Suspicious")
						end

						-- Harvester
						if ( bit.band(octet4, 2) == 2) then
							table.insert(activity, "Harvester")
						end

						-- Comment spammer
						if ( bit.band(octet4, 4)  == 4) then
							table.insert(activity, "Comment spammer")
						end
						
						table.insert(result, activity)
					end

					return { state = "ATTACK", details = result }
				end
			end,
		},

		["all.bl.blocklist.de"] = {
			new = function(self, ip, mode, config)
				local o = { ip = ip, mode = mode, config = config }
				setmetatable(o, self)
				self.__index = self
				return o
			end,
			resp_parser = function(self, r)
 				local responses = {
 					["127.0.0.2"] = "Amavis",
 					["127.0.0.3"] = "DDoS",
 					["127.0.0.4"] = "Asterisk, SIP, VoIP",
 					["127.0.0.5"] = "Badbot",
 					["127.0.0.6"] = "FTP",
 					["127.0.0.7"] = "IMAP",
 					["127.0.0.8"] = "IRC bot",
 					["127.0.0.9"] = "Mail",
 					["127.0.0.10"] = "POP3",
 					["127.0.0.11"] = "Registration bot",
 					["127.0.0.12"] = "Remote file inclusion",
 					["127.0.0.13"] = "SASL",
 					["127.0.0.14"] = "SSH",
 					["127.0.0.15"] = "w00tw00t",
 					["127.0.0.16"] = "Port flood",
 				}
 				if ( "short" == self.mode and r[1] ) then
 					return "ATTACK"
 				else
 					return ( r[1] and responses[r[1]] ) and { state = "ATTACK",
 						details = {
 							("Type: %s"):format(responses[r[1]])
 						}
 					}
 				end
 			end,
 		}
	},
	
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
		for name, svc in pairs(SERVICES[self.category]) do
			if ( svc.configuration ) then
				local service = {}
				service['name'] = name

				for config, description in pairs(svc.configuration) do
					table.insert(service, ("config: %s.%s - %s"):format(
						name, config, description))
				end

				table.insert(services, service )
			else
				table.insert(services, name)
			end
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
	
	doQuery = function(self, ip, name, svc, answers)

		local condvar = nmap.condvar(answers)
		local config = {}

		if ( svc.configuration ) then
			for key in pairs(svc.configuration) do
				config[key] = stdnse.get_script_args(("%s.%s"):format(name, key))
			end
		end

		svc = svc:new(ip, self.mode, config)

		local ns_type = ( svc.ns_type and svc.ns_type[self.mode] ) and svc.ns_type[self.mode] or "A"
		local query

		if ( not(svc.fmt_query) ) then
			local rev_ip = dns.reverse(ip):match("^(.*)%.in%-addr%.arpa$")
			query = ("%s.%s"):format(rev_ip, name)
		else
			query = svc:fmt_query()
		end

		if ( query ) then
			local status, answer = dns.query(query, {dtype=ns_type, retAll=true} )
			answers[name] = { status = status, answer = answer, svc = svc }
		else
			stdnse.print_debug("Query function returned nothing, skipping '%s'", name)
		end
		
		condvar "signal"
	end,
	
	-- Runs the DNS blacklist check for the given IP against all non-filtered
	-- services in the given category.
	-- @param ip string containing the IP address to check
	-- @return result table containing the results of the BL checks
	checkBL = function(self, ip)
		local result, answers, threads = {}, {}, {}
		local condvar = nmap.condvar(answers)
		
		for name, svc in pairs(self:getServices()) do
			local co = stdnse.new_thread(self.doQuery, self, ip, name, svc, answers)
			threads[co] = true
		end

		repeat
			for t in pairs(threads) do
				if ( coroutine.status(t) == "dead" ) then threads[t] = nil end
			end
			if ( next(threads) ) then
				condvar "wait"
			end
		until( next(threads) == nil )
		
		for name, answer in pairs(answers) do
			local status, answer, svc = answer.status, answer.answer, answer.svc
			if ( status ) then
				local svc_result = svc:resp_parser(answer)
				if ( not(svc_result) ) then
					local resp = ( #answer > 0 and ("UNKNOWN (%s)"):format(answer[1]) or "UNKNOWN" )
					stdnse.print_debug(2, ("%s received %s"):format(name, resp))
				end
	
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

return _ENV;
