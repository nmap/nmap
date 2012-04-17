---
--
-- A small CUPS ipp library implementation
--
--

module(... or "ipp", package.seeall)

local bin = require('bin')

-- The IPP layer
IPP = {
	
	StatusCode = {
		OK        = 0,
	},
	
	OperationID = {
		IPP_GET_JOB_ATTRIBUTES   = 0x0009,
		IPP_GET_JOBS             = 0x000a,
		CUPS_GET_PRINTERS        = 0x4002,
	},
	
	PrinterState = {
		IPP_PRINTER_IDLE         = 3,
		IPP_PRINTER_PROCESSING   = 4,
		IPP_PRINTER_STOPPED      = 5,
	},
	
	Attribute = {

		IPP_TAG_OPERATION	= 0x01,
		IPP_TAG_JOB			= 0x02,
		IPP_TAG_END			= 0x03,
		IPP_TAG_PRINTER     = 0x04,
		IPP_TAG_NAME        = 0x42,
		IPP_TAG_KEYWORD     = 0x44,
		IPP_TAG_URI         = 0x45,
		IPP_TAG_CHARSET 	= 0x47,
		IPP_TAG_LANGUAGE	= 0x48,
		
		new = function(self, tag, name, value)
			local o = { tag = tag, name = name, value = value }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		parse = function(data, pos)
			local attrib = IPP.Attribute:new()
			local val
			pos, attrib.tag, attrib.name, val = bin.unpack(">CPP", data, pos)
			
			attrib.value = {}		
			table.insert(attrib.value, { tag = attrib.tag, val = val })
			
			repeat
				local tag, name_len, val
				
				if ( #data < pos + 3 ) then
					break
				end

				pos, tag, name_len = bin.unpack(">CS", data, pos)
				if ( name_len == 0 ) then
					pos, val = bin.unpack(">P", data, pos)
					table.insert(attrib.value, { tag = tag, val = val })
					--print("val", val)
				else
					pos = pos - 3
				end
			until( name_len ~= 0 )
			
			if ( 1 == #attrib.value ) then
				attrib.value = attrib.value[1].val
			end
			
			return pos, attrib
		end,
		
		__tostring = function(self)
			if ( "string" == type(self.value) ) then
				return bin.pack(">CSASA", self.tag, #self.name, self.name, #self.value, self.value)
			else
				local data = bin.pack(">CSASA", self.tag, #self.name, self.name, #self.value[1].val, self.value[1].val)
				for i=2, #self.value do
					data = data .. bin.pack(">CSP", self.value[i].tag, 0, self.value[i].val)
				end
				return data
			end
		end
		
	},
	
	-- An attribute group, groups several attributes
	AttributeGroup = {
		
		new = function(self, tag, attribs)
			local o = { tag = tag, attribs = attribs or {} }
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		addAttribute = function(self, attrib)
			table.insert(self.attribs, attrib)
		end,
		
		getAttribute = function(self, name)
			for _, attrib in ipairs(self.attribs) do
				if ( attrib.name == name ) then
					return attrib
				end
			end
		end,

		getAttributeValue = function(self, name)
			for _, attrib in ipairs(self.attribs) do
				if ( attrib.name == name ) then
					return attrib.value
				end
			end
		end,
		
		__tostring = function(self)
			local data = bin.pack("C", self.tag)
		
			for _, attrib in ipairs(self.attribs) do
				data = data .. tostring(attrib)
			end
			return data
		end
		
	},
	
	-- The IPP request
	Request = {
	
		new = function(self, opid, reqid)
			local o = { 
				version        = 0x0101,
				opid           = opid,
				reqid          = reqid,
				attrib_groups  = {},
			}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		addAttributeGroup = function(self, group)
			table.insert( self.attrib_groups, group )
		end,
		
		__tostring = function(self)
			local data = bin.pack(">SSI", self.version, self.opid, self.reqid )

			for _, group in ipairs(self.attrib_groups) do
				data = data .. tostring(group)
			end
			data = data .. bin.pack("C", IPP.Attribute.IPP_TAG_END)
			return data
		end,
		
	},
	
	-- A class to handle responses from the server
	Response = {
		
		-- Creates a new instance of response
		new = function(self)
			local o = {}
			setmetatable(o, self)
			self.__index = self
			return o
		end,
		
		getAttributeGroups = function(self, tag)
			local groups = {}
			for _, v in ipairs(self.attrib_groups or {}) do
				if ( v.tag == tag ) then
					table.insert(groups, v)
				end
			end
			return groups
		end,
		
		parse = function(data)
			local resp = IPP.Response:new()
			local pos
			
			pos, resp.version, resp.status, resp.reqid = bin.unpack(">SSI", data)
			
			resp.attrib_groups = {}
			local group
			repeat
				local tag, attrib
				pos, tag = bin.unpack(">C", data, pos)
								
				if ( tag == IPP.Attribute.IPP_TAG_OPERATION or
					 tag == IPP.Attribute.IPP_TAG_JOB or
					 tag == IPP.Attribute.IPP_TAG_PRINTER or
					 tag == IPP.Attribute.IPP_TAG_END ) then
										
					if ( group ) then
						table.insert(resp.attrib_groups, group)
						group = ipp.IPP.AttributeGroup:new(tag)
					else
						group = ipp.IPP.AttributeGroup:new(tag)
					end
				else
					pos = pos - 1
				end
				
				if ( not(group) ) then
					stdnse.print_debug(2, "Unexpected tag: %d", tag)
					return
				end
				
				pos, attrib = IPP.Attribute.parse(data, pos)
				group:addAttribute(attrib)
				
			until( pos == #data  + 1)
			
			return resp
		end,
		
	},
	
	
}


Helper = {
	
	new = function(self, host, port, options)
		local o = { host = host, port = port, options = options or {} }
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	connect = function(self)
		self.socket = nmap.new_socket()
		self.socket:set_timeout(self.options.timeout or 10000)
		return self.socket:connect(self.host, self.port)
	end,
	
	getPrinters = function(self)
		local headers = {
			['Content-Type'] = 'application/ipp',
			['User-Agent'] = 'CUPS/1.5.1',
		}

		local attribs = {
			IPP.Attribute:new(ipp.IPP.Attribute.IPP_TAG_CHARSET, "attributes-charset", "utf-8" ),
			IPP.Attribute:new(ipp.IPP.Attribute.IPP_TAG_LANGUAGE, "attributes-natural-language", "en"),
		}

		local ag = IPP.AttributeGroup:new(ipp.IPP.Attribute.IPP_TAG_OPERATION, attribs)
		local request = IPP.Request:new(IPP.OperationID.CUPS_GET_PRINTERS, 1)
		request:addAttributeGroup(ag)

		local http_resp = http.post(self.host, self.port, '/', { header = headers }, nil, tostring(request))
		if ( http_resp.status ~= 200 ) then
			return false, "Unexpected response from server"
		end

		local response = ipp.IPP.Response.parse(http_resp.body)
		local printers = {}
		
		for _, ag in ipairs(response:getAttributeGroups(ipp.IPP.Attribute.IPP_TAG_PRINTER)) do
			local attrib = { 
				["printer-name"] = "name", 
				["printer-location"] = "location",
				["printer-make-and-model"] = "model",
				["printer-state"] = "state",
				["queued-job-count"] = "queue_count",
				["printer-dns-sd-name"] = "dns_sd_name",
			}
			
			local printer = {}
			for k, v in pairs(attrib) do
				if ( ag:getAttributeValue(k) ) then
					printer[v] = ag:getAttributeValue(k)
				end
			end
			table.insert(printers, printer)
		end
		return true, printers
	end,
	
	-- getQueueInfo = function(self, uri)
	-- 	local headers = {
	-- 		['Content-Type'] = 'application/ipp',
	-- 		['User-Agent'] = 'CUPS/1.5.1',
	-- 	}
	-- 
	-- 	local uri = uri or ("ipp://%s/"):format(self.host.ip)
	-- 
	-- 	local attribs = {
	-- 		IPP.Attribute:new(ipp.IPP.Attribute.IPP_TAG_CHARSET, "attributes-charset", "utf-8" ),
	-- 		IPP.Attribute:new(ipp.IPP.Attribute.IPP_TAG_LANGUAGE, "attributes-natural-language", "en-us"),
	-- 		IPP.Attribute:new(ipp.IPP.Attribute.IPP_TAG_URI, "printer-uri", uri),
	-- 		IPP.Attribute:new(ipp.IPP.Attribute.IPP_TAG_KEYWORD, "requested-attributes", {
	-- 			{ tag = ipp.IPP.Attribute.IPP_TAG_KEYWORD, val = "job-id" },
	-- 			{ tag = ipp.IPP.Attribute.IPP_TAG_KEYWORD, val = "job-k-octets" },
	-- 			{ tag = ipp.IPP.Attribute.IPP_TAG_KEYWORD, val = "job-name" },
	-- 			{ tag = ipp.IPP.Attribute.IPP_TAG_KEYWORD, val = "job-originating-user-name" },
	-- 			{ tag = ipp.IPP.Attribute.IPP_TAG_KEYWORD, val = "job-printer-state-message" },
	-- 			{ tag = ipp.IPP.Attribute.IPP_TAG_KEYWORD, val = "job-printer-uri" },
	-- 			{ tag = ipp.IPP.Attribute.IPP_TAG_KEYWORD, val = "time-at-creation" } } ),
	-- 		IPP.Attribute:new(ipp.IPP.Attribute.IPP_TAG_NAME, "requesting-user-name", "nmap" ),
	-- 		IPP.Attribute:new(ipp.IPP.Attribute.IPP_TAG_KEYWORD, "which-jobs", "not-completed" )
	-- 	}
	-- 
	-- 	local ag = IPP.AttributeGroup:new(ipp.IPP.Attribute.IPP_TAG_OPERATION, attribs)
	-- 	local request = IPP.Request:new(IPP.OperationID.IPP_GET_JOBS, 1)
	-- 	request:addAttributeGroup(ag)
	-- 
	-- 	local http_resp = http.post(self.host, self.port, '/', { header = headers }, nil, tostring(request))
	-- 	if ( http_resp.status ~= 200 ) then
	-- 		return false, "Unexpected response from server"
	-- 	end
	-- 
	-- 	local response = ipp.IPP.Response.parse(http_resp.body)
	-- 	
	-- end,
	
	close = function(self)
		return self.socket:close()
	end,
}
