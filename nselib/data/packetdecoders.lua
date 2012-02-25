--- The following file contains a list of decoders used by the
-- broadcast-listener script. A decoder can be either "ethernet" based or IP
-- based. As we're only monitoring broadcast traffic (ie. traffic not
-- explicitly addressed to us) we're mainly dealing with:
-- o UDP broadcast or multicast traffic
-- o ethernet broadcast traffic
--
-- Hence, the Decoder table defines two sub tables ether and udp.
-- In order to match an incoming UDP packet the destination port number is
-- used, therefore each function is indexed based on their destination port
-- for the udp based decoders. For the ether table each decoder function is
-- indexed according to a pattern that the decoding engine attempts to match.
--
-- Each decoder defines three functions:
-- o <code>new</code> - creates a new instance of the decoder
-- o <code>process</code> - process a packet passed through the 
--							<code>data</code> argument.
-- o <code>getResults</code> - retrieve any discovered results
--
-- The discovery engine creates an instance of each decoder once it's needed.
-- Then discovery engine stores this instance in a decoder table for reference
-- once the next packet of the same type comes in. This allows the engine to
-- discard duplicate packets and to request the collected results at the end
-- of the session.
--
-- Currently, the packet decoder decodes the following protocols:
-- o Ether
--   x ARP requests (IPv4)
--   x CDP - Cisco Discovery Protocol
--   x EIGRP - Cisco Enhanced Interior Gateway Routing Protocol
--
-- o UDP
--   x DHCP
-- 	 x Netbios
--   x SSDP
--   x HSRP
--   x DropBox
--   x Logitech SqueezeBox Discovery
--   x Multicast DNS/Bonjour/ZeroConf
--   x Spotify
--
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- @copyright Same as Nmap--See http://nmap.org/book/man-legal.html

-- Version 0.2
-- Created 07/25/2011 - v0.1 - created by Patrik Karlsson
--         02/12/2012 - v.02 - added support for EIGRP - Tom Sellers

require 'target'

Decoders = {

	ether = {
	
		-- ARP IPv4
		['^00..08000604'] = {
			
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
			
			process = function(self, data)
				local ipOps = require("ipOps")
				local pos, hw, proto, hwsize, protosize, opcode = bin.unpack(">SSCCS", data)
				
				-- this shouldn't ever happen, given our filter
				if ( hwsize ~= 6 ) then	return end
				local sender, target = {}, {}
				
				-- if this isn't an ARP request, abort
				if ( opcode ~= 1 ) then return end
				
				pos, sender.mac, 
					sender.ip, 
					target.mac, 
					target.ip = bin.unpack("<H" .. hwsize .. "IH" .. hwsize .. "I", data, pos)
					
				if ( not(self.results) ) then
					self.results = tab.new(3)
					tab.addrow(self.results, 'sender ip', 'sender mac', 'target ip')
				end

				if ( not(self.dups[("%d:%s"):format(sender.ip,sender.mac)]) ) then
					if ( target.ALLOW_NEW_TARGETS ) then target.add(sender.ip) end
					local mac = sender.mac:gsub("(..)(..)(..)(..)(..)(..)","%1:%2:%3:%4:%5:%6")
					self.dups[("%d:%s"):format(sender.ip,sender.mac)] = true
					tab.addrow(self.results, ipOps.fromdword(sender.ip), mac, ipOps.fromdword(target.ip))
				end
				
			end,
			
			getResults = function(self)	return { name = "ARP Request", (self.results and tab.dump(self.results) or "")  } end,
		},
		
		-- CDP
		['^AAAA..00000C2000'] = {

			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,

			getAddresses = function(data)
				local ipOps = require("ipOps")
				local pos, proto_type, proto_len, addr_proto, addr_len, dev_addr, count
				local addr_list = ''
						
				pos, count = bin.unpack(">I", data)
				for i=1, count do
					pos, proto_type, proto_len = bin.unpack(">CC", data, pos)
					pos, addr_proto = bin.unpack(">H" .. proto_len, data, pos)
					if ( addr_proto == 'CC' ) then
						-- IPv4 address, extract it
						pos, addr_len = bin.unpack(">S", data, pos)
						pos, dev_addr = bin.unpack("<I", data, pos)
						addr_list = addr_list .. ' ' .. ipOps.fromdword(dev_addr)
					end
					-- Add code here for IPv6, others
				end
				
				return addr_list
			end,
			
			process = function(self, data)

				local pos, ver, ttl, chk = bin.unpack(">CCS", data, 9)
				if ( ver ~= 2 ) then return end
				if ( not(self.results) ) then
					self.results = tab.new(5)				
					tab.addrow(	self.results, 'ip', 'id', 'platform', 'version', 'notes' )
				end

				local result_part = {}
				result_part.notes = ''
				while ( pos < #data ) do
					local typ, len, typdata
					pos, typ, len = bin.unpack(">SS", data, pos)
					pos, typdata = bin.unpack("A" .. len - 4, data, pos)
					
					-- Device ID
					if ( typ == 1 ) then
						result_part.id = typdata
					-- Version
					elseif ( typ == 5 ) then
						result_part.version = typdata:match(", Version (.-),")
					-- Platform
					elseif ( typ == 6 ) then
						result_part.platform = typdata
					-- Address
					elseif ( typ == 2 ) then
						result_part.ip = self.getAddresses(typdata)
					elseif ( typ == 10) then
						local _, mgmt_vlan = bin.unpack(">S", data,pos - 2)
						result_part.notes = result_part.notes .. 'native vlan:' .. mgmt_vlan .. ' '
					-- Management Address
					elseif ( typ == 22 ) then
						result_part.notes = result_part.notes .. 'mgmt ip:' .. self.getAddresses(typdata) .. ' '
					-- TODO: add more decoding of types here ...
					end
				end
				
				-- TODO: add code for dups check
				if ( not(self.dups[result_part.ip]) ) then
					self.dups[result_part.ip] = true
					tab.addrow( self.results, result_part.ip, result_part.id, result_part.platform, result_part.version, result_part.notes )
				end
			end,
			
			getResults = function(self)	return { name = "CDP", (self.results and tab.dump(self.results) or "")  } end,
		},
		
		
		-- EIGRP Query & Update
		['020[13]....00000000'] = {

			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
						self.__index = self
				return o
			end,

			process = function(self, layer3)
		  
				local p = packet.Packet:new( layer3, #layer3 ) 
				-- EIGRP is IP protocol 88 (0x58), so verify this
				if ( p.ip_p ~= 88 ) then return end
				
				local data = layer3:sub(p.ip_data_offset + 1)
				
				-- Extract the EIGRP header
				local pos, ver, opcode, checksum, flags, seq, ack, asnum = bin.unpack(">CCSiiii", data)

			  local route_type, size, nexthop, delay, bandwidth, temp, mtu, orig_router, orig_as, arbtag
				local hop_count, reliability, load, reserved, mask
				local destination
				
				-- Iterate over the routes
				while ( pos < #data ) do 
					-- Get the route type as the packet construction varies
					pos,route_type = bin.unpack(">S", data, pos)
					
					if ( route_type == 258 ) then
						route_type = 'internal' 
						pos, size, nexthop, delay, bandwidth, temp, mtu = bin.unpack(">SiiiCS", data, pos)
						pos, hop_count, reliability, load, reserved, mask = bin.unpack(">CCCSC", data, pos)

						local oct1, oct2, oct3, oct4 = 0, 0, 0, 0
						-- unneeded address octets are left out of the packets, lets fill in the gaps
						if ( size == 29 ) then
							-- mask 25 or above
							pos, oct1, oct2, oct3, oct4 = bin.unpack(">CCCC", data, pos)
						elseif ( size == 28 ) then
							pos, oct1, oct2, oct3 = bin.unpack(">CCC", data, pos)
						elseif ( size == 27 ) then
							pos, oct1, oct2 = bin.unpack(">CC", data, pos)
						elseif ( size == 26 ) then
							pos, oct1 = bin.unpack(">C", data, pos)
						end
					
						destination = oct1 .. '.' .. oct2 .. '.' .. oct3 .. '.' .. oct4 .. "/" .. mask
						orig_router = 'n/a'
					elseif ( route_type == 259 ) then
					  -- external route, from a different routing protocol
						pos, size, nexthop = bin.unpack(">Si", data, pos)
						local orig_rtr_oct1, orig_rtr_oct2, orig_rtr_oct3, orig_rtr_oct4
						pos, orig_rtr_oct1, orig_rtr_oct2, orig_rtr_oct3, orig_rtr_oct4 = bin.unpack(">CCCC", data, pos)
						orig_router = orig_rtr_oct1 .. '.' .. orig_rtr_oct2 .. '.' .. orig_rtr_oct3 .. '.' .. orig_rtr_oct4
						pos, orig_as, arbtag, ext_metric = bin.unpack(">iii", data, pos)
						pos, reserved, ext_proto_id, flags, delay, bandwidth = bin.unpack(">SCCii", data, pos)
						pos, temp, mtu, hop_count, reliability, load, reserved, mask = bin.unpack(">CSCCCSC", data, pos)
						
						local oct1, oct2, oct3, oct4 = 0, 0, 0, 0
						-- unneeded address octets are left out of the packets, lets fill in the gaps
						if ( size == 49 ) then
							-- mask 25 or above
							pos, oct1, oct2, oct3, oct4 = bin.unpack(">CCCC", data, pos)
						elseif ( size == 48 ) then
							pos, oct1, oct2, oct3 = bin.unpack(">CCC", data, pos)
						elseif ( size == 47 ) then
							pos, oct1, oct2 = bin.unpack(">CC", data, pos)
						elseif ( size == 46 ) then
							pos, oct1 = bin.unpack(">C", data, pos)
						end
					
						destination = oct1 .. '.' .. oct2 .. '.' .. oct3 .. '.' .. oct4 .. "/" .. mask
						
						local Proto_Types = {
							[1] = 'external (IGRP)',
							[2] = 'external (EIGRP)',
							[3] = 'external (static)',
							[4] = 'external (RIP)',
							[6] = 'external (OSPF)',
							[9] = 'external (RIP)'
						}
						
						route_type = Proto_Types[ext_proto_id]
					end
				
					if ( not(self.results) ) then
						self.results = tab.new(9)
						tab.addrow(self.results, 'sender ip', 'AS#', 'route type', 'destination', 'hop', 'bandwidth', 'delay', 'seq','orig router')
					end
					  

					if (delay == -1) then delay = 'unreachable' end
					
					if ( not(self.dups[("%s:%s:s:%s"):format(p.ip_src,asnum,destination,seq)]) ) then
						if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
						self.dups[("%s:%s:%s:%s"):format(p.ip_src,asnum,destination,seq)] = true
						tab.addrow( self.results, p.ip_src, asnum, route_type, destination, hop_count, bandwidth, delay, seq, orig_router )
					end
				end
			end,
			
			getResults = function(self)	return { name = "EIGRP Query", (self.results and tab.dump(self.results) or "")  } end,
		},
		
		['0205....00000000'] = {

			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
						self.__index = self
				return o
			end,

			process = function(self, layer3)
		  
				local p = packet.Packet:new( layer3, #layer3 ) 
				-- EIGRP is IP protocol 88 (0x58), so verify this
				if ( p.ip_p ~= 88 ) then return end
				
				local data = layer3:sub(p.ip_data_offset + 1)			
				-- Extract the EIGRP header
				local pos, ver, opcode, checksum, flags, seq, ack, asnum = bin.unpack(">CCSiiii", data)

				-- Skip the parameters for now.
				pos = pos + 10
		
				local holdtime, software, size, ios_major, ios_minor, eigrp_major, eigrp_minor
				pos, holdtime, software, size, ios_major, ios_minor, eigrp_major, eigrp_minor = bin.unpack(">SSSCCCC", data, pos)

				if ( not(self.results) ) then
					self.results = tab.new(5)
					tab.addrow(self.results, 'sender ip', 'AS number', 'hold time', 'EIGRP version', 'IOS version')
				end
				
				if ( not(self.dups[("%s:%s"):format(p.ip_src,asnum)]) ) then
					if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
					self.dups[("%s:%s"):format(p.ip_src,asnum)] = true
					tab.addrow( self.results, p.ip_src, asnum, holdtime, eigrp_major .. '.' .. eigrp_minor, ios_major .. '.' .. ios_minor )
				end
			
			end,
			
			getResults = function(self)	return { name = "EIGRP Hello", (self.results and tab.dump(self.results) or "")  } end,
		},
		
	},
	
	udp = {
		
		-- DHCP
		[68] = {
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
		
			getOption = function(options, name)
				for _, v in ipairs(options) do
					if ( v.name == name ) then
						if ( type(v.value) == "table" ) then
							return stdnse.strjoin(", ", v.value)
						else
							return v.value
						end
					end
				end
			end,
		
			process = function(self, layer3)
				local dhcp = require("dhcp")
				local p = packet.Packet:new( layer3, #layer3 )
				local data = layer3:sub(p.udp_offset + 9)
				
				-- the dhcp.parse function isn't optimal for doing
				-- this, but it will do for now. First, we need to
				-- extract the xid as the parse function checks that it
				-- was the same as in the request, which we didn't do.
				local pos, msgtype, _, _, _, xid = bin.unpack("<CCCCA4", data)

				-- attempt to parse the data
				local status, result = dhcp.dhcp_parse(data, xid)
								
				if ( status ) then
					if ( not(self.results) ) then
						self.results = tab.new(5)
						tab.addrow(self.results, "srv ip", "cli ip", "mask", "gw", "dns" )
					end
					local uniq_key = ("%s:%s"):format(p.ip_src, result.yiaddr_str)

					if ( not(self.dups[uniq_key]) ) then
						if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
						local mask = self.getOption(result.options, "Subnet Mask") or "-"
						local gw = self.getOption(result.options, "Router") or "-"
						local dns = self.getOption(result.options, "Domain Name Server") or "-"
						tab.addrow(self.results, p.ip_src, result.yiaddr_str, mask, gw, dns )
					end
				end
				
			end,
			
			getResults = function(self)	return { name = "DHCP", (self.results and tab.dump(self.results) or "") } end,
		},
		
		-- Netbios
		[137] = {
			
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
		
			process = function(self, layer3)
				local dns = require('dns')
				local bin = require('bin')
				local netbios = require('netbios')
				local p = packet.Packet:new( layer3, #layer3 )
				local data = layer3:sub(p.udp_offset + 9)

				local dresp = dns.decode(data)
				if ( not(dresp.questions) or #dresp.questions < 1 ) then return end
				
				local name = netbios.name_decode("\32" .. dresp.questions[1].dname)

				if ( not(self.results) ) then
					self.results = tab.new(2)				
					tab.addrow(	self.results, 'ip', 'query' )
				end
			
				-- check for duplicates
				if ( not(self.dups[("%s:%s"):format(p.ip_src, name)]) ) then
					if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
					tab.addrow( self.results, p.ip_src, name )
					self.dups[("%s:%s"):format(p.ip_src, name)] = true
				end
			end,

			getResults = function(self)	return { name = "Netbios", (self.results and tab.dump(self.results) or "") } end,
		},

		--- SSDP
		[1900] = {
		
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
		
			process = function(self, layer3)
				local p = packet.Packet:new( layer3, #layer3 )
				local data = layer3:sub(p.udp_offset + 9)

				local headers = stdnse.strsplit("\r\n", data)
				for _, h in ipairs(headers) do
					local st = ""
					if ( h:match("^ST:.*") ) then
						st = h:match("^ST:(.*)")
						if ( not(self.results) ) then
							self.results = tab.new(1)
							tab.addrow(	self.results, 'ip', 'uri' )
						end
						if ( not(self.dups[("%s:%s"):format(p.ip_src,st)]) ) then
							if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
							tab.addrow(	self.results, p.ip_src, st )
							self.dups[("%s:%s"):format(p.ip_src,st)] = true
						end
					end
				end			
			end,
		
			getResults = function(self)	return { name = "SSDP", (self.results and tab.dump(self.results) or "") } end,
		
		},

		--- HSRP
		[1985] = {
		
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
		
			process = function(self, layer3)
				local p = packet.Packet:new( layer3, #layer3 )
				local data = layer3:sub(p.udp_offset + 9)
				local ipOps = require("ipOps")
				
				local State = {
					[0] = "Initial",
					[1] = "Learn",
					[2] = "Listen",
					[4] = "Speak",
					[8] = "Standby",
					[16] = "Active"
				}
				
				local Op = {
					[0] = "Hello",
					[1] = "Coup",
					[2] = "Resign",
				}

				local pos, version, op, state, _, _, prio, group, _, secret = bin.unpack("CCCCCCCCz", data) 
				if ( version ~= 0 ) then return end
				pos = pos + ( 7 - #secret )
				local virtip
				pos, virtip = bin.unpack("<I", data, pos)
				
				if ( not(self.dups[p.ip_src]) ) then
					if ( not(self.results) ) then
						self.results = tab.new(7)
						tab.addrow(self.results, 'ip', 'version', 'op', 'state', 'prio', 'group', 'secret', 'virtual ip')
					end
					if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
					self.dups[p.ip_src] = true
					tab.addrow(self.results, p.ip_src, version, Op[op], State[state], prio, group, secret, ipOps.fromdword(virtip))
				end
					
			end,
		
			getResults = function(self)	return { name = "HSRP", (self.results and tab.dump(self.results) or "") } end,
		
		},


		-- Dropbox
		[17500] = {
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
		
			process = function(self, layer3)
				local json = require("json")
				local p = packet.Packet:new( layer3, #layer3 )
				local data = layer3:sub(p.udp_offset + 9)
				local status, info = json.parse(data)
				if ( not(status) ) then
					return false, "Failed to parse JSON data"
				end
			
				-- Add host to list.
				for _, key1 in pairs({"namespaces", "version"}) do
					for key2, val in pairs(info[key1]) do
						info[key1][key2] = tostring(info[key1][key2])
					end
				end
			
				if ( not(self.results) ) then
					self.results = tab.new(6)
					tab.addrow(
						self.results,
						'displayname',
						'ip',
						'port',
						'version',
						'host_int',
						'namespaces'
					)
				end
			
				if ( not(self.dups[p.ip_src]) ) then
					tab.addrow(
						self.results,
						info.displayname,
						p.ip_src,
						info.port,
						stdnse.strjoin(".", info.version),
						info.host_int,
						stdnse.strjoin(", ", info.namespaces)
					)
					self.dups[p.ip_src] = true
					if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
				end
			end,
		
			getResults = function(self)	return { name = "DropBox", (self.results and tab.dump(self.results) or "") } end,
		
		},
	
		--- Squeezebox Discovery
		[3483] = {
		
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
		
			process = function(self, layer3)
				local p = packet.Packet:new( layer3, #layer3 )
				local data = layer3:sub(p.udp_offset + 9)
		
				if ( data:match("^eIPAD") ) then
					if ( not(self.results) ) then
						self.results = tab.new(1)
						tab.addrow(	self.results, 'ip' )
					end
			
					if ( not(self.dups[p.ip_src]) ) then
						tab.addrow(	self.results, p.ip_src )
						self.dups[p.ip_src] = true
						if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
					end
				end
			
			end,
		
			getResults = function(self)	return { name = "Squeezebox Discovery", (self.results and tab.dump(self.results) or "") } end,
		
		},
		
		-- Multicast DNS/BonJour/ZeroConf
		[5353] = {
			
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
		
			process = function(self, layer3)
				local dns = require('dns')
				local bin = require('bin')

				local p = packet.Packet:new( layer3, #layer3 )
				local data = layer3:sub(p.udp_offset + 9)

				local dresp = dns.decode(data)
				local name
				
				if ( dresp.questions and #dresp.questions > 0 ) then
					name = dresp.questions[1].dname
				elseif ( dresp.answers and #dresp.answers > 0 ) then
					name = dresp.answers[1].dname
				end
				
				if ( not(name) ) then return end
				
				if ( not(self.results) ) then
					self.results = tab.new(2)				
					tab.addrow(	self.results, 'ip', 'query' )
				end
			
				-- check for duplicates
				if ( not(self.dups[("%s:%s"):format(p.ip_src, name)]) ) then
					tab.addrow( self.results, p.ip_src, name )
					self.dups[("%s:%s"):format(p.ip_src, name)] = true
					if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
				end
			end,

			getResults = function(self)	return { name = "MDNS", (self.results and tab.dump(self.results) or "") } end,
		},
	
		--- Spotify
		[57621] = {
		
			new = function(self)
				local o = { dups = {} }
				setmetatable(o, self)
		        self.__index = self
				return o
			end,
		
			process = function(self, layer3)
				local p = packet.Packet:new( layer3, #layer3 )
				local data = layer3:sub(p.udp_offset + 9)
		
				if ( data:match("^SpotUdp") ) then
					if ( not(self.results) ) then
						self.results = tab.new(1)
						tab.addrow(	self.results, 'ip' )
					end
			
					if ( not(self.dups[p.ip_src]) ) then
						tab.addrow(	self.results, p.ip_src )
						self.dups[p.ip_src] = true
						if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
					end
				end
			
			end,
		
			getResults = function(self)	return { name = "Spotify", (self.results and tab.dump(self.results) or "") } end,
		
		}
	
	}
}