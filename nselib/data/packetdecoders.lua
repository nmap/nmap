local bin = require "bin"
local packet = require "packet"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local target = require "target"

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
--                          <code>data</code> argument.
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
--   x OSPF - Open Shortest Path First
--
-- o UDP
--   x DHCP
--   x Netbios
--   x SSDP
--   x HSRP
--   x DropBox
--   x Logitech SqueezeBox Discovery
--   x Multicast DNS/Bonjour/ZeroConf
--   x Spotify
--
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

-- Version 0.2
-- Created 07/25/2011 - v0.1 - created by Patrik Karlsson
--         02/12/2012 - v0.2 - added support for EIGRP - Tom Sellers
--         07/13/2012 - v0.3 - added support for OSPF - Hani Benhabiles

local bin    = require 'bin'
local target = require 'target'
local tab    = require 'tab'
local packet = require 'packet'

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
        if ( hwsize ~= 6 ) then return end
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

        local mac = sender.mac:gsub("(..)(..)(..)(..)(..)(..)","%1:%2:%3:%4:%5:%6")
        stdnse.debug1("Decoded ARP: %s, %s, %s", ipOps.fromdword(sender.ip), mac, ipOps.fromdword(target.ip))
        if ( not(self.dups[("%u:%s"):format(sender.ip,sender.mac)]) ) then
          if ( target.ALLOW_NEW_TARGETS ) then target.add(sender.ip) end
          self.dups[("%u:%s"):format(sender.ip,sender.mac)] = true
          tab.addrow(self.results, ipOps.fromdword(sender.ip), mac, ipOps.fromdword(target.ip))
        end

      end,

      getResults = function(self) return { name = "ARP Request", (self.results and tab.dump(self.results)) } end,
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
          tab.addrow( self.results, 'ip', 'id', 'platform', 'version', 'notes' )
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

      getResults = function(self) return { name = "CDP", (self.results and tab.dump(self.results) or "") } end,
    },


    -- EIGRP Update
    ['0201....0000'] = {

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
        local eigrp = require("eigrp")
        local route_type, proto_name
        -- Extract the EIGRP header
        local response = eigrp.EIGRP.parse(data)

        if response then
          -- Iterate over tlv tables
          for _, tlv in pairs(response.tlvs) do
            if eigrp.EIGRP.isRoutingTLV(tlv.type) then
              if ( not(self.results) ) then
                self.results = tab.new(7)
                tab.addrow(self.results, 'Sender IP', 'AS#', 'Route Type', 'Destination', 'Next hop', 'Ext Protocol', 'Orig Router ID')
              end
              if tlv.type == 0x102 then
                route_type = "Internal"
              elseif tlv.type == 0x103 then
                route_type = "External"
                for name, value in pairs(eigrp.EXT_PROTO) do
                  if value == tlv.eproto then
                    proto_name = name
                    break
                  end
                end
              end
              if ( not(self.dups[("%s:%s:s:%s"):format(p.ip_src, response.as, tlv.type, tlv.dst)]) ) then
                if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
                self.dups[("%s:%s:%s:%s"):format(p.ip_src, response.as, tlv.type, tlv.dst)] = true
                tab.addrow( self.results, p.ip_src, response.as, route_type, tlv.dst, tlv.nexth, proto_name or 'X', tlv.orouterid or 'X')
              end
            end
          end
        end
      end,

      getResults = function(self) return { name = "EIGRP Update", (self.results and tab.dump(self.results) or "") } end,
    },

    ['0205....0000'] = {

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
        local eigrp = require("eigrp")
        -- Extract the EIGRP header
        local response = eigrp.EIGRP.parse(data)
        -- See if Software version TLV is included
        local swvertlv
        for num, tlv in pairs(response.tlvs) do
          if tlv.type == eigrp.TLV.SWVER then
            swvertlv = num
          end
        end

        if swvertlv then
          if ( not(self.results) ) then
            self.results = tab.new(5)
            tab.addrow(self.results, 'Sender IP', 'AS number', 'EIGRP version', 'IOS version')
          end

          if ( not(self.dups[("%s:%s"):format(p.ip_src,response.as)]) ) then
            if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
            self.dups[("%s:%s"):format(p.ip_src,response.as)] = true
            tab.addrow( self.results, p.ip_src, response.as, response.tlvs[swvertlv].majv .. '.' .. response.tlvs[swvertlv].minv, response.tlvs[swvertlv].majtlv .. '.' .. response.tlvs[swvertlv].mintlv)
          end
        end
      end,

      getResults = function(self) return { name = "EIGRP Hello", (self.results and tab.dump(self.results) or "") } end,
    },

    -- OSPF
    ['02010'] = { -- OSPFv2 Hello packet

    new = function(self)
      local o = { dups = {} }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    process = function(self, layer3)
      local p = packet.Packet:new( layer3, #layer3 )
      -- IP Protocol is 89 for OSPF
      if p.ip_p ~= 89 then return end

      local ospf = require("ospf")
      local data = layer3:sub(p.ip_data_offset + 1)
      local header = ospf.OSPF.Header.parse(data)
      if header then
        if not(self.results) then
          self.results = tab.new(5)
          tab.addrow(self.results, 'Source IP', 'Router ID', 'Area ID', 'Auth Type', 'Password')
        end
        local srcip = p.ip_src
        local areaid = header.area_id
        local routerid = header.router_id
        local authtype = header.auth_type
        local authdata

        -- Format authentication type and data
        if header.auth_type == 0 then
          authtype = "None"
          authdata = ''
        elseif header.auth_type == 1 then
          authtype = "Password"
          authdata = header.auth_data.password
        elseif header.auth_type == 2 then
          authtype = "OSPF MD5"
          authdata = "" -- Not really helpful, as the MD5
          -- is applied to the whole packet+password
        else
          -- Error
          stdnse.debug1("Unknown OSPF auth type %d", header.auth_type)
          return
        end

        if ( not(self.dups[("%s:%s"):format(routerid,areaid)]) ) then
          if ( target.ALLOW_NEW_TARGETS ) then target.add(routerid) end
          self.dups[("%s:%s"):format(routerid,areaid)] = true
          tab.addrow( self.results, srcip, routerid, areaid, authtype, authdata)
        end
      else
        return nil
      end
    end,

    getResults = function(self) return { name = "OSPF Hello", (self.results and tab.dump(self.results)) } end,
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
          self.results = tab.new(6)
          tab.addrow(self.results, "srv ip", "cli ip", "mask", "gw", "dns", "vendor" )
        end
        local uniq_key = ("%s:%s"):format(p.ip_src, result.yiaddr_str)

        if ( not(self.dups[uniq_key]) ) then
          if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
          local mask = self.getOption(result.options, "Subnet Mask") or "-"
          local gw = self.getOption(result.options, "Router") or "-"
          local dns = self.getOption(result.options, "Domain Name Server") or "-"
          local vendor = self.getOption(result.options, "Class Identifier") or "-"
          stdnse.debug1("Decoded DHCP: %s, %s, %s, %s, %s, %s", p.ip_src, result.yiaddr_str, mask, gw, dns, vendor)
          tab.addrow(self.results, p.ip_src, result.yiaddr_str, mask, gw, dns, vendor )
        end
      end
    end,

    getResults = function(self) return { name = "DHCP", (self.results and tab.dump(self.results) or "") } end,
  },

  -- Netbios
  [137] = {

    new = function(self)
      local o = {
        reg_dups = {},
        query_dups = {},
        reg_result = tab.new(2),
        query_result = tab.new(2)
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    process = function(self, layer3)
      local dns = require('dns')
      local bin = require('bin')
      local netbios = require('netbios')
      local tab = require('tab')
      local p = packet.Packet:new( layer3, #layer3 )
      local data = layer3:sub(p.udp_offset + 9)

      local dresp = dns.decode(data)
      if ( not(dresp.questions) or #dresp.questions < 1 ) then return end

      local name = netbios.name_decode("\32" .. dresp.questions[1].dname)

      local function add_record(isreg, ip, name)
        local res = (isreg and self.reg_result or self.query_result)
        local dup = (isreg and self.reg_dups or self.query_dups)

        if ( #res == 0 ) then
          tab.addrow(res, 'ip', 'query')
        end
        stdnse.debug1('Decoded Netbios(%s): %s, %s', (isreg and "Registration" or "Query"), ip, name)

        if ( not(dup[ip]) or not(dup[ip][name]) ) then
          if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
          tab.addrow(res, ip, name)
          dup[ip] = dup[ip] or {}
          dup[ip][name] = true
        end
      end
      add_record( ( dresp.flags.OC2 and dresp.flags.OC4 ), p.ip_src, name )
    end,

    getResults = function(self)
      local result = { name = "Netbios" }
      if ( #self.reg_result > 1) then
        table.insert(result, { name = "Registrations", tab.dump(self.reg_result) })
      end
      if ( #self.query_result > 1 ) then
        table.insert(result, { name = "Query", tab.dump(self.query_result) })
      end
      return result
    end,
  },

  -- BROWSER
  [138] = {

    new = function(self)
      local o = { dups = {} }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    process = function(self, layer3)
      local bin = require('bin')
      local netbios = require('netbios')
      local tab = require('tab')
      local ipOps = require("ipOps")
      local p = packet.Packet:new( layer3, #layer3 )
      local data = layer3:sub(p.udp_offset + 9)

      local pos, ip, _, src, dst = 5
      pos, ip, _, _, _, src, dst = bin.unpack("<ISSSA34A34", data, pos)

      ip = ipOps.fromdword(ip)
      src = netbios.name_decode(src)
      dst = netbios.name_decode(dst)
      stdnse.debug1("Decoded BROWSER: %s, %s, %s", ip, src, dst)

      local dup_rec = ("%s:%s:%s"):format(ip, src, dst)
      if ( not(self.dups[dup_rec]) ) then
        self.dups[dup_rec] = true
        if ( not(self.results) ) then
          self.results = tab.new(3)
          tab.addrow(self.results, 'ip', 'src', 'dst')
        end
        tab.addrow(self.results, ip, src, dst)
      end
    end,

    getResults = function(self) return { name = "Browser", (self.results and tab.dump(self.results)) } end,
  },

  -- DHCPv6
  [547] = {

    new = function(self)
      local o = { dups = {} }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    process = function(self, layer3)
      local tab = require('tab')
      local p = packet.Packet:new( layer3, #layer3 )
      local data = layer3:sub(p.udp_offset + 9)

      local dhcpv6 = require("dhcp6")
      local resp = dhcpv6.DHCP6.Response.parse(data)

      for _, v in ipairs(resp.opts or {}) do
        if v.resp and v.resp.fqdn then
          if ( not(self.results) ) then
            self.results = tab.new(2)
            tab.addrow(self.results, 'ip', 'fqdn')
          end
          if ( not(self.dups[p.ip_src]) or not(self.dups[p.ip_src][v.resp.fqdn]) ) then
            tab.addrow(self.results, p.ip_src, v.resp.fqdn )
            self.dups[p.ip_src] = self.dups[p.ip_src] or {}
            self.dups[p.ip_src][v.resp.fqdn] = true
          end
        end
      end
    end,

    getResults = function(self) return { name = "DHCP6", (self.results and tab.dump(self.results)) } end,
  },

  -- CUPS
  [631] = {

    new = function(self)
      local o = { dups = {} }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    process = function(self, layer3)
      local tab = require('tab')
      local p = packet.Packet:new( layer3, #layer3 )
      local data = layer3:sub(p.udp_offset + 9)

      local function split(str)
        local start, pos, stop = 1, 1
        local pattern = ""
        local result = {}

        while(pos) do
          start = pos + #pattern
          pos, stop = str:find("\"", start)
          pattern = (pos == start and "\" " or " ")
          pos, stop = str:find(pattern, start + 1)
          table.insert(result, str:sub(start, (stop and stop - (#pattern))))
        end
        return ( #result > 0 and result or nil )
      end

      local results = split(data)
      local uri = ( #results > 3 and results[3]:match('[^%"]+') )
      local loc = ( #results > 4 and results[4]:match('[^%"]+') or "")
      local info = ( #results > 5 and results[5]:match('[^%"]+') or "")
      local model = ( #results > 6 and results[6]:match('[^%"]+') or "")

      if ( not(self.results) ) then
        self.results = tab.new(4)
        tab.addrow(self.results, 'ip', 'uri', 'loc', 'model')
      end

      stdnse.debug1("Decoded CUPS: %s, %s, %s, %s", p.ip_src, uri, loc, model)
      if ( not(self.dups[p.ip_src]) or not(self.dups[p.ip_src][uri]) ) then
        tab.addrow(self.results, p.ip_src, uri, loc, model)
        self.dups[p.ip_src] = self.dups[p.ip_src] or {}
        self.dups[p.ip_src][uri] = self.dups[p.ip_src][uri] or true
      end
    end,

    getResults = function(self) return { name = "CUPS", (self.results and tab.dump(self.results)) } end,

  },

  -- SSDP
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
            tab.addrow( self.results, 'ip', 'uri' )
          end
          if ( not(self.dups[("%s:%s"):format(p.ip_src,st)]) ) then
            if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
            tab.addrow( self.results, p.ip_src, st )
            self.dups[("%s:%s"):format(p.ip_src,st)] = true
          end
        end
      end
    end,

    getResults = function(self) return { name = "SSDP", (self.results and tab.dump(self.results)) } end,
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

    getResults = function(self) return { name = "HSRP", (self.results and tab.dump(self.results) or "") } end,

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

    getResults = function(self) return { name = "DropBox", (self.results and tab.dump(self.results) or "") } end,
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
          tab.addrow( self.results, 'ip' )
        end

        if ( not(self.dups[p.ip_src]) ) then
          tab.addrow( self.results, p.ip_src )
          self.dups[p.ip_src] = true
          if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
        end
      end

    end,

    getResults = function(self) return { name = "Squeezebox Discovery", (self.results and tab.dump(self.results) or "") } end,

  },

  -- Multicast DNS/BonJour/ZeroConf
  [5353] = {

    new = function(self)
      local o = {
        dups = {},
        macbooks = {},
        generic = {}
      }
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
        -- Identify MacBooks
        local macbook, model, ip, ipv6

        if ( p.ip_src:match(":") ) then
          ipv6 = p.ip_src
        else
          ip = p.ip_src
        end

        for i in ipairs(dresp.answers) do
          if ( dresp.answers[i]['data'] ) then
            local _, data = bin.unpack("p", dresp.answers[i]['data'])
            if ( data ) then
              model = data:match("^model=(.*)")
              if ( model ) then
                macbook = dresp.answers[i]['dname']:match("^(.-)%._")
              end
            end
          elseif ( dresp.answers[i]['ip'] ) then
            ip = dresp.answers[i]['ip']
          elseif ( dresp.answers[i]['ipv6'] ) then
            ipv6 = dresp.answers[i]['ipv6']
          elseif ( not(macbook) and dresp.answers[i]['domain'] ) then
            macbook = dresp.answers[i]['domain']
          end
        end
        if ( macbook and model ) then
          self.macbooks[macbook] = self.macbooks[macbook] or {}
          self.macbooks[macbook]['macbook'] = self.macbooks[macbook]['macbook'] or macbook
          self.macbooks[macbook]['model'] = self.macbooks[macbook]['model'] or model
          self.macbooks[macbook]['ip'] = self.macbooks[macbook]['ip'] or ip
          self.macbooks[macbook]['ipv6'] = self.macbooks[macbook]['ipv6'] or ipv6
          stdnse.debug1("Decoded MDNS(MacBook): %s, %s, %s, %s",
          (self.macbooks[macbook]['ip'] or ""), (self.macbooks[macbook]['ipv6'] or ""),
          self.macbooks[macbook]['model'], self.macbooks[macbook]['macbook'])
        else
          name = dresp.answers[1].dname
          if ( not(name) ) then return end
          self.generic[name] = self.generic[name] or {}
          self.generic[name]['name'] = self.generic[name]['name'] or name
          if ( p.ip_src:match(":") ) then
            self.generic[name]['ipv6'] = p.ip_src
          else
            self.generic[name]['ip'] = p.ip_src
          end
          stdnse.debug1("Decoded MDNS(Generic): %s, %s", name, p.ip_src)
        end
      end
    end,

    getResults = function(self)
      local tab = require('tab')
      local result = { name = "MDNS" }

      -- build a macbooks table
      local macbooks, generic

      if ( next(self.generic) ) then
        table.sort(self.generic)
        generic = tab.new(3)
        tab.addrow(generic, 'ip', 'ipv6', 'name')

        for name, v in pairs(self.generic) do
          tab.addrow(generic, (v.ip or ""), (v.ipv6 or ""), name)
        end
        table.insert(result, { name = 'Generic', tab.dump(generic) } )
      end

      if ( next(self.macbooks) ) then
        table.sort(self.macbooks)
        macbooks = tab.new(4)
        tab.addrow(macbooks, 'ip', 'ipv6', 'name', 'model')

        for _, v in pairs(self.macbooks) do
          tab.addrow(macbooks, (v.ip or ""), (v.ipv6 or ""), v.macbook, v.model)
        end
        table.insert(result, { name = 'Macbooks', tab.dump(macbooks) } )
      end

      return result
    end,
  },

  [5355] = { -- LLMNR
  new = function(self)
    local o = { dups = {} }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  process = function(self, layer3)
    local tab = require('tab')
    local dns = require('dns')
    local p = packet.Packet:new( layer3, #layer3 )
    local data = layer3:sub(p.udp_offset + 9)

    local resp = dns.decode(data)
    if ( not(self.results) ) then
      self.results = tab.new(2)
      tab.addrow(self.results, 'ip', 'query')
    end

    local name = (( resp.questions and #resp.questions > 0 ) and resp.questions[1].dname )
    if ( not(name) ) then return end
    stdnse.debug1("Decoded LLMNR: %s, %s", p.ip_src, name)

    if ( not(self.dups[("%s:%s"):format(p.ip_src, name)]) ) then
      self.dups[("%s:%s"):format(p.ip_src, name)] = true
      tab.addrow(self.results, p.ip_src, name)
    end
  end,

  getResults = function(self) return { name = "LLMNR", (self.results and tab.dump(self.results)) } end,
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
        tab.addrow( self.results, 'ip' )
      end

      if ( not(self.dups[p.ip_src]) ) then
        tab.addrow( self.results, p.ip_src )
        self.dups[p.ip_src] = true
        if ( target.ALLOW_NEW_TARGETS ) then target.add(p.ip_src) end
      end
    end

  end,

  getResults = function(self) return { name = "Spotify", (self.results and tab.dump(self.results)) } end,

}

  }
}
