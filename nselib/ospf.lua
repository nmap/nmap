---
-- A limited OSPF (Open Shortest Path First routing protocol) library, currently supporting IPv4 and the following
-- OSPF message types: HELLO, DB_DESCRIPTION, LS_REQUEST, LS_UPDATE
--
-- The library consists of an OSPF class that contains code to handle OSPFv2 packets.
--
-- @author Patrik Karlsson <patrik@cqure.net>
-- @author Emiliano Ticci <emiticci@gmail.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local bin = require "bin"
local bit = require "bit"
local math = require "math"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local ipOps = require "ipOps"
local packet = require "packet"
_ENV = stdnse.module("ospf", stdnse.seeall)

local have_ssl, openssl = pcall(require, "openssl")

-- The OSPF class.
OSPF = {

  -- Message Type constants
  Message = {
    HELLO = 1,
    DB_DESCRIPTION = 2,
    LS_REQUEST = 3,
    LS_UPDATE = 4,
  },

  Header = {
    size = 24,
    new = function(self, type, area_id, router_id, auth_type, auth_data)
      local o = {
        ver = 2,
        type = type,
        length = 0,
        router_id = router_id or 0,
        area_id = area_id or 0,
        chksum = 0,
        auth_type = auth_type or 0,
        auth_data = auth_data or {},
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    parse = function(data)
      local header = OSPF.Header:new()
      local pos
      pos, header.ver, header.type, header.length = bin.unpack(">CCS", data)
      assert( header.ver == 2, "Invalid OSPF version detected")

      pos, header.router_id, header.area_id, header.chksum, header.auth_type
      = bin.unpack(">IISS", data, pos)

      -- No authentication
      if header.auth_type == 0x00 then
        header.auth_data.password = nil
        -- Clear text password
      elseif header.auth_type == 0x01 then
        pos, header.auth_data.password = bin.unpack(">A8", data, pos)
        -- MD5 hash authentication
      elseif header.auth_type == 0x02 then
        local _
        _, header.auth_data.keyid = bin.unpack(">C", data, pos+2)
        _, header.auth_data.length = bin.unpack(">C", data, pos+3)
        _, header.auth_data.seq = bin.unpack(">I", data, pos+4)
        _, header.auth_data.hash = bin.unpack(">H"..header.auth_data.length, data, header.length+1)
      else
        -- Shouldn't happen
        stdnse.debug1("Unknown authentication type " .. header.auth_type)
        return nil
      end
      header.router_id = ipOps.fromdword(header.router_id)
      return header
    end,

    --- Sets the OSPF Area ID
    -- @param areaid Area ID.
    setAreaID = function(self, areaid)
      self.area_id = (type(areaid) == "number") and areaid or ipOps.todword(areaid)
    end,

    --- Sets the OSPF Router ID
    -- @param router_id Router ID.
    setRouterId = function(self, router_id)
      self.router_id = router_id
    end,

    --- Sets the OSPF Packet length
    -- @param length Packet length.
    setLength = function(self, length)
      self.length = self.size + length
    end,

    __tostring = function(self)
      local auth
      if self.auth_type == 0x00 then
        auth = bin.pack(">L", 0x00)
      elseif self.auth_type == 0x01 then
        auth = bin.pack(">A", self.auth_data.password)
      elseif self.auth_type == 0x02 then
        auth = bin.pack(">SCCI", 0, self.auth_data.keyid, self.auth_data.length, self.auth_data.seq)
      end
      local hdr = bin.pack(">CCS", self.ver, self.type, self.length )
      .. bin.pack(">IISS", ipOps.todword(self.router_id), self.area_id, self.chksum, self.auth_type)
      .. auth
      return hdr
    end,

  },

  Hello = {
    new = function(self)
      local o = {
        header = OSPF.Header:new(OSPF.Message.HELLO),
        options = 0x02,
        prio = 0,
        interval = 10,
        router_dead_interval = 40,
        neighbors = {},
        DR = "0.0.0.0",
        BDR = "0.0.0.0",
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    --- Adds a neighbor to the list of neighbors.
    -- @param neighbor IP Address of the neighbor.
    addNeighbor = function(self, neighbor)
      table.insert(self.neighbors, neighbor)
    end,

    --- Sets the OSPF netmask.
    -- @param netmask Netmask in A.B.C.D
    setNetmask = function(self, netmask)
      if netmask then
        self.netmask = netmask
      end
    end,

    --- Sets the OSPF designated Router.
    -- @param router IP address of the designated router.
    setDesignatedRouter = function(self, router)
      if router then
        self.DR = router
      end
    end,

    --- Sets the OSPF backup Router.
    -- @param router IP Address of the backup router.
    setBackupRouter = function(self, router)
      if router then
        self.BDR = router
      end
    end,

    __tostring = function(self)
      self.neighbors = self.neighbors or {}
      local function tostr()
        local data = bin.pack(">ISCCIII", ipOps.todword(self.netmask), self.interval, self.options, self.prio, self.router_dead_interval, ipOps.todword(self.DR), ipOps.todword(self.BDR))
        for _, n in ipairs(self.neighbors) do
          data = data .. bin.pack(">I", ipOps.todword(n))
        end
        self.header:setLength(#data)
        if self.header.auth_data.hash then
          data = data .. self.header.auth_data.hash
        end
        return tostring(self.header) .. data
      end
      local data = tostr()
      if have_ssl and self.header.auth_type == 0x02 then
        while string.len(self.header.auth_data.key) < 16 do
          self.header.auth_data.key = self.header.auth_data.key .. "\0"
        end
        self.header.auth_data.hash = openssl.md5(data .. bin.pack(">A", self.header.auth_data.key))
      else
        self.header.chksum = packet.in_cksum(data:sub(1,16) .. data:sub(25))
      end
      return tostr()
    end,

    parse = function(data)
      local hello = OSPF.Hello:new()
      local pos = OSPF.Header.size + 1
      hello.header = OSPF.Header.parse(data)
      assert( #data >= hello.header.length, "OSPF packet too short")
      pos, hello.netmask, hello.interval, hello.options, hello.prio,
      hello.router_dead_interval, hello.DR,
      hello.BDR = bin.unpack(">ISCCIII", data, pos)

      hello.netmask = ipOps.fromdword(hello.netmask)
      hello.DR = ipOps.fromdword(hello.DR)
      hello.BDR = ipOps.fromdword(hello.BDR)

      if ( ( #data - pos + 1 ) % 4 ~= 0 ) then
        stdnse.debug2("Unexpected OSPF packet length, aborting ...")
        return
      end

      local neighbor_count = ( hello.header.length - pos + 1 ) / 4
      local neighbor

      hello.neighbors = {}
      for i=1, neighbor_count do
        pos, neighbor = bin.unpack(">I", data, pos)
        neighbor = ipOps.fromdword(neighbor)
        table.insert(hello.neighbors, neighbor)
      end
      return hello
    end,

  },

  LSA = {
    Header = {
      size = 20,
      new = function(self)
        local o = {
          age = 0,
          options = 0,
          type = 1,
          id = 0,
          adv_router = 0,
          sequence = 0,
          checksum = 0,
          length = 0,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      parse = function(data)
        local lsa_h = OSPF.LSA.Header:new()
        local pos = 1
        pos, lsa_h.age, lsa_h.options, lsa_h.type, lsa_h.id, lsa_h.adv_router, lsa_h.sequence, lsa_h.checksum, lsa_h.length = bin.unpack(">SCCIIH4H2S", data, pos)

        lsa_h.id = ipOps.fromdword(lsa_h.id)
        lsa_h.adv_router = ipOps.fromdword(lsa_h.adv_router)
        return lsa_h
      end,

    },

    Link = {
      new = function(self)
        local o = {
          id = 0,
          data = 0,
          type = 2,
          num_metrics = 0,
          metric = 10,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      parse = function(data)
        local lsa_link = OSPF.LSA.Link:new()
        local pos = 1
        pos, lsa_link.id, lsa_link.data, lsa_link.type, lsa_link.num_metrics, lsa_link.metric = bin.unpack(">IICCS", data, pos)
        lsa_link.id = ipOps.fromdword(lsa_link.id)
        lsa_link.data = ipOps.fromdword(lsa_link.data)
        return lsa_link
      end,
    },

    Router = {
      new = function(self)
        local o = {
          header = OSPF.LSA.Header:new(),
          flags = 0,
          num_links = 0,
          links = {},
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      parse = function(data)
        local router = OSPF.LSA.Router:new()
        local pos = OSPF.LSA.Header.size + 1
        router.header = OSPF.LSA.Header.parse(data)
        pos, router.flags, router.num_links = bin.unpack(">CxS", data, pos)

        while ( pos < router.header.length ) do
          table.insert(router.links, OSPF.LSA.Link.parse(data:sub(pos, pos + 12)))
          pos = pos + 12
        end

        return router
      end,
    },

    ASExternal = {
      new = function(self)
        local o = {
          header = OSPF.LSA.Header:new(),
          netmask = 0,
          ext_type = 1,
          metric = 1,
          fw_address = 0,
          ext_tag = 0,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      parse = function(data)
        local as_ext = OSPF.LSA.ASExternal:new()
        local pos = OSPF.LSA.Header.size + 1
        as_ext.header = OSPF.LSA.Header.parse(data)

        pos, as_ext.netmask, as_ext.metric, as_ext.fw_address, as_ext.ext_tag = bin.unpack(">IIII", data, pos)
        as_ext.netmask = ipOps.fromdword(as_ext.netmask)
        as_ext.ext_type = 1 + bit.rshift(bit.band(as_ext.metric, 0xFF000000), 31)
        as_ext.metric = bit.band(as_ext.metric, 0x00FFFFFF)
        as_ext.fw_address = ipOps.fromdword(as_ext.fw_address)

        return as_ext
      end,
    },

    parse = function(data)
      local header = OSPF.LSA.Header.parse(data)
      if header.type == 1 then
        return OSPF.LSA.Router.parse(data)
      elseif header.type == 5 then
        return OSPF.LSA.ASExternal.parse(data)
      end
      return header.length
    end,
  },

  DBDescription = {

    new = function(self)
      local o = {
        header = OSPF.Header:new(OSPF.Message.DB_DESCRIPTION),
        mtu = 1500,
        options = 2, -- external routing capability
        init = true,
        more = true,
        master = true,
        sequence = math.random(123456789),
        lsa_headers = {}
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    __tostring = function(self)
      local function tostr()
        local flags = 0
        if ( self.init ) then flags = flags + 4 end
        if ( self.more ) then flags = flags + 2 end
        if ( self.master) then flags= flags + 1 end

        local data = bin.pack(">SCCI", self.mtu, self.options, flags, self.sequence)
        self.header:setLength(#data)
        if self.header.auth_data.hash then
          data = data .. self.header.auth_data.hash
        end
        return tostring(self.header) .. data
      end
      local data = tostr()
      if have_ssl and self.header.auth_type == 0x02 then
        while string.len(self.header.auth_data.key) < 16 do
          self.header.auth_data.key = self.header.auth_data.key .. "\0"
        end
        self.header.auth_data.hash = openssl.md5(data .. bin.pack(">A", self.header.auth_data.key))
      else
        self.header.chksum = packet.in_cksum(data:sub(1,16) .. data:sub(25))
      end
      return tostr()
    end,

    parse = function(data)
      local desc = OSPF.DBDescription:new()
      local pos = OSPF.Header.size + 1
      desc.header = OSPF.Header.parse(data)
      assert( #data >= desc.header.length, "OSPF packet too short")

      local flags = 0
      pos, desc.mtu, desc.options, flags, desc.sequence = bin.unpack(">SCCI", data, pos)

      desc.init = ( bit.band(flags, 4) == 4 )
      desc.more = ( bit.band(flags, 2) == 2 )
      desc.master = ( bit.band(flags, 1) == 1 )

      while ( pos < desc.header.length ) do
        table.insert(desc.lsa_headers, OSPF.LSA.Header.parse(data:sub(pos, pos + 20)))
        pos = pos + 20
      end

      if ( desc.init or not(desc.more) ) then
        return desc
      end

      return desc
    end,

  },

  LSRequest = {
    new = function(self)
      local o = {
        header = OSPF.Header:new(OSPF.Message.LS_REQUEST),
        ls_requests = {},
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    --- Adds a request to the list of requests.
    -- @param type LS Type.
    -- @param id Link State ID
    -- @param adv_router Advertising Router
    addRequest = function(self, type, id, adv_router)
      local request = {
        type = type,
        id = id,
        adv_router = adv_router
      }
      table.insert(self.ls_requests, request)
    end,

    __tostring = function(self)
      local function tostr()
        local data = ""
        for _, req in ipairs(self.ls_requests) do
          data = data .. bin.pack(">III", req.type, ipOps.todword(req.id), ipOps.todword(req.adv_router))
        end
        self.header:setLength(#data)
        if self.header.auth_data.hash then
          data = data .. self.header.auth_data.hash
        end
        return tostring(self.header) .. data
      end
      local data = tostr()
      if have_ssl and self.header.auth_type == 0x02 then
        while string.len(self.header.auth_data.key) < 16 do
          self.header.auth_data.key = self.header.auth_data.key .. "\0"
        end
        self.header.auth_data.hash = openssl.md5(data .. bin.pack(">A", self.header.auth_data.key))
      else
        self.header.chksum = packet.in_cksum(data:sub(1,16) .. data:sub(25))
      end
      return tostr()
    end,

    parse = function(data)
      local ls_req = OSPF.LSRequest:new()
      local pos = OSPF.Header.size + 1
      ls_req.header = OSPF.Header.parse(data)
      assert( #data >= ls_req.header.length, "OSPF packet too short")

      while ( pos < #data ) do
        local req = {}
        pos, req.type, req.id, req.adv_router = bin.unpack(">III", data, pos)
        table.insert(ls_req.ls_requests, req)
      end

      return ls_req
    end,
  },

  LSUpdate = {
    new = function(self)
      local o = {
        header = OSPF.Header:new(OSPF.Message.LS_UPDATE),
        num_lsas = 0,
        lsas = {},
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    parse = function(data)
      local lsu = OSPF.LSUpdate:new()
      local pos = OSPF.Header.size + 1
      lsu.header = OSPF.Header.parse(data)
      assert( #data >= lsu.header.length, "OSPF packet too short")

      pos, lsu.num_lsas = bin.unpack(">I", data, pos)

      while ( pos < lsu.header.length ) do
        local lsa = OSPF.LSA.parse(data:sub(pos))
        if ( type(lsa) == "table" ) then
          table.insert(lsu.lsas, lsa)
          pos = pos + lsa.header.length
        else
          pos = pos + lsa
        end
      end

      return lsu
    end,
  },

  Response = {

    parse = function(data)
      local pos, ver, ospf_type = bin.unpack("CC", data)
      if ( ospf_type == OSPF.Message.HELLO ) then
        return OSPF.Hello.parse( data )
      elseif( ospf_type == OSPF.Message.DB_DESCRIPTION ) then
        return OSPF.DBDescription.parse(data)
      elseif( ospf_type == OSPF.Message.LS_REQUEST ) then
        return OSPF.LSRequest.parse(data)
      elseif( ospf_type == OSPF.Message.LS_UPDATE ) then
        return OSPF.LSUpdate.parse(data)
      end
      return
    end,

  }
}

return _ENV;
