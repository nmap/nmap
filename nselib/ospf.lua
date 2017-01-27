---
-- A minimalistic OSPF (Open Shortest Path First routing protocol) library, currently supporting IPv4 and the following
-- OSPF message types: HELLO
--
-- The library consists of an OSPF class that contains code to handle OSPFv2 packets.
--
-- @author Patrik Karlsson <patrik@cqure.net>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local bin = require "bin"
local bit = require "bit"
local math = require "math"
local stdnse = require "stdnse"
local table = require "table"
local ipOps = require "ipOps"
local packet = require "packet"
_ENV = stdnse.module("ospf", stdnse.seeall)

-- The OSPF class.
OSPF = {

  -- Message Type constants
  Message = {
    HELLO = 1,
    DB_DESCRIPTION = 2,
    LS_UPDATE = 4,
  },

  LSUpdate = {

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
      = bin.unpack("<I>ISS", data, pos)

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
        _, header.auth_data.seq = bin.unpack(">C", data, pos+4)
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
        auth = bin.pack(">A8", self.auth_data.password)
      elseif self.auth_type == 0x02 then
        auth = bin.pack(">A".. self.auth_data.length, self.auth_data.hash)
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
        return tostring(self.header) .. data
      end
      local data = tostr()
      self.header.chksum = packet.in_cksum(data:sub(1,12) .. data:sub(25))
      return tostr()
    end,

    parse = function(data)
      local hello = OSPF.Hello:new()
      local pos = OSPF.Header.size + 1
      hello.header = OSPF.Header.parse(data)
      assert( #data >= hello.header.length, "OSPF packet too short")
      pos, hello.netmask, hello.interval, hello.options, hello.prio,
      hello.router_dead_interval, hello.DR,
      hello.BDR = bin.unpack("<ISCCIII", data, pos)

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
        pos, neighbor = bin.unpack("<I", data, pos)
        neighbor = ipOps.fromdword(neighbor)
        table.insert(hello.neighbors, neighbor)
      end
      return hello
    end,

  },

  DBDescription = {

    LSAHeader = {

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

    },

    new = function(self)
      local o = {
        header = OSPF.Header:new(OSPF.Message.DB_DESCRIPTION),
        mtu = 1500,
        options = 2, -- external routing capability
        init = true,
        more = true,
        master = true,
        sequence = math.random(123456789)
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
        return tostring(self.header) .. data
      end
      local data = tostr()
      self.header.chksum = packet.in_cksum(data:sub(1,12) .. data:sub(25))
      return tostr()
    end,

    parse = function(data)
      local desc = OSPF.DBDescription:new()
      local pos = OSPF.Header.size + 1
      desc.header = OSPF.Header.parse(data)
      assert( #data == desc.header.length, "OSPF packet too short")

      local flags = 0
      pos, desc.mtu, desc.options, flags, desc.sequence = bin.unpack(">SCCI", data, pos)

      desc.init = ( bit.band(flags, 4) == 4 )
      desc.more = ( bit.band(flags, 2) == 2 )
      desc.master = ( bit.band(flags, 1) == 1 )

      if ( desc.init or not(desc.more) ) then
        return desc
      end

      return desc
    end,

  },

  Response = {

    parse = function(data)
      local pos, ver, ospf_type = bin.unpack("CC", data)
      if ( ospf_type == OSPF.Message.HELLO ) then
        return OSPF.Hello.parse( data )
      elseif( ospf_type == OSPF.Message.DB_DESCRIPTION ) then
        return OSPF.DBDescription.parse(data)
      end
      return
    end,

  }
}

return _ENV;
