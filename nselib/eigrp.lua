--- A library supporting parsing and generating a limited subset of the Cisco' EIGRP packets.
--
-- @author Hani Benhabiles
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- Version 0.1
--  19/07/2012 - First version.

local bin = require "bin"
local table = require "table"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local ipOps = require "ipOps"
local packet = require "packet"
_ENV = stdnse.module("eigrp", stdnse.seeall)


-- TLV Type constants
TLV = {
  PARAM = 0x0001,
  AUTH = 0x0002,
  SEQ = 0x0003,
  SWVER = 0x0004,
  MSEQ = 0x0005,
  STUB = 0x0006,
  TERM = 0x0007,
  TIDLIST = 0x0008,
  REQ = 0x0101,
  INT = 0x0102,
  EXT = 0x0103,
  COM = 0x0104,
  INT6 = 0x0402,
  EXT6 = 0x0403,
  COM6 = 0x0404,
}

-- External protocols constants
EXT_PROTO = {
  NULL      = 0x00,
  IGRP      = 0x01,
  EIGRP     = 0x02,
  Static    = 0x03,
  RIP       = 0x04,
  HELLO     = 0x05,
  OSPF      = 0x06,
  ISIS      = 0x07,
  EGP       = 0x08,
  BGP       = 0x09,
  IDRP      = 0x10,
  Connected = 0x11,
}

-- Packets opcode constants
OPCODE = {
  UPDATE = 0x01,
  RESERVED = 0x02,
  QUERY = 0x03,
  REPLY = 0x04,
  HELLO = 0x05,
}

-- The EIGRP Class
EIGRP = {

  --- Creates a new instance of EIGRP class.
  -- @param opcode integer Opcode. Defaults to 5 (Hello)
  -- @param as integer Autonomous System. Defaults to 0.
  -- @param routerid integer virtual router ID. defaults to 0.
  -- @param flags integer flags field value. Defaults to 0.
  -- @param seq integer sequence value. Defaults to 0.
  -- @param ack integer acknowledge value. Defaults to 0.
  -- @param Checksum integer EIGRP packet checksum. Calculated automatically
  --                 if not manually set.
  -- @param Table TLVs table.
  -- @return o Instance of EIGRP
  new = function(self, opcode, as, routerid, flags, seq, ack, checksum, tlvs)
    local o = {
      ver = 2,
      opcode = opcode or TLV.HELLO,
      as = as or 0,
      routerid = routerid or 0,
      flags = flags or 0,
      seq = seq or 0x00,
      ack = ack or 0x00,
      checksum = checksum,
      tlvs = tlvs or {},
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Parses a raw eigrp packet and returns a structured response.
  -- @param eigrp_raw string EIGRP Raw packet.
  -- @return response table Structured eigrp packet.
  parse = function(eigrp_raw)
    if type(eigrp_raw) ~= 'string' then
      stdnse.debug1("eigrp.lua: parse input should be string.")
      return
    end
    if #eigrp_raw < 20 then
      stdnse.debug1("eigrp.lua: raw packet size lower then 20.")
      return
    end
    local tlv
    local eigrp_packet = {}
    local index = 1
    index, eigrp_packet.ver = bin.unpack(">C", eigrp_raw, index)
    index, eigrp_packet.opcode = bin.unpack(">C", eigrp_raw, index)
    index, eigrp_packet.checksum = bin.unpack(">S", eigrp_raw, index)
    index, eigrp_packet.flags = bin.unpack(">I", eigrp_raw, index)
    index, eigrp_packet.seq = bin.unpack(">I", eigrp_raw, index)
    index, eigrp_packet.ack = bin.unpack(">I", eigrp_raw, index)
    index, eigrp_packet.routerid = bin.unpack(">S", eigrp_raw, index)
    index, eigrp_packet.as = bin.unpack(">S", eigrp_raw, index)
    eigrp_packet.tlvs = {}
    while index < #eigrp_raw do
      tlv = {}
      index, tlv.type = bin.unpack(">S", eigrp_raw, index)
      index, tlv.length = bin.unpack(">S", eigrp_raw, index)
      if tlv.length == 0x00 then
        -- In case someone wants to DoS us :)
        stdnse.debug1("eigrp.lua: stopped parsing due to null TLV length.")
        break
      end
      if tlv.type == TLV.PARAM then
        -- Parameters
        local k = {}
        index, k[1], k[2], k[3], k[4], k[5], k[6]  = bin.unpack(">CCCCCC", eigrp_raw, index)
        index, tlv.htime = bin.unpack(">S", eigrp_raw, index)
        index = index + tlv.length - 12
      elseif tlv.type == TLV.AUTH then
        index, tlv.authtype = bin.unpack(">S", eigrp_raw, index)
        index, tlv.authlen = bin.unpack(">S", eigrp_raw, index)
        index, tlv.keyid = bin.unpack(">I", eigrp_raw, index)
        index, tlv.keyseq = bin.unpack(">I", eigrp_raw, index)
        -- Null pad == tlv.length - What was already parsed - authlen
        index, tlv.digest = bin.unpack(">S", eigrp_raw, index + (tlv.length - tlv.authlen - index + 1))
      elseif tlv.type == TLV.SEQ then
        -- Sequence
        index, tlv.addlen = bin.unpack(">S", eigrp_raw, index)
        index, tlv.address = bin.unpack("A".. tlv.addlen, eigrp_raw, index)
        tlv.address = ipOps.str_to_ip(tlv.address)
        index = index + tlv.length - 7
      elseif tlv.type == TLV.SWVER then
        -- Software version
        index, tlv.majv = bin.unpack(">C", eigrp_raw, index)
        index, tlv.minv = bin.unpack(">C", eigrp_raw, index)
        index, tlv.majtlv = bin.unpack(">C", eigrp_raw, index)
        index, tlv.mintlv = bin.unpack(">C", eigrp_raw, index)
        index = index + tlv.length - 8
      elseif tlv.type == TLV.MSEQ then
        -- Next Multicast Sequence
        index, tlv.mseq = bin.unpack(">I", eigrp_raw, index)
        index = index + tlv.length - 8
      elseif tlv.type == TLV.STUB then
        -- TODO
        stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        index = index + tlv.length - 4
      elseif tlv.type == TLV.TERM then
        -- TODO
        stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        index = index + tlv.length - 4
      elseif tlv.type == TLV.TIDLIST then
        -- TODO
        stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        index = index + tlv.length - 4
      elseif tlv.type == TLV.REQ then
        -- TODO
        stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        index = index + tlv.length - 4
      elseif tlv.type == TLV.INT then
        -- Internal Route
        index, tlv.nexth = bin.unpack(">I", eigrp_raw, index)
        tlv.nexth = ipOps.fromdword(tlv.nexth)
        index, tlv.mask = bin.unpack(">S", eigrp_raw, index + 15)
        -- Destination varies in length
        -- e.g trailing 0's are omitted
        -- if length = 29 => destination is 4 bytes
        -- if length = 28 => destination is 3 bytes
        -- if length = 27 => destination is 2 bytes
        -- if length = 26 => destination is 1 byte
        local dst = {}
        index, dst[1], dst[2], dst[3], dst[4] = bin.unpack(">C" .. 4 + tlv.length - 29, eigrp_raw, index)
        for i=2,4 do
          if not dst[i] then
            dst[i] = '0'
          end
        end
        tlv.dst = dst[1] .. '.' .. dst[2] .. '.' .. dst[3] .. '.' .. dst[4]
      elseif tlv.type == TLV.EXT then
        -- External Route
        index, tlv.nexth = bin.unpack(">I", eigrp_raw, index)
        tlv.nexth = ipOps.fromdword(tlv.nexth)
        index, tlv.orouterid = bin.unpack(">I", eigrp_raw, index)
        tlv.orouterid = ipOps.fromdword(tlv.orouterid)
        index, tlv.oas = bin.unpack(">I", eigrp_raw, index)
        index, tlv.tag = bin.unpack(">I", eigrp_raw, index)
        index, tlv.emetric = bin.unpack(">I", eigrp_raw, index)
        -- Skip 2 reserved bytes
        index, tlv.eproto = bin.unpack(">C", eigrp_raw, index + 2)
        index, tlv.eflags = bin.unpack(">C", eigrp_raw, index)
        index, tlv.lmetrics = bin.unpack(">L"..2, eigrp_raw, index)
        index, tlv.mask = bin.unpack(">C", eigrp_raw, index)
        -- Destination varies in length
        -- if length = 49 => destination is 4 bytes
        -- if length = 48 => destination is 3 bytes
        -- if length = 47 => destination is 2 bytes
        -- if length = 46 => destination is 1 byte
        local dst = {}
        index, dst[1], dst[2], dst[3], dst[4] = bin.unpack(">C" .. 4 + tlv.length - 49, eigrp_raw, index)
        for i=2,4 do
          if not dst[i] then
            dst[i] = '0'
          end
        end
        tlv.dst = dst[1] .. '.' .. dst[2] .. '.' .. dst[3] .. '.' .. dst[4]
      elseif tlv.type == TLV.COM then
        -- TODO
        stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        index = index + tlv.length - 4
      elseif tlv.type == TLV.INT6 then
        -- TODO
        stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        index = index + tlv.length - 4
      elseif tlv.type == TLV.EXT6 then
        -- TODO
        stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        index = index + tlv.length - 4
      elseif tlv.type == TLV.COM6 then
        -- TODO
        stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        index = index + tlv.length - 4
      else
        stdnse.debug1("eigrp.lua: eigrp.lua: TLV type %d unknown.", tlv.type)
        index = index + tlv.length - 4
      end
      table.insert(eigrp_packet.tlvs, tlv)
    end
    return eigrp_packet
  end,

  --- Adds a TLV table to the table of TLVs.
  -- @param tlv TLV table.
  addTLV = function(self, tlv)
    if type(tlv) == 'table' then
      table.insert(self.tlvs, tlv)
    else
      stdnse.debug1("eigrp.lua: TLV should be a table, not %s", type(tlv))
    end
  end,

  --- Checks if TLV type is one that should contain routing information.
  -- @param tlvtype integer TLV type integer to check.
  -- @return status true if tlvtype is a routing information tlv.
  isRoutingTLV = function(tlvtype)
    if tlvtype == 0x101 or tlvtype == 0x102
      or tlvtype == 0x103 or tlvtype == 0x104
      or tlvtype == 0x402 or tlvtype == 0x403
      or tlvtype == 0x404 then
      return true
    end
  end,

  --- Sets the EIGRP version.
  -- @param ver integer version to set.
  setVersion = function(self, ver)
    self.ver = ver
  end,
  --- Sets the EIGRP Packet opcode
  -- @param opcode integer EIGRP opcode.
  setOpcode = function(self, opcode)
    self.opcode = opcode
  end,
  --- Sets the EIGRP packet checksum
  -- @param integer checksum Checksum to set.
  setChecksum = function(self, checksum)
    self.checksum = checksum
  end,
  --- Sets the EIGRP packet flags field.
  -- @param flags Flags integer value.
  setFlags = function(self, flags)
    self.flags = flags
    end,
    --- Sets the EIGRP packet sequence field.
    -- @param seq EIGRP sequence.
    setSequence = function(self, seq)
      self.seq = seq
    end,
    --- Sets the EIGRP Packet acknowledge field.
    -- @param ack EIGRP acknowledge.
    setAcknowledge = function(self, ack)
      self.ack = ack
    end,
    --- Sets the EIGRP Packet Virtual Router ID.
    -- @param routerid EIGRP Virtual Router ID.
    setRouterID = function(self, routerid)
      self.routerid = routerid
    end,
    --- Sets the EIGRP Packet Autonomous System.
    -- @param as EIGRP A.S.
    setAS = function(self, as)
      self.as = as
    end,
    --- Sets the EIGRP Packet tlvs
    -- @param tlvs table of EIGRP tlvs.
    setTlvs = function(self, tlvs)
      self.tlvs = tlvs
    end,
    --- Converts the request to a string suitable to be sent over a socket.
    -- @return data string containing the complete request to send over the socket
    __tostring = function(self)
      local data = strbuf.new()
      data = data .. bin.pack(">C", self.ver) -- Version 2
      data = data .. bin.pack(">C", self.opcode) -- Opcode: Hello

      -- If checksum not manually.
      -- set to 0, then calculate it later
      if self.checksum then
        data = data .. bin.pack(">S", self.checksum)
      else
        data = data .. bin.pack(">S", 0x0000) -- Calculated later.
      end
      data = data .. bin.pack(">I", self.flags) -- Flags
      data = data .. bin.pack(">I", self.seq) -- Sequence 0
      data = data .. bin.pack(">I", self.ack) -- Acknowledge 0
      data = data .. bin.pack(">S", self.routerid) -- Virtual Router ID 0
      data = data .. bin.pack(">S", self.as) -- Autonomous system
      for _, tlv in pairs(self.tlvs) do
        if tlv.type == TLV.PARAM then
          data = data .. bin.pack(">S", TLV.PARAM)
          data = data .. bin.pack(">S", 0x000c) -- Length: 12
          data = data .. bin.pack(">CCCCCC", tlv.k[1],tlv.k[2],tlv.k[3],
          tlv.k[4],tlv.k[5],tlv.k[6])
          data = data .. bin.pack(">S", tlv.htime)
        elseif tlv.type == TLV.AUTH then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.SEQ then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.SWVER then
          data = data .. bin.pack(">S", TLV.SWVER)
          data = data .. bin.pack(">S", 0x0008)
          data = data .. bin.pack(">CC", tonumber(tlv.majv), tonumber(tlv.minv))
          data = data .. bin.pack(">CC", tonumber(tlv.majtlv), tonumber(tlv.mintlv))
        elseif tlv.type == TLV.MSEQ then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.STUB then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.TERM then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.TIDLIST then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.REQ then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.INT then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.EXT then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.COM then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.INT6 then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.EXT6 then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.COM6 then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        else
          stdnse.debug1("eigrp.lua: TLV type %d unknown.", tlv.type)
        end
      end
      data = strbuf.dump(data)
      -- In the end, correct the checksum if not manually set
      if not self.checksum then
        data = data:sub(1,2) .. bin.pack(">S", packet.in_cksum(data)) .. data:sub(5)
      end
      return data
    end,
  }

  return _ENV;
