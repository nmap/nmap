--- A library supporting parsing and generating a limited subset of the Cisco' EIGRP packets.
--
-- @author Hani Benhabiles
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- Version 0.1
--  19/07/2012 - First version.

local table = require "table"
local stdnse = require "stdnse"
local strbuf = require "strbuf"
local string = require "string"
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
    eigrp_packet.ver,
    eigrp_packet.opcode,
    eigrp_packet.checksum,
    eigrp_packet.flags,
    eigrp_packet.seq,
    eigrp_packet.ack,
    eigrp_packet.routerid,
    eigrp_packet.as, index = string.unpack(">BBI2I4I4I4I2I2", eigrp_raw, index)
    eigrp_packet.tlvs = {}
    while index < #eigrp_raw do
      tlv = {}
      tlv.type, tlv.length, index = string.unpack(">I2I2", eigrp_raw, index)
      if tlv.length == 0x00 then
        -- In case someone wants to DoS us :)
        stdnse.debug1("eigrp.lua: stopped parsing due to null TLV length.")
        break
      end
      -- TODO: These padding calculations seem suspect, especially the ones
      -- that assume a static length for a variable-length field like TLV.SEQ
      if tlv.type == TLV.PARAM then
        -- Parameters
        local k = {}
        k[1], k[2], k[3], k[4], k[5], k[6], tlv.htime, index = string.unpack(">BBBBBBI2", eigrp_raw, index)
        tlv.k = k
        index = index + tlv.length - 12
      elseif tlv.type == TLV.AUTH then
        tlv.authtype,
        tlv.authlen,
        tlv.keyid,
        tlv.keyseq, index = string.unpack(">I2I2I4I4", eigrp_raw, index)
        -- Null pad == tlv.length - What was already parsed - authlen
        tlv.digest, index = string.unpack(">I2", eigrp_raw, index + (tlv.length - tlv.authlen - index + 1))
      elseif tlv.type == TLV.SEQ then
        -- Sequence
        tlv.address, index = string.unpack(">s2", eigrp_raw, index)
        tlv.address = ipOps.str_to_ip(tlv.address)
        index = index + tlv.length - 7
      elseif tlv.type == TLV.SWVER then
        -- Software version
        tlv.majv,
        tlv.minv,
        tlv.majtlv,
        tlv.mintlv, index = string.unpack(">BBBB", eigrp_raw, index)
        index = index + tlv.length - 8
      elseif tlv.type == TLV.MSEQ then
        -- Next Multicast Sequence
        tlv.mseq, index = string.unpack(">I4", eigrp_raw, index)
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
        tlv.nexth, index = string.unpack(">I4", eigrp_raw, index)
        tlv.nexth = ipOps.fromdword(tlv.nexth)
        tlv.mask, index = string.unpack(">I2", eigrp_raw, index + 15)
        -- Destination varies in length
        -- e.g trailing 0's are omitted
        -- if length = 29 => destination is 4 bytes
        -- if length = 28 => destination is 3 bytes
        -- if length = 27 => destination is 2 bytes
        -- if length = 26 => destination is 1 byte
        local dst = {0,0,0,0}
        for i = 1, (4 + tlv.length - 29) do
          dst[i], index = string.unpack("B", eigrp_raw, index)
        end
        tlv.dst = table.concat(dst, '.')
      elseif tlv.type == TLV.EXT then
        -- External Route
        tlv.nexth,
        tlv.orouterid,
        tlv.oas,
        tlv.tag,
        tlv.emetric,
        -- Skip 2 reserved bytes
        tlv.eproto,
        tlv.eflags,
        tlv.lmetrics,
        tlv.mask, index = string.unpack(">I4I4I4I4I4xxBBc16B", eigrp_raw, index)
        tlv.nexth = ipOps.fromdword(tlv.nexth)
        tlv.orouterid = ipOps.fromdword(tlv.orouterid)
        -- Destination varies in length
        -- if length = 49 => destination is 4 bytes
        -- if length = 48 => destination is 3 bytes
        -- if length = 47 => destination is 2 bytes
        -- if length = 46 => destination is 1 byte
        local dst = {0,0,0,0}
        for i = 1, (4 + tlv.length - 49) do
          dst[i], index = string.unpack("B", eigrp_raw, index)
        end
        tlv.dst = table.concat(dst, '.')
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
      data = data .. string.pack(">BBI2I4I4I4I2I2",
        self.ver, -- Version 2
        self.opcode, -- Opcode: Hello
        self.checksum or 0, -- Calculated later.
        self.flags, -- Flags
        self.seq, -- Sequence 0
        self.ack, -- Acknowledge 0
        self.routerid, -- Virtual Router ID 0
        self.as) -- Autonomous system

      for _, tlv in pairs(self.tlvs) do
        if tlv.type == TLV.PARAM then
          data = data .. string.pack(">I2I2 BBBBBB I2",
            TLV.PARAM,
            12, -- Length
            tlv.k[1], tlv.k[2], tlv.k[3], tlv.k[4], tlv.k[5], tlv.k[6],
            tlv.htime)
        elseif tlv.type == TLV.AUTH then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.SEQ then
          -- TODO
          stdnse.debug1("eigrp.lua: TLV type %d skipped due to no parser.", tlv.type)
        elseif tlv.type == TLV.SWVER then
          data = data .. string.pack(">I2I2 BB BB",
            TLV.SWVER,
            0x0008,
            tonumber(tlv.majv), tonumber(tlv.minv),
            tonumber(tlv.majtlv), tonumber(tlv.mintlv))
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
        data = data:sub(1,2) .. string.pack(">I2", packet.in_cksum(data)) .. data:sub(5)
      end
      return data
    end,
  }

  return _ENV;
