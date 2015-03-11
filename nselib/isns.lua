---
-- A minimal Internet Storage Name Service (iSNS) implementation
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--

local bin    = require('bin')
local ipops  = require('ipOps')
local match  = require('match')
local nmap = require('nmap')
local stdnse = require('stdnse')
local table = require('table')
_ENV = stdnse.module("isns", stdnse.seeall);

iSCSI = {

  NodeType = {
    TARGET    = 1,
    INITIATOR = 2,
    CONTROL   = 4,
  }

}


Header = {

  VERSION = 1,

  --
  -- Creates a header instance
  --
  -- @param func_id number containing the function ID of the message
  -- @param pdu_len number containing the length of the PDU
  -- @param flags number containing the message flags
  -- @param trans_id number containing the transaction id
  -- @param seq_id number containing the sequence id
  -- @return o new class instance
  new = function(self, func_id, pdu_len, flags, trans_id, seq_id)
    local o = {
      ver = Header.VERSION,
      func_id = func_id,
      flags = flags,
      trans_id = trans_id,
      seq_id = seq_id,
      pdu_len = pdu_len,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --
  -- Parses a opaque string and creates a new Header instance
  --
  -- @param data opaques string containing the raw data
  -- @return hdr new instance of Header
  parse = function(data)
    local hdr = Header:new()
    local pos

    pos, hdr.ver, hdr.func_id, hdr.pdu_len, hdr.flags, hdr.trans_id,
    hdr.seq_id = bin.unpack(">SSSSSS", data)

    return hdr
  end,

  --
  -- Converts the instance to an opaque string
  -- @return str containing an opaque string
  __tostring = function(self)
    return bin.pack(">SSSSSS", self.ver, self.func_id,
    self.pdu_len, self.flags, self.trans_id, self.seq_id )
  end

}

Attribute = {

  Tag = {
    ISNS_TAG_DELIMITER = 0,
    ISNS_TAG_ENTITY_IDENTIFIER = 1,
    ISNS_TAG_ENTITY_PROTOCOL = 2,
    ISNS_TAG_MGMT_IP_ADDRESS = 3,
    ISNS_TAG_TIMESTAMP = 4,
    ISNS_TAG_PROTOCOL_VERSION_RANGE = 5,
    ISNS_TAG_REGISTRATION_PERIOD = 6,
    ISNS_TAG_ENTITY_INDEX = 7,
    ISNS_TAG_ENTITY_NEXT_INDEX = 8,
    ISNS_TAG_ENTITY_ISAKMP_PHASE_1 = 11,
    ISNS_TAG_ENTITY_CERTIFICATE = 12,
    ISNS_TAG_PORTAL_IP_ADDRESS = 16,
    ISNS_TAG_PORTAL_TCP_UDP_PORT = 17,
    ISNS_TAG_PORTAL_SYMBOLIC_NAME = 18,
    ISNS_TAG_ESI_INTERVAL = 19,
    ISNS_TAG_ESI_PORT = 20,
    ISNS_TAG_PORTAL_INDEX = 22,
    ISNS_TAG_SCN_PORT = 23,
    ISNS_TAG_PORTAL_NEXT_INDEX = 24,
    ISNS_TAG_PORTAL_SECURITY_BITMAP = 27,
    ISNS_TAG_PORTAL_ISAKMP_PHASE_1 = 28,
    ISNS_TAG_PORTAL_ISAKMP_PHASE_2 = 29,
    ISNS_TAG_PORTAL_CERTIFICATE = 31,
    ISNS_TAG_ISCSI_NAME = 32,
    ISNS_TAG_ISCSI_NODE_TYPE = 33,
    ISNS_TAG_ISCSI_ALIAS = 34,
    ISNS_TAG_ISCSI_SCN_BITMAP = 35,
    ISNS_TAG_ISCSI_NODE_INDEX = 36,
    ISNS_TAG_WWNN_TOKEN = 37,
    ISNS_TAG_ISCSI_NODE_NEXT_INDEX = 38,
    ISNS_TAG_ISCSI_AUTHMETHOD = 42,
    ISNS_TAG_PG_ISCSI_NAME = 48,
    ISNS_TAG_PG_PORTAL_IP_ADDR = 49,
    ISNS_TAG_PG_PORTAL_TCP_UDP_PORT = 50,
    ISNS_TAG_PG_TAG = 51,
    ISNS_TAG_PG_INDEX = 52,
    ISNS_TAG_PG_NEXT_INDEX = 53,
    ISNS_TAG_FC_PORT_NAME_WWPN = 64,
    ISNS_TAG_PORT_ID = 65,
    ISNS_TAG_FC_PORT_TYPE = 66,
    ISNS_TAG_SYMBOLIC_PORT_NAME = 67,
    ISNS_TAG_FABRIC_PORT_NAME = 68,
    ISNS_TAG_HARD_ADDRESS = 69,
    ISNS_TAG_PORT_IP_ADDRESS = 70,
    ISNS_TAG_CLASS_OF_SERVICE = 71,
    ISNS_TAG_FC4_TYPES = 72,
    ISNS_TAG_FC4_DESCRIPTOR = 73,
    ISNS_TAG_FC4_FEATURES = 74,
    ISNS_TAG_IFCP_SCN_BITMAP = 75,
    ISNS_TAG_PORT_ROLE = 76,
    ISNS_TAG_PERMANENT_PORT_NAME = 77,
    ISNS_TAG_FC4_TYPE_CODE = 95,
    ISNS_TAG_FC_NODE_NAME_WWNN = 96,
    ISNS_TAG_SYMBOLIC_NODE_NAME = 97,
    ISNS_TAG_NODE_IP_ADDRESS = 98,
    ISNS_TAG_NODE_IPA = 99,
    ISNS_TAG_PROXY_ISCSI_NAME = 101,
    ISNS_TAG_SWITCH_NAME = 128,
    ISNS_TAG_PREFERRED_ID = 129,
    ISNS_TAG_ASSIGNED_ID = 130,
    ISNS_TAG_VIRTUAL_FABRIC_ID = 131,
    ISNS_TAG_SERVER_VENDOR_OUI = 256,
    ISNS_TAG_DD_SET_ID = 2049,
    ISNS_TAG_DD_SET_SYMBOLIC_NAME = 2050,
    ISNS_TAG_DD_SET_STATUS = 2051,
    ISNS_TAG_DD_SET_NEXT_ID = 2052,
    ISNS_TAG_DD_ID = 2065,
    ISNS_TAG_DD_SYMBOLIC_NAME = 2066,
    ISNS_TAG_DD_MEMBER_ISCSI_INDEX = 2067,
    ISNS_TAG_DD_MEMBER_ISCSI_NAME = 2068,
    ISNS_TAG_DD_MEMBER_FC_PORT_NAME = 2069,
    ISNS_TAG_DD_MEMBER_PORTAL_INDEX = 2070,
    ISNS_TAG_DD_MEMBER_PORTAL_IP_ADDR = 2071,
    ISNS_TAG_DD_MEMBER_PORTAL_TCP_UDP_PORT = 2072,
    ISNS_TAG_DD_FEATURES = 2078,
    ISNS_TAG_DD_NEXT_ID = 2079,
    ISNS_VENDOR_SPECIFIC_SERVER_BASE = 257,
    ISNS_VENDOR_SPECIFIC_ENTITY_BASE = 385,
    ISNS_VENDOR_SPECIFIC_PORTAL_BASE = 513,
    ISNS_VENDOR_SPECIFIC_NODE_BASE = 641,
    ISNS_VENDOR_SPECIFIC_DD_BASE = 1024,
    ISNS_VENDOR_SPECIFIC_DDSET_BASE = 1281,
    ISNS_VENDOR_SPECIFIC_OTHER_BASE = 1537,
  },

  --
  -- Creates a new Attribute instance
  --
  -- @param tag number containing the tag number
  -- @param val string containing the tag value
  -- @param len number containing the tag length
  -- @return o new Attribute instance
  new = function(self, tag, val, len)
    local o = { tag = tag, len = ( len or (val and #val or 0) ), val = val or "" }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --
  -- Creates a new Attribute instance
  --
  -- @param data string containing an opaque string of raw data
  -- @return attr new instance of Attribute
  parse = function(data)
    local attr = Attribute:new()
    local pos

    pos, attr.tag, attr.len = bin.unpack(">II", data)
    pos, attr.val = bin.unpack(">A" .. attr.len, pos)

    return attr
  end,

  --
  -- Converts the instance to an opaque string
  -- @return str containing an opaque string
  __tostring = function(self)
    return bin.pack(">IIA", self.tag, self.len, self.val)
  end,

}

Attributes = {

  --
  -- Creates a new Attributes table
  -- @return o new instance of Attributes
  new = function(self)
    local o = { attribs = {} }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --
  -- Adds a new Attribute to the table
  -- @param tag number containing the tag number
  -- @param val string containing the tag value
  -- @param len number containing the tag length
  add = function(self, tag, val, len)
    table.insert(self, Attribute:new(tag, val, len))
  end,

  --
  -- Converts the instance to an opaque string
  -- @return str containing an opaque string
  __tostring = function(self)
    local str = ""
    for _, attr in ipairs(self) do
      str = str .. tostring(attr)
    end
    return str
  end,

}

Request = {

  FuncId = {
    DevAttrReg = 0x0001,
    DevAttrQry = 0x0002,
    DevGetNext = 0x0003,
    DevDereg   = 0x0004,
    SCNReg     = 0x0005,
    SCNDereg   = 0x0006,
    SCNEvent   = 0x0007,
    SCN        = 0x0008,
    DDReg      = 0x0009,
    DDDereg    = 0x000A,
    DDSReg     = 0x000B,
    DDSDereg   = 0x000C,
    ESI        = 0x000D,
    Heartbeat  = 0x000E,
  },

  --
  -- Creates a new Request message
  -- @param func_id number containing the function ID of the message
  -- @param flags number containing the message flags
  -- @param data string containing the opaque raw data
  -- @param auth string containing the opaque raw auth data
  -- @param trans_id number containing the transaction id
  -- @param seq_id number containing the sequence id
  -- @return o new instance of Request
  new = function(self, func_id, flags, data, auth, trans_id, seq_id)
    local o = {
      header = Header:new(func_id, ( data and #data ) or 0, flags, ( trans_id or -1 ), ( seq_id or -1 )),
      data = data or ""
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --
  -- Converts the instance to an opaque string
  -- @return str containing an opaque string
  __tostring = function(self)
    return tostring(self.header) .. tostring(self.data) ..
    ( self.auth and self.auth or "" )
  end,


}

Response = {

  Error = {
    [0] = "Successful",
    [1] = "Unknown Error",
    [2] = "Message Format Error",
    [3] = "Invalid Registration",
    [4] = "RESERVED",
    [5] = "Invalid Query",
    [6] = "Source Unknown",
    [7] = "Source Absent",
    [8] = "Source Unauthorized",
    [9] = "No Such Entry",
    [10] = "Version Not Supported",
    [11] = "Internal Error",
    [12] = "Busy",
    [13] = "Option Not Understood",
    [14] = "Invalid Update",
    [15] = "Message (FUNCTION_ID) Not Supported",
    [16] = "SCN Event Rejected",
    [17] = "SCN Registration Rejected",
    [18] = "Attribute Not Implemented",
    [19] = "FC_DOMAIN_ID Not Available",
    [20] = "FC_DOMAIN_ID Not Allocated",
    [21] = "ESI Not Available",
    [22] = "Invalid Deregistration",
    [23] = "Registration Feature Not Supported",
  },

  --
  -- Creates a new Response instance
  -- @return o new instance of Response
  new = function(self)
    local o = { attrs = Attributes:new() }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --
  -- Creates a new Response instance
  --
  -- @param data string containing an opaque string of raw data
  -- @return attr new instance of Response
  parse = function(data)
    local hdr = Header.parse(data)
    local pos = #(tostring(hdr)) + 1
    local resp = Response:new()

    pos, resp.error = bin.unpack(">I", data, pos)
    if ( resp.error ~= 0 ) then
      return resp
    end

    while( pos < #data ) do
      local tag, len, val
      pos, tag, len = bin.unpack(">II", data, pos)
      pos, val = bin.unpack("A" .. len, data, pos)
      resp.attrs:add( tag, val, len )
    end
    return resp
  end,

}


Session = {

  --
  -- Creates a new Session instance
  -- @param host table
  -- @param port table
  -- @return o instance of Session
  new = function(self, host, port)
    local o = {
      host = host,
      port = port,
      seq_id = 0,
      trans_id = 0,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --
  -- Connects to the server
  -- @return status true on success, false on failure
  connect = function(self)
    self.socket = nmap.new_socket()
    self.socket:set_timeout(5000)
    return self.socket:connect(self.host, self.port)
  end,

  --
  -- Sends data to the server
  -- @return status true on success, false on failure
  -- @return err string containing the error message on failure
  send = function(self, req)
    if ( not(req.header) or not(req.header.seq_id) or not(req.header.trans_id) ) then
      return false, "Failed to send invalid request"
    end

    -- update the sequence and transaction ID's
    req.header.seq_id = self.seq_id
    req.header.trans_id = self.trans_id

    local status, err = self.socket:send(tostring(req))
    self.trans_id = self.trans_id + 1

    return status, err
  end,

  --
  -- Receives data from the server
  -- @return status true on success, false on failure
  -- @return response instance of response
  receive = function(self)
    -- receive the 24 byte header
    local status, buf_hdr = self.socket:receive_buf(match.numbytes(12), true)
    if ( not(status) ) then
      return status, buf_hdr
    end

    local hdr = Header.parse(buf_hdr)

    -- receive the data
    local buf_data = nil
    status, buf_data = self.socket:receive_buf(match.numbytes(hdr.pdu_len), true)
    if ( not(status) ) then
      return status, buf_data
    end

    return true, Response.parse(buf_hdr .. buf_data)
  end,

  close = function(self)
    return self.close()
  end
}


Helper = {

  --
  -- Creates a new Helper instance
  -- @param host param
  -- @param port param
  -- @return o new instance of Helper
  new = function(self, host, port)
    local o = { session = Session:new(host, port) }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --
  -- Connects to the server
  -- @return status true on success, false on failure
  connect = function(self)
    return self.session:connect()
  end,

  --
  -- Lists portals
  -- @return status true on success, false on failure
  -- @return results list of iSCSI nodes, err string on failure
  listPortals = function(self)
    local attribs, name = Attributes:new(), "iqn.control.node\0por"

    attribs:add(Attribute.Tag.ISNS_TAG_ISCSI_NAME, name)
    attribs:add(Attribute.Tag.ISNS_TAG_PORTAL_IP_ADDRESS)
    attribs:add(Attribute.Tag.ISNS_TAG_DELIMITER)
    attribs:add(Attribute.Tag.ISNS_TAG_PORTAL_IP_ADDRESS)
    attribs:add(Attribute.Tag.ISNS_TAG_PORTAL_TCP_UDP_PORT)
    attribs:add(Attribute.Tag.ISNS_TAG_ENTITY_IDENTIFIER)

    local flags = 0x8c00 -- Sender is iSNS client, Last PDU, First PDU

    local req = Request:new(Request.FuncId.DevAttrQry, flags, tostring(attribs))
    if ( not(self.session:send(req)) ) then
      return false, "Failed to send message to server"
    end

    local status, resp = self.session:receive()
    if ( not(status) ) then
      return false, "Failed to receive message from server"
    end

    local results = {}
    local addr, proto, port
    for _, attr in ipairs(resp.attrs) do
      if ( attr.tag == Attribute.Tag.ISNS_TAG_PORTAL_IP_ADDRESS ) then
        addr = attr.val
        local pos, is_ipv4 = bin.unpack("A12", addr)
        if ( is_ipv4 == "\0\0\0\0\0\0\0\0\0\0\xFF\xFF" ) then
          local pos, bin_ip = bin.unpack("B4", addr, 13)
          addr = ipops.bin_to_ip(bin_ip)
        else
          local pos, bin_ip = bin.unpack("B16", addr)
          addr = ipops.bin_to_ip(bin_ip)
        end
      elseif ( attr.tag == Attribute.Tag.ISNS_TAG_PORTAL_TCP_UDP_PORT ) then
        local pos, s1
        pos, s1, port = bin.unpack(">SS", attr.val)

        if ( s1 == 1 ) then
          proto = "udp"
        elseif ( s1 == 0 ) then
          proto = "tcp"
        else
          proto = "UNKNOWN"
        end
      elseif ( addr and proto and port ) then
        table.insert(results, { addr = addr, proto = proto, port = port } )
        addr, proto, port = nil, nil, nil
      end
    end
    return true, results
  end,

  --
  -- Lists iSCSI nodes
  -- @return status true on success, false on failure
  -- @return results list of iSCSI nodes, err string on failure
  listISCINodes = function(self)
    local attribs = Attributes:new()
    local name = "iqn.control.node\0por"
    attribs:add(Attribute.Tag.ISNS_TAG_ISCSI_NAME, name)
    attribs:add(Attribute.Tag.ISNS_TAG_ISCSI_NAME)
    attribs:add(Attribute.Tag.ISNS_TAG_DELIMITER)
    attribs:add(Attribute.Tag.ISNS_TAG_ISCSI_NAME)
    attribs:add(Attribute.Tag.ISNS_TAG_ISCSI_NODE_TYPE)

    local flags = 0x8c00 -- Sender is iSNS client, Last PDU, First PDU

    local req = Request:new(Request.FuncId.DevAttrQry, flags, tostring(attribs))
    if ( not(self.session:send(req)) ) then
      return false, "Failed to send message to server"
    end

    local status, resp = self.session:receive()
    if ( not(status) ) then
      return false, "Failed to receive message from server"
    end

    local name, ntype
    local results = {}
    for _, attr in ipairs(resp.attrs) do
      if ( attr.tag == Attribute.Tag.ISNS_TAG_ISCSI_NAME ) then
        name = attr.val
      elseif( attr.tag == Attribute.Tag.ISNS_TAG_ISCSI_NODE_TYPE ) then
        local _, val = bin.unpack(">I", attr.val)
        if ( val == iSCSI.NodeType.CONTROL ) then
          ntype = "Control"
        elseif ( val == iSCSI.NodeType.INITIATOR ) then
          ntype = "Initiator"
        elseif ( val == iSCSI.NodeType.TARGET ) then
          ntype = "Target"
        else
          ntype = "Unknown"
        end
      end
      if ( name and ntype ) then
        table.insert(results, { name = name:match("^([^\0]*)"), type = ntype })
        name, ntype = nil, nil
      end
    end
    return true, results
  end,

  close = function(self)
    return self.session:close()
  end,

}

return _ENV;
