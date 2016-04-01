local bin = require "bin"
local bit = require "bit"
local comm = require "comm"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"

_ENV = stdnse.module("mqtt", stdnse.seeall)

---
-- An implementation of MQTT 3.1.1
-- https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
--
-- This library does not currently implement the entire MQTT protocol,
-- only those control packets which are necessary for existing scripts
-- are included. Extending to accomodate additional control packets
-- should not be difficult.
--
-- @author "Mak Kolybabi <mak@kolybabi.com>"
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

MQTT = {
  -- Types of control packets
  packet = {
    ["CONNECT"] = {
      number = 1,
      options = {
        "client_id",
        "keep_alive_secs",
        "password",
        "username",
        "will_message",
        "will_topic",
        "clean_session",
        "will_qos",
        "will_retain",
        "protocol_level",
        "protocol_name",
      },
      build = nil,
      parse = nil,
    },
    ["CONNACK"] = {
      number = 2,
      options = {},
      build = nil,
      parse = nil,
    },
    ["PUBLISH"] = {
      number = 3,
      options = {},
      build = nil,
      parse = nil,
    },
    ["PUBACK"] = {
      number = 4,
      options = {},
      build = nil,
      parse = nil,
    },
    ["PUBREC"] = {
      number = 5,
      options = {},
      build = nil,
      parse = nil,
    },
    ["PUBREL"] = {
      number = 6,
      options = {},
      build = nil,
      parse = nil,
    },
    ["PUBCOMP"] = {
      number = 7,
      options = {},
      build = nil,
      parse = nil,
    },
    ["SUBSCRIBE"] = {
      number = 8,
      options = {
        "filters",
      },
      build = nil,
      parse = nil,
    },
    ["SUBACK"] = {
      number = 9,
      options = {},
      build = nil,
      parse = nil,
    },
    ["UNSUBSCRIBE"] = {
      number = 10,
      options = {},
      build = nil,
      parse = nil,
    },
    ["UNSUBACK"] = {
      number = 11,
      options = {},
      build = nil,
      parse = nil,
    },
    ["PINGREQ"] = {
      number = 12,
      options = {},
      build = nil,
      parse = nil,
    },
    ["PINGRESP"] = {
      number = 13,
      options = {},
      build = nil,
      parse = nil,
    },
    ["DISCONNECT"] = {
      number = 14,
      options = {},
      build = nil,
      parse = nil,
    },
  },

  build_req = function(self, type, options)
  end,
}

Comm = {
  --- Creates a new Client instance.
  --
  -- @name Comm.new
  --
  -- @param host Table as received by the action method.
  -- @param port Table as received by the action method.
  -- @param options Table as received by the action method.
  -- @return o Instance of Client.
  new = function(self, host, port, options)
    local o = {host = host, port = port, options = options or {}}
    o["packet_id"] = 0
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects to the MQTT broker.
  --
  -- @name Comm.connect
  --
  -- @return status true on success, false on failure.
  -- @return err string containing the error message on failure.
  connect = function(self)
    -- XXX-MAK: This should be changed to support TLS.
    self.socket = nmap.new_socket()
    self.socket:set_timeout(self.options.timeout or 5000)
    return self.socket:connect(self.host, self.port)
  end,

  --- Sends an MQTT control packet.
  --
  -- @name Comm.send
  --
  -- @param type Type of MQTT control packet to build and send.
  -- @param options Table of options accepted by the requested type of
  --        control packet.
  -- @return status true on success, false on failure.
  -- @return err string containing the error message on failure.
  send = function(self, type, options)
    -- Ensure the requested packet type is known.
    local pkt = MQTT.packet[type]
    assert(pkt, ("Control packet type '%s' is not known."):format(type))

    -- Ensure the requested packet type is handled.
    local fn = pkt.build
    assert(fn, ("Control packet type '%s' has not been implemented."):format(type))

    -- Validate the options.
    options = options or {}
    local o = {["packet_id"] = self:packet_identifier()}
    for _, key in pairs(pkt.options) do
      o[key] = false
    end

    for key, val in pairs(options) do
      -- Reject unrecognized options.
      assert(o[key] ~= nil, ("Control packet type '%s' does not have the option '%s'."):format(type, key))
      o[key] = val
    end

    -- Build the packet as specified.
    local status, req = fn(o)
    if not status then
      return status, req
    end

    -- Send the packet.
    return self.socket:send(req)
  end,

  --- Receives an MQTT control packet.
  --
  -- @name Comm.receive
  --
  -- @return status True on success, false on failure.
  -- @return response Table representing a control packet on success,
  --         string containing the error message on failure.
  receive = function(self)
    -- Receive the type and flags of the response packet's fixed header.
    local status, buf = self.socket:receive_buf(match.numbytes(1), true)
    if not status then
      return false, "Failed to receive response from server."
    end

    -- Extract the control packet type and fixed header flags of the packet.
    local _, type_and_flags = bin.unpack("C", buf)

    -- Retrieve the remaining length.
    -- 2.2.3 Remaining Length
    -- This only happens for large packets of size >= 128 bytes.
    local multiplier = 1
    local length = 0
    repeat
      status, buf = self.socket:receive_buf(match.numbytes(1), true)
      if not status then
        return false, "Failed to receive response from server."
      end
      local _, byte = bin.unpack("C", buf)
      length = length + bit.band(byte, 0x7F) * multiplier
      if (multiplier > 0x200000) then
        return false, "Server response contained invalid packet length."
      end
      multiplier = bit.lshift(multiplier, 7)
    until bit.band(byte, 0x80) == 0
    assert(length >= 0)

    -- Pull the rest of the packet off the wire.
    status, buf = self.socket:receive_buf(match.numbytes(length), true)
    if not status then
      return status, buf
    end
    assert(buf:len() == length, ("Length of packet (%d) doesn't match expectation (%d)."):format(buf:len(), length))

    -- Parse type and flags.
    local type = bit.rshift(bit.band(type_and_flags, 0xF0), 4)
    local fhflags = bit.band(type_and_flags, 0x0F)

    -- Search for the definition of the packet type.
    local pkt = nil
    for key,val in pairs(MQTT.packet) do
      if val.number == type then
        type = key
        pkt = val
        break
      end
    end

    -- Ensure the requested packet type is handled.
    if not pkt then
      return false, ("Control packet type '%d' is not known."):format(type)
    end

    -- Ensure the requested packet type is handled.
    local fn = pkt.parse
    if not fn then
      return false, ("Control packet type '%s' is not implemented."):format(type)
    end

    return fn(fhflags, buf)
  end,

  --- Disconnects from the MQTT broker.
  --
  -- @name Comm.close
  close = function(self)
    return self.socket:close()
  end,

  --- Generates a packet identifier.
  --
  -- @name Comm.packet_identifier
  --
  -- See "2.3.1 Packet Identifier" section of the standard.
  --
  -- @return Unique identifier for a packet.
  packet_identifier = function(self)
    self.packet_id = self.packet_id + 1
    local num = bin.pack(">S", self.packet_id)
    return num
  end,
}

Helper = {
  --- Creates a new Helper instance.
  --
  -- @name Helper.create
  --
  -- @param host Table as received by the action method.
  -- @param port Table as received by the action method.
  -- @return o instance of Client
  new = function(self, host, port, opt)
    local o = { host = host, port = port, opt = opt or {} }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects to the MQTT broker.
  --
  -- @name Helper.connect
  --
  -- @param options Table of options for the CONNECT control packet.
  -- @return status True on success, false on failure.
  -- @return response Table representing a CONNACK control packet on
  --         success, string containing the error message on failure.
  connect = function(self, options)
    self.comm = Comm:new(self.host, self.port, self.opt)

    local result, status = self.comm:connect()
    if not result then
      return false, status
    end

    return self:request("CONNECT", options, "CONNACK")
  end,

  --- Sends a request to the MQTT broker, and receive a response.
  --
  -- @name Helper.request
  --
  -- @param req_type Type of control packet to build and send.
  -- @param options Table of options for the CONNECT control packet.
  -- @param res_type Type of control packet to receive and parse.
  -- @return status True on success, false on failure.
  -- @return response Table representing a <code>res_type</code>
  --         control packet on success, string containing the error
  --         message on failure.
  request = function(self, req_type, options, res_type)
    assert(type(req_type) == "string")

    local status, result = self.comm:send(req_type, options)
    if not status then
       return false, result
    end

    return self.comm:receive({res_type})
  end,

  --- Listens for a response matching a list of types.
  --
  -- @name Helper.receive
  --
  -- @param types Type of control packet to build and send.
  -- @param timeout Number of seconds to listen for matching response.
  -- @param res_type Table of types of control packet to receive and
  --        parse.
  -- @return status True on success, false on failure.
  -- @return response Table representing any <code>res_type</code>
  --         control packet on success, string containing the error
  --         message on failure.
  receive = function(self, types, timeout)
    assert(type(types) == "table")
    assert(type(timeout) == "number")

    local end_time = nmap.clock_ms() + timeout * 1000
    while true do
      local status, result = self.comm:receive()

      -- Check for failures.
      if not status then
        return false, result
      end

      -- Check for messages matching our filters.
      for _, type in pairs(types) do
        if result.type == type then
          return true, result
        end
      end

      -- Check timeout, but only if we care about it.
      if timeout > 0 then
        if nmap.clock_ms() >= end_time then
          break
        end
      end
    end

    return false, ("No messages received in %d seconds matching desired types."):format(timeout)
  end,

  -- Closes the socket with the server.
  --
  -- @name Helper.close
  close = function(self)
    self.comm:send("DISCONNECT")
    return self.comm:close()
  end,
}

--- Build an MQTT CONNECT control packet.
--
-- See "3.1 CONNECT – Client requests a connection to a Server"
-- section of the standard.
--
-- @param options Table of options accepted by this type of control
--        packet.
-- @return A string representing a CONNECT control packet.
MQTT.packet["CONNECT"].build = function(options)
  assert(type(options) == "table")

  local head = ""
  local tail = ""

  -- 3.1.2.1 Protocol Name
  local protocol_name = options.protocol_name
  if not protocol_name then
    protocol_name = "MQTT"
  end
  assert(type(protocol_name) == "string")
  head = head .. MQTT.utf8_build(protocol_name)

  -- 3.1.2.2 Protocol Level
  local protocol_level = options.protocol_level
  if not protocol_level then
    protocol_level = 4
  end
  assert(type(protocol_level) == "number")
  head = head .. bin.pack("C", protocol_level)

  -- 3.1.3.1 Client Identifier
  local client_id = options.client_id
  if not client_id then
    -- We throw in randomness in case there are multiple scripts using this
    -- library on a single port.
    client_id = "nmap" .. stdnse.generate_random_string(16)
  end
  assert(type(client_id) == "string")
  tail = tail .. MQTT.utf8_build(client_id)

  -- 3.1.2.3 Connect Flags
  local cflags = 0x00

  -- 3.1.2.4 Clean Session
  if options.clean_session then
    cflags = bit.bor(cflags, 0x02)
  end

  -- 3.1.2.6 Will QoS
  if not options.will_qos then
    options.will_qos = 0
  end
  assert(options.will_qos >= 0)
  assert(options.will_qos <= 2)
  cflags = bit.bor(cflags, bit.lshift(options.will_qos, 3))

  -- 3.1.2.7 Will Retain
  if options.will_retain then
    cflags = bit.bor(cflags, 0x20)
  end

  -- 3.1.2.5 Will Flag
  if options.will_topic and options.will_message then
    cflags = bit.bor(cflags, 0x04)
    tail = tail .. MQTT.utf8_build(options.will_topic)
    tail = tail .. MQTT.utf8_build(options.will_message)
  end

  -- 3.1.2.8 User Name Flag
  if options.username then
    cflags = bit.bor(cflags, 0x80)
    tail = tail .. MQTT.utf8_build(options.username)
  end

  -- 3.1.2.9 Password Flag
  if options.password then
    cflags = bit.bor(cflags, 0x40)
    tail = tail .. MQTT.utf8_build(options.password)
  end

  head = head .. bin.pack("C", cflags)

  -- 3.1.2.10 Keep Alive
  if not options.keep_alive_secs then
    options.keep_alive_secs = 30
  end
  head = head .. bin.pack(">S", options.keep_alive_secs)

  return true, MQTT.fixed_header(1, 0x0, head .. tail)
end

--- Parse an MQTT CONNACK control packet.
--
-- See "3.2 CONNACK – Acknowledge connection request" section of the
-- standard.
--
-- @param fhflags The flags of the control packet.
-- @param buf The string representing the control packet.
-- @return status True on success, false on failure.
-- @return response Table representing a CONNACK control packet on
--         success, string containing the error message on failure.
MQTT.packet["CONNACK"].parse = function(fhflags, buf)
  assert(type(fhflags) == "number")
  assert(type(buf) == "string")

  -- 3.2.1 Fixed header
  -- We expect that the packet structure is rigid. We allow variation, but we
  -- warn about it just in case.
  if fhflags ~= 0x00 then
    stdnse.debug4("Fixed header flags in CONNACK packet were %d, should be 0.", fhflags)
  end
  if buf:len() ~= 2 then
    stdnse.debug4("Fixed header remaining length in CONNACK packet was %d, should be 2.", buf:len())
  end

  -- 3.2.2.1 Connect Acknowledge Flags
  local res = {["type"] = "CONNACK"}
  local _, caflags, crcode = bin.unpack("CC", buf)

  -- 3.2.2.2 Session Present
  res.session_present = (bit.band(caflags, 0x01) == 1)

  -- 3.2.2.3 Connect Return code
  res.accepted = (crcode == 0x00)
  if crcode == 0x01 then
     res.reason = "Unacceptable Protocol Version"
  elseif crcode == 0x02 then
     res.reason = "Client Identifier Rejected"
  elseif crcode == 0x03 then
     res.reason = "Server Unavailable"
  elseif crcode == 0x04 then
     res.reason = "Bad User Name or Password"
  elseif crcode == 0x05 then
     res.reason = "Not Authorized"
  else
     res.reason = "Unrecognized Connect Return Code"
  end

  return true, res
end

--- Build an MQTT SUBSCRIBE control packet.
--
-- See "3.8 SUBSCRIBE - Subscribe to topics" section of the standard.
--
-- @param options Table of options accepted by this type of control
--        packet.
-- @return A string representing a SUBSCRIBE control packet.
MQTT.packet["SUBSCRIBE"].build = function(options)
  assert(type(options) == "table")

  local pkt = ""

  -- 3.8.2 Variable header
  pkt = pkt .. options.packet_id

  for key, val in pairs(options.filters) do
    local name = val.filter
    assert(type(name) == "string")

    local qos = val.qos
    if not qos then
      qos = 0
    end
    assert(type(qos) == "number")
    assert(qos >= 0)
    assert(qos <= 2)

    pkt = pkt .. MQTT.utf8_build(name)
    pkt = pkt .. bin.pack("C", qos)
  end

  return true, MQTT.fixed_header(8, 0x2, pkt)
end

--- Parse an MQTT SUBACK control packet.
--
-- See "3.9 SUBACK – Subscribe acknowledgement" section of the
-- standard.
--
-- @param fhflags The flags of the control packet.
-- @param buf The string representing the control packet.
-- @return status True on success, false on failure.
-- @return response Table representing a SUBACK control packet on
--         success, string containing the error message on failure.
MQTT.packet["SUBACK"].parse = function(fhflags, buf)
  assert(type(fhflags) == "number")
  assert(type(buf) == "string")

  -- 3.9.1 Fixed header
  -- We expect that the packet structure is rigid. We allow variation, but we
  -- warn about it just in case.
  if fhflags ~= 0x00 then
    stdnse.debug4("Fixed header flags in CONNACK packet were %d, should be 0.", fhflags)
  end

  local res = {["type"] = "SUBACK"}
  local length = buf:len()

  -- 3.9.2 Variable header
  if length < 2 then
    return false, ("Failed to parse SUBACK packet, too short.")
  end
  local pos, packet_id = bin.unpack(">S", buf)
  res.packet_id = packet_id

  -- 3.9.3 Payload
  local code
  local codes = {}
  while pos <= length do
    pos, code = bin.unpack("C", buf, pos)
    if code == 0x00 then
      table.insert(codes, {["success"] = true, ["max_qos"] = 0})
    elseif code == 0x01 then
      table.insert(codes, {["success"] = true, ["max_qos"] = 1})
    elseif code == 0x02 then
      table.insert(codes, {["success"] = true, ["max_qos"] = 2})
    else
      table.insert(codes, {["success"] = false})
    end
  end
  res.filters = codes

  return true, res
end

--- Parse an MQTT PUBLISH control packet.
--
-- See "3.3 PUBLISH – Publish message" section of the standard.
--
-- @param fhflags The flags of the control packet.
-- @param buf The string representing the control packet.
-- @return
-- @return status True on success, false on failure.
-- @return response Table representing a PUBLISH control packet on
--         success, string containing the error message on failure.
MQTT.packet["PUBLISH"].parse = function(fhflags, buf)
  assert(type(fhflags) == "number")
  assert(type(buf) == "string")

  -- 3.9.1 Fixed header
  local res = {["type"] = "PUBLISH"}

  -- 3.3.1.1 DUP
  local dup = (bit.band(fhflags, 0x8) == 0x8)
  res.dup = dup

  -- 3.3.1.2 QoS
  local qos = bit.rshift(bit.band(fhflags, 0x6), 1)
  res.qos = qos

  -- 3.3.1.3 RETAIN
  local ret = (bit.band(fhflags, 0x1) == 0x8)
  res.retain = ret

  -- 3.3.2.1 Topic Name
  local pos, val = MQTT.utf8_parse(buf)
  if not pos then
    return false, val
  end
  res.topic = val

  -- 3.3.2.2 Packet Identifier
  if qos == 1 or qos == 2 then
    pos, val = bin.unpack(">S", buf, pos)
    if not pos then
      return false, val
    end
    res.packet_id = val
  end

  -- 3.3.3 Payload
  local length = buf:len()
  res.payload = buf:sub(pos, length)

  return true, res
end

--- Build an MQTT DISCONNECT control packet.
--
-- See "3.14 DISCONNECT – Disconnect notification" section of the
-- standard.
--
-- @param options Table of options accepted by this type of control
--        packet.
-- @return A string representing a DISCONNECT control packet.
MQTT.packet["DISCONNECT"].build = function(options)
  assert(type(options) == "table")
  return true, MQTT.fixed_header(14, 0x00, "")
end

--- Build a UTF-8 string in MQTT's length-prefixed format.
--
-- See section "1.5.3 UTF-8 encoded strings" of the standard.
--
-- @param str The string to convert.
-- @return A length-prefixed string.
MQTT.utf8_build = function(str)
  assert(type(str) == "string")

  return bin.pack(">P", str)
end

--- Parser a UTF-8 string in MQTT's length-prefixed format.
--
-- See section "1.5.3 UTF-8 encoded strings" of the standard.
--
-- @param buf The bytes to parse.
-- @param pos The position from which to start parsing.
-- @return status True on success, false on failure.
-- @return response Parsed string on success, string containing the
--         error message on failure.
MQTT.utf8_parse = function(buf, pos)
  assert(type(buf) == "string")

  if not pos then
    pos = 0
  end
  assert(type(pos) == "number")

  local buf_length = buf:len()
  if pos + 2 > buf_length then
    return false, ("Buffer at position %d has no space for a UTF-8 length-prefixed string."):format(pos)
  end

  local _, str_length = bin.unpack(">S", buf, pos)
  if pos + 2 + str_length > buf_length then
    return false, ("Buffer at position %d has no space for a %d-byte UTF-8 string."):format(pos, str_length)
  end

  return bin.unpack(">P", buf, pos)
end

--- Prefix the body of an MQTT packet with a fixed header.
--
-- See section "2.2 Fixed header" of the standard.
--
-- @param num The type of the control packet.
-- @param flags The flags of the control packet.
-- @param pkt The string representing the control packet.
-- @return A string representing a completed MQTT control packet.
MQTT.fixed_header = function(num, flags, pkt)
  assert(type(num) == "number")
  assert(type(flags) == "number")
  assert(type(pkt) == "string")

  -- Build the fixed header.
  -- 2.2.1 MQTT Control Packet type
  -- 2.2.2 Flags
  local hdr = bit.bor(bit.lshift(num, 4), flags)

  -- Construct the remaining length.
  -- 2.2.3 Remaining Length
  local tlen = pkt:len()
  local rlen = ""
  repeat
    local byte = bit.band(tlen, 0x7F)
    tlen = bit.rshift(tlen, 7)
    if tlen > 0 then
      byte = bit.bor(byte, 0x80)
    end
    rlen = bin.pack("C", byte) .. rlen
  until tlen == 0

  return bin.pack("C", hdr) .. rlen .. pkt
end

return _ENV;
