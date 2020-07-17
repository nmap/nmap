local comm = require "comm"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unittest = require "unittest"
local rand = require "rand"

_ENV = stdnse.module("mqtt", stdnse.seeall)

---
-- An implementation of MQTT 3.1.1
-- https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
--
-- This library does not currently implement the entire MQTT protocol,
-- only those control packets which are necessary for existing scripts
-- are included. Extending to accommodate additional control packets
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
  connect = function(self, options)
    -- Build the CONNECT control  packet that initiates an MQTT session.
    local status, pkt = self:build("CONNECT", options)
    if not status then
      return false, pkt
    end

    -- The MQTT protocol requires us to sent the initial CONNECT
    -- control packet before it will respond.
    local sd, response, _, _ = comm.tryssl(self.host, self.port, pkt)
    if not sd then
      return false, response
    end

    -- The socket connected successfully over whichever protocol.
    self.socket = sd

    -- We now have some data that came back from the connection, which
    -- the protocol guarantees will be the 4-byte CONNACK packet.
    if #response ~= 4 then
      return false, "More bytes were returned from tryssl() than expected."
    end

    return self:parse(response)
  end,

  --- Sends an MQTT control packet.
  --
  -- @name Comm.send
  --
  -- @param pkt String representing a raw control packet.
  -- @return status true on success, false on failure.
  -- @return err string containing the error message on failure.
  send = function(self, pkt)
    return self.socket:send(pkt)
  end,

  --- Receives an MQTT control packet.
  --
  -- @name Comm.receive
  --
  -- @return status True on success, false on failure.
  -- @return response String representing a raw control packet on
  --         success, string containing the error message on failure.
  receive = function(self)
    -- Receive the type and flags of the response packet's fixed header.
    local status, type_and_flags = self.socket:receive_buf(match.numbytes(1), true)
    if not status then
      return false, "Failed to receive control packet from server."
    end

    -- To avoid reimplementing the length parsing, we will perform a
    -- naive loop that gets the correct number of bytes for the
    -- variable-length numeric field without interpreting it.
    local length = ""
    for i = 1, 4 do
      -- Get the next byte from the socket.
      local status, chunk = self.socket:receive_buf(match.numbytes(1), true)
      if not status then
        return false, chunk
      end

      -- Add the received data to the length buffer.
      length = length .. chunk

      -- If the byte has the continuation bit cleared, stop receiving.
      local byte = string.unpack("B", chunk)
      if byte < 128 then
        break
      end
    end

    -- Parse the length buffer.
    local pos, num = MQTT.length_parse(length)
    if not pos then
      return false, num
    end

    -- Get the remainder of the packet from the socket.
    local status, body = self.socket:receive_buf(match.numbytes(num), true)
    if not status then
      return false, body
    end
    assert(#body == num)

    -- Reassemble the packet.
    local pkt = type_and_flags .. length .. body
    assert(#pkt == 1 + #length + num)

    return true, pkt
  end,

  --- Builds an MQTT control packet.
  --
  -- @name Comm.build
  --
  -- @param type Type of MQTT control packet to build.
  -- @param options Table of options accepted by the requested type of
  --        control packet.
  -- @return status true on success, false on failure.
    -- @return response String representing a raw control packet on
  --         success, or containing the error message on failure.
  build = function(self, type, options)
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
    local status, pkt = fn(o)
    if not status then
      return status, pkt
    end

    -- Send the packet.
    return true, pkt
  end,

  --- Parses an MQTT control packet.
  --
  -- @name Comm.parse
  --
  -- @param buf String from which to parse the control packet.
  -- @param pos Position from which to start parsing.
  -- @return pos String index on success, false on failure.
  -- @return response Table representing a control packet on success,
  --         string containing the error message on failure.
  parse = function(self, buf, pos)
    assert(type(buf) == "string")

    pos = pos or 1
    assert(type(pos) == "number")

    -- Parse the type and flags of the control packet's fixed header.
    if pos > #buf then
      return false, "Failed to parse control packet."
    end
    local type_and_flags, pos = string.unpack("B", buf, pos)

    -- Parse the remaining length.
    local pos, length = MQTT.length_parse(buf, pos)
    if not pos then
      return false, length
    end

    -- Extract the body.
    local end_pos = pos + length
    if end_pos - 1 > #buf then
      return false, ("End of packet body (%d) is goes past end of buffer (%d)."):format(end_pos, #buf)
    end
    local body = buf:sub(pos, end_pos)
    pos = end_pos

    -- Parse type and flags.
    local type = type_and_flags >> 4
    local fhflags = type_and_flags & 0x0F

    -- Search for the definition of the packet type.
    local def = nil
    for key, val in pairs(MQTT.packet) do
      if val.number == type then
        type = key
        def = val
        break
      end
    end

    -- Ensure the requested packet type is handled.
    if not def then
      return false, ("Control packet type '%d' is not known."):format(type)
    end

    -- Ensure the requested packet type is handled.
    local fn = def.parse
    if not fn then
      return false, ("Control packet type '%s' is not implemented."):format(type)
    end

    -- Parse the packet
    local status, response = fn(fhflags, body)
    if not status then
      return false, response
    end

    return pos, response
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
    local num = string.pack(">I2", self.packet_id)
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
    return self.comm:connect(options)
  end,

  --- Sends a request to the MQTT broker.
  --
  -- @name Helper.send
  --
  -- @param req_type Type of control packet to build and send.
  -- @param options Table of options for the request control packet.
  -- @return status True on success, false on failure.
  -- @return err String containing the error message on failure.
  send = function(self, req_type, options)
    assert(type(req_type) == "string")

    local status, pkt = self.comm:build(req_type, options)
    if not status then
       return false, pkt
    end

    return self.comm:send(pkt)
  end,

  --- Sends a request to the MQTT broker, and receive a response.
  --
  -- @name Helper.request
  --
  -- @param req_type Type of control packet to build and send.
  -- @param options Table of options for the request control packet.
  -- @param res_type Type of control packet to receive and parse.
  -- @return status True on success, false on failure.
  -- @return response Table representing a <code>res_type</code>
  --         control packet on success, string containing the error
  --         message on failure.
  request = function(self, req_type, options, res_type)
    local status, pkt = self:send(req_type, options)
    if not status then
       return false, pkt
    end

    return self:receive({res_type})
  end,

  --- Listens for a response matching a list of types.
  --
  -- @name Helper.receive
  --
  -- @param types Type of control packet to build and send.
  -- @param timeout Number of seconds to listen for matching response,
  --                defaults to 5s.
  -- @param res_type Table of types of control packet to receive and
  --        parse.
  -- @return status True on success, false on failure.
  -- @return response Table representing any <code>res_type</code>
  --         control packet on success, string containing the error
  --         message on failure.
  receive = function(self, types, timeout)
    assert(type(types) == "table")

    if not timeout then
      timeout = 5
    end
    assert(type(timeout) == "number")

    local end_time = nmap.clock_ms() + timeout * 1000
    while true do
      -- Get the raw packet from the socket.
      local status, pkt = self.comm:receive()
      if not status then
        return false, pkt
      end

      -- Parse the raw packet into a table.
      local status, result = self.comm:parse(pkt)
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
    self:send("DISCONNECT")
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
  head = head .. string.pack("B", protocol_level)

  -- 3.1.3.1 Client Identifier
  local client_id = options.client_id
  if not client_id then
    -- We throw in randomness in case there are multiple scripts using this
    -- library on a single port.
    client_id = "nmap" .. rand.random_alpha(16)
  end
  assert(type(client_id) == "string")
  tail = tail .. MQTT.utf8_build(client_id)

  -- 3.1.2.3 Connect Flags
  local cflags = 0x00

  -- 3.1.2.4 Clean Session
  if options.clean_session then
    cflags = cflags | 0x02
  end

  -- 3.1.2.6 Will QoS
  if not options.will_qos then
    options.will_qos = 0
  end
  assert(options.will_qos >= 0)
  assert(options.will_qos <= 2)
  cflags = cflags | (options.will_qos << 3)

  -- 3.1.2.7 Will Retain
  if options.will_retain then
    cflags = cflags | 0x20
  end

  -- 3.1.2.5 Will Flag
  if options.will_topic and options.will_message then
    cflags = cflags | 0x04
    tail = tail .. MQTT.utf8_build(options.will_topic)
    tail = tail .. MQTT.utf8_build(options.will_message)
  end

  -- 3.1.2.8 User Name Flag
  if options.username then
    cflags = cflags | 0x80
    tail = tail .. MQTT.utf8_build(options.username)
  end

  -- 3.1.2.9 Password Flag
  if options.password then
    cflags = cflags | 0x40
    tail = tail .. MQTT.utf8_build(options.password)
  end

  head = head .. string.pack("B", cflags)

  -- 3.1.2.10 Keep Alive
  if not options.keep_alive_secs then
    options.keep_alive_secs = 30
  end
  head = head .. string.pack(">I2", options.keep_alive_secs)

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
  local caflags, crcode = string.unpack("BB", buf)

  -- 3.2.2.2 Session Present
  res.session_present = ((caflags & 0x01) == 1)

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

  -- 3.8.2 Variable header
  local pkt = {options.packet_id}

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

    pkt[#pkt+1] = MQTT.utf8_build(name)
    pkt[#pkt+1] = string.pack("B", qos)
  end

  return true, MQTT.fixed_header(8, 0x2, table.concat(pkt))
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
  local packet_id, pos = string.unpack(">I2", buf)
  res.packet_id = packet_id

  -- 3.9.3 Payload
  local code
  local codes = {}
  while pos <= length do
    code, pos = string.unpack("B", buf, pos)
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
  local dup = ((fhflags & 0x8) == 0x8)
  res.dup = dup

  -- 3.3.1.2 QoS
  local qos = ((fhflags & 0x6) >> 1)
  res.qos = qos

  -- 3.3.1.3 RETAIN
  local ret = ((fhflags & 0x1) == 0x1)
  res.retain = ret

  -- 3.3.2.1 Topic Name
  local pos, val = MQTT.utf8_parse(buf)
  if not pos then
    return false, val
  end
  res.topic = val

  -- 3.3.2.2 Packet Identifier
  if qos == 1 or qos == 2 then
    if #buf - pos + 1 < 2 then
      return false, "packet truncated"
    end
    val, pos = string.unpack(">I2", buf, pos)
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

--- Build a numeric field in MQTT's variable-length format.
--
-- See section "2.2.3 Remaining Length" of the standard.
--
-- @param num The value of the field.
-- @return A variable-length field.
MQTT.length_build = function(num)
  -- This field represents a limited range of integers (0 through 128^4-1)
  assert(num >= 0)
  assert(num < 0x10000000)

  local field = {}
  repeat
    local byte = num & 0x7F
    num = num >> 7
    if num > 0 then
      byte = byte | 0x80
    end
    field[#field+1] = string.pack("B", byte)
  until num == 0

  -- This field has a limit on its length in binary form.
  assert(#field >= 1)
  assert(#field <= 4)

  return table.concat(field)
end

--- Parse a numeric field in MQTT's variable-length format.
--
-- See section "2.2.3 Remaining Length" of the standard.
--
-- @param buf String from which to parse the numeric field.
-- @param pos Position from which to start parsing.
-- @return pos String index on success, false on failure.
-- @return response Parsed numeric field on success, string containing
--         the error message on failure.
MQTT.length_parse = function(buf, pos)
  assert(type(buf) == "string")
  if #buf == 0 then
    return false, "Cannot parse an empty string."
  end

  pos = pos or 1
  assert(type(pos) == "number")

  local multiplier = 1
  local offset = 0
  local byte = nil
  local num = 0

  repeat
    if pos > #buf then
      return false, "Reached end of buffer before variable-length numeric field was parsed."
    end
    byte, pos = string.unpack("B", buf, pos)
    num = num + (byte & 0x7F) * multiplier
    if offset > 3 then
      return false, "Buffer contained an invalid variable-length numeric field."
    end
    multiplier = multiplier << 7
    offset = offset + 1
  until (byte & 0x80) == 0

  -- This field represents a limited range of integers (0 through 128^4-1)
  assert(num >= 0)
  assert(num < 0x10000000)

  return pos, num
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

--- Build a UTF-8 string in MQTT's length-prefixed format.
--
-- See section "1.5.3 UTF-8 encoded strings" of the standard.
--
-- @param str The string to convert.
-- @return A length-prefixed string.
MQTT.utf8_build = function(str)
  assert(type(str) == "string")

  return string.pack(">s2", str)
end

--- Parse a UTF-8 string in MQTT's length-prefixed format.
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
  if #buf < 2 then
    return false, "Cannot parse a string of less than two bytes."
  end

  pos = pos or 1
  assert(type(pos) == "number")

  local buf_length = buf:len()
  if pos > buf_length - 1 then
    return false, ("Buffer at position %d has no space for a UTF-8 length-prefixed string."):format(pos)
  end

  local str_length = string.unpack(">I2", buf, pos)
  if pos + 1 + str_length > buf_length then
    return false, ("Buffer at position %d has no space for a %d-byte UTF-8 string."):format(pos, str_length)
  end

  local value, pos = string.unpack(">s2", buf, pos)
  return pos, value
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
  local hdr = (num << 4) | flags

  return string.pack("B", hdr) .. MQTT.length_build(#pkt) .. pkt
end

-- Skip unit tests unless we're explicitly testing.
if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()

-- 2.2.3 Remaining Length
local tests = {
  { 1, 0,         "\x00"            },
  { 1, 127,       "\x7F"            },
  { 2, 128,       "\x80\x01"        },
  { 2, 16383,     "\xFF\x7F"        },
  { 3, 16384,     "\x80\x80\x01"    },
  { 3, 2097151,   "\xFF\xFF\x7F"    },
  { 4, 2097152,   "\x80\x80\x80\x01"},
  { 4, 268435455, "\xFF\xFF\xFF\x7F"},
}

for i, test in ipairs(tests) do
  local test_len = test[1]
  local test_num = test[2]
  local test_str = test[3]

  local str = MQTT.length_build(test_num)
  test_suite:add_test(unittest.equal(#str, test_len), ("Test %d: length_build, length"):format(i))
  test_suite:add_test(unittest.equal(str, test_str), ("Test %d: length_build, content"):format(i))

  -- Parse, implicitly from the first character.
  local pos, num = MQTT.length_parse(test_str)
  test_suite:add_test(unittest.equal(num, test_num), ("Test %d: length_parse, number"):format(i))
  test_suite:add_test(unittest.equal(pos, test_len + 1), ("Test %d: length_parse, pos"):format(i))

  -- Parse, explicitly from the one-indexed second character.
  local pos, num = MQTT.length_parse("!" .. test_str, 2)
  test_suite:add_test(unittest.equal(num, test_num), ("Test %d: length_parse offset, number"):format(i))
  test_suite:add_test(unittest.equal(pos, test_len + 2), ("Test %d: length_parse offset, pos"):format(i))

  -- Truncate string and attempt to parse, expecting error.
  local short_str = test_str:sub(1, test_len - 1)
  local pos, _ = MQTT.length_parse(short_str)
  test_suite:add_test(unittest.is_false(pos), ("Test %d: length_parse, expected error"):format(i))
end

-- Ensure that parsing a string with too many continuation bytes,
-- which have their MSB set, fails as expected.
local long_str = "\xFF\xFF\xFF\xFF\x7F"
local pos, _ = MQTT.length_parse(long_str)
test_suite:add_test(unittest.is_false(pos), "length_parse too many continuation bytes")

-- 1.5.3 UTF-8 encoded strings
local str = MQTT.utf8_build("")
test_suite:add_test(unittest.equal(str, "\x00\x00"), "utf8_build empty string")

local str = MQTT.utf8_build("A")
test_suite:add_test(unittest.equal(str, "\x00\x01\x41"), "utf8_build 'A'")

local pos, _ = MQTT.utf8_parse("")
test_suite:add_test(unittest.is_false(pos), "utf8_parse expected failure: ''")

local pos, _ = MQTT.utf8_parse("!")
test_suite:add_test(unittest.is_false(pos), "utf8_parse expected failure: '!'")

local pos, str = MQTT.utf8_parse("\x00\x01")
test_suite:add_test(unittest.is_false(pos), "utf8_parse expected failure: 0001")

local pos, str = MQTT.utf8_parse("\x00\x02\x41")
test_suite:add_test(unittest.is_false(pos), "utf8_parse expected failure: 000241")

local pos, str = MQTT.utf8_parse("\0\0")
test_suite:add_test(unittest.equal(str, ""), "utf8_parse empty string")
test_suite:add_test(unittest.equal(pos, 3), "utf8_parse empty string (pos)")

local pos, str = MQTT.utf8_parse("\x00\x01\x41")
test_suite:add_test(unittest.equal(str, "A"), "utf8_parse 'A'")
test_suite:add_test(unittest.equal(pos, 4), "utf8_parse 'A' (pos)")

return _ENV;
