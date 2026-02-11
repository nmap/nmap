local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects ZeroMQ ZMTP (ZeroMQ Message Transport Protocol) services by performing
a protocol handshake. Supports both ZMTP 2.0 and 3.x. Reports the protocol
version, security mechanism (NULL, PLAIN, or CURVE), socket type (REP, PULL,
ROUTER, PUB, etc.), and additional metadata properties.

For ZMTP 3.x with NULL mechanism, performs a READY handshake to extract
metadata such as Socket-Type, Identity, and any custom properties. For ZMTP
2.0, extracts socket type and identity directly from the greeting.

ZeroMQ is a high-performance asynchronous messaging library used in distributed
systems, microservices, financial trading, IoT, and ML/AI infrastructure.

References:
* https://rfc.zeromq.org/spec/15/ (ZMTP 2.0)
* https://rfc.zeromq.org/spec/23/ (ZMTP 3.0)
* https://rfc.zeromq.org/spec/37/ (ZMTP 3.1)
]]

---
-- @usage
-- nmap --script zmtp-info -p 5555,41459 <target>
-- nmap --script zmtp-info -sV <target>
--
-- @output
-- PORT      STATE SERVICE VERSION
-- 5555/tcp  open  zmtp    ZeroMQ ZMTP 3.1 (mechanism: NULL; socket: REP)
-- | zmtp-info:
-- |   protocol: ZMTP
-- |   version: 3.1
-- |   mechanism: NULL
-- |   as-server: true
-- |   socket-type: REP
-- |_  identity: worker-1
--
-- @output
-- PORT      STATE SERVICE VERSION
-- 5556/tcp  open  zmtp    ZeroMQ ZMTP 3.1 (mechanism: NULL; socket: ROUTER)
-- | zmtp-info:
-- |   protocol: ZMTP
-- |   version: 3.1
-- |   mechanism: NULL
-- |   as-server: false
-- |_  socket-type: ROUTER
--
-- @output
-- PORT      STATE SERVICE VERSION
-- 5557/tcp  open  zmtp    ZeroMQ ZMTP 2.0 (socket: PUB)
-- | zmtp-info:
-- |   protocol: ZMTP
-- |   version: 2.0
-- |_  socket-type: PUB

author = "Valentin Lobstein (Chocapikk)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe", "version"}

-- ZMTP 3.1 greeting: 64 bytes
-- Signature: 0xFF + 8 padding bytes + 0x7F
-- Version: 0x03 0x01 (ZMTP 3.1)
-- Mechanism: "NULL" + 16 zero bytes (20 bytes total)
-- As-server: 0x00 (client role)
-- Filler: 31 zero bytes
local ZMTP_GREETING = "\xff\x00\x00\x00\x00\x00\x00\x00\x01\x7f" -- signature
  .. "\x03\x01"                                                    -- version 3.1
  .. "NULL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -- mechanism
  .. "\x00"                                                        -- as-server = false
  .. string.rep("\x00", 31)                                        -- filler

-- ZMTP 2.0 socket type byte to name mapping
local ZMTP2_SOCKET_TYPES = {
  [0] = "PAIR",
  [1] = "PUB",
  [2] = "SUB",
  [3] = "REQ",
  [4] = "REP",
  [5] = "DEALER",
  [6] = "ROUTER",
  [7] = "PULL",
  [8] = "PUSH",
}

-- NULL mechanism READY command
-- Frame: flags(1) + size(1) + "\x05READY" + metadata
local function build_ready_command(socket_type)
  local name = "\x05READY"
  local prop_name = "Socket-Type"
  local prop_name_len = string.char(#prop_name)
  local prop_val_len = string.char(0, 0, 0, #socket_type)
  local metadata = prop_name_len .. prop_name .. prop_val_len .. socket_type
  local body = name .. metadata
  return "\x04" .. string.char(#body) .. body
end

-- Parse metadata properties from a READY command body
-- Format: repeated [name-length(1) name value-length(4 BE) value]
local function parse_metadata(data)
  local props = {}
  local pos = 1
  while pos <= #data do
    local name_len = string.byte(data, pos)
    if not name_len then break end
    pos = pos + 1
    if pos + name_len - 1 > #data then break end
    local name = string.sub(data, pos, pos + name_len - 1)
    pos = pos + name_len
    if pos + 3 > #data then break end
    local b1, b2, b3, b4 = string.byte(data, pos, pos + 3)
    local val_len = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
    pos = pos + 4
    if val_len > 0 and pos + val_len - 1 > #data then break end
    local value = ""
    if val_len > 0 then
      value = string.sub(data, pos, pos + val_len - 1)
    end
    pos = pos + val_len
    props[name] = value
  end
  return props
end

-- Parse a ZMTP command frame and return command name + body
local function parse_command_frame(data)
  if #data < 2 then return nil, nil end
  local flags = string.byte(data, 1)
  local is_command = (flags == 0x04) or (flags == 0x06)
  if not is_command then return nil, nil end

  local body
  if flags == 0x04 then
    -- Short frame
    local size = string.byte(data, 2)
    if #data < 2 + size then return nil, nil end
    body = string.sub(data, 3, 2 + size)
  else
    -- Long frame (0x06)
    if #data < 9 then return nil, nil end
    local size = 0
    for i = 2, 9 do
      size = size * 256 + string.byte(data, i)
    end
    if #data < 9 + size then return nil, nil end
    body = string.sub(data, 10, 9 + size)
  end

  if not body or #body < 1 then return nil, nil end
  local cmd_name_len = string.byte(body, 1)
  if #body < 1 + cmd_name_len then return nil, nil end
  local cmd_name = string.sub(body, 2, 1 + cmd_name_len)
  local cmd_data = string.sub(body, 2 + cmd_name_len)
  return cmd_name, cmd_data
end

-- Apply all metadata properties from READY to the output table
local function apply_metadata(props, output)
  if props["Socket-Type"] then
    output["socket-type"] = props["Socket-Type"]
  end
  if props["Identity"] and #props["Identity"] > 0 then
    output["identity"] = props["Identity"]
  end
  if props["Resource"] and #props["Resource"] > 0 then
    output["resource"] = props["Resource"]
  end
  -- Dump any additional custom properties
  for name, value in pairs(props) do
    local lname = name:lower()
    if lname ~= "socket-type" and lname ~= "identity" and lname ~= "resource" then
      if #value > 0 then
        output[name] = value
      end
    end
  end
end

-- Parse ZMTP 2.0 greeting (after the 10-byte signature)
-- Format: revision(1) + socket-type(1), then identity frame follows
local function parse_zmtp2(response, output)
  output.version = "2.0"

  if #response >= 12 then
    local sock_type_byte = string.byte(response, 12)
    local sock_name = ZMTP2_SOCKET_TYPES[sock_type_byte]
    if sock_name then
      output["socket-type"] = sock_name
    else
      output["socket-type"] = string.format("unknown(%d)", sock_type_byte)
    end
  end

  -- Identity frame: flags(1) + length(1) + data
  -- flags byte at offset 13: 0x00 = final short frame
  if #response >= 14 then
    local id_flags = string.byte(response, 13)
    local is_long = (id_flags % 4) >= 2
    if not is_long then
      local id_len = string.byte(response, 14)
      if id_len and id_len > 0 and #response >= 14 + id_len then
        local identity = string.sub(response, 15, 14 + id_len)
        output["identity"] = identity
      end
    end
  end
end

-- Parse ZMTP 3.x greeting (full 64-byte greeting) and perform READY handshake
local function parse_zmtp3(response, socket, output)
  local minor = 0
  if #response >= 12 then
    minor = string.byte(response, 12)
  end
  output.version = string.format("3.%d", minor)

  -- Parse mechanism (20 bytes at offset 13-32, null-padded string)
  local mechanism
  if #response >= 32 then
    local mech_raw = string.sub(response, 13, 32)
    mechanism = mech_raw:match("^(%Z+)")
    if mechanism then
      output.mechanism = mechanism
    end
  end

  -- Parse as-server flag (byte 33)
  if #response >= 33 then
    output["as-server"] = (string.byte(response, 33) == 1)
  end

  -- For NULL mechanism, perform READY handshake to extract metadata
  if mechanism == "NULL" then
    local ready_cmd = build_ready_command("DEALER")
    local status, err = socket:send(ready_cmd)
    if not status then
      stdnse.debug1("Failed to send READY: %s", err)
      return
    end

    local ready_data
    -- Server may piggyback READY on the greeting (same TCP segment)
    if #response > 64 then
      ready_data = string.sub(response, 65)
      stdnse.debug1("READY piggybacked on greeting (%d extra bytes)", #ready_data)
    else
      local ready_response
      status, ready_response = socket:receive_bytes(2)
      if status and ready_response and #ready_response > 0 then
        ready_data = ready_response
      end
    end

    if ready_data and #ready_data > 0 then
      local cmd_name, cmd_data = parse_command_frame(ready_data)
      if cmd_name == "READY" and cmd_data then
        local props = parse_metadata(cmd_data)
        apply_metadata(props, output)
      elseif cmd_name == "ERROR" and cmd_data then
        output["error"] = cmd_data
        stdnse.debug1("Server returned ERROR: %s", cmd_data)
      end
    end
  end
end

portrule = function(host, port)
  if port.version and port.version.name == "zmtp" then
    return true
  end
  return shortport.port_or_service(
    {41459, 50051, 56441},
    {"zmtp", "zeromq"},
    "tcp",
    "open"
  )(host, port)
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host, port)
  if not status then
    stdnse.debug1("Failed to connect: %s", err)
    return nil
  end

  -- Send ZMTP 3.1 greeting (backwards-compatible with 2.0)
  status, err = socket:send(ZMTP_GREETING)
  if not status then
    socket:close()
    stdnse.debug1("Failed to send greeting: %s", err)
    return nil
  end

  -- Receive at least the 10-byte signature.
  -- For ZMTP 3.x we typically get 64+ bytes, for 2.0 we get ~14 bytes.
  local response
  status, response = socket:receive_bytes(10)

  if not status or #response < 11 then
    socket:close()
    stdnse.debug1("No valid response received")
    return nil
  end

  -- Validate ZMTP signature: first byte 0xFF, byte 10 is 0x7F
  local sig_start = string.byte(response, 1)
  local sig_end = string.byte(response, 10)

  if sig_start ~= 0xFF or sig_end ~= 0x7F then
    socket:close()
    stdnse.debug1("Not a ZMTP service (signature mismatch: %02x...%02x)", sig_start, sig_end)
    return nil
  end

  local output = stdnse.output_table()
  output.protocol = "ZMTP"

  local major = string.byte(response, 11)

  if major >= 3 then
    -- ZMTP 3.x: ensure we have the full 64-byte greeting
    if #response < 64 then
      local s, more = socket:receive_bytes(64 - #response)
      if s and more then
        response = response .. more
      end
    end
    parse_zmtp3(response, socket, output)
  elseif major == 1 or major == 2 then
    -- ZMTP 2.0 (revision byte 0x01) or ZMTP 2.1 (0x02)
    parse_zmtp2(response, output)
  else
    -- Unknown version, report what we know
    output.version = string.format("%d.0", major)
    stdnse.debug1("Unknown ZMTP major version: %d", major)
  end

  socket:close()

  -- Update port version info for -sV output
  port.version.name = "zmtp"
  port.version.product = "ZeroMQ ZMTP"
  if output.version then
    port.version.version = output.version
  end
  local extra = {}
  if output.mechanism then
    extra[#extra + 1] = "mechanism: " .. output.mechanism
  end
  if output["socket-type"] then
    extra[#extra + 1] = "socket: " .. output["socket-type"]
  end
  if #extra > 0 then
    port.version.extrainfo = table.concat(extra, "; ")
  end
  nmap.set_port_version(host, port)

  return output
end
