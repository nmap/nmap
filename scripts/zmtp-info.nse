local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects ZeroMQ ZMTP (ZeroMQ Message Transport Protocol) services by performing
a ZMTP 3.x greeting and NULL mechanism handshake. Reports the protocol version,
security mechanism (NULL, PLAIN, or CURVE), socket type (REP, PULL, ROUTER,
PUB, etc.), and additional metadata properties.

ZeroMQ is a high-performance asynchronous messaging library used in distributed
systems, microservices, financial trading, IoT, and ML/AI infrastructure.

References:
* https://rfc.zeromq.org/spec/23/ (ZMTP 3.0)
* https://rfc.zeromq.org/spec/37/ (ZMTP 3.1)
]]

---
-- @usage
-- nmap --script zmtp-info -p 41459,50051,56441 <target>
-- nmap --script zmtp-info -sV <target>
--
-- @output
-- PORT      STATE SERVICE VERSION
-- 41459/tcp open  zmtp    ZeroMQ ZMTP 3.1 (mechanism: NULL)
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
-- 56441/tcp open  zmtp    ZeroMQ ZMTP 3.1 (mechanism: NULL)
-- | zmtp-info:
-- |   protocol: ZMTP
-- |   version: 3.1
-- |   mechanism: NULL
-- |   as-server: false
-- |_  socket-type: ROUTER

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

-- NULL mechanism READY command
-- Frame: flags(1) + size(1) + "READY" + metadata
-- For NULL mechanism, we just send READY with our Socket-Type
local function build_ready_command(socket_type)
  local name = "\x05READY"
  -- Metadata: Socket-Type property
  local prop_name = "Socket-Type"
  local prop_name_len = string.char(#prop_name)
  local prop_val_len = string.char(0, 0, 0, #socket_type)
  local metadata = prop_name_len .. prop_name .. prop_val_len .. socket_type
  local body = name .. metadata
  -- Short command frame: flags=0x04 (command), size
  return "\x04" .. string.char(#body) .. body
end

-- Parse metadata properties from a READY command body
-- Format: repeated [name-length(1) name value-length(4 BE) value]
local function parse_metadata(data)
  local props = {}
  local pos = 1
  while pos <= #data do
    -- Property name length (1 byte)
    local name_len = string.byte(data, pos)
    if not name_len then break end
    pos = pos + 1
    if pos + name_len - 1 > #data then break end
    local name = string.sub(data, pos, pos + name_len - 1)
    pos = pos + name_len
    -- Property value length (4 bytes big-endian)
    if pos + 3 > #data then break end
    local b1, b2, b3, b4 = string.byte(data, pos, pos + 3)
    local val_len = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
    pos = pos + 4
    if pos + val_len - 1 > #data then break end
    local value = string.sub(data, pos, pos + val_len - 1)
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

  local body_start, body
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

  -- Send ZMTP greeting
  status, err = socket:send(ZMTP_GREETING)
  if not status then
    socket:close()
    stdnse.debug1("Failed to send greeting: %s", err)
    return nil
  end

  -- Receive 64-byte greeting response
  local response
  status, response = socket:receive_bytes(64)

  if not status or #response < 10 then
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

  -- Parse version
  local major, minor
  if #response >= 12 then
    major = string.byte(response, 11)
    minor = string.byte(response, 12)
    output.version = string.format("%d.%d", major, minor)
  end

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
    local as_server = string.byte(response, 33)
    output["as-server"] = (as_server == 1)
  end

  -- For NULL mechanism, perform handshake to get metadata (Socket-Type, Identity, etc.)
  if mechanism == "NULL" and major and major >= 3 then
    -- Send READY command with Socket-Type=DEALER (most permissive)
    local ready_cmd = build_ready_command("DEALER")
    status, err = socket:send(ready_cmd)
    if status then
      local ready_data
      -- The server may send its READY command in the same TCP segment as the greeting.
      -- If we received more than 64 bytes, the extra bytes are the READY command.
      if #response > 64 then
        ready_data = string.sub(response, 65)
        stdnse.debug1("READY piggybacked on greeting (%d extra bytes)", #ready_data)
      else
        -- READY arrived separately, read it now
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
          if props["Socket-Type"] then
            output["socket-type"] = props["Socket-Type"]
          end
          if props["Identity"] and #props["Identity"] > 0 then
            output["identity"] = props["Identity"]
          end
          if props["Resource"] and #props["Resource"] > 0 then
            output["resource"] = props["Resource"]
          end
        end
      end
    end
  end

  socket:close()

  -- Update port version info
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
