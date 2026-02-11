local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local comm = require "comm"
local string = require "string"

description = [[
Detects ZeroMQ ZMTP (ZeroMQ Message Transport Protocol) services by performing
a ZMTP 3.x greeting handshake. Reports the protocol version, security mechanism
(NULL, PLAIN, or CURVE), and socket role (client/server).

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
-- PORT      STATE SERVICE
-- 41459/tcp open  zmtp
-- | zmtp-info:
-- |   protocol: ZMTP
-- |   version: 3.1
-- |   mechanism: NULL
-- |_  as-server: true
--
-- @output
-- PORT      STATE SERVICE
-- 56441/tcp open  zmtp
-- | zmtp-info:
-- |   protocol: ZMTP
-- |   version: 3.0
-- |   mechanism: CURVE
-- |_  as-server: false

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

local KNOWN_MECHANISMS = {
  NULL = true,
  PLAIN = true,
  CURVE = true,
}

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
  socket:close()

  if not status or #response < 10 then
    stdnse.debug1("No valid response received")
    return nil
  end

  -- Validate ZMTP signature: first byte 0xFF, byte 10 is 0x7F
  local sig_start = string.byte(response, 1)
  local sig_end = string.byte(response, 10)

  if sig_start ~= 0xFF or sig_end ~= 0x7F then
    stdnse.debug1("Not a ZMTP service (signature mismatch: %02x...%02x)", sig_start, sig_end)
    return nil
  end

  local output = stdnse.output_table()
  output.protocol = "ZMTP"

  -- Parse version
  if #response >= 12 then
    local major = string.byte(response, 11)
    local minor = string.byte(response, 12)
    output.version = string.format("%d.%d", major, minor)
  end

  -- Parse mechanism (20 bytes at offset 13-32, null-padded string)
  if #response >= 32 then
    local mech_raw = string.sub(response, 13, 32)
    local mechanism = mech_raw:match("^(%Z+)")
    if mechanism then
      output.mechanism = mechanism
    end
  end

  -- Parse as-server flag (byte 33)
  if #response >= 33 then
    local as_server = string.byte(response, 33)
    output["as-server"] = (as_server == 1)
  end

  -- Update port version info
  port.version.name = "zmtp"
  port.version.product = "ZeroMQ ZMTP"
  if output.version then
    port.version.version = output.version
  end
  if output.mechanism then
    port.version.extrainfo = "mechanism: " .. output.mechanism
  end
  nmap.set_port_version(host, port)

  return output
end
