-- ============================================================================
-- NSE Script: Armagetron Advanced Server Information Discovery
-- ============================================================================
-- Queries UDP-based Armagetron Advanced game servers for detailed status
-- including server configuration, player information, and protocol details.

description = [[
Queries an Armagetron Advanced game server for status information:
server name, listen address, version, protocol versions, player count, player names,
global IDs, options, URL.

The script sends a BigRequest query (descriptor 0x35) to discover servers
listening on the default Armagetron ports (4534-4540) or any port matching
the "armagetron" service name. The server responds with a BigServerInfo
message containing structured game state data encoded in Armagetron's custom
binary format, including player names mapped to their global IDs and server
configuration options.
]]

---
-- @usage
-- nmap -sU -p <port> <host> --script armagetronad-server-info [--script-trace]
--~
-- @output
-- Host script results:
-- | armagetronad-server-info:
-- |   server name: The CLASSIC Submarine 51
-- |   version: 0.2.9-sty+ct+ap.3_alpha_z3883 unix dedicated
-- |   listen address: tron.thefarm51.com:4534
-- |   protocol: min=14 max=17
-- |   players: 2/12
-- |   player names:
-- |     MyloVer
-- |     Monarki (ID: P4@thefarm51.com)
-- |   options: The Classic Submarine alike gameplay. Work in progress.
-- |_  url: https://retrocycles.net
--
-- @xmloutput
-- <elem key="server name">The CLASSIC Submarine 51</elem>
-- <elem key="version">0.2.9-sty+ct+ap.3_alpha_z3883 unix dedicated</elem>
-- <elem key="listen address">tron.thefarm51.com:4534</elem>
-- <table key="protocol">
--   <elem key="min">14</elem>
--   <elem key="max">17</elem>
-- </table>
-- <table key="players">
--   <elem key="count">2</elem>
--   <elem key="max">12</elem>
--   <table key="player names">
--     <table>
--       <elem key="name">MyloVer</elem>
--     </table>
--     <table>
--       <elem key="name">Monarki</elem>
--       <elem key="id">P4@thefarm51.com</elem>
--     </table>
--   </table>
-- </table>
-- <elem key="options">The Classic Submarine alike gameplay. Work in progress.</elem>
-- <elem key="url">https://retrocycles.net</elem>

author = "P4 https://keybase.io/P4"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "udp"
     and port.state ~= "closed"
     and (
         (port.number >= 4534 and port.number <= 4540)
         or port.service:match("^armagetron")
         or port.service == "unknown"
     )
end

local nmap = require "nmap"
local stdnse = require "stdnse"

--;
-- Decodes AA (Armagetron Advanced) custom string format.
--
-- Protocol encodes strings as:
--   - 2-byte big-endian length (byte count, not including length field)
--   - Length padded to even boundary (required for 2-byte processing)
--   - Payload: series of 2-byte big-endian words
--
-- Decoding logic per word:
--   - Low byte (c1) = word & 0xFF
--   - High byte (c2) = word >> 8
--   - If c1 > 127: adjust c2 = (c2 + 1) % 256 (sign-bit correction)
--   - Output c1 if non-zero; output c2 if also non-zero
--   - Skip null bytes (c1 == 0) to remove embedded nulls
--   - Strip Armagetron color codes (e.g., '0xFFFFFF')
--
-- @param data Binary string buffer to decode from.
-- @param pos Starting position (1-indexed) in data.
-- @return Decoded string and updated position after parsing.
-- @see readInt
local function decodeAAString(data, pos)
  -- Bounds check: need at least 2 bytes for length field
  if pos + 1 > #data then return "", pos end

  -- Read 2-byte big-endian length prefix
  local len = data:byte(pos) * 256 + data:byte(pos+1)
  pos = pos + 2

  -- Ensure length is even for 2-byte word processing
  -- Odd lengths are padded by incrementing
  local padLen = (len % 2 == 1) and (len + 1) or len
  
  -- Clamp padLen if we don't have enough data remaining
  if pos + padLen - 1 > #data then
    padLen = #data - pos + 1
  end

  -- Extract raw payload bytes
  local raw = data:sub(pos, pos + padLen - 1)
  pos = pos + padLen

  local out = {}

  -- Process 2-byte words (big-endian): combine bytes, apply AA string encoding rules
  for i = 1, #raw - 1, 2 do
    local w = raw:byte(i) * 256 + raw:byte(i+1)
    local c1 = w % 256              -- Low byte
    local c2 = (w // 256)           -- High byte

    -- Adjust high byte if low byte sign bit set
    if c1 > 127 then
      c2 = (c2 + 1) % 256
    end

    -- Output non-zero bytes to reconstruct string
    -- Skip c1==0 to strip embedded null bytes
    if c1 ~= 0 then
      out[#out+1] = string.char(c1)
      if c2 ~= 0 then
        out[#out+1] = string.char(c2)
      end
    end
  end

  local decoded = table.concat(out)

  -- Remove Armagetron color codes
  -- Pattern: '0xFFFFFF' (0x prefix followed by 6 hex digits)
  decoded = decoded:gsub("0x%x%x%x%x%x%x", "")

  return decoded, pos
end

--;
-- Reads a 4-byte little-endian integer from binary data.
--
-- Format: Two 16-bit big-endian values are read sequentially:
--   - First word (pos to pos+1): lower 16 bits of result
--   - Second word (pos+2 to pos+3): upper 16 bits of result
-- This sequence creates a 32-bit little-endian value.
-- Combined as: (high16 * 65536) + low16
--
-- @param data Binary string buffer to read from.
-- @param pos Starting position (1-indexed) in data.
-- @return Integer value (0 if insufficient data) and updated position.
-- @see decodeAAString
local function readInt(data, pos)
  -- Bounds check: need 4 bytes
  if pos + 3 > #data then return 0, pos end

  -- Read first 16-bit word in big-endian (lower 16 bits of result)
  local low16  = data:byte(pos) * 256 + data:byte(pos+1)
  -- Read second 16-bit word in big-endian (upper 16 bits of result)
  local high16 = data:byte(pos+2) * 256 + data:byte(pos+3)

  -- Combine as 32-bit little-endian (high16 is upper bits, low16 is lower bits)
  return high16 * 65536 + low16, pos + 4
end

action = function(host, port)

  local sock = nmap.new_socket("udp")
  sock:set_timeout(500)

  local ok, err = sock:connect(host.ip, port.number, "udp")
  if not ok then
    return stdnse.format_output(false, "ERROR: "..err)
  end

  -- Build BigRequest query packet (descriptor 0x35).
  -- Protocol header format (8 bytes big-endian):
  --   - descriptor (2 bytes): 0x0035
  --   - message_id (2 bytes): 0x0000 (no ack needed)
  --   - payload_len (2 bytes): 0x0000 (no parameters)
  --   - client_id (2 bytes): 0x0000
  local payload = string.char(
    0x00, 0x35,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00
  )
  sock:send(payload)

  local chunks = {}
  local timeout = 500
  local t_start = nmap.clock_ms()

  while nmap.clock_ms() - t_start < timeout do
    local status, resp = sock:receive()
    if status and resp then
      chunks[#chunks+1] = resp
    else
      stdnse.sleep(0.02)
    end
  end

  sock:close()

  if #chunks == 0 then
    return nil
  end

  local data = table.concat(chunks)

  -- Parse response header: skip padding and locate BigServerInfo response.
  -- Armagetron protocol allows zero-descriptor padding at message
  -- boundaries; we slide the parsing window forward until we find a
  -- non-zero descriptor.
  local pos = 1
  local descriptor = 0

  -- Slide through buffer skipping zero-descriptors (padding bytes)
  -- until we find a non-zero descriptor marking actual message start
  while true do
    -- Bounds check: need at least 6 bytes for descriptor + message header
    if pos + 5 > #data then return nil end

    descriptor = data:byte(pos) * 256 + data:byte(pos + 1)

    if descriptor == 0 then
      -- Zero-descriptor = padding; skip 2 bytes and continue sliding
      pos = pos + 2
    else
      -- Found non-zero descriptor; skip full 6-byte header
      -- to position at payload start
      pos = pos + 6
      break
    end
  end

  -- Verify response is BigServerInfo (descriptor 0x33).
  -- Any other descriptor indicates protocol mismatch or unexpected message.
  if descriptor ~= 0x33 then
    return stdnse.format_output(false,
      ("Unexpected descriptor: 0x%02x"):format(descriptor))
  end

  -- Parse BigServerInfo payload fields in protocol order.
  
  local port_by_server
  port_by_server, pos = readInt(data, pos)

  local host_by_server
  host_by_server, pos = decodeAAString(data, pos)

  local server_name
  server_name, pos = decodeAAString(data, pos)

  local num_players
  num_players, pos = readInt(data, pos)

  local version_min
  version_min, pos = readInt(data, pos)

  local version_max
  version_max, pos = readInt(data, pos)

  local version_str
  version_str, pos = decodeAAString(data, pos)

  local max_players
  max_players, pos = readInt(data, pos)

  local players_raw
  players_raw, pos = decodeAAString(data, pos)

  local players = {}
  if players_raw and players_raw ~= "" then
    players_raw = players_raw:gsub("\n$", "")
    for p in players_raw:gmatch("[^\n]+") do
      players[#players+1] = p
    end
  end

  local options_str
  options_str, pos = decodeAAString(data, pos)

  local uri_str
  uri_str, pos = decodeAAString(data, pos)

  -- Extract player global IDs only if data remains in buffer.
  local global_ids = {}
  if pos - 1 < #data then
    local global_ids_raw
    global_ids_raw, pos = decodeAAString(data, pos)

    if global_ids_raw and global_ids_raw ~= "" then
      global_ids_raw = global_ids_raw:gsub("\n$", "")
      for g in global_ids_raw:gmatch("[^\n]+") do
        global_ids[#global_ids+1] = g
      end
    end
  end

  local out = {}

  out[#out+1] = ("server name: %s"):format(server_name)
  out[#out+1] = ("version: %s"):format(version_str)

  if host_by_server ~= "" then
    out[#out+1] = ("listen address: %s:%d"):format(host_by_server, port_by_server)
  else
    out[#out+1] = ("listen port: %d"):format(port_by_server)
  end

  out[#out+1] = ("protocol: min=%d max=%d"):format(version_min, version_max)

  out[#out+1] = ("players: %d/%d"):format(#players, max_players)

  if #players > 0 then
    local players_table = { name = "player names" }
    for i, p in ipairs(players) do
      if global_ids[i] then
        players_table[#players_table+1] = ("%s (ID: %s)"):format(p, global_ids[i])
      else
        players_table[#players_table+1] = p
      end
    end
    out[#out+1] = players_table
  end

  if options_str ~= "" then
    out[#out+1] = ("options: %s"):format(options_str)
  end

  if uri_str ~= "" then
    out[#out+1] = ("url: %s"):format(uri_str)
  end

  return stdnse.format_output(true, out)
end
