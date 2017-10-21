local bin = require "bin"
local comm = require "comm"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Extracts information from Quake game servers and other game servers
which use the same protocol.

Quake uses UDP packets, which because of source spoofing can be used to amplify
a denial-of-service attack. For each request, the script reports the payload
amplification as a ratio. The format used is
<code>response_bytes/request_bytes=ratio</code>

http://www.gamers.org/dEngine/quake/QDP/qnp.html
]]

---
-- @usage
-- nmap -n -sU -Pn --script quake1-info -pU:26000-26004 -- <target>
--
-- @output
-- PORT      STATE SERVICE
-- 26000/udp open  quake
-- | quake1-info:
-- |   server info exchange payload amplification: 59/12=4.916667
-- |   listen address: 10.200.200.10:26000
-- |   server name: An anonymous Debian server
-- |   level name: dm1
-- |   players: 1/8
-- |   player table
-- |     player 1: fragmeister
-- |       player info exchange payload amplification: 49/6=8.166667
-- |       client address: 192.168.0.10:40430
-- |       connect time: 55587 secs
-- |       frags: -1
-- |       shirt: green3
-- |       pants: orange6
-- |_  protocol version: released (0x3)
--
-- @xmloutput
-- <elem key="server_ratio">59/12=4.916667</elem>
-- <elem key="listen_address">10.200.200.10:26000</elem>
-- <elem key="server_name">An anonymous Debian server</elem>
-- <elem key="level_name">dm1</elem>
-- <elem key="players">1/8</elem>
-- <table key="player_table">
--   <table key="player 1">
--     <elem key="player_ratio">49/6=8.166667</elem>
--     <elem key="name">fragmeister</elem>
--     <elem key="client_address">192.168.0.10:40430</elem>
--     <elem key="connect_time">55587 secs</elem>
--     <elem key="frags">-1</elem>
--     <elem key="shirt">green3</elem>
--     <elem key="pants">orange6</elem>
--   </table>
-- </table>
-- <elem key="protocol_version">released (0x3)</elem>


categories = {"default", "discovery", "safe", "version"}
author = "Ulrik Haugen"
copyright = "Linköpings universitet 2014, Ulrik Haugen 2014"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"


--- Proceed with action on open/open|filtered udp ports in interval
-- [26000, 26004] and whatever Quake is listed under in nmap-services.
function portrule(host, port)
  return (port.state == 'open' or port.state == 'open|filtered')
  and port.protocol == 'udp'
  and ((26000 <= port.number and port.number <= 26004)
    or port.service == 'quake')
  and nmap.version_intensity() >= 7
end


--- Like assert but put /message/ in the ERROR key in /results_table/ to
-- better suit collate_results and pass 0 as level to error to ensure
-- the error message will not be prefixed with file and line number.
-- /results_table/ may be left out.
local function assert_w_table(condition, message, results_table)
  if condition then
    return condition
  else
    results_table = results_table or {}
    results_table.ERROR = message
    error(results_table, 0)
  end
end


-- Protocol constants and tables.
local ctrl_pkt_type = 0x8000
local ccreq_server_info = 0x02
local ccrep_server_info = 0x83
local ccreq_player_info = 0x03
local ccrep_player_info = 0x84
local game_name = "QUAKE"
local net_protocol_versions = {
  [ 0x01 ] = "qtest1",
  [ 0x02 ] = "unknown",
  [ 0x03 ] = "released"
}
local net_protocol_released = 0x03
local color_codes = {
  [ 0x0 ] = "gray0",
  [ 0x1 ] = "brown1",
  [ 0x2 ] = "lavender2",
  [ 0x3 ] = "green3",
  [ 0x4 ] = "red4",
  [ 0x5 ] = "light green5",
  [ 0x6 ] = "orange6",
  [ 0x7 ] = "light brown7",
  [ 0x8 ] = "violet8",
  [ 0x9 ] = "pink9",
  [ 0xa ] = "beige10",
  [ 0xb ] = "green11",
  [ 0xc ] = "yellow12",
  [ 0xd ] = "blue13"
}


--- Request player info from /host/:/port/ for player /id/, return
-- player info as a table on success and raise an error on failure.
local function get_player_info(host, port, id)
  local player_info = stdnse.output_table()
  local req_pl = bin.pack('>SSCC',
    ctrl_pkt_type,     -- packet type
    2+2+1+1,           -- packet length
    ccreq_player_info, -- operation code
    id - 1)            -- player number (0 indexed)
  -- iptables -m u32 --u32 '0x1c=0x80000006&&0x1d&0xff=0x03'

  local status, rep_pl = comm.exchange(host, port, req_pl)
  assert_w_table(status, "No response to request for player info")

  player_info.player_ratio = string.format("%d/%d=%f",
    rep_pl:len(), req_pl:len(),
    rep_pl:len()/req_pl:len() )

  local pos, rep_pkt_type, rep_pl_len = bin.unpack('>SS', rep_pl)
  assert_w_table(rep_pl_len == rep_pl:len(),
    string.format("Incorrect reply packet length: %d"
      .. " received, %d bytes in packet",
      rep_pl_len, rep_pl:len()),
    player_info)
  local term_pos = rep_pl_len + 1
  assert_w_table(rep_pkt_type == ctrl_pkt_type,
    "Bad reply packet type", player_info)

  -- frags and connect_time are sent little endian:
  local pos, rep_opc, player_id, name, colors, frags, connect_time, client_address = bin.unpack('>CCzCxxx<iI>z', rep_pl, pos)
  assert_w_table(pos == term_pos, "Error parsing reply (packet type/ length)",
    player_info)
  assert_w_table(rep_opc == ccrep_player_info,
    string.format("Incorrect operation code 0x%x in reply,"
      .. " should be 0x%x",
      rep_opc, ccrep_player_info),
    player_info)

  player_info.name = name
  player_info.client_address = client_address
  player_info.connect_time = string.format("%d secs", connect_time)
  player_info.frags = frags
  player_info.shirt = color_codes[colors >> 4] or "INVALID"
  player_info.pants = color_codes[colors & 0x0f] or "INVALID"
  return player_info
end


--- Request player info from /host/:/port/ for players [1,
-- /cur_players/], return player infos or errors in a table.
local function get_player_table(host, port, cur_players)
  local player_table = stdnse.output_table()
  for id = 1, cur_players do
    -- At this point we have established that the target is a Quake
    -- game server so lost ccreq or ccrep player info packets are
    -- merely noted in the output, they don't abort the script.
    local status, player_info = pcall(get_player_info, host, port, id)
    player_table[string.format("player %d", id)] = player_info
  end
  return player_table
end


--- Request server info and possibly player infos from /host/:/port/,
-- return server info and any player infos as a table on success and
-- raise an error on failure.
local function get_server_info(host, port)
  local server_info = stdnse.output_table()
  local req_pl = bin.pack('>SSCzC',
    ctrl_pkt_type,             -- packet type
    2+2+1+game_name:len()+1+1, -- packet length
    ccreq_server_info,         -- operation code
    game_name,
    net_protocol_released)     -- net protocol version
  -- iptables -m u32 --u32 '0x1c=0x8000000c&&0x20=0x02515541&&0x24=0x4b450003'

  local status, rep_pl = comm.exchange(host, port, req_pl)
  assert_w_table(status, "No response to request for server info")

  nmap.set_port_state(host, port, 'open')
  server_info.server_ratio = string.format("%d/%d=%f",
    rep_pl:len(), req_pl:len(),
    rep_pl:len()/req_pl:len())

  local pos, rep_pkt_type, rep_pl_len = bin.unpack('>SS', rep_pl)
  assert_w_table(rep_pkt_type == ctrl_pkt_type,
    string.format("Bad reply packet type 0x%x, expected 0x%x",
    rep_pkt_type, ctrl_pkt_type), server_info)
  assert_w_table(rep_pl_len == rep_pl:len(),
    string.format("Bad reply packet length: %d received,"
      .. " %d bytes in packet",
    rep_pl_len, rep_pl:len()), server_info)
  local term_pos = rep_pl_len + 1

  local pos, rep_opc = bin.unpack('>C', rep_pl, pos)
  assert_w_table(rep_opc == ccrep_server_info,
    string.format("Bad operation code 0x%x in reply,"
      .. " expected 0x%x",
    rep_opc, ccrep_server_info), server_info)
  local pos, server_address, server_host_name, level_name, cur_players, max_players, net_protocol_version = bin.unpack('>zzzCCC', rep_pl, pos)
  assert_w_table(pos == term_pos, "Error parsing reply (packet type/length)",
    server_info)

  port.version.name = "quake"
  port.version.product = "Quake 1 server"
  port.version.version = net_protocol_versions[net_protocol_version]
  nmap.set_port_version(host, port)

  local player_table = get_player_table(host, port, cur_players)

  server_info.listen_address = server_address
  server_info.server_name = server_host_name
  server_info.level_name = level_name
  server_info.players = string.format("%d/%d", cur_players, max_players)
  server_info.player_table = player_table
  server_info.protocol_version = string.format(
    "%s (0x%x)",
    net_protocol_versions[net_protocol_version], net_protocol_version)
  return server_info
end


--- Return a function from structured to unstructured output indenting
-- nested tables /offset/ or two spaces with special treatment of name
-- keys and optionally using /xlate_key/ to format keys.
local function make_formatter(offset, xlate_key)
  offset = offset or 2
  xlate_key = xlate_key or function(key) return key:gsub("_", " ") end

  --- Format /results_table/ as a string starting /indent/ or zero
  -- steps from the margin for the name key and adding offset steps
  -- for other table contents and again for the contents of nested
  -- tables.
  local function formatter(results_table, indent)
    indent = indent or 0
    local output = {}

    if results_table.name then
      table.insert(output,
        string.format("%s%s", ({ [ false ] = ": ",
            [ true ] = "\n" })[indent == 0],
        results_table.name))
    end

    for key, value in pairs(results_table) do
      -- name is printed already
      if key ~= 'name' then
        if type(value) == 'table' then
          table.insert(output,
            string.format("\n%s%s",
              string.rep(" ", indent + offset),
            xlate_key(key)))
          table.insert(output, formatter(value, indent + offset))
        else
          table.insert(output,
            string.format("\n%s%s: %s",
              string.rep(" ", indent + offset),
            xlate_key(key), value))
        end
      end
    end
    return table.concat(output, '')
  end

  return formatter
end


--- Use /formatter/ to produce unstructured output from
-- /results_table/ considering /status/. Return structured and
-- unstructured output.
local function collate_results(formatter, status, results_table)
  if not status and nmap.debugging() < 1 then
    return nil
  end
  return results_table, formatter(results_table)
end


--- Nmap entry point.
function action(host, port)
  local xlate_table = {
    player_ratio = "player info exchange payload amplification",
    server_ratio = "server info exchange payload amplification",
  }

  local function xlate_key(key)
    return xlate_table[key] or key:gsub("_", " ")
  end

  return collate_results(make_formatter(nil, xlate_key),
    pcall(get_server_info, host, port))
end
