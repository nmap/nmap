local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"
local bit = require "bit"
local stdnse = require "stdnse"

description = [[
Detects the Freelancer game server (FLServer.exe) service by sending a
status query UDP probe.

When run as a version detection script (<code>-sV</code>), the script
will report on the server name, current number of players, maximum
number of players, and whether it has a password set. When run
explicitly (<code>--script freelancer-info</code>), the script will
additionally report on the server description, whether players can harm
other players, and whether new players are allowed.

See http://sourceforge.net/projects/gameq/
(relevant files: games.ini, packets.ini, freelancer.php)
]]

---
-- @usage
-- nmap -sU -sV -p 2302 <target>
-- nmap -sU -p 2302 --script=freelancer-info <target>
-- @output
-- PORT     STATE SERVICE    REASON       VERSION
-- 2302/udp open  freelancer udp-response Freelancer (name: Discovery Freelancer RP 24/7; players: 152/225; password: no)
-- | freelancer-info:
-- |   server name: Discovery Freelancer RP 24/7
-- |   server description: This is the official discovery freelancer RP server. To know more about the server, please visit www.discoverygc.com
-- |   players: 152
-- |   max. players: 225
-- |   password: no
-- |   allow players to harm other players: yes
-- |_  allow new players: yes
--
-- @xmloutput
-- <elem key="server name">Discovery Freelancer RP 24/7</elem>
-- <elem key="server description">This is the official discovery freelancer RP server. To know more about the server, please visit www.discoverygc.com</elem>
-- <elem key="players">152</elem>
-- <elem key="max. players">225</elem>
-- <elem key="password">no</elem>
-- <elem key="allow players to harm other players">yes</elem>
-- <elem key="allow new players">yes</elem>

author = "Marin Maržić"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "default", "discovery", "safe", "version" }

portrule = shortport.version_port_or_service({2302}, "freelancer", "udp")

action = function(host, port)
  local status, data = comm.exchange(host, port,
    "\x00\x02\xf1\x26\x01\x26\xf0\x90\xa6\xf0\x26\x57\x4e\xac\xa0\xec\xf8\x68\xe4\x8d\x21",
    { timeout = 3000 })
  if not status then
    return
  end

  -- port is open
  nmap.set_port_state(host, port, "open")

  local passwordbyte, maxplayers, numplayers, name, pvpallow, newplayersallow, description =
    string.match(data, "^\x00\x03\xf1\x26............(.)...(.)...(.)...................................................................(.*)\0\0(.):(.):.*:.*:.*:(.*)\0\0$")
  if not passwordbyte then
    return
  end

  local o = stdnse.output_table()

  o["server name"] = string.gsub(name, "[^%g%s]", "")
  o["server description"] = string.gsub(description, "[^%g%s]", "")
  o["players"] = numplayers:byte(1) - 1
  o["max. players"] = maxplayers:byte(1) - 1

  passwordbyte = passwordbyte:byte(1)
  if bit.band(passwordbyte, 128) ~= 0 then
    o["password"] = "yes"
  else
    o["password"] = "no"
  end

  o["allow players to harm other players"] = "n/a"
  if pvpallow == "1" then
    o["allow players to harm other players"] = "yes"
  elseif pvpallow == "0" then
    o["allow players to harm other players"] = "no"
  end

  o["allow new players"] = "n/a"
  if newplayersallow == "1" then
    o["allow new players"] = "yes"
  elseif newplayersallow == "0" then
    o["allow new players"] = "no"
  end

  port.version.name = "freelancer"
  port.version.name_confidence = 10
  port.version.product = "Freelancer"
  port.version.extrainfo = "name: " .. o["server name"] .. "; players: " ..
  o["players"] .. "/" ..  o["max. players"] .. "; password: " .. o["password"]

  nmap.set_port_version(host, port, "hardmatched")

  return o
end
