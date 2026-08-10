local datafiles = require "datafiles"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Shows extra information about IPv6 addresses, such as embedded MAC or IPv4 addresses when available.

Some IP address formats encode extra information; for example some IPv6
addresses encode an IPv4 address or MAC address. This script can decode
these address formats:
* IPv4-compatible IPv6 addresses,
* IPv4-mapped IPv6 addresses,
* Teredo IPv6 addresses,
* 6to4 IPv6 addresses,
* IPv6 addresses using an EUI-64 interface ID,
* IPv4-embedded IPv6 addresses,
* IPv4-translated IPv6 addresses and
* ISATAP Modified EUI-64 IPv6 addresses.

See RFC 4291 for general IPv6 addressing architecture and the
definitions of some terms.
]]

---
-- @output
-- Nmap scan report for ::1.2.3.4
-- Host script results:
-- | address-info:
-- |   IPv4-compatible:
-- |_    IPv4 address: 1.2.3.4
--
-- Nmap scan report for ::ffff:1.2.3.4
-- Host script results:
-- | address-info:
-- |   IPv4-mapped:
-- |_    IPv4 address: 1.2.3.4
--
-- Nmap scan report for 2001:0:506:708:282a:3d75:fefd:fcfb
-- Host script results:
-- | address-info:
-- |   Teredo:
-- |     Server IPv4 address: 5.6.7.8
-- |     Client IPv4 address: 1.2.3.4
-- |_    UDP port: 49802
--
-- Nmap scan report for 2002:102:304::1
-- Host script results:
-- | address-info:
-- |   6to4:
-- |_    IPv4 address: 1.2.3.4
--
-- Nmap scan report for fe80::a8bb:ccff:fedd:eeff
-- Host script results:
-- | address-info:
-- |   IPv6 EUI-64:
-- |     MAC address:
-- |       address: aa:bb:cc:dd:ee:ff
-- |_      manuf: Unknown
--
-- Nmap scan report for 64:ff9b::c000:221
-- Host script results:
-- | address-info:
-- |   IPv4-embedded IPv6 address:
-- |_    IPv4 address: 192.0.2.33
--
-- Nmap scan report for ::ffff:0:c0a8:101
-- Host script results:
-- | address-info:
-- |   IPv4-translated IPv6 address:
-- |_    IPv4 address: 192.168.1.1

-- * ISATAP. RFC 5214.
--   XXXX:XXXX:XXXX:XX00:0000:5EFE:a.b.c.d

---
--@xmloutput
-- <table key="IPv4-mapped">
--   <elem key="IPv4 address">1.2.3.4</elem>
-- </table>
--
-- <table key="IPv4-compatible">
--   <elem key="IPv4 address">1.2.3.4</elem>
-- </table>
--
-- <table key="Teredo">
--   <elem key="Server IPv4 address">5.6.7.8</elem>
--   <elem key="Client IPv4 address">1.2.3.4</elem>
--   <elem key="UDP port">49802</elem>
-- </table>
--
-- <table key="6to4">
--   <elem key="IPv4 address">1.2.3.4</elem>
-- </table>
--
-- <table key="IPv6 EUI-64">
--   <table key="MAC address">
--     <elem key="address">aa:bb:cc:dd:ee:ff</elem>
--     <elem key="manuf">Unknown</elem>
--   </table>
-- </table>
--
-- <table key="IPv4-embedded IPv6 address">
--   <elem key="IPv4 address">192.0.2.33</elem>
-- </table>
--
-- <table key="IPv4-translated IPv6 address">
--   <elem key="IPv4 address">192.168.1.1</elem>
-- </table>

author = "David Fifield"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "safe"}


hostrule = function(host)
  return true
end

-- Match an address (array of bytes) against a hex-encoded pattern. "XX" in the
-- pattern is a wildcard.
local function matches(addr, pattern)
  local octet_patterns

  octet_patterns = {}
  for op in pattern:gmatch("([%xX][%xX])") do
    octet_patterns[#octet_patterns + 1] = op
  end

  if #addr ~= #octet_patterns then
    return false
  end

  for i = 1, #addr do
    local a, op

    a = addr[i]
    op = octet_patterns[i]
    if not (op == "XX" or a == tonumber(op, 16)) then
      return false
    end
  end

  return true
end

local function get_manuf(mac)
  local catch = function() return "Unknown" end
  local try = nmap.new_try(catch)
  local mac_prefixes = try(datafiles.parse_mac_prefixes())
  local prefix = string.upper(string.format("%02x%02x%02x", mac[1], mac[2], mac[3]))
  return mac_prefixes[prefix] or "Unknown"
end

local function format_mac(mac)
  local out = stdnse.output_table()
  out.address = stdnse.format_mac(string.char(table.unpack(mac)))
  out.manuf = get_manuf(mac)
  return out
end

local function format_ipv4(ipv4)
  local octets

  octets = {}
  for _, v in ipairs(ipv4) do
    octets[#octets + 1] = string.format("%d", v)
  end

  return table.concat(octets, ".")
end

local function do_ipv4(addr)
  -- intentionally empty
end

-- EUI-64 from MAC, RFC 4291.
local function decode_eui_64(eui_64)
  if eui_64[4] == 0xff and eui_64[5] == 0xfe then
    return { (eui_64[1] ~ 0x02),
      eui_64[2], eui_64[3], eui_64[6], eui_64[7], eui_64[8] }
  end
end

local function do_ipv6(addr)
  local label
  local output

  output = stdnse.output_table()

  if matches(addr, "0000:0000:0000:0000:0000:0000:0000:0001") then
    -- ::1 is localhost. Not much to report.
    return nil
  elseif matches(addr, "0000:0000:0000:0000:0000:0000:XXXX:XXXX") then
    -- RFC 4291 2.5.5.1.
    local ipv4 = { addr[13], addr[14], addr[15], addr[16] }
    return {["IPv4-compatible"]= { ["IPv4 address"] = format_ipv4(ipv4) } }
  elseif matches(addr, "0000:0000:0000:0000:0000:ffff:XXXX:XXXX") then
    -- RFC 4291 2.5.5.2.
    local ipv4 = { addr[13], addr[14], addr[15], addr[16] }
    return {["IPv4-mapped"]= { ["IPv4 address"] = format_ipv4(ipv4) } }
  elseif matches(addr, "2001:0000:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX") then
    -- Teredo, RFC 4380.
    local server_ipv4 = { addr[5], addr[6], addr[7], addr[8] }
    -- RFC 5991 makes the flags mostly meaningless.
    local flags = addr[9] * 256 + addr[10]
    local obs_port = addr[11] * 256 + addr[12]
    local obs_client_ipv4 = { addr[13], addr[14], addr[15], addr[16] }
    local port, client_ipv4

    -- Invert obs_port.
    port = obs_port ~ 0xffff

    -- Invert obs_client_ipv4.
    client_ipv4 = {}
    for _, octet in ipairs(obs_client_ipv4) do
      client_ipv4[#client_ipv4 + 1] = octet ~ 0xff
    end

    output["Server IPv4 address"] = format_ipv4(server_ipv4)
    output["Client IPv4 address"] = format_ipv4(client_ipv4)
    output["UDP port"] = tostring(port)

    return {["Teredo"] = output}
  elseif matches(addr, "0064:ff9b:XXXX:XXXX:00XX:XXXX:XXXX:XXXX") then
    --IPv4-embedded IPv6 addresses. RFC 6052, Section 2

    --skip addr[9]
    if matches(addr,"0064:ff9b:0000:0000:0000:0000:XXXX:XXXX") then
      local ipv4 = {addr[13], addr[14], addr[15], addr[16]}
      return {["IPv4-embedded IPv6 address"]= {["IPv4 address"] = format_ipv4(ipv4)}}
    elseif addr[5] ~= 0x01 then
      local ipv4 = {addr[5], addr[6], addr[7], addr[8]}
      return {["IPv4-embedded IPv6 address"]= {["IPv4 address"] = format_ipv4(ipv4)}}
    elseif addr[6] ~= 0x22 then
      local ipv4 = {addr[6], addr[7], addr[8], addr[10]}
      return {["IPv4-embedded IPv6 address"]= {["IPv4 address"] = format_ipv4(ipv4)}}
    elseif addr[7] ~= 0x03 then
      local ipv4 = {addr[7], addr[8], addr[10], addr[11]}
      return {["IPv4-embedded IPv6 address"]= {["IPv4 address"] = format_ipv4(ipv4)}}
    elseif addr[8] ~= 0x44 then
      local ipv4 = {addr[8], addr[10], addr[11], addr[12]}
      return {["IPv4-embedded IPv6 address"]= {["IPv4 address"] = format_ipv4(ipv4)}}
    elseif addr[10] == 0x00 and addr[11] == 0x00 and addr[12] == 0x00 then
      local ipv4 = {addr[13], addr[14], addr[15], addr[16]}
      return {["IPv4-embedded IPv6 address"]= {["IPv4 address"] = format_ipv4(ipv4)}}
    end
  elseif matches(addr, "0000:0000:0000:0000:ffff:0000:XXXX:XXXX") then
    -- IPv4-translated IPv6 addresses. RFC 2765, Section 2.1
    return {["IPv4-translated IPv6 address"]=
      {["IPv4 address"] = format_ipv4( {addr[13], addr[14], addr[15], addr[16]})}}
  elseif matches(addr, "XXXX:XXXX:XXXX:XX00:0000:5efe:XXXX:XXXX") then
    -- ISATAP. RFC 5214, Appendix A
    -- XXXX:XXXX:XXXX:XX00:0000:5EFE:a.b.c.d
    return {["ISATAP Modified EUI-64 IPv6 Address"]=
      {["IPv4 address"] = format_ipv4( {addr[13], addr[14], addr[15], addr[16]})}}
  end

  -- These following use common handling for the Interface ID part
  -- (last 64 bits).

  if matches(addr, "2002:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX") then
    -- 6to4, RFC 3056.
    local ipv4 = { addr[3], addr[4], addr[5], addr[6] }

    label = "6to4"
    output["IPv4 address"] = format_ipv4(ipv4)
  end

  local mac = decode_eui_64({ addr[9], addr[10], addr[11], addr[12],
    addr[13], addr[14], addr[15], addr[16] })
  if mac then
    output["MAC address"] = format_mac(mac)
    if not label then
      label = "IPv6 EUI-64"
    end
  end

  if label then
    return {[label]= output}
  end
  -- else no match
end

action = function(host)
  local addr_s, addr_t

  addr_s = host.bin_ip
  addr_t = { string.byte(addr_s, 1, #addr_s) }

  if #addr_t == 4 then
    return do_ipv4(addr_t)
  elseif #addr_t == 16 then
    return do_ipv6(addr_t)
  end
end
