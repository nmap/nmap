local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Attempts to extract system information from the point-to-point tunneling protocol (PPTP) service.
]]
-- rev 0.2 (11-14-2007)

---
-- @output
-- PORT     STATE SERVICE VERSION
-- 1723/tcp open  pptp    YAMAHA Corporation (Firmware: 32838)
-- Service Info: Host: RT57i

author = "Thomas Buchanan"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"version"}


portrule = shortport.version_port_or_service(1723)

action = function(host, port)
  -- build a PPTP Start-Control-Connection-Request packet
  -- copied from packet capture of pptp exchange
  -- for details of packet structure, see http://www.ietf.org/rfc/rfc2637.txt
  local payload = "\000\156\000\001\026\043\060\077" .. -- length=156, Message type=control, cookie
  "\000\001\000\000\001\000\000\000" .. -- Control type=Start-Control-Connection-Request, Reserved, Protocol=1.0, Reserverd
  "\000\000\000\001\000\000\000\001" .. -- Framing Capabilities, Bearer Capabilities
  "\255\255\000\001" .. "none" .. -- Maximum channels, firmware version, hostname
  "\000\000\000\000\000\000\000\000" .. -- padding for hostname
  "\000\000\000\000\000\000\000\000" .. -- padding for hostname
  "\000\000\000\000\000\000\000\000" .. -- padding for hostname
  "\000\000\000\000\000\000\000\000" .. -- padding for hostname
  "\000\000\000\000\000\000\000\000" .. -- padding for hostname
  "\000\000\000\000\000\000\000\000" .. -- padding for hostname
  "\000\000\000\000\000\000\000\000" .. -- padding for hostname
  "\000\000\000\000" .. "nmap" .. -- padding for hostname, vendor name
  "\000\000\000\000\000\000\000\000" .. -- padding for vendor name
  "\000\000\000\000\000\000\000\000" .. -- padding for vendor name
  "\000\000\000\000\000\000\000\000" .. -- padding for vendor name
  "\000\000\000\000\000\000\000\000" .. -- padding for vendor name
  "\000\000\000\000\000\000\000\000" .. -- padding for vendor name
  "\000\000\000\000\000\000\000\000" .. -- padding for vendor name
  "\000\000\000\000\000\000\000\000" .. -- padding for vendor name
  "\000\000\000\000"; -- padding for vendor name

  local try = nmap.new_try()
  local response = try(comm.exchange(host, port, payload, {timeout=5000}))

  local result

  -- check to see if the packet we got back matches the beginning of a PPTP Start-Control-Connection-Reply packet
  result = string.match(response, "\0\156\0\001\026\043(.*)")
  local output

  if result ~= nil and #result > 88 then
    -- get the firmware version (2 octets)
    -- get the hostname (64 octets)
    local firmware, hostname, pos = (">I2c64"):unpack(result, 22)

    hostname = string.match(hostname, "(.-)\0")

    -- get the vendor (should be 64 octets, but capture to end of the string to be safe)
    local vendor = string.sub(result, pos)
    vendor = string.match(vendor, "(.-)\0")

    port.version.name = "pptp"
    port.version.name_confidence = 10
    if vendor ~= nil then port.version.product = vendor end
    if firmware ~= 0 then port.version.version = "(Firmware: " .. firmware .. ")" end
    if hostname ~= nil then port.version.hostname = hostname end

    port.version.service_tunnel = "none"
    nmap.set_port_version(host, port)
  end

end
