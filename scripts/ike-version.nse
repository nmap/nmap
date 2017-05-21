local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local ike = require "ike"


description=[[
Obtains information (such as vendor and device type where available) from an
IKE service by sending four packets to the host.  This scripts tests with both
Main and Aggressive Mode and sends multiple transforms per request.
]]


---
-- @usage
-- nmap -sU -sV -p 500 <target>
-- nmap -sU -p 500 --script ike-version <target>
--
-- @output
-- PORT    STATE SERVICE REASON       VERSION
-- 500/udp open  isakmp  udp-response Fortinet FortiGate v5
-- | ike-version:
-- |   vendor_id: Fortinet FortiGate v5
-- |   attributes:
-- |     Dead Peer Detection v1.0
-- |_    XAUTH
-- Service Info: OS: Fortigate v5; Device: Network Security Appliance; CPE: cpe:/h:fortinet:fortigate
--
-- @xmloutput
-- <elem key="vendor_id">Fortinet FortiGate v5</elem>
-- <table key="unmatched_ids">
--   <elem>1234567890abcdef</elem>
-- </table>
-- <table key="attributes">
--   <elem>Dead Peer Detection v1.0</elem>
--   <elem>XAUTH</elem>
-- </table>
---


author = "Jesper Kueckelhahn"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe", "version"}

portrule = shortport.version_port_or_service(500, "isakmp", "udp")


-- Test different methods for getting version
--
local function get_version(host, port)
  local packet, version, t
  local auth = {"psk", "rsa", "Hybrid", "XAUTH"}
  local encryption = {"des", "3des", "aes/128", "aes/192", "aes/256"}
  local hash = {"md5", "sha1"}
  local group = {"768", "1024", "1536"}


  -- generate transforms
  t = {}
  for h,a in pairs(auth) do
    for i,e in pairs(encryption) do
      for j,h in pairs(hash) do
        for k,g in pairs(group) do
          table.insert(t, { ['auth'] = a, ['encryption'] = e, ['hash'] = h, ['group'] = g});
        end
      end
    end
  end


  -- try aggressive mode (diffie hellman group 2)
  local diffie = 2
  stdnse.debug1("Sending Aggressive mode packet ...")
  packet = ike.request(port.number, port.protocol, 'Aggressive', t, diffie, 'vpngroup')
  version = ike.send_request(host, port, packet)
  if version.success then
    return version
  end
  stdnse.debug1("Aggressive mode (dh 2) failed")

  -- try aggressive mode (diffie hellman group 1)
  diffie = 1
  stdnse.debug1("Sending Aggressive mode packet ...")
  packet = ike.request(port.number, port.protocol, 'Aggressive', t, diffie, 'vpngroup')
  version = ike.send_request(host, port, packet)
  if version.success then
    return version
  end
  stdnse.debug1("Aggressive mode (dh 1) failed")

  -- try aggressive mode (diffie hellman group 2, no id)
  -- some checkpoint devices respond to this
  local diffie = 2
  stdnse.debug1("Sending Aggressive mode packet ...")
  packet = ike.request(port.number, port.protocol, 'Aggressive', t, diffie, '')
  version = ike.send_request(host, port, packet)
  if version.success then
    return version
  end
  stdnse.debug1("Aggressive mode (dh 2, no id) failed")

  -- try main mode
  stdnse.debug1("Sending Main mode packet ...")
  packet = ike.request(port.number, port.protocol, 'Main', t, '')
  version = ike.send_request(host, port, packet)
  if version.success then
    return version
  end
  stdnse.debug1("Main mode failed")

  stdnse.debug1("Version detection not possible")
  return false
end


action = function( host, port )
  local ike_response = get_version(host, port)

  if ike_response then
    -- get_version only returns something if ike.send_request().success == true
    nmap.set_port_state(host, port, "open")

    -- Extra information found in the response. Kept for future reference.
    -- local mode = ike_response['mode']
    -- local vids = ike_response['vids']

    local info = ike_response['info']
    local set_version = false
    local out = stdnse.output_table()
    if info.vendor ~= nil then
      set_version = true
      if info.vendor.vendor then
        out.vendor_id = info.vendor.vendor
        port.version.product = info.vendor.vendor
      end
      if info.vendor.version then
        port.version.version = info.vendor.version
        out.vendor_id = (out.vendor_id or "") .. " " .. info.vendor.version
      end
      port.version.ostype  = info.vendor.ostype
      port.version.devicetype = info.vendor.devicetype
      table.insert(port.version.cpe, info.vendor.cpe)
    end

    local attribs = {}
    for i, attrib in ipairs(info.attribs) do
      attribs[i] = attrib.text
      if attrib.ostype or attrib.devicetype or attrib.cpe then
        set_version = true
        port.version.ostype = port.version.ostype or attrib.ostype
        port.version.devicetype = port.version.devicetype or attrib.devicetype
        table.insert(port.version.cpe, attrib.cpe)
      end
    end

    out.unmatched_ids = info.unmatched_ids
    if next(attribs) then
      out.attributes = attribs
    end

    if set_version then
      nmap.set_port_version(host, port, "hardmatched")
    end
    stdnse.debug1("Version: %s", port.version.product )
    return out
  end
end



