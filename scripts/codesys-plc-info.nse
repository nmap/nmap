local shortport = require "shortport"
local stdnse = require "stdnse"
local codesys3 = require "codesys3"

description = [[
Identifies a Codesys V3 PLC on the LAN by sending a Codesys V3 Device Discovery request.
]]

---
-- @usage
-- nmap --script codesys-plc-info
--
-- @output
-- 1740/udp open|filtered encore
-- | codesys-plc-info: 
-- |   192.168.20.12: 
-- |     deviceAddress: 192.168.20.12
-- |     targetVendor: WAGO
-- |     targetName: WAGO 750-8215 PFC200 G2 4ETH CAN USB
-- |     deviceName: PFC200V3-4538EF
-- |     targetID: 0x1006120b
-- |     targetType: 0x1000
-- |_    targetVersion: 5.15.4.0
--
-- @args codesys-plc-info.timeout timespec defining how long to wait for a
--       response. (default 3s)

--
-- Version 0.1
-- Created 23/06/2021 - v0.1 - created by Andreas Galauner <agalauner@rapid7.com>
--

author = "Andreas Galauner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
portrule = shortport.portnumber({1740,1741,1742,1743}, "udp")

--- Returns the network interface used to send packets to a target host.
-- @param target host to which the interface is used.
-- @return interface Network interface used for target host.
local getInterface = function(target)
  -- First, create dummy UDP connection to get interface
  local sock = nmap.new_socket()
  local status, err = sock:connect(target, "12345", "udp")
  if not status then
    stdnse.verbose1("%s", err)
    return
  end
  local status, address, _, _, _ = sock:get_info()
  if not status then
    stdnse.verbose1("%s", err)
    return
  end
  for _, interface in pairs(nmap.list_interfaces()) do
    if interface.address == address then
      return interface
    end
  end
end

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  timeout = (timeout or 3) * 1000

  -- Try to determine the interface we can reach our target with. We need this for the name service request
  local iface = getInterface(host)
  if not iface then
    return fail(string.format("Couldn't get interface for target IP address %s", host))
  end
  
  local socket = nmap.new_socket("udp")
  socket:set_timeout(timeout)

  -- Bind to source port 1740, because we are using port index 0 in the name service request
  -- We need to send the packet from this source port, otherwise the PLC doesn't seem to reply
  local status, err = socket:bind(nil, 1740)
  if not status then
    return fail(string.format("Bind failed: %s", err))
  end

  -- Generate the name service request to send and send it out
  local cs = codesys3.CodesysV3.NameServiceRequest:new(0, iface.address, iface.netmask)
  local packet = tostring(cs)

  local status, err = socket:sendto(host, port, packet)
  if not status then
    return fail(string.format("Sendto failed: %s", err))
  end

  -- Receive the responses from the PLCs and parse them
  local result = {}
  repeat
    local data
    status, data = socket:receive()
    if ( status ) then
      local _, _, _, rhost, _ = socket:get_info()
      local status, response = codesys3.CodesysV3.NameServiceResponse:new(data)
      if ( status ) then
        response.ip = rhost
        table.insert(result, response)
      end
    end
  until( not(status) )

  socket:close()

  -- Display the results
  local response = stdnse.output_table()

  for _, r in ipairs(result) do
    local out = stdnse.output_table()

    out["deviceAddress"] = r.ip
    out["targetVendor"] = r.vendorName
    out["targetName"] = r.deviceName
    out["deviceName"] = r.nodeName
    out["targetID"] = string.format("0x%x", r.targetId)
    out["targetType"] = string.format("0x%x", r.targetType)
    out["targetVersion"] = codesys3.version_to_str(r.targetVersion)

    response[r.ip] = out
  end

  return response
end
