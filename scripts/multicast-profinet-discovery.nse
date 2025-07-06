local coroutine = require "coroutine"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"
local packet = require "packet"
local ipOps  = require "ipOps"

description = [[
Sends a multicast PROFINET DCP Identify All message and prints the responses.

Reference:
* https://profinetuniversity.com/naming-addressing/profinet-dcp/
]]

---@output
--multicast-profinet-discovery:
--|   00:0E:8C:C9:41:15:
--|       Interface: eth0
--|       IP:
--|         ip_info: IP set
--|         ip_addr: 10.253.81.37
--|         subnetmask: 255.255.255.0
--|         gateway: 10.253.81.1
--|       Device:
--|         vendorId: 002A
--|         deviceId: 0105
--|         vendorValue: S7-300
--|         deviceRole: 0x00 (None)
--|         nameOfStation: pn-io
--|         instance: low: 0, high: 100
--|
--|   AC:64:17:2C:C9:46:
--|       Interface: eth0
--|       IP:
--|         ip_info: IP set
--|         ip_addr: 10.253.81.26
--|         subnetmask: 255.255.255.0
--|         gateway: 10.253.81.1
--|       Device:
--|         vendorId: 002A
--|         deviceId: 0404
--|         vendorValue: SIMATIC-HMI
--|         deviceRole: 0x01 (IO-Device)
--|_        nameOfStation: xd134xbvisu.profinetxaschnittstellexb103b2

author = {"Stefan Eiwanger, DINA-community", "Andreas Galauner"}
license = "BSD-2-Clause Plus Patent License. For further details, please refer https://spdx.org/licenses/BSD-2-Clause-Patent.html"
categories = {"discovery","info", "safe", "broadcast"}

prerule = function()
  if not nmap.is_privileged() then
    stdnse.debug(1, "Nmap is NOT running as privileged.")
    return false
  end

  return true
end

local pn_dcp_multicast = "01:0e:cf:00:00:00"


-- generate raw profinet identify all message
--@param iface interface table containing mac address
--@return eth_packet ethernet packet for sending over socket
build_eth_frame= function(iface)

  stdnse.debug(1, "Build packet for dcp identify all call.")
  stdnse.debug(1, "Interface: " .. iface.device)
  local eth_packet = packet.Frame:new()
  eth_packet.mac_src = iface.mac


  eth_packet.mac_dst = packet.mactobin(pn_dcp_multicast)
  eth_packet.ether_type = packet.ETHER_TYPE_PROFINET

  -- pn-dcp request frame : [FrameID | ServiceID | ServiceType | Xid | ResponseDelay | DCPDataLength | Option | Suboption ]
  eth_packet.buf = string.pack(">I2BBI4I2I2BBI2",
    0xfefe,     -- Frame ID
    0x05,       -- Service ID: 5 = Identify
    0x00,       -- Service Type: 0 = Request
    math.random(0xffffffff), -- Xid (transaction ID)
    math.random(9),     -- Response delay * 10ms
    0x0004,     -- DCP Data length (length of following data)
    0xff,       -- Option: 0xff = all
    0xff,       -- Suboption: 0xff = all
    0x0000      -- Length of following block data: 0
    )

  -- build the packet
  eth_packet:build_ether_frame()

  -- fill the rest of the packet with 0x00 till ethernet min size is reached
  return eth_packet.frame_buf
end


local PNDCP_IP_INFO = {
  [0] = "No IP set",
  [1] = "IP set",
  [2] = "IP set via DHCP",
}

local PNDCP_DEVICE_ROLES = {
  [0x01] = "IO-Device",
  [0x02] = "IO-Controller",
  [0x04] = "IO-Multidevice",
  [0x08] = "PN-Supervisor",
}

local function parse_string (block)
  -- skip 2-byte block info
  return block:sub(3)
end

local function create_parser (parsefunc, label)
  return function (block, results)
    results[label] = parsefunc(block)
  end
end

local parser = {
  -- Option IP
  ['\x01\x01'] = function (block, results)
    local _, mac = string.unpack(">I2 c6")
    results.mac_addr = stdnse.format_mac(mac)
  end,
  ['\x01\x02'] = function (block, results)
    local block_info, ipdw, netdw, gwdw = string.unpack(">I2 I4 I4 I4", block)

    local ipinfo = PNDCP_IP_INFO[block_info & 0xf]
    if block_info & 0x80 > 0 then
      ipinfo = ipinfo .. " (conflict)"
    end
    results.ip_info = ipinfo

    if ipdw > 0 then
      results.ip_addr = ipOps.fromdword(ipdw)
    end
    if netdw > 0 then
      results.subnetmask = ipOps.fromdword(netdw)
    end
    if gwdw > 0 then
      results.gateway = ipOps.fromdword(gwdw)
    end
  end,
  -- device properties
  ['\x02\x01'] = function (block, results)
    results.vendorValue = block:sub(3)
  end,
  ['\x02\x02'] = function (block, results)
    results.nameOfStation = block:sub(3)
  end,
  ['\x02\x03'] = function (block, results)
    local vendorid, deviceid = string.unpack(">xx I2 I2", block)
    results.vendorId = ("0x%04x"):format(vendorid)
    results.deviceId = ("0x%04x"):format(deviceid)
  end,
  ['\x02\x04'] = function (block, results)
    local deviceRole = string.unpack(">xxBx", block)

    --  device role
    local device_role_strings = {}
    if deviceRole == 0x00 then
      table.insert(device_role_strings, "None")
    else
      for flag, name in pairs(PNDCP_DEVICE_ROLES) do
        if deviceRole & flag ~= 0 then
          table.insert(device_role_strings, name)
        end
      end
    end
    results.deviceRole = ("0x%02x (%s)"):format(deviceRole,
      table.concat(device_role_strings, ", "))
  end,
  --['\x02\x05'] device options?
  ['\x02\x06'] = function (block, results)
    results.alias = block:sub(3)
  end,
  ['\x02\x07'] = function (block, results)
    local low, high = string.unpack(">xx BB", block)
    results.instance = ("low: %d, high: %d"):format(low, high)
  end,
  ['\x02\x08'] = function (block, results)
    local vendorid, deviceid = string.unpack(">xx I2 I2", block)
    results.OEMvendorId = ("0x%04x"):format(vendorid)
    results.OEMdeviceId = ("0x%04x"):format(deviceid)
  end,
}

-- ensure any option can be used without crashing
setmetatable(parser, {
    __index = function(self, key)
      local option, suboption = string.byte(key, 1, 2)
      stdnse.debug(1, "Unknown option/suboption %d/%d", option, suboption)
      return function () end
    end,
  })

-- extract data from incoming dcp packets and store them into a table
--@param pn_data profinet part of the recieved packet == ethernet packetload
--@return device table with all extraced data from the pn_dcp
parse_pndcp = function(pn_data)
  stdnse.debug(1, "Start parsing of answer")

  -- check if the packet is a request
  local dcp_header_format = ">I2 B B xxxx xx xx" -- skip Xid, delay, length
  if #pn_data < dcp_header_format:packsize() then
    return nil
  end
  local frame_id, service_id, service_type, pos = string.unpack(dcp_header_format, pn_data)
  if frame_id ~= 0xfeff or service_id ~= 5 or service_type ~= 1 then
    return nil
  end

  -- extract data from DCP block
  local result = {}
  while(pos < #pn_data) do

    local option, block
    option, block, pos = string.unpack("!2 c2 >s2", pn_data, pos)
    parser[option](block, result)

  end -- close while

  return result
end


-- helpfunction for thread call
--@param iface interface table
--@param to_ms timeout in ms to wait for responses
--@param pn_dcp ethernet dcp packet to send
--@param devices table for results
--@return devices, table with devices which answered to the dcp identify all call
discoverThread = function(iface, to_ms, pn_dcp, devices)
  local condvar = nmap.condvar(devices)
  local dnet = nmap.new_dnet()
  local pcap_s = nmap.new_socket()
  pcap_s:set_timeout(100)
  dnet:ethernet_open(iface.device)
  pcap_s:pcap_open(iface.device, 256, false, ("ether proto 0x%04x"):format(packet.ETHER_TYPE_PROFINET))

  dnet:ethernet_send(pn_dcp)	-- send the frame
  dnet:ethernet_close();	-- close the sender

  local start = nmap.clock_ms()
  while (nmap.clock_ms() - start) < to_ms do
    local status, length, ethData, pn_data = pcap_s:pcap_receive()

    if(status) then
      local dev = parse_pndcp(pn_data)
      if dev then
        local out = stdnse.output_table()
        out.Interface = iface.device
        out.IP = stdnse.output_table()
        if dev.ip_addr then
          -- Add new target if desired
          target.add(dev.ip_addr)
          out.IP.ip_addr = dev.ip_addr
        end
        out.IP.ip_info = dev.ip_info
        out.IP.subnetmask = dev.subnetmask
        out.IP.gateway = dev.gateway
        out.Device = stdnse.output_table()
        out.Device.vendorId = dev.vendorId
        out.Device.deviceId = dev.deviceId
        out.Device.vendorValue = dev.vendorValue
        out.Device.deviceRole = dev.deviceRole
        out.Device.nameOfStation = dev.nameOfStation
        -- extract device mac address
        local mac = string.unpack("c6", ethData, 7)
        devices[stdnse.format_mac(mac)] = out
      end
    end
  end

  pcap_s:close(iface.device)
  condvar "signal"
  return devices
end

-- main fuction
--@return output_tab table for nmap to show the gathered information
action = function()

  local output_tab = stdnse.output_table()

  -- check interface parameter

  local macs = {}
  local filter_interfaces = function (iface)
    if iface.link == "ethernet" and iface.up == "up" and
      iface.mac and not macs[iface.mac] then
      macs[iface.mac] = true
      return iface
    end
  end
  local interfaces = stdnse.get_script_interfaces(filter_interfaces)

  -- check if at least one interface is available
  if #interfaces == 0 then
    print("No interfaces found")
    return
  end

  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  local to_ms = (timeout or 2) * 1000

  local threads = {}

  local condvar = nmap.condvar(output_tab)


  for _, iface in ipairs(interfaces) do
    local pn_dcp = build_eth_frame(iface)
    --print(iface.device)

    local co = stdnse.new_thread(discoverThread, iface, to_ms, pn_dcp, output_tab)
    threads[co] = true
  end

  -- wait for all threads to finish sniffing
  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then
        threads[thread] = nil
      end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil

  -- check the output if something is doubled there
  if #output_tab == 0 then
    print("No profinet devices in the subnet")
    return
  end


  return output_tab

end
