local coroutine = require "coroutine"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local packet = require "packet"
local ipOps  = require "ipOps"


description = [[
Sends a multicast PROFINET DCP Identify All message and prints the responses.

Reference:
* https://profinetuniversity.com/naming-addressing/profinet-dcp/
]]

---@output
--multicast-profinet-discovery:
--|   devices:
--|
--|       ip_addr: 10.253.81.37
--|       mac_addr: 00:0E:8C:C9:41:15
--|       subnetmask: 255.255.255.0
--|       vendorId: 002A
--|       deviceId: 0105
--|       vendorvalue: S7-300
--|       deviceRole: 00
--|       nameOfStation: pn-io
--|
--|       ip_addr: 10.253.81.26
--|       mac_addr: AC:64:17:2C:C9:46
--|       subnetmask: 255.255.255.0
--|       vendorId: 002A
--|       deviceId: 0404
--|       vendorvalue: SIMATIC-HMI
--|       deviceRole: 00
--|_      nameOfStation: xd134xbvisu.profinetxaschnittstellexb103b2

author = "Stefan Eiwanger, DINA-community"
license = "BSD-2-Clause Plus Patent License. For further details, please refer https://spdx.org/licenses/BSD-2-Clause-Patent.html"
categories = {"discovery","info", "safe"}

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
  local pn_dcp_size = 46	-- min size of ethernet packet
  local eth_packet
  local src_mac = iface.mac


  local dest_mac = packet.mactobin(pn_dcp_multicast)
  local eth_proto = string.pack("I2", 0x9288)

  -- pn-dcp request frame : [FrameID | ServiceID | ServiceType | Xid | ResponseDelay | DCPDataLength | Option | Suboption ]
  local blockData = string.pack("I2BBI4I2I2BB", 0xfefe, 0x05,0x00,0x10000010, 0x0400, 0x0400,0xff, 0xff)
  local padbyte = string.pack("B", 0x00)

  -- build the packet
  eth_packet = dest_mac .. src_mac .. eth_proto .. blockData
  local length = string.len(eth_packet)

  -- fill the rest of the packet with 0x00 till ethernet min size is reached
  local padding = string.rep(padbyte, (pn_dcp_size-length))
  eth_packet = eth_packet .. padding
  return eth_packet
end



-- extract data from incoming dcp packets and store them into a table
--@param eth_data ethernet part of the recieved packet
--@param pn_data profinet part of the recieved packet == ethernet packetload
--@return device table with all extraced data from the pn_dcp
parse_pndcp = function(eth_data, pn_data)
  stdnse.debug(1, "Start parsing of answer")
  local pos = 7	-- start after the destination mac address (host)
  local deviceMacAddress
  local deviceRoleInterpretation = {}
  deviceRoleInterpretation [0] = "PNIO Device"
  deviceRoleInterpretation [1] = "PNIO Controller"
  deviceRoleInterpretation [2] = "PNIO Multidevice"
  deviceRoleInterpretation [3] = "PNIO Supervisor"

  -- extract device mac address
  local mac
  mac, pos = string.unpack("c6", eth_data, pos)
  deviceMacAddress = stdnse.format_mac(mac)

  stdnse.debug(1, "Device MAC address: %s", deviceMacAddress)

  -- check if the packet is a request
  local serviceType
  serviceType= string.unpack("B", pn_data, 4)
  stdnse.debug(1, "Servicetype %x", serviceType)
  if (serviceType == 0) then return end


  -- start extrating data from pn_dcp_response -- start with 1
  pos = 11

  local gesDCPDataLength = ""
  gesDCPDataLength, pos = string.unpack(">I2", pn_data, pos)
  stdnse.debug(1,"DCP Datalength of full packet: %d", gesDCPDataLength)

  -- extract data from DCP block
  local option, suboption
  local IP, deviceVendorValue, deviceRole, deviceId, nameofstation, dcpDatalength, subnetmask, standardGateway, vendorId = "", "", "", "", "", "", "", "", ""
  stdnse.debug(1, "Start extracting data from DCP block")
  while(pos < gesDCPDataLength) do

    --  Option IP, suboption IP
    option, suboption, pos = string.unpack("BB", pn_data, pos)

    local dcpDataLength, _
    if option == 1 then -- IP
      if(suboption == 2) then
        stdnse.debug(1, "Option IP, suboption IP")

        --  DCP block length
        dcpDataLength, pos = string.unpack(">I2", pn_data, pos)
        --stdnse.debug(1,"* DCP Datalength of IP/IP %d", dcpDataLength)

        --  block info
        _, pos = string.unpack(">I2", pn_data, pos)

        local dword = ""
        --  IP
        dword, pos = string.unpack(">I4", pn_data, pos)
        IP = ipOps.fromdword(dword)
        stdnse.debug(1, "* IP address: %s", IP)

        --  subnetmask
        dword, pos = string.unpack(">I4", pn_data, pos)
        subnetmask = ipOps.fromdword(dword)
        stdnse.debug(1, "* Subnetmask: %s", subnetmask)

        --  standard gateway
        dword, pos = string.unpack(">I4", pn_data, pos)
        standardGateway = ipOps.fromdword(dword)
        stdnse.debug(1, "* Default gateway: %s", standardGateway)

        --[[if dcpDataLength%2 ~= 0 then
        pos = pos +1 -- add padding
        end
        --]]
      else
        stdnse.debug(1, "Option IP, suboption something else: %d", suboption)

        --  DCP block length
        dcpDataLength, pos = string.unpack(">I2", pn_data, pos)
        --stdnse.debug(1, "* DCP datalength of IP/else: %d", dcpDataLength)

        if dcpDataLength%2 ~= 0 then
          pos = pos +1 -- add padding
          stdnse.debug(1, "dcpDatalength was odd, add padding +1 to pos")
        end

      end
    elseif option == 2 then -- device properties
      if suboption == 1 then-- deviceVendorValue  manufacturer specific option
        stdnse.debug(1, "Option device properties, suboption manufacturer specific")

        --  DCP block length
        dcpDataLength, pos = string.unpack(">I2", pn_data, pos)
        --stdnse.debug(1,"* DCP Datalength of device properties/manufacturer specific %d", dcpDataLength)

        --  block info
        _, pos = string.unpack(">I2", pn_data, pos)

        --  device vendor
        deviceVendorValue, pos = string.unpack("c" .. (dcpDataLength - 2) ,pn_data, pos)
        stdnse.debug(1, "* Device Vendor: %s", deviceVendorValue)

        if dcpDataLength%2 ~= 0 then
          stdnse.debug(1, "dcpDatalength was odd, add padding +1 to pos")
          pos = pos +1 -- add padding
        end

      elseif suboption == 2 then -- nameofstation
        stdnse.debug(1, "Option device properties, suboption name of station")

        --  DCP block length
        dcpDataLength, pos = string.unpack(">I2", pn_data, pos)
        --stdnse.debug(1,"* DCP Datalength of device properties/name of station %d", dcpDataLength)

        --  block info
        _, pos = string.unpack(">I2", pn_data, pos)

        --  name of station
        nameofstation, pos = string.unpack("c" .. (dcpDataLength - 2) ,pn_data, pos)
        stdnse.debug(1, "* Name Of Station: %s", nameofstation)

        if dcpDataLength%2 ~= 0 then
          stdnse.debug(1, "dcpDatalength was odd, add padding +1 to pos")
          pos = pos +1 -- add padding
        end

      elseif suboption == 3 then -- device id, vendor Id
        stdnse.debug(1, "Option device properties, suboption device ID")

        --  DCP block length
        dcpDataLength, pos = string.unpack(">I2", pn_data, pos)
        --stdnse.debug(1,"* DCP Datalength of device properties/device ID %d", dcpDataLength)

        --  block info
        _, pos = string.unpack(">I2", pn_data, pos)

        --  vendor ID
        local tmpvendorId, tmpdeviceId = "", ""
        tmpvendorId, pos = string.unpack("c2", pn_data, pos)
        vendorId = stdnse.tohex(tmpvendorId)
        vendorId = "0x" .. vendorId
        stdnse.debug(1, "* Vendor ID: %s", vendorId)

        --  device ID
        tmpdeviceId, pos = string.unpack("c2", pn_data, pos)
        deviceId = stdnse.tohex(tmpdeviceId)
        deviceId = "0x" .. deviceId
        stdnse.debug(1, "* Device ID: %s", deviceId)

      elseif suboption == 4 then -- device role
        stdnse.debug(1, "Option device properties, suboption device role")

        --  DCP block length
        dcpDataLength, pos = string.unpack(">I2", pn_data, pos)
        --stdnse.debug(1,"* DCP Datalength of device properties/device role %d", dcpDataLength)

        --  block info
        _, pos = string.unpack(">I2", pn_data, pos)

        --  device role
        deviceRole, pos = string.unpack("B", pn_data, pos)
        deviceRole = deviceRoleInterpretation[deviceRole] .. ' 0x0' .. deviceRole
        stdnse.debug(1, "* Device Role: %s", deviceRole)

        --  reserved
        _, pos = string.unpack("B", pn_data, pos)
      else
        stdnse.debug(1, "Option device properties, suboption something else: %d", suboption)

        --  DCP block length
        dcpDataLength, pos = string.unpack(">I2", pn_data, pos)
        --stdnse.debug(1,"* DCP Datalength of device properties/device role %d", dcpDataLength)

        pos = pos + dcpDataLength
        if dcpDataLength%2 ~= 0 then
          stdnse.debug(2, "dcpDatalength was odd, add padding +1 to pos")
          pos = pos +1 -- add padding
        end

      end
    else
      stdnse.debug(1, "Option something else: %d", option)

      --  DCP block length
      dcpDataLength, pos = string.unpack(">I2", pn_data, pos)
      --stdnse.debug(1,"* DCP Datalength of device properties/device role %d", dcpDataLength)

      pos = pos + dcpDataLength
      if dcpDataLength%2 ~= 0 then
        stdnse.debug(1, "dcpDatalength was odd, add padding +1 to pos")
        pos = pos +1 -- add padding
      end

    end -- close if

  end -- close while

  -- store data into table
  local device = stdnse.output_table()
  device.ip_addr = IP
  device.mac_addr = deviceMacAddress
  device.subnetmask = subnetmask
  device.vendorId = vendorId
  device.deviceId = deviceId
  device.vendorvalue = deviceVendorValue
  device.deviceRole = deviceRole
  device.nameOfStation = nameofstation

  stdnse.debug(1, "End of parsing\n")

  return device
end

-- get all possible interfaces
--@param link  type of interface e.g. "ethernet"
--@param up status of the interface
--@return result table with all interfaces which match the given requirements
getInterfaces = function(link, up)
  if( not(nmap.list_interfaces) ) then return end
  local interfaces, err = nmap.list_interfaces()
  local result = {}

  if ( not(err) ) then
    for _, iface in ipairs(interfaces) do
      if ( iface.link == link and
          iface.up == up and
          iface.mac ) then
        if #result == 0 then
          table.insert(result, iface)
        else
          local exists = false
          for _, intface in ipairs(result) do
            if intface.mac == iface.mac then
              exists = true
            end
          end
          if not exists then
            table.insert(result, iface)
          end
        end
      end
    end
  end
  return result
end

-- helpfunction for thread call
--@param iface interface table
--@param pn_dcp ethernet dcp packet to send
--@param devices table for results
--@return devices, table with devices which answered to the dcp identify all call
discoverThread = function(iface, pn_dcp, devices)
  local condvar = nmap.condvar(devices)
  local dnet = nmap.new_dnet()
  local pcap_s = nmap.new_socket()
  pcap_s:set_timeout(2000)
  dnet:ethernet_open(iface.device)
  pcap_s:pcap_open(iface.device, 256, false, "ether proto 0x8892")

  local status, ethData, length, pn_data

  dnet:ethernet_send(pn_dcp)	-- send the frame

  status = true
  while status do
    status, length, ethData, pn_data = pcap_s:pcap_receive()

    if(status) then
      devices[#devices + 1] = parse_pndcp(ethData, pn_data)
    end
  end
  dnet:ethernet_close(iface.device);	-- close the sender



  pcap_s:close(iface.device)
  condvar "signal"
  return devices
end

-- main fuction
--@return 0 if no devices were found
--@return output_tab table for nmap to show the gathered information
action = function()
  local interface_e = nmap.get_interface()
  local interfaces = {}

  local output_tab = stdnse.output_table()
  output_tab.devices = {}

  -- check interface parameter

  local dnet = nmap.new_dnet()
  local pcap_s = nmap.new_socket()
  pcap_s:set_timeout(4000)


  if(interface_e) then -- interface supplied with -e
    local iface = nmap.get_interface_info(interface_e)
    if not (iface and iface.link == 'ethernet') then
      stdnse.debug(1, "%s not supported with %s", iface, SCRIPT_NAME)
      return false
    end
    table.insert(interfaces, iface)
  else -- discover interfaces
    interfaces = getInterfaces("ethernet", "up")
  end

  -- check if at least one interface is available
  if #interfaces == 0 then
    print("No interfaces found")
    return false
  end

  -- get the frame we want to send


  local threads = {}

  local condvar = nmap.condvar(output_tab.devices)


  for _, iface in ipairs(interfaces) do
    local pn_dcp = build_eth_frame(iface)
    --print(iface.device)

    local co = stdnse.new_thread(discoverThread, iface, pn_dcp, output_tab.devices)
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
  if #output_tab.devices == 0 then
    print("No profinet devices in the subnet")
    return 0
  end


  return output_tab

end
