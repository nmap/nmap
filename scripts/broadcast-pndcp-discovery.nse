local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local packet = require "packet"
local datafiles = require "datafiles"
local coroutine = require "coroutine"
local string = require "string"
local ipOps = require "ipOps"
local target = require "target"

description = [[
Sends a DCP identify request to the Profinet DCP identification MAC address
01:0e:cf:00:00:00 and reports the resulsts.
The script displays information about the responding Profinet devices which
can contain the station name, vendor information and IP address configuration.

Please note that this script is not 100% feature complete as not all my
devices in my lab support all of the possible options.

In order to prevent flooding of your production network, you can set the timeout
value of this script to a higher value. The responseDelay field in the DCP
identify request frame will be calculated according to the specification. This
results in a spread of the answers the devices on the network will send out.

The script needs to be run as a privileged user, typically root.
]]

---
-- @usage
-- nmap -e <interface> --script=broadcast-pndcp-discovery
--
-- @output
-- Pre-scan script results:
-- | broadcast-pndcp-discovery:
-- |   00:30:de:40:29:c7 (Wago Kontakttechnik Gmbh):
-- |     Interface: enp11s0f0.20
-- |     IP:
-- |       IP Info: IP set
-- |       IP: 192.168.20.101
-- |       Netmask: 255.255.255.0
-- |       Gateway: 192.168.20.101
-- |     Device:
-- |       Name of Station: wago-750-375
-- |       Vendor ID: 0x011d
-- |       Device ID: 0x02ee
-- |       Device manufacturer: WAGO-I/O-SYSTEM 750/753
-- |       Device Role: 0x01 (IO-Device)
-- |   e0:dc:a0:62:57:83 (Siemens Industrial Automation Products Chengdu):
-- |     Interface: enp11s0f0.20
-- |     IP:
-- |       IP Info: IP set
-- |       IP: 192.168.20.100
-- |       Netmask: 255.255.255.0
-- |       Gateway: 0.0.0.0
-- |     Device:
-- |       Device manufacturer: S7-1200
-- |       Name of Station: plc
-- |       Vendor ID: 0x002a
-- |       Device ID: 0x010d
-- |       Device Role: 0x02 (IO-Controller)
-- |       Device Instance High: 0x00
-- |       Device Instance Low: 0x64
-- |   00:01:05:3c:94:16 (Beckhoff Automation GmbH):
-- |     Interface: enp11s0f0.20
-- |     IP:
-- |       IP Info: IP set
-- |       IP: 192.168.20.102
-- |       Netmask: 255.255.255.0
-- |       Gateway: 192.168.20.102
-- |     Device:
-- |       Vendor ID: 0x0120
-- |       Device ID: 0x0021
-- |       Device manufacturer: TwinCAT Profinet I/O
-- |       Name of Station: cx5140
-- |       Device Instance High: 0x00
-- |       Device Instance Low: 0x00
-- |       Device Role: 0x01 (IO-Device)
-- |       OEM Vendor ID: 0x0120
-- |_      OEM Device ID: 0x0021
--

author = "Andreas Galauner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "broadcast"}

prerule = function()
  if ( not(nmap.is_privileged()) ) then
    stdnse.verbose1("not running due to lack of privileges.")
    return false
  end
  return true
end

local ETHER_TYPE_8021Q = 0x8100

local PNDCP_OPTION_IP                         = 0x01
local PNDCP_OPTION_DEVICE                     = 0x02
local PNDCP_OPTION_DHCP                       = 0x03
-- NOTE: The following two options are used to perform actions in
-- the device using a Set request, we don't do that
-- local PNDCP_OPTION_CONTROL                    = 0x05
-- local PNDCP_OPTION_DEVICEINITIATIVE           = 0x06

local PNDCP_SUBOPTION_IP_MAC                  = 0x01
local PNDCP_SUBOPTION_IP_IP                   = 0x02

-- DIN/EN 61158-5-10 6.3.1.3.1 (IP Info)
local PNDCP_SUBOPTION_IP_IP_IPINFO_NOTSET           = 0x00
local PNDCP_SUBOPTION_IP_IP_IPINFO_SET              = 0x01
local PNDCP_SUBOPTION_IP_IP_IPINFO_SETDHCP          = 0x02
local PNDCP_SUBOPTION_IP_IP_IPINFO_NOTSET_CONFLICT  = 0x80
local PNDCP_SUBOPTION_IP_IP_IPINFO_SET_CONFLICT     = 0x81
local PNDCP_SUBOPTION_IP_IP_IPINFO_SETDHCP_CONFLICT = 0x82

local PNDCP_SUBOPTION_DEVICE_MANUF            = 0x01
local PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION    = 0x02
local PNDCP_SUBOPTION_DEVICE_DEV_ID           = 0x03
local PNDCP_SUBOPTION_DEVICE_DEV_ROLE         = 0x04
local PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS      = 0x05
local PNDCP_SUBOPTION_DEVICE_ALIAS_NAME       = 0x06
local PNDCP_SUBOPTION_DEVICE_DEV_INSTANCE     = 0x07
local PNDCP_SUBOPTION_DEVICE_OEM_DEV_ID       = 0x08

local PNDCP_DEVICE_ROLES = {
  [0x01] = "IO-Device",
  [0x02] = "IO-Controller",
  [0x04] = "IO-Multidevice",
  [0x08] = "PN-Supervisor",
}

local PNDCP_IP_INFO = {
  [PNDCP_SUBOPTION_IP_IP_IPINFO_NOTSET] = "No IP set",
  [PNDCP_SUBOPTION_IP_IP_IPINFO_SET] = "IP set",
  [PNDCP_SUBOPTION_IP_IP_IPINFO_SETDHCP] = "IP set via DHCP",
  [PNDCP_SUBOPTION_IP_IP_IPINFO_NOTSET_CONFLICT] = "No IP set (address conflict detected)",
  [PNDCP_SUBOPTION_IP_IP_IPINFO_SET_CONFLICT] = "IP set (address conflict detected)",
  [PNDCP_SUBOPTION_IP_IP_IPINFO_SETDHCP_CONFLICT] = "IP set via DHCP (address conflict detected)",
}

-- Converts a 6 byte string into the familiar MAC address formatting
--
-- @param mac string containing the MAC address
-- @return formatted string suitable for printing
local get_mac_addr = function(mac)
  local status, mac_prefixes = datafiles.parse_mac_prefixes()
  if not status then
    mac_prefixes = {}
  end

  if mac:len() ~= 6 then
    return "Unknown"
  else
    local prefix = string.upper(string.format("%02x%02x%02x", mac:byte(1), mac:byte(2), mac:byte(3)))
    local manuf = mac_prefixes[prefix] or "Unknown"
    return string.format("%s (%s)", stdnse.format_mac(mac), manuf )
  end
end

-- Parses a DCP block in a DCP identify response
-- This function parses a single DCP block and returns the option, suboption, block length,
-- data and position where the next block should be parsed
--
-- @param suboption message the raw message to be parsed
-- @param suboption the position in the message where the parsing should start
-- @return the option, suboption, block length, data of the parsed block and position where the next block should be parsed
local parseBlock = function(message, pos)
  local option, suboption, blocklen
  local dcp_block_format = ">B B I2"

  if #message - pos + 1 < string.packsize(dcp_block_format) then
    return nil, "Message too short for DCP block"
  end

  option, suboption, blocklen, pos = string.unpack(dcp_block_format, message, pos)

  -- Sanity check if the message is long enough to contain the payload data of this DCP block
  if #message - pos + 1 < blocklen then
    return nil, "Message too short for payload data in DCP block"
  end

  local blockdata = string.sub(message, pos, pos + blocklen - 1)
  pos = pos + blocklen

  -- skip padding byte - blocks always need to be aligned to 2 bytes
  pos = pos + (pos + 1) % 2

  return option, suboption, blocklen, blockdata, pos
end

-- Parses a DCP IP block suboption in a DCP identify response
--
-- @param suboption type of the suboption
-- @param block the raw block data to parse
-- @param results A resulsts table to be filled with the parsed data
local pndcpParseIpBlock = function(suboption, block, results)
  stdnse.debug1("Parsing IP block: Suboption: %u, Data: %s", suboption, stdnse.tohex(block))

  -- FIXME: PNDCP_SUBOPTION_IP_MAC parsing is untested, none of my devices report this
  if suboption == PNDCP_SUBOPTION_IP_MAC then
    local dcp_suboption_ip_mac_format = ">xx c6"
    if #block >= string.packsize(dcp_suboption_ip_mac_format) then
      local macaddr = string.unpack(dcp_suboption_ip_mac_format, block)
      results["MAC address"] = get_mac_addr(macaddr)
    end

  elseif suboption == PNDCP_SUBOPTION_IP_IP then
    local dcp_suboption_ip_ip_format = ">I2 I4 I4 I4"
    if #block >= string.packsize(dcp_suboption_ip_ip_format) then
      local block_info, ip, netmask, gateway = string.unpack(dcp_suboption_ip_ip_format, block)
      ip = ipOps.fromdword(ip)

      results["IP Info"] = PNDCP_IP_INFO[block_info]
      results["IP"] = ip
      results["Netmask"] = ipOps.fromdword(netmask)
      results["Gateway"] = ipOps.fromdword(gateway)

      -- Add new target if desired and if IP address looks valid
      if target.ALLOW_NEW_TARGETS and ip ~= "0.0.0.0" then
        target.add(ip)
      end
    end
  end
end

-- Parses a DCP Device block suboption in a DCP identify response
--
-- @param suboption type of the suboption
-- @param block the raw block data to parse
-- @param results A resulsts table to be filled with the parsed data
local pndcpParseDeviceBlock = function(suboption, block, results)
  stdnse.debug1("Parsing device block: Suboption: %u, Data: %s", suboption, stdnse.tohex(block))

  if suboption == PNDCP_SUBOPTION_DEVICE_MANUF then
    results["Device manufacturer"] = string.sub(block, 3)

  elseif suboption == PNDCP_SUBOPTION_DEVICE_NAMEOFSTATION then
    results["Name of Station"] = string.sub(block, 3)

  elseif suboption == PNDCP_SUBOPTION_DEVICE_DEV_ID then
    local dcp_suboption_device_id_format = ">x x I2 I2"
    if #block >= string.packsize(dcp_suboption_device_id_format) then
      local vendor_id, device_id = string.unpack(dcp_suboption_device_id_format, block)
      results["Vendor ID"] = ("0x%04x"):format(vendor_id)
      results["Device ID"] = ("0x%04x"):format(device_id)
    end

  elseif suboption == PNDCP_SUBOPTION_DEVICE_DEV_ROLE then
    local dcp_suboption_device_role_format = ">x x B x"
    if #block >= string.packsize(dcp_suboption_device_role_format) then
      local device_role = string.unpack(dcp_suboption_device_role_format, block)

      local device_role_strings = {}
      if device_role == 0x00 then
        table.insert(device_role_strings, "None")
      end

      for flag, name in pairs(PNDCP_DEVICE_ROLES) do
        if device_role & flag ~= 0 then
          table.insert(device_role_strings, name)
        end
      end

      results["Device Role"] = ("0x%02x (%s)"):format(device_role, table.concat(device_role_strings, ", "))
    end

  -- NOTE: Contains a list what options/suboptions the device supports,
  -- no need to parse this explicitly, I think
  elseif suboption == PNDCP_SUBOPTION_DEVICE_DEV_OPTIONS then
    local dcp_suboption_device_id_format = ">x x I2 I2"
    if #block >= string.packsize(dcp_suboption_device_id_format) then
      local vendor_id, device_id = string.unpack(dcp_suboption_device_id_format, block)
      results["Vendor ID"] = ("0x%04x"):format(vendor_id)
      results["Device ID"] = ("0x%04x"):format(device_id)
    end

  elseif suboption == PNDCP_SUBOPTION_DEVICE_ALIAS_NAME then
    results["Alias Name"] = string.sub(block, 3)

  elseif suboption == PNDCP_SUBOPTION_DEVICE_DEV_INSTANCE then
    local dcp_suboption_device_instance_format = ">x x B B"
    if #block >= string.packsize(dcp_suboption_device_instance_format) then
      local instance_high, instance_low = string.unpack(dcp_suboption_device_instance_format, block)
      results["Device Instance High"] = ("0x%02x"):format(instance_high)
      results["Device Instance Low"] = ("0x%02x"):format(instance_low)
    end

  elseif suboption == PNDCP_SUBOPTION_DEVICE_OEM_DEV_ID then
    local dcp_suboption_oem_device_id_format = ">x x I2 I2"
    if #block >= string.packsize(dcp_suboption_oem_device_id_format) then
      local oem_vendor_id, oem_device_id = string.unpack(dcp_suboption_oem_device_id_format, block)
      results["OEM Vendor ID"] = ("0x%04x"):format(oem_vendor_id)
      results["OEM Device ID"] = ("0x%04x"):format(oem_device_id)
    end

  else
    local unparsed = results["Unknown suboptions"] or {}
    unparsed[#unparsed+1] = suboption
    results["Unparsed suboptions"] = unparsed
  end
end

-- FIXME: believe it or not, but none of my devices support DHCP, so I can't test this
-- -- Parses a DCP DHCP block suboption in a DCP identify response
-- --
-- -- @param suboption type of the suboption
-- -- @param block the raw block data to parse
-- -- @param results A resulsts table to be filled with the parsed data
-- local pndcpParseDhcpBlock = function(suboption, block, results)
-- end

-- Listens for Profinet DCP Identify response packets.
-- @param interface Interface to listen on.
-- @param timeout Amount of time to listen for.
-- @param responses table to put valid responses into.
local pndcpListener = function(interface, timeout, responses)
  local listening = nmap.condvar(stdnse.base())
  local results = nmap.condvar(responses)
  local start = nmap.clock_ms()
  local listener = nmap.new_socket()
  local status, l2data, l3data, _
  listener:set_timeout(100)
  listener:pcap_open(interface.device, 1500, false, 'ether proto 0x8892 or (vlan and ether proto 0x8892)')

  stdnse.debug1("Listener started")

  -- Signal the main thread that we are started
  listening "signal"

  while (nmap.clock_ms() - start) < timeout do
    status, _, l2data, l3data = listener:pcap_receive()
    if status then
      local f = packet.Frame:new(l2data)

      -- check ethertype in l2data to see if the DCP frame is VLAN tagged
      -- if that's the case, drop the VLAN header from the l3data
      local dcp_frame
      if f.ether_type == ETHER_TYPE_8021Q then
        dcp_frame = string.sub(l3data, 5)
      else
        dcp_frame = l3data
      end

      -- parse the DCP frame
      local dcp_header_format = ">I2 B B I4 x x I2"
      if #dcp_frame >= string.packsize(dcp_header_format) then
        local frame_id, service_id, service_type, xid, dcp_datalen, pos = string.unpack(dcp_header_format, dcp_frame)

        -- Profinet DCP frames need to have an appropriate Frame ID
        if frame_id >= 0xfefc and frame_id <= 0xfeff then
          stdnse.debug1("Received DCP frame - Service ID: %u, Service Type: %u, XID: %u, Datalen: %u", service_id, service_type, xid, dcp_datalen)

          -- check if the Profinet Frame ID is 0xfeff = PN DCP Identify response
          -- Service ID needs to be 5 = Identify
          -- Service Type needs to be 1 = Response Success
          if frame_id == 0xfeff and service_id == 5 and service_type == 1 then
            stdnse.debug1("DCP Frame seems to be an Identify Response Success")

            local identify_response = stdnse.output_table()
            identify_response.Interface = interface.device

            identify_response.IP = stdnse.output_table()
            identify_response.Device = stdnse.output_table()
            -- FIXME: believe it or not, but none of my devices support DHCP, so I can't test this
            --identify_response.DHCP = stdnse.output_table()

            while pos < #dcp_frame do
              local option, suboption, blocklen, blockdata
              local block_pos = pos

              option, suboption, blocklen, blockdata, pos = parseBlock(dcp_frame, block_pos)

              if not option then
                stdnse.debug1("Error while parsing DCP blocks: %s", suboption)
                break
              end

              stdnse.debug1("Parsed DCP block info: Postion: %u, Option: %u, Suboption: %u, Blocklen: %u, Data: %s, Next position: %u", block_pos, option, suboption, blocklen, stdnse.tohex(blockdata), pos)

              if option == PNDCP_OPTION_IP then
                pndcpParseIpBlock(suboption, blockdata, identify_response.IP)

              elseif option == PNDCP_OPTION_DEVICE then
                pndcpParseDeviceBlock(suboption, blockdata, identify_response.Device)

              elseif option == PNDCP_OPTION_DHCP then
                -- FIXME: believe it or not, but none of my devices support DHCP, so I can't test this
                --pndcpParseDhcpBlock(suboption, blockdata, identify_response.DHCP)

              else
                stdnse.debug1("Encountered unknown DCP block: Postion: %u, Option: %u, Suboption: %u, Blocklen: %u, Data: %s, Next position: %u", block_pos, option, suboption, blocklen, stdnse.tohex(blockdata), pos)
              end

            end

            responses[get_mac_addr(f.mac_src)] = identify_response
          end
        end
      end
    end
  end

  -- Signal the main thread that we are done here
  results "signal"
end

-- Sends a Profinet DCP identify request.
-- @param interface Network interface to send on.
local pndcpIdentify = function(interface, responseDelay)
  local sock = nmap.new_dnet()
  stdnse.debug1("Opening ethernet interface %s", interface.device)

  local status = sock:ethernet_open(interface.device)
  if ( not(status) ) then
    fail("Unable to open raw sopcket on %s", interface.device)
    return
  end

  -- Build DCP probe
  local pn_dcp_identify = string.pack(">I2 B B I4 I2 I2 B B I2",
    0xfefe,     -- Frame ID
    0x05,       -- Service ID: 5 = Identify
    0x00,       -- Service Type: 0 = Request
    0x00000001, -- Xid (transaction ID): 1
    responseDelay, -- Response delay
    0x0004,     -- DCP Data length (length of following data)

    0xff,       -- Option: 0xff = all
    0xff,       -- Suboption: 0xff = all
    0x0000      -- Length of following block data: 0
  )

  -- Build probe ethernet frame
  local probe = packet.Frame:new()
  probe.mac_src = interface.mac
  probe.mac_dst = packet.mactobin("01:0e:cf:00:00:00")
  probe.ether_type = string.pack(">I2", 0x8892)
  probe.buf = pn_dcp_identify
  probe:build_ether_frame()

  sock:ethernet_send(probe.frame_buf)
  sock:ethernet_close()
end


action = function(host, port)
  local responses, interfaces, lthreads = {}, {}, {}

  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  local interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface")

  -- Calculate response delay values as per spec
  -- See DIN/EN 61158-6-10 chapter 4.3.1.3.5
  timeout = (timeout or 1)
  local responseDelay = (timeout - 1) * 100

  -- clamp the response delay to allowed values per spec
  if responseDelay <= 0 then
    responseDelay = 1
  elseif responseDelay > 6400 then
    responseDelay = 6400
  end

  -- Check the interface
  interface = interface or nmap.get_interface()
  if interface then
    -- Get the interface information
    interface = nmap.get_interface_info(interface)
    if not interface then
      return stdnse.format_output(false, ("Failed to retrieve %s interface information."):format(interface))
    end
    interfaces = {interface}
    stdnse.debug1("Will use %s interface.", interface.shortname)
  else
    local ifacelist = nmap.list_interfaces()
    for _, iface in ipairs(ifacelist) do

      -- Match all ethernet interfaces
      -- NOTE: The call to `nmap.get_interface_info` makes sure that `ethernet_open`
      -- won't error out. `ethernet_open` calls the C-equivalent of this function
      -- internally and raises an error when it fails. This happens for example
      -- when an interface is up but has no carrier. I didn't find another way
      -- to check for this condition.
      if iface.up == "up" and iface.link == "ethernet" and nmap.get_interface_info(iface.shortname) then
        stdnse.debug1("Will use %s interface.", iface.shortname)
        table.insert(interfaces, iface)
      end
    end
  end

  -- Iterate over interfaces, start listening threads and send identify requests out
  for _, interface in pairs(interfaces) do
    -- Start the listener thread
    local co = stdnse.new_thread(pndcpListener, interface, timeout * 1000, responses)

    -- Wait for the listener thread signal it's ready
    local listening = nmap.condvar(co)
    listening "wait"

    -- Make sure we got woken by a ready listener, not because the listener thread crashed
    -- then send the identify request out
    if coroutine.status(co) ~= "dead" then
      pndcpIdentify(interface, responseDelay)
      lthreads[co] = true
    end
  end

  local results = nmap.condvar(responses)
  -- Wait for the listening threads to finish
  repeat
    for thread in pairs(lthreads) do
      if coroutine.status(thread) == "dead" then lthreads[thread] = nil end
    end
    if ( next(lthreads) ) then
      results "wait"
    end
  until next(lthreads) == nil;

  return responses
end
