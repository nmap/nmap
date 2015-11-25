local nmap = require "nmap"
local coroutine = require "coroutine"
local stdnse = require "stdnse"
local table = require "table"
local bin = require "bin"
local bit = require "bit"
local packet = require "packet"
local ipOps = require "ipOps"
local string = require "string"
local target = require "target"

description = [[
Discovers KNX gateways by sending a KNX Search Request to the multicast address
224.0.23.12 including a UDP payload with destination port 3671. KNX gateways
will respond with a KNX Search Response including various information about the
gateway, such as KNX address and supported services.

Further information:
  * DIN EN 13321-2
  * http://www.knx.org/
]]

author = "Niklaus Schiess <nschiess@ernw.de>, Dominik Schneider <dschneider@ernw.de>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "broadcast"}

---
--@args timeout Max time to wait for a response. (default 3s)
--
--@usage
-- nmap --script knx-gateway-discover -e eth0
--
--@output
-- Pre-scan script results:
-- | knx-gateway-discover:
-- |   192.168.178.11:
-- |     Body:
-- |       HPAI:
-- |         Port: 3671
-- |       DIB_DEV_INFO:
-- |         KNX address: 15.15.255
-- |         Decive serial: 00ef2650065c
-- |         Multicast address: 0.0.0.0
-- |         Device MAC address: 00:05:26:50:06:5c
-- |         Device friendly name: IP-Viewer
-- |       DIB_SUPP_SVC_FAMILIES:
-- |         KNXnet/IP Core version 1
-- |         KNXnet/IP Device Management version 1
-- |         KNXnet/IP Tunnelling version 1
-- |_        KNXnet/IP Object Server version 1
--

prerule = function()
  if not nmap.is_privileged() then
    stdnse.verbose1("Not running due to lack of privileges.")
    return false
  end
  return true
end

local knxServiceFamilies = {
  [0x02]="KNXnet/IP Core",
  [0x03]="KNXnet/IP Device Management",
  [0x04]="KNXnet/IP Tunnelling",
  [0x05]="KNXnet/IP Routing",
  [0x06]="KNXnet/IP Remote Logging",
  [0x08]="KNXnet/IP Object Server",
  [0x07]="KNXnet/IP Remote Configuration and Diagnosis"
}

local knxDibDescriptionTypes = {
  [0x01]="Device Information",
  [0x02]="Supp_Svc_families",
  [0x03]="IP_Config",
  [0x04]="IP_Cur_Config",
  [0x05]="IP_Config"
}

local knxMediumTypes = {
  [0x01]="reserved",
  [0x02]="KNX TP1",
  [0x04]="KNX PL110",
  [0x08]="reserved",
  [0x10]="KNX RF",
  [0x20]="KNX IP"
}

--- Returns a raw knx search request
-- @param ip_address IP address of the sending host
-- @param port Port where gateways should respond to
local knxQuery = function(ip_address, port)
  return bin.pack(">C2S2C2IS",
    0x06, -- Header length
    0x10, -- Protocol version
    0x0201, -- Service type
    0x000e, -- Total length
    0x08, -- Structure length
    0x01, -- Host protocol
    ipOps.todword(ip_address),
    port
  )
end

--- Sends a knx search request
-- @param query KNX search request message
-- @param mcat Multicast destination address
-- @param port Port to sent to
local knxSend = function(query, mcast, mport)
  -- Multicast IP and UDP port
  local sock = nmap.new_socket()
  local status, err = sock:connect(mcast, mport, "udp")
  if not status then
    stdnse.debug1("%s", err)
    return
  end
  sock:send(query)
  sock:close()
end

-- Parse a KNX address from raw bytes
-- @param addr Unpacked 2 bytes
local parseKnxAddress = function(addr)
  local a = bit.rshift(bit.band(addr, 0xf000),12)
  local b = bit.rshift(bit.band(addr, 0x0f00), 8)
  local c = bit.band(addr, 0xff)
  return a..'.'..b..'.'..c
end

local fam_meta = {
  __tostring = function (self)
    return ("%s version %d"):format(
      knxServiceFamilies[self.service_id] or self.service_id,
      self.Version
      )
  end
}

--- Parse a Search Response
-- @param knxMessage Payload of captures UDP packet
local knxParseSearchResponse = function(ips, results, knxMessage)
  local _, knx_header_length =  bin.unpack('>C', knxMessage)
  local _, knx_protocol_version = bin.unpack('>C', knxMessage, _)
  local _, knx_service_type = bin.unpack('>S', knxMessage, _)
  local _, knx_total_length = bin.unpack('>S', knxMessage, _)

  if knx_header_length ~= 0x06 and knx_protocol_version ~= 0x10 and  knx_service_type ~= 0x0202 then
    return
  end

  local _, knx_hpai_structure_length = bin.unpack('>C', knxMessage, _)
  local _, knx_hpai_protocol_code = bin.unpack('>A1', knxMessage, _)
  local _, knx_hpai_ip_address = bin.unpack('>A4', knxMessage, _)
  knx_hpai_ip_address = ipOps.str_to_ip(knx_hpai_ip_address)
  local _, knx_hpai_port = bin.unpack('>S', knxMessage, _)

  local _, knx_dib_structure_length = bin.unpack('>C', knxMessage, _)
  local _, knx_dib_description_type = bin.unpack('>C', knxMessage, _)
  knx_dib_description_type = knxDibDescriptionTypes[knx_dib_description_type]
  local _, knx_dib_knx_medium = bin.unpack('>C', knxMessage, _)
  knx_dib_knx_medium = knxMediumTypes[knx_dib_knx_medium]
  local _, knx_dib_device_status = bin.unpack('>A1', knxMessage, _)
  local _, knx_dib_knx_address = bin.unpack('>S', knxMessage, _)
  local _, knx_dib_project_install_ident = bin.unpack('>A2', knxMessage, _)
  local _, knx_dib_dev_serial = bin.unpack('>A6', knxMessage, _)
  local _, knx_dib_dev_multicast_addr = bin.unpack('>A4', knxMessage, _)
  knx_dib_dev_multicast_addr = ipOps.str_to_ip(knx_dib_dev_multicast_addr)
  local _, knx_dib_dev_mac = bin.unpack('>A6', knxMessage, _)
  knx_dib_dev_mac = stdnse.format_mac(knx_dib_dev_mac)
  local _, knx_dib_dev_friendly_name = bin.unpack('>A30', knxMessage, _)

  local knx_supp_svc_families = {}
  local _, knx_supp_svc_families_structure_length = bin.unpack('>C', knxMessage, _)
  local _, knx_supp_svc_families_description = bin.unpack('>C', knxMessage, _)
  knx_supp_svc_families_description = knxDibDescriptionTypes[knx_supp_svc_families_description] or knx_supp_svc_families_description

  for i=0,(knx_total_length-_),2 do
    local family = {}
    _, family.service_id, family.Version = bin.unpack('CC', knxMessage, _)
    setmetatable(family, fam_meta)
    knx_supp_svc_families[#knx_supp_svc_families+1] = family
  end

  local search_response = stdnse.output_table()
  if nmap.debugging() > 0 then
    search_response.Header = stdnse.output_table()
    search_response.Header["Header length"] = knx_header_length
    search_response.Header["Protocol version"] = knx_protocol_version
    search_response.Header["Service type"] = "SEARCH_RESPONSE (0x0202)"
    search_response.Header["Total length"] = knx_total_length

    search_response.Body = stdnse.output_table()
    search_response.Body.HPAI = stdnse.output_table()
    search_response.Body.HPAI["Protocol code"] = stdnse.tohex(knx_hpai_protocol_code)
    search_response.Body.HPAI["IP address"] = knx_hpai_ip_address
    search_response.Body.HPAI["Port"] = knx_hpai_port

    search_response.Body.DIB_DEV_INFO = stdnse.output_table()
    search_response.Body.DIB_DEV_INFO["Description type"] = knx_dib_description_type
    search_response.Body.DIB_DEV_INFO["KNX medium"] = knx_dib_knx_medium
    search_response.Body.DIB_DEV_INFO["Device status"] = stdnse.tohex(knx_dib_device_status)
    search_response.Body.DIB_DEV_INFO["KNX address"] = parseKnxAddress(knx_dib_knx_address)
    search_response.Body.DIB_DEV_INFO["Project installation identifier"] = stdnse.tohex(knx_dib_project_install_ident)
    search_response.Body.DIB_DEV_INFO["Decive serial"] = stdnse.tohex(knx_dib_dev_serial)
    search_response.Body.DIB_DEV_INFO["Multicast address"] = knx_dib_dev_multicast_addr
    search_response.Body.DIB_DEV_INFO["Device MAC address"] = knx_dib_dev_mac
    search_response.Body.DIB_DEV_INFO["Device friendly name"] = knx_dib_dev_friendly_name
    search_response.Body.DIB_SUPP_SVC_FAMILIES = knx_supp_svc_families
  else
    search_response.Body = stdnse.output_table()
    search_response.Body.HPAI = stdnse.output_table()
    search_response.Body.HPAI["Port"] = knx_hpai_port

    search_response.Body.DIB_DEV_INFO = stdnse.output_table()
    search_response.Body.DIB_DEV_INFO["KNX address"] = parseKnxAddress(knx_dib_knx_address)
    search_response.Body.DIB_DEV_INFO["Decive serial"] = stdnse.tohex(knx_dib_dev_serial)
    search_response.Body.DIB_DEV_INFO["Multicast address"] = knx_dib_dev_multicast_addr
    search_response.Body.DIB_DEV_INFO["Device MAC address"] = knx_dib_dev_mac
    search_response.Body.DIB_DEV_INFO["Device friendly name"] = knx_dib_dev_friendly_name
    search_response.Body.DIB_SUPP_SVC_FAMILIES = knx_supp_svc_families
  end

  ips[#ips+1] = knx_hpai_ip_address
  results[knx_hpai_ip_address] = search_response
end

--- Listens for knx search responses
-- @param interface Network interface to listen on.
-- @param timeout Maximum time to listen.
-- @param ips Table to put IP addresses into.
-- @param result Table to put responses into.
local knxListen = function(interface, timeout, ips, results)
  local condvar = nmap.condvar(results)
  local start = nmap.clock_ms()
  local listener = nmap.new_socket()
  local threads = {}
  local status, l3data, _
  local filter = 'dst host ' .. interface.address .. ' and udp src port 3671'
  listener:set_timeout(100)
  listener:pcap_open(interface.device, 1024, true, filter)

  while (nmap.clock_ms() - start) < timeout do
    status, _, _, l3data = listener:pcap_receive()
    if status then
      local p = packet.Packet:new(l3data, #l3data)
      -- Skip IP and UDP headers
      local knxMessage = string.sub(l3data, p.ip_hl*4 + 8 + 1)
      local co = stdnse.new_thread(knxParseSearchResponse, ips, results, knxMessage)
      threads[co] = true;
    end
  end

  repeat
    for thread in pairs(threads) do
      if coroutine.status(thread) == "dead" then threads[thread] = nil end
    end
    if ( next(threads) ) then
      condvar "wait"
    end
  until next(threads) == nil;
  condvar("signal")
end

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

--- Make a dummy connection and return a free source port
-- @param target host to which the interface is used.
-- @return lport Local port which can be used in KNX messages.
local getSourcePort = function(target)
  local socket = nmap.new_socket()
  local _, _ = socket:connect(target, "12345", "udp")
  local _, _, lport, _, _ = socket:get_info()
  return lport
end

action = function()
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  timeout = (timeout or 3) * 1000
  local ips, results = {}, {}
  local mcast = "224.0.23.12"
  local mport = 3671
  local lport = getSourcePort(mcast)

  -- Check if a valid interface was provided
  local interface = nmap.get_interface()
  if interface then
    interface = nmap.get_interface_info(interface)
  else
    interface = getInterface(mcast)
  end
  if not interface then
    return ("\n ERROR: Couldn't get interface for %s"):format(mcast)
  end

  -- Launch listener thread
  stdnse.new_thread(knxListen, interface, timeout, ips, results)
  -- Craft raw query
  local query = knxQuery(interface.address, lport)
  -- Small sleep so the listener doesn't miss the response
  stdnse.sleep(0.5)
  -- Send query
  knxSend(query, mcast, mport)
  -- Wait for listener thread to finish
  local condvar = nmap.condvar(results)
  condvar("wait")

  -- Check responses
  if #ips > 0 then
    local sort_by_ip = function(a, b)
      return ipOps.compare_ip(a, "lt", b)
    end
    table.sort(ips, sort_by_ip)
    local output = stdnse.output_table()

    for i=1, #ips do
      local ip = ips[i]
      output[ip] = results[ip]

      if target.ALLOW_NEW_TARGETS then
        target.add(ip)
      end
    end

    return output
  end
end
