local nmap = require "nmap"
local coroutine = require "coroutine"
local stdnse = require "stdnse"
local table = require "table"
local packet = require "packet"
local ipOps = require "ipOps"
local string = require "string"
local target = require "target"
local knx = require "knx"

description = [[
Discovers KNX gateways by sending a KNX Search Request to the multicast address
224.0.23.12 including a UDP payload with destination port 3671. KNX gateways
will respond with a KNX Search Response including various information about the
gateway, such as KNX address and supported services.

Further information:
  * DIN EN 13321-2
  * http://www.knx.org/
]]

author = {"Niklaus Schiess <nschiess@ernw.de>", "Dominik Schneider <dschneider@ernw.de>"}
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

local fam_meta = {
  __tostring = function (self)
    return ("%s version %d"):format(
      knx.knxServiceFamilies[self.service_id] or self.service_id,
      self.Version
      )
  end
}

--- Parse a Search Response
-- @param knxMessage Payload of captures UDP packet
local knxParseSearchResponse = function(ips, results, knxMessage)
  local knx_header_length, knx_protocol_version, knx_service_type, knx_total_length, pos = knx.parseHeader(knxMessage)

  if not knx_header_length then
    stdnse.debug1("KNX header error: %s", knx_protocol_version)
    return
  end

  local message_format = '>B c1 c4 I2 BBB c1 I2 c2 c6 c4 c6 c30 BB'
  if #knxMessage - pos + 1 < string.packlen(message_format) then
    stdnse.debug1("Message too short for KNX message")
    return
  end

  local knx_hpai_structure_length,
  knx_hpai_protocol_code,
  knx_hpai_ip_address,
  knx_hpai_port,
  knx_dib_structure_length,
  knx_dib_description_type,
  knx_dib_knx_medium,
  knx_dib_device_status,
  knx_dib_knx_address,
  knx_dib_project_install_ident,
  knx_dib_dev_serial,
  knx_dib_dev_multicast_addr,
  knx_dib_dev_mac,
  knx_dib_dev_friendly_name,
  knx_supp_svc_families_structure_length,
  knx_supp_svc_families_description, pos = string.unpack(message_format, knxMessage, pos)

  knx_hpai_ip_address = ipOps.str_to_ip(knx_hpai_ip_address)

  knx_dib_description_type = knx.knxDibDescriptionTypes[knx_dib_description_type]
  knx_dib_knx_medium = knx.knxMediumTypes[knx_dib_knx_medium]
  knx_dib_dev_multicast_addr = ipOps.str_to_ip(knx_dib_dev_multicast_addr)
  knx_dib_dev_mac = stdnse.format_mac(knx_dib_dev_mac)

  local knx_supp_svc_families = {}
  knx_supp_svc_families_description = knx.knxDibDescriptionTypes[knx_supp_svc_families_description] or knx_supp_svc_families_description

  for i=0,(knx_total_length - pos),2 do
    local family = {}
    family.service_id, family.Version, pos = string.unpack('BB', knxMessage, pos)
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
    search_response.Body.DIB_DEV_INFO["KNX address"] = knx.parseKnxAddress(knx_dib_knx_address)
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
    search_response.Body.DIB_DEV_INFO["KNX address"] = knx.parseKnxAddress(knx_dib_knx_address)
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
  local query = knx.query(0x0201, interface.address, lport)
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
