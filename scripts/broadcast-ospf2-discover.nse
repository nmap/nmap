local ipOps  = require "ipOps"
local nmap   = require "nmap"
local ospf   = require "ospf"
local packet = require "packet"
local stdnse = require "stdnse"
local target = require "target"
local os = require "os"
local string = require "string"
local table = require "table"

local have_ssl, openssl = pcall(require,'openssl')

description = [[
Discover IPv4 networks using Open Shortest Path First version 2(OSPFv2) protocol.

The script works by listening for OSPF Hello packets from the 224.0.0.5
multicast address. The script then replies and attempts to create a neighbor
relationship, in order to discover network database.

If no interface was provided as a script argument or through the -e option,
the script will fail unless a single interface is present on the system.
]]

---
-- @usage
-- nmap --script=broadcast-ospf2-discover
-- nmap --script=broadcast-ospf2-discover -e wlan0
--
-- @args broadcast-ospf2-discover.md5_key MD5 digest key to use if message digest
-- authentication is disclosed.
--
-- @args broadcast-ospf2-discover.router_id Router ID to use. Defaults to 0.0.0.1
--
-- @args broadcast-ospf2-discover.timeout Time in seconds that the script waits for
-- hello from other routers. Defaults to 10 seconds, matching OSPFv2 default
-- value for hello interval.
--
-- @args broadcast-ospf2-discover.interface Interface to send on (overrides -e). Mandatory
-- if not using -e and multiple interfaces are present.
--
-- @output
-- Pre-scan script results:
-- | broadcast-ospf2-discover:
-- |   Area ID: 0.0.0.0
-- |   External Routes
-- |     192.168.24.0/24
-- |_  Use the newtargets script-arg to add the results as targets
--

author     = "Emiliano Ticci"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "discovery", "safe"}

prerule = function()
  if nmap.address_family() ~= "inet" then
    stdnse.print_verbose("is IPv4 only.")
    return false
  end
  if not nmap.is_privileged() then
    stdnse.print_verbose("not running for lack of privileges.")
    return false
  end
  return true
end

-- Script constants
OSPF_ALL_ROUTERS = "224.0.0.5"
OSPF_MSG_HELLO   = 0x01
OSPF_MSG_DBDESC  = 0x02
OSPF_MSG_LSREQ   = 0x03
OSPF_MSG_LSUPD   = 0x04
local md5_key, router_id

-- Convenience functions
local function fail(err) return stdnse.format_output(false, err) end

-- Print OSPFv2 LSA Header packet details to debug output.
-- @param hello OSPFv2 LSA Header packet
local ospfDumpLSAHeader = function(lsa_h)
  if 2 > nmap.debugging() then
    return
  end
  stdnse.print_debug(2, "|   LS Age: %s", lsa_h.age)
  stdnse.print_debug(2, "|   Options: %s", lsa_h.options)
  stdnse.print_debug(2, "|   LS Type: %s", lsa_h.type)
  stdnse.print_debug(2, "|   Link State ID: %s", lsa_h.id)
  stdnse.print_debug(2, "|   Advertising Router: %s", lsa_h.adv_router)
  stdnse.print_debug(2, "|   Sequence: 0x%s", lsa_h.sequence)
  stdnse.print_debug(2, "|   Checksum: 0x%s", lsa_h.checksum)
  stdnse.print_debug(2, "|   Length: %s", lsa_h.length)
end

-- Print OSPFv2 Database Description packet details to debug output.
-- @param hello OSPFv2 Database Description packet
local ospfDumpDBDesc = function(db_desc)
  if 2 > nmap.debugging() then
    return
  end
  stdnse.print_debug(2, "| MTU:      %s", db_desc.mtu)
  stdnse.print_debug(2, "| Options:  %s", db_desc.options)
  stdnse.print_debug(2, "| Init:     %s", db_desc.init)
  stdnse.print_debug(2, "| More:     %s", db_desc.more)
  stdnse.print_debug(2, "| Master:   %s", db_desc.master)
  stdnse.print_debug(2, "| Sequence: %s", db_desc.sequence)
  if #db_desc.lsa_headers > 0 then
    stdnse.print_debug(2, "| LSA Headers:")
    for i, lsa_h in ipairs(db_desc.lsa_headers) do
      ospfDumpLSAHeader(lsa_h)
      if i < #db_desc.lsa_headers then
        stdnse.print_debug(2, "|")
      end
    end
  end
end

-- Print OSPFv2 Hello packet details to debug output.
-- @param hello OSPFv2 Hello packet
local ospfDumpHello = function(hello)
  if 2 > nmap.debugging() then
    return
  end
  stdnse.print_debug(2, "| Router ID:         %s", hello.header.router_id)
  stdnse.print_debug(2, "| Area ID:           %s", ipOps.fromdword(hello.header.area_id))
  stdnse.print_debug(2, "| Checksum:          %s", hello.header.chksum)
  stdnse.print_debug(2, "| Auth Type:         %s", hello.header.auth_type)
  if hello.header.auth_type == 0x01 then
    stdnse.print_debug(2, "| Auth Password:     %s", hello.header.auth_data.password)
  elseif hello.header.auth_type == 0x02 then
    stdnse.print_debug(2, "| Auth Crypt Key ID: %s", hello.header.auth_data.keyid)
    stdnse.print_debug(2, "| Auth Data Length:  %s", hello.header.auth_data.length)
    stdnse.print_debug(2, "| Auth Crypt Seq:    %s", hello.header.auth_data.seq)
  end
  stdnse.print_debug(2, "| Netmask:           %s", hello.netmask)
  stdnse.print_debug(2, "| Hello interval:    %s", hello.interval)
  stdnse.print_debug(2, "| Options:           %s", hello.options)
  stdnse.print_debug(2, "| Priority:          %s", hello.prio)
  stdnse.print_debug(2, "| Dead interval:     %s", hello.router_dead_interval)
  stdnse.print_debug(2, "| Designated Router: %s", hello.DR)
  stdnse.print_debug(2, "| Backup Router:     %s", hello.BDR)
  stdnse.print_debug(2, "| Neighbors:         %s", table.concat(hello.neighbors, ","))
end

-- Print OSPFv2 LS Request packet details to debug output.
-- @param ls_req OSPFv2 LS Request packet
local ospfDumpLSRequest = function(ls_req)
  if 2 > nmap.debugging() then
    return
  end
  for i, req in ipairs(ls_req.ls_requests) do
    stdnse.print_debug(2, "| LS Type:           %s", req.type)
    stdnse.print_debug(2, "| Link State ID:     %s", req.id)
    stdnse.print_debug(2, "| Avertising Router: %s", req.adv_router)
    if i < #ls_req.ls_requests then
      stdnse.print_debug(2, "|")
    end
  end
end

-- Print OSPFv2 LS Update packet details to debug output.
-- @param ls_upd OSPFv2 LS Update packet
local ospfDumpLSUpdate = function(ls_upd)
  stdnse.print_debug(2, "| Number of LSAs: %s", ls_upd.num_lsas)
  for i, lsa in ipairs(ls_upd.lsas) do
    -- Only Type 1 (Router-LSA) and Type 5 (AS-External-LSA) are supported at the moment
    ospfDumpLSAHeader(lsa.header)
    if lsa.header.type == 1 then
      stdnse.print_debug(2, "|   Flags: %s", lsa.flags)
      stdnse.print_debug(2, "|   Number of links: %s", lsa.num_links)
      for j, link in ipairs(lsa.links) do
        stdnse.print_debug(2, "|     Link ID: %s", link.id)
        stdnse.print_debug(2, "|     Link Data: %s", link.data)
        stdnse.print_debug(2, "|     Link Type: %s", link.type)
        stdnse.print_debug(2, "|     Number of Metrics: %s", link.num_metrics)
        stdnse.print_debug(2, "|     0 Metric: %s", link.metric)
        if j < #lsa.links then
          stdnse.print_debug(2, "|")
        end
      end
      if i < #ls_upd.lsas then
        stdnse.print_debug(2, "|")
      end
    elseif lsa.header.type == 5 then
      stdnse.print_debug(2, "|   Netmask: %s", lsa.netmask)
      stdnse.print_debug(2, "|   External Type: %s", lsa.ext_type)
      stdnse.print_debug(2, "|   Metric: %s", lsa.metric)
      stdnse.print_debug(2, "|   Forwarding Address: %s", lsa.fw_address)
      stdnse.print_debug(2, "|   External Route Tag: %s", lsa.ext_tag)
    end
  end
end

-- Send OSPFv2 packet to specified destination.
-- @param interface   Source interface to use
-- @param ip_dst      Destination IP address
-- @param mac_dst     Destination MAC address
-- @param ospf_packet Raw OSPF packet
local ospfSend = function(interface, ip_dst, mac_dst, ospf_packet)
  local dnet  = nmap.new_dnet()
  local probe = packet.Frame:new()

  probe.mac_src    = interface.mac
  probe.mac_dst    = mac_dst
  probe.ip_bin_src = ipOps.ip_to_str(interface.address)
  probe.ip_bin_dst = ipOps.ip_to_str(ip_dst)
  probe.l3_packet  = ospf_packet
  probe.ip_dsf     = 0xc0
  probe.ip_p       = 89
  probe.ip_ttl     = 1

  probe:build_ip_packet()
  probe:build_ether_frame()

  dnet:ethernet_open(interface.device)
  dnet:ethernet_send(probe.frame_buf)
  dnet:ethernet_close()
end

-- Prepare OSPFv2 packet header for reply.
-- @param packet_in  Source packet
-- @param packet_out Destination packet
local ospfSetHeader = function(packet_in, packet_out)
  packet_out.header:setRouterId(router_id)
  packet_out.header:setAreaID(packet_in.header.area_id)
  if packet_in.header.auth_type == 0x01 then
    packet_out.header.auth_type = 0x01
    packet_out.header.auth_data.password = packet_in.header.auth_data.password
  elseif packet_in.header.auth_type == 0x02 then
    packet_out.header.auth_type = 0x02
    packet_out.header.auth_data.key = md5_key
    packet_out.header.auth_data.keyid = packet_in.header.auth_data.keyid
    packet_out.header.auth_data.length = 16
    packet_out.header.auth_data.seq = os.time()
  end

  return packet_out
end

-- Reply to OSPFv2 Database Description with an LS Request.
-- @param interface  Source interface
-- @param mac_dst    Destination MAC address
-- @param db_desc_in OSPFv2 Database Description packet to reply for
local ospfSendLSRequest = function(interface, mac_dst, db_desc_in)
  local ls_req_out = ospf.OSPF.LSRequest:new()
  ls_req_out = ospfSetHeader(db_desc_in, ls_req_out)

  for i, lsa_h in ipairs(db_desc_in.lsa_headers) do
    ls_req_out:addRequest(lsa_h.type, lsa_h.id, lsa_h.adv_router)
  end

  stdnse.print_debug(2, "Crafted OSPFv2 LS Request packet with the following parameters:")
  ospfDumpLSRequest(ls_req_out)
  ospfSend(interface, db_desc_in.header.router_id, mac_dst, tostring(ls_req_out))
end

-- Reply to given OSPFv2 Database Description packet.
-- @param interface  Source interface
-- @param mac_dst    Destination MAC address
-- @param db_desc_in OSPFv2 Database Description packet to reply for
local ospfReplyDBDesc = function(interface, mac_dst, db_desc_in)
  local reply       = false
  local db_desc_out = ospf.OSPF.DBDescription:new()
  db_desc_out = ospfSetHeader(db_desc_in, db_desc_out)

  if db_desc_in.init == true then
    db_desc_out.init     = false
    db_desc_out.more     = db_desc_in.more
    db_desc_out.master   = false
    db_desc_out.sequence = db_desc_in.sequence
    reply = true
  elseif #db_desc_in.lsa_headers > 0 then
    ospfSendLSRequest(interface, mac_dst, db_desc_in)
    return true
  end

  if reply then
    stdnse.print_debug(2, "Crafted OSPFv2 Database Description packet with the following parameters:")
    ospfDumpDBDesc(db_desc_out)
    ospfSend(interface, db_desc_in.header.router_id, mac_dst, tostring(db_desc_out))
  end

  return reply
end

-- Reply to given OSPFv2 Hello packet sending another Hello to
-- "All OSPF Routers" multicast address (224.0.0.5).
-- @param interface Source interface
-- @param hello_in  OSPFv2 Hello packet to reply for
local ospfReplyHello = function(interface, hello_in)
  local hello_out = ospf.OSPF.Hello:new()
  hello_out = ospfSetHeader(hello_in, hello_out)
  hello_out.interval             = hello_in.interval
  hello_out.router_dead_interval = hello_in.router_dead_interval
  hello_out:setDesignatedRouter(hello_in.header.router_id)
  hello_out:setNetmask(hello_in.netmask)
  hello_out:addNeighbor(hello_in.header.router_id)

  stdnse.print_debug(2, "Crafted OSPFv2 Hello packet with the following parameters:")
  ospfDumpHello(hello_out)

  ospfSend(interface, OSPF_ALL_ROUTERS, "\x01\x00\x5e\x00\x00\x05", tostring(hello_out))
end

-- Listen for OSPF packets on a specified interface.
-- @param interface Interface to use
-- @param timeout   Amount of time to listen in seconds
local ospfListen = function(interface, timeout)
  local status, l2_data, l3_data, ospf_raw, _
  local start  = nmap.clock_ms()

  stdnse.print_debug("Start listening on interface %s...", interface.shortname)
  local listener = nmap.new_socket()
  listener:set_timeout(1000)
  listener:pcap_open(interface.device, 1500, true, "ip proto 89 and not (ip src host " .. interface.address .. ")")
  while (nmap.clock_ms() - start) < (timeout * 1000) do
    status, _, l2_data, l3_data = listener:pcap_receive()
    if status then
      stdnse.print_debug(2, "Packet received on interface %s.", interface.shortname)
      local p = packet.Packet:new(l3_data, #l3_data)
      local ospf_raw = string.sub(l3_data, p.ip_hl * 4 + 1)
      if ospf_raw:byte(1) == 0x02 and ospf_raw:byte(2) == OSPF_MSG_HELLO then
        stdnse.print_debug(2, "OSPFv2 Hello packet detected.")

        local ospf_hello = ospf.OSPF.Hello.parse(ospf_raw)
        stdnse.print_debug(2, "Captured OSPFv2 Hello packet with the following parameters:")
        ospfDumpHello(ospf_hello)

        -- Additional checks required for message digest authentication
        if ospf_hello.header.auth_type == 0x02 then
          if not md5_key then
            return fail("Argument md5_key must be present when message digest authentication is disclosed.")
          elseif not have_ssl then
            return fail("Cannot handle message digest authentication unless openssl is compiled in.")
          end
        end

        ospfReplyHello(interface, ospf_hello)
        start = nmap.clock_ms()
      elseif ospf_raw:byte(1) == 0x02 and ospf_raw:byte(2) == OSPF_MSG_DBDESC then
        stdnse.print_debug(2, "OSPFv2 Database Description packet detected.")

        local ospf_db_desc = ospf.OSPF.DBDescription.parse(ospf_raw)
        stdnse.print_debug(2, "Captured OSPFv2 Database Description packet with the following parameters:")
        ospfDumpDBDesc(ospf_db_desc)

        if not ospfReplyDBDesc(interface, string.sub(l2_data, 7, 12), ospf_db_desc) then
          return
        end
      elseif ospf_raw:byte(1) == 0x02 and ospf_raw:byte(2) == OSPF_MSG_LSUPD then
        stdnse.print_debug(2, "OSPFv2 LS Update packet detected.")

        local ospf_ls_upd = ospf.OSPF.LSUpdate.parse(ospf_raw)
        stdnse.print_debug(2, "Captured OSPFv2 LS Update packet with the following parameters:")
        ospfDumpLSUpdate(ospf_ls_upd)

        local targets = {}
        for i, lsa in ipairs(ospf_ls_upd.lsas) do
          -- Only Type 1 (Router-LSA) and Type 5 (AS-External-LSA) are supported at the moment
          if lsa.header.type == 1 then
            for j, link in ipairs(lsa.links) do
              if link.type == 3 then
                local target = link.id .. ipOps.subnet_to_cidr(link.data)
                targets[target] = 1
              end
            end
          elseif lsa.header.type == 5 then
            local target = lsa.header.id .. ipOps.subnet_to_cidr(lsa.netmask)
            targets[target] = 1
          end
        end
        local output = stdnse.output_table()
        if next(targets) then
          local out_links = {}
          output["Area ID"] = ipOps.fromdword(ospf_ls_upd.header.area_id)
          output["External Routes"] = out_links
          for t, _ in pairs(targets) do
            table.insert(out_links, t)
            if target.ALLOW_NEW_TARGETS then
              target.add(t)
            end
          end
          if not target.ALLOW_NEW_TARGETS then
            stdnse.verbose("Use the newtargets script-arg to add the results as targets")
          end
        end
        return output
      end
    end
  end
  listener:pcap_close()
end

action = function()
  -- Get script arguments
  md5_key   = stdnse.get_script_args(SCRIPT_NAME .. ".md5_key") or false
  router_id = stdnse.get_script_args(SCRIPT_NAME .. ".router_id") or "0.0.0.1"
  local timeout   = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 10
  local interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface")
  stdnse.print_debug("Value for router ID argument: %s.", router_id)
  stdnse.print_debug("Value for timeout argument: %s.", timeout)

  -- Determine interface to use
  interface  = interface or nmap.get_interface()
  if interface then
    interface = nmap.get_interface_info(interface)
    if not interface then
      return fail(("Failed to retrieve %s interface information."):format(interface))
    end
    stdnse.print_debug("Will use %s interface.", interface.shortname)
  else
    local interface_list = nmap.list_interfaces()
    local interface_good = {}
    for _, os_interface in ipairs(interface_list) do
      if os_interface.address and os_interface.link == "ethernet" and
        os_interface.address:match("%d+%.%d+%.%d+%.%d+") then

        stdnse.print_debug(2, "Found usable interface: %s.", os_interface.shortname)
        table.insert(interface_good, os_interface)
      end
    end
    if #interface_good == 1 then
      interface = interface_good[1]
      stdnse.print_debug("Will use %s interface.", interface.shortname)
    elseif #interface_good == 0 then
      return fail("Source interface not found.")
    else
      return fail("Ambiguous source interface, please specify it with -e or interface parameter.")
    end
  end

  return ospfListen(interface, timeout)
end
