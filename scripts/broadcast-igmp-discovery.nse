local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local bin = require "bin"
local packet = require "packet"
local ipOps = require "ipOps"
local target = require "target"
local coroutine = require "coroutine"
local string = require "string"
local io = require "io"

description = [[
Discovers targets that have IGMP Multicast memberships and grabs interesting information.

The scripts works by sending IGMP Membership Query message to the 224.0.0.1 All
Hosts multicast address and listening for IGMP Membership Report messages. The
script then extracts all the interesting information from the report messages
such as the version, group, mode, source addresses (depending on the version).

The script defaults to sending an IGMPv2 Query but this could be changed to
another version (version 1 or 3) or to sending queries of all three version. If
no interface was specified as a script argument or with the -e option, the
script will proceed to sending queries through all the valid ethernet
interfaces.
]]

---
-- @args broadcast-igmp-discovery.timeout Time to wait for reports in seconds.
-- Defaults to <code>5</code> seconds.
--
-- @args broadcast-igmp-discovery.version IGMP version to use. Could be
-- <code>1</code>, <code>2</code>, <code>3</code> or <code>all</code>. Defaults to <code>2</code>
--
-- @args broadcast-igmp-discovery.interface Network interface to use.
--
-- @args broadcast-igmp-discovery.mgroupnamesdb Database with multicast group names
--
--@usage
-- nmap --script broadcast-igmp-discovery
-- nmap --script broadcast-igmp-discovery -e wlan0
-- nmap --script broadcast-igmp-discovery
-- --script-args 'broadcast-igmp-discovery.version=all, broadcast-igmp-discovery.timeout=3'
--
--@output
--Pre-scan script results:
-- | broadcast-igmp-discovery:
-- |   192.168.2.2
-- |     Interface: tap0
-- |     Version: 3
-- |     Group: 239.1.1.1
-- |       Mode: EXCLUDE
-- |       Description: Organization-Local Scope (rfc2365)
-- |     Group: 239.1.1.2
-- |       Mode: EXCLUDE
-- |       Description: Organization-Local Scope (rfc2365)
-- |     Group: 239.1.1.44
-- |       Mode: INCLUDE
-- |       Description: Organization-Local Scope (rfc2365)
-- |       Sources:
-- |           192.168.31.1
-- |   192.168.1.3
-- |     Interface: wlan0
-- |     Version: 2
-- |     Group: 239.255.255.250
-- |     Description: Organization-Local Scope (rfc2365)
-- |   192.168.1.3
-- |     Interface: wlan0
-- |     Version: 2
-- |     Group: 239.255.255.253
-- |     Description: Organization-Local Scope (rfc2365)
-- |_  Use the newtargets script-arg to add the results as targets
--

--
-- The Multicast Group names DB can be created by the following script:
--
-- #!/usr/bin/awk -f
-- BEGIN { FS="<|>"; }
-- /<record/ { r=1; addr1=""; addr2=""; rfc=""; }
-- /<addr>.*-.*<\/addr>/ { T=$3; FS="-"; $0=T; addr1=$1; addr2=$2; FS="<|>"; }
-- /<addr>[^-]*<\/addr>/ { addr1=$3; addr2=$3; }
-- /<description>/ { desc=$3; }
-- /<xref type=\"rfc\"/ { T=$2; FS="\""; $0=T; rfc=" ("  $4  ")"; FS="<|>"; }
-- /<\/record/ { r=0; if (addr1) { print addr1 "\t" addr2 "\t" desc rfc; } }
--
-- wget -O- http://www.iana.org/assignments/multicast-addresses/multicast-addresses.xml | \
--      ./extract-mg-names >nselib/data/mgroupnames.db


prerule = function()
  if nmap.address_family() ~= 'inet' then
    stdnse.verbose1("is IPv4 only.")
    return false
  end
  if ( not(nmap.is_privileged()) ) then
    stdnse.verbose1("not running due to lack of privileges.")
    return false
  end
  return true
end

author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe", "broadcast"}

--- Parses a raw igmp packet and return a structured packet.
-- @param data string IGMP Raw packet.
-- @return response table Structured igmp packet.
local igmpParse = function(data)
  local index
  local response = {}
  local group, source
  -- Report type (0x12 == v1, 0x16 == v2, 0x22 == v3)
  index, response.type = bin.unpack(">C", data, index)
  if response.type == 0x12 or response.type == 0x16 then
    -- Max response time
    index, response.maxrt = bin.unpack(">C", data, index)
    -- Checksum
    index, response.checksum = bin.unpack(">S", data, index)
    -- Multicast group
    index, response.group = bin.unpack(">I", data, index)
    response.group = ipOps.fromdword(response.group)
    return response
  elseif response.type == 0x22 and #data >= 12 then
    -- Skip reserved byte
    index = index + 1
    -- Checksum
    index, response.checksum = bin.unpack(">S", data, index)
    -- Skip reserved byte
    index = index + 2
    -- Number of groups
    index, response.ngroups = bin.unpack(">S", data, index)
    response.groups = {}
    for i=1,response.ngroups do
      group = {}
      -- Mode is either INCLUDE or EXCLUDE
      index, group.mode = bin.unpack(">C", data, index)
      -- Auxiliary data length in the group record (in 32bits units)
      index, group.auxdlen = bin.unpack(">C", data, index)
      -- Number of source addresses
      index, group.nsrc = bin.unpack(">S", data, index)
      index, group.address = bin.unpack(">I", data, index)
      group.address = ipOps.fromdword(group.address)
      group.src = {}
      if group.nsrc > 0 then
        for i=1,group.nsrc do
          index, source = bin.unpack(">I", data, index)
          table.insert(group.src, ipOps.fromdword(source))
        end
      end
      -- Skip auxiliary data
      index = index + group.auxdlen
      -- Insert group
      table.insert(response.groups, group)
    end
    return response
  end
end

--- Listens for IGMP Membership reports packets.
-- @param interface Interface to listen on.
-- @param timeout Amount of time to listen for.
-- @param responses table to put valid responses into.
local igmpListener = function(interface, timeout, responses)
  local condvar = nmap.condvar(responses)
  local start = nmap.clock_ms()
  local listener = nmap.new_socket()
  local p, igmp_raw, status, l3data, response, _
  local devices = {}
  listener:set_timeout(100)
  listener:pcap_open(interface.device, 1024, true, 'ip proto 2')

  while (nmap.clock_ms() - start) < timeout do
    status, _, _, l3data = listener:pcap_receive()
    if status then
      p = packet.Packet:new(l3data, #l3data)
      igmp_raw = string.sub(l3data, p.ip_hl*4 + 1)
      if p then
        -- check the first byte before sending to the parser
        -- response 0x12 == Membership Response version 1
        -- response 0x16 == Membership Response version 2
        -- response 0x22 == Membership Response version 3
        local igmptype = igmp_raw:byte(1)
        if igmptype == 0x12 or igmptype == 0x16 or igmptype == 0x22 then
          response = igmpParse(igmp_raw)
          if response then
            response.src = p.ip_src
            response.interface = interface.shortname
            -- Many hosts return more than one same response message
            -- this is to not output duplicates
            if not devices[response.src..response.type..(response.group or response.ngroups)] then
              devices[response.src..response.type..(response.group or response.ngroups)] = true
              table.insert(responses, response)
            end
          end
        end
      end
    end
  end
  condvar("signal")
end

--- Crafts a raw IGMP packet.
-- @param interface Source interface of the packet.
-- @param version IGMP version. Could be 1, 2 or 3.
-- @return string Raw IGMP packet.
local igmpRaw = function(interface, version)
  -- Only 1, 2 and 3 are valid IGMP versions
  if version ~= 1 and version ~= 2 and version ~= 3 then
    stdnse.debug1("IGMP version %s doesn't exist.", version)
    return
  end

  -- Let's craft an IGMP Membership Query
  local igmp_raw = bin.pack(">CCSI",
    0x11, -- Membership Query, same for all versions
    version == 1 and 0 or 0x16, -- Max response time: 10 Seconds, for version 2 and 3
    0, -- Checksum, calculated later
    0  -- Multicast Address: 0.0.0.0
    )

  if version == 3 then
    igmp_raw = bin.pack(">ACCSI", igmp_raw,
      0, -- Reserved = 4 bits (Should be zeroed)
      -- Supress Flag = 1 bit
      -- QRV (Querier's Robustness Variable) = 3 bits
      -- all are set to 0
      0x10, -- QQIC (Querier's Query Interval Code) in seconds = Set to 0 to get insta replies.
      0x0001, -- Number of sources (in the next arrays) = 1 ( Our IP only)
      ipOps.todword(interface.address) -- Source = Our IP address
      )
  end

  igmp_raw = igmp_raw:sub(1,2) .. bin.pack(">S", packet.in_cksum(igmp_raw)) .. igmp_raw:sub(5)

  return igmp_raw
end


local igmpQuery;
--- Sends an IGMP Membership query.
-- @param interface Network interface to send on.
-- @param version IGMP version. Could be 1, 2, 3 or all.
igmpQuery = function(interface, version)
  local srcip = interface.address
  local dstip = "224.0.0.1"

  if version == 'all' then
    -- Small pause to let listener begin and not miss reports.
    stdnse.sleep(0.5)
    igmpQuery(interface, 3)
    igmpQuery(interface, 2)
    igmpQuery(interface, 1)
  else
    local igmp_raw = igmpRaw(interface, version)

    local ip_raw = stdnse.fromhex( "45c00040ed780000010218bc0a00c8750a00c86b") .. igmp_raw
    local igmp_packet = packet.Packet:new(ip_raw, ip_raw:len())
    igmp_packet:ip_set_bin_src(ipOps.ip_to_str(srcip))
    igmp_packet:ip_set_bin_dst(ipOps.ip_to_str(dstip))
    igmp_packet:ip_set_len(#igmp_packet.buf)
    igmp_packet:ip_count_checksum()

    local sock = nmap.new_dnet()
    sock:ethernet_open(interface.device)

    -- Ethernet IPv4 multicast, our ethernet address and type IP
    local eth_hdr = bin.pack("HAH", "01 00 5e 00 00 01", interface.mac, "08 00")
    sock:ethernet_send(eth_hdr .. igmp_packet.buf)
    sock:ethernet_close()
  end
end

-- Function to compare weight of an IGMP response message.
-- Used to sort elements in responses table.
local respCompare = function(a,b)
  return ipOps.todword(a.src) + a.type + (a.ngroups or ipOps.todword(a.group))
  < ipOps.todword(b.src) + b.type + (b.ngroups or ipOps.todword(b.group))
end

local mgroup_names_fetch = function(filename)
  local groupnames_db = {}

  local file = io.open(filename, "r")
  if not file then
    return false
  end

  for l in file:lines() do
    groupnames_db[#groupnames_db + 1] = stdnse.strsplit("\t", l)
  end

  file:close()
  return groupnames_db
end

local mgroup_name_identify = function(db, ip)
  --stdnse.debug1("'%s'", ip)
  for _, mg in ipairs(db) do
    local ip1 = mg[1]
    local ip2 = mg[2]
    local desc = mg[3]
    --stdnse.debug1("try: %s <= %s <= %s (%s)", ip1, ip, ip2, desc)
    if (not ipOps.compare_ip(ip, "lt", ip1) and not ipOps.compare_ip(ip2, "lt", ip)) then
      --stdnse.debug1("found! %s <= %s <= %s (%s)", ip1, ip, ip2, desc)
      return desc
    end
  end
  return false
end

action = function(host, port)
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  local version = stdnse.get_script_args(SCRIPT_NAME .. ".version") or 2
  local interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface")
  timeout = (timeout or 7) * 1000
  if version ~= 'all' then
    version = tonumber(version)
  end

  local responses, results, interfaces, lthreads = {}, {}, {}, {}
  local result, grouptable, sourcetable

  local group_names_fname = stdnse.get_script_args(SCRIPT_NAME .. ".mgroupnamesdb") or
  nmap.fetchfile("nselib/data/mgroupnames.db")
  local mg_names_db = group_names_fname and mgroup_names_fetch(group_names_fname)

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
      if iface.address and iface.link=="ethernet" and
        iface.address:match("%d+%.%d+%.%d+%.%d+") then

        stdnse.debug1("Will use %s interface.", iface.shortname)
        table.insert(interfaces, iface)
      end
    end
  end


  -- We should iterate over interfaces
  for _, interface in pairs(interfaces) do
    local co = stdnse.new_thread(igmpListener, interface, timeout, responses)
    igmpQuery(interface, version)
    lthreads[co] = true
  end

  local condvar = nmap.condvar(responses)
  -- Wait for the listening threads to finish
  repeat
    for thread in pairs(lthreads) do
      if coroutine.status(thread) == "dead" then lthreads[thread] = nil end
    end
    if ( next(lthreads) ) then
      condvar("wait")
    end
  until next(lthreads) == nil;

  -- Output useful info from the responses
  if #responses > 0 then
    -- We should sort our list here.
    -- This is useful to have consistent results for tools such as Ndiff.
    table.sort(responses, respCompare)

    for _, response in pairs(responses) do
      result = {}
      result.name = response.src
      table.insert(result, "Interface: " .. response.interface)
      -- Add to new targets if newtargets script arg provided
      if target.ALLOW_NEW_TARGETS then target.add(response.src) end
      if response.type == 0x12 then
        table.insert(result, "Version: 1")
        table.insert(result, "Multicast group: ".. response.group)
      elseif response.type == 0x16 then
        table.insert(result, "Version: 2")
        table.insert(result, "Group: ".. response.group)
        local mg_desc = mgroup_name_identify(mg_names_db, response.group)
        if mg_desc then
          table.insert(result, "Description: ".. mg_desc)
        end
      elseif response.type == 0x22 then
        table.insert(result, "Version: 3")
        for _, group in pairs(response.groups) do
          grouptable = {}
          grouptable.name = "Group: " .. group.address
          if group.mode == 0x01 then
            table.insert(grouptable, "Mode: INCLUDE")
          elseif group.mode == 0x02 then
            table.insert(grouptable, "Mode: EXCLUDE")
          end
          local mg_desc = mgroup_name_identify(mg_names_db, group.address)
          if mg_desc then
            table.insert(grouptable, "Description: ".. mg_desc)
          end
          if group.nsrc > 0 then
            sourcetable = {}
            sourcetable.name = "Sources:"
            table.insert(sourcetable, group.src)
            table.insert(grouptable, sourcetable)
          end
          table.insert(result, grouptable)
        end
      end
      table.insert(results, result)
    end
    if #results>0 and not target.ALLOW_NEW_TARGETS then
      table.insert(results,"Use the newtargets script-arg to add the results as targets")
    end
    return stdnse.format_output(true, results)
  end
end
