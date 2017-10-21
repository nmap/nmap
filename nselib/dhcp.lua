---Implement a Dynamic Host Configuration Protocol (DHCP) client.
--
-- DHCP, defined in rfc2132 and rfc2131, is a protocol for hosts to automatically
-- configure themselves on a network (that is, obtain an ip address). This library,
-- which have a trivial one-function interface, can send out DHCP packets of many
-- types and parse the responses.
--
-- @author Ron Bowes

--
-- 2011-12-28 - Revised by Patrik Karlsson <patrik@cqure.net>
--   o Split dhcp_send into dhcp_send, dhcp_receive
--   o Added basic support for adding options to requests
--   o Added possibility to override transaction id
--   o Added WPAD action

local bin = require "bin"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local strbuf = require "strbuf"
local table = require "table"
_ENV = stdnse.module("dhcp", stdnse.seeall)


request_types =
{
  DHCPDISCOVER = 1,
  DHCPOFFER    = 2,
  DHCPREQUEST  = 3,
  DHCPDECLINE  = 4,
  DHCPACK      = 5,
  DHCPNAK      = 6,
  DHCPRELEASE  = 7,
  DHCPINFORM   = 8
}

--Invert a one-to-one mapping
local function invert(t)
  local out = {}
  for k, v in pairs(t) do
    out[v] = k
  end
  return out
end

request_types_str = invert(request_types)

---Read an IP address or a list of IP addresses. Print an error if the length isn't a multiple of 4.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_ip(data, pos, length)
  if(length ~= 4) then
    if((length % 4) ~= 0) then
      stdnse.debug1("dhcp-discover: Invalid length for an ip address (%d)", length)
      pos = pos + length

      return pos, nil
    else
      local results = {}
      for i=1, length, 4 do
        local value
        pos, value = bin.unpack(">I", data, pos)
        table.insert(results, ipOps.fromdword(value))
      end

      return pos, results
    end
  else
    local value
    pos, value = bin.unpack(">I", data, pos)

    return pos, ipOps.fromdword(value)
  end
end

---Read a string. The length of the string is given by the length field.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_string(data, pos, length)
  return bin.unpack(string.format("A%d", length), data, pos)
end

---Read a single byte. Print an error if the length isn't 1.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_1_byte(data, pos, length)
  if(length ~= 1) then
    stdnse.debug1("dhcp-discover: Invalid length for data (%d; should be %d)", length, 1)
    pos = pos + length
    return pos, nil
  end
  return bin.unpack("C", data, pos)
end

---Read a message type. This is a single-byte value that's looked up in the <code>request_types_str</code>
-- table. Print an error if the length isn't 1.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_message_type(data, pos, length)
  local value

  pos, value = read_1_byte(data, pos, length)
  if(value == nil) then
    stdnse.debug1("dhcp-discover: Couldn't read the 1-byte message type")
    return pos, nil
  end

  return pos, request_types_str[value]
end

---Read a single byte, and return 'false' if it's 0, or 'true' if it's non-zero. Print an error if the
-- length isn't 1.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_boolean(data, pos, length)
  local result
  pos, result = read_1_byte(data, pos, length)

  if(result == nil) then
    stdnse.debug1("dhcp-discover: Couldn't read the 1-byte boolean")
    return pos, nil
  elseif(result == 0) then
    return pos, "false"
  else
    return pos, "true"
  end
end

---Read a 2-byte unsigned little endian value. Print an error if the length isn't 2.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_2_bytes(data, pos, length)
  if(length ~= 2) then
    stdnse.debug1("dhcp-discover: Invalid length for data (%d; should be %d)", length, 2)
    pos = pos + length
    return pos, nil
  end
  return bin.unpack(">S", data, pos)
end


---Read a list of 2-byte unsigned little endian values. Print an error if the length isn't a multiple
-- of 2.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_2_bytes_list(data, pos, length)
  if((length % 2) ~= 0) then
    stdnse.debug1("dhcp-discover: Invalid length for data (%d; should be multiple of %d)", length, 2)
    pos = pos + length

    return pos, nil
  else
    local results = {}
    for i=1, length, 2 do
      local value
      pos, value = bin.unpack(">S", data, pos)
      table.insert(results, value)
    end

    return pos, results
  end
end


---Read a 4-byte unsigned little endian value. Print an error if the length isn't 4.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_4_bytes(data, pos, length)
  if(length ~= 4) then
    stdnse.debug1("dhcp-discover: Invalid length for data (%d; should be %d)", length, 4)
    pos = pos + length
    return pos, nil
  end
  return bin.unpack(">I", data, pos)
end

---Read a 4-byte unsigned little endian value, and interpret it as a time offset value. Print an
-- error if the length isn't 4.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_time(data, pos, length)
  local result
  if(length ~= 4) then
    stdnse.debug1("dhcp-discover: Invalid length for data (%d; should be %d)", length, 4)
    pos = pos + length
    return pos, nil
  end
  pos, result = bin.unpack(">I", data, pos)

  return pos, stdnse.format_time(result)
end

---Read a list of static routes. Each of them are a pair of IP addresses, a destination and a
-- router. Print an error if the length isn't a multiple of 8.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_static_route(data, pos, length)
  if((length % 8) ~= 0) then
    stdnse.debug1("dhcp-discover: Invalid length for data (%d; should be multiple of %d)", length, 8)
    pos = pos + length

    return pos, nil
  else
    local results = {}
    for i=1, length, 8 do
      local destination, router
      pos, destination = read_ip(data, pos, 4)
      pos, router      = read_ip(data, pos, 4)
      table.insert(results, {destination=destination, router=router})
    end

    return pos, results
  end
end

---Read a list of policy filters. Each of them are a pair of IP addresses, an address and a
-- mask. Print an error if the length isn't a multiple of 8.
--
--@param data The packet.
--@param pos  The position in the packet.
--@param length The length that the server claims the field is.
--@return The new position (will always be pos + length, no matter what we think it should be)
--@return The value of the field, or nil if the field length was wrong.
local function read_policy_filter(data, pos, length)
  if((length % 8) ~= 0) then
    stdnse.debug1("dhcp-discover: Invalid length for data (%d; should be multiple of %d)", length, 8)
    pos = pos + length

    return pos, nil
  else
    local results = {}
    for i=1, length, 8 do
      local address, router, mask
      pos, address = read_ip(data, pos, 4)
      pos, mask    = read_ip(data, pos, 4)
      table.insert(results, {address=address, mask=mask})
    end

    return pos, results
  end
end

---These are the different fields for DHCP. These have to come after the read_* function
-- definitions.
-- TODO: Add more from https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml#options
local actions = {
  [1]  = {name="Subnet Mask",                     func=read_ip,             default=true},
  [2]  = {name="Time Offset",                     func=read_4_bytes,        default=false},
  [3]  = {name="Router",                          func=read_ip,             default=true},
  [4]  = {name="Time Server",                     func=read_ip,             default=true},
  [5]  = {name="Name Server",                     func=read_ip,             default=true},
  [6]  = {name="Domain Name Server",              func=read_ip,             default=true},
  [7]  = {name="Log Server",                      func=read_ip,             default=true},
  [8]  = {name="Cookie Server",                   func=read_ip,             default=true},
  [9]  = {name="LPR Server",                      func=read_ip,             default=true},
  [10] = {name="Impress Server",                  func=read_ip,             default=true},
  [11] = {name="Resource Location Server",        func=read_ip,             default=true},
  [12] = {name="Hostname",                        func=read_string,         default=true},
  [13] = {name="Boot File Size",                  func=read_2_bytes,        default=false},
  [14] = {name="Merit Dump File",                 func=read_string,         default=false},
  [15] = {name="Domain Name",                     func=read_string,         default=true},
  [16] = {name="Swap Server",                     func=read_ip,             default=true},
  [17] = {name="Root Path",                       func=read_string,         default=false},
  [18] = {name="Extensions Path",                 func=read_string,         default=false},
  [19] = {name="IP Forwarding",                   func=read_boolean,        default=false},
  [20] = {name="Non-local Source Routing",        func=read_boolean,        default=true},
  [21] = {name="Policy Filter",                   func=read_policy_filter,  default=false},
  [22] = {name="Maximum Datagram Reassembly Size",func=read_2_bytes,        default=false},
  [23] = {name="Default IP TTL",                  func=read_1_byte,         default=false},
  [24] = {name="Path MTU Aging Timeout",          func=read_time,           default=false},
  [25] = {name="Path MTU Plateau",                func=read_2_bytes_list,   default=false},
  [26] = {name="Interface MTU",                   func=read_2_bytes,        default=false},
  [27] = {name="All Subnets are Local",           func=read_boolean,        default=false},
  [28] = {name="Broadcast Address",               func=read_ip,             default=true},
  [29] = {name="Perform Mask Discovery",          func=read_boolean,        default=false},
  [30] = {name="Mask Supplier",                   func=read_boolean,        default=false},
  [31] = {name="Perform Router Discovery",        func=read_boolean,        default=false},
  [32] = {name="Router Solicitation Address",     func=read_ip,             default=true},
  [33] = {name="Static Route",                    func=read_static_route,   default=true},
  [34] = {name="Trailer Encapsulation",           func=read_boolean,        default=false},
  [35] = {name="ARP Cache Timeout",               func=read_time,           default=false},
  [36] = {name="Ethernet Encapsulation",          func=read_boolean,        default=false},
  [37] = {name="TCP Default TTL",                 func=read_1_byte,         default=false},
  [38] = {name="TCP Keepalive Interval",          func=read_4_bytes,        default=false},
  [39] = {name="TCP Keepalive Garbage",           func=read_boolean,        default=false},
  [40] = {name="NIS Domain",                      func=read_string,         default=true},
  [41] = {name="NIS Servers",                     func=read_ip,             default=true},
  [42] = {name="NTP Servers",                     func=read_ip,             default=true},
  [43] = {name="Vendor Specific Information",     func=read_string,         default=false},
  [44] = {name="NetBIOS Name Server",             func=read_ip,             default=true},
  [45] = {name="NetBIOS Datagram Server",         func=read_ip,             default=true},
  [46] = {name="NetBIOS Node Type",               func=read_1_byte,         default=false},
  [47] = {name="NetBIOS Scope",                   func=read_string,         default=false},
  [48] = {name="X Window Font Server",            func=read_ip,             default=true},
  [49] = {name="X Window Display Manager",        func=read_ip,             default=true},
  [50] = {name="Requested IP Address (client)",   func=read_ip,             default=false},
  [51] = {name="IP Address Lease Time",           func=read_time,           default=false},
  [52] = {name="Option Overload",                 func=read_1_byte,         default=false},
  [53] = {name="DHCP Message Type",               func=read_message_type,   default=false},
  [54] = {name="Server Identifier",               func=read_ip,             default=true},
  [55] = {name="Parameter Request List (client)", func=read_string,         default=false},
  [56] = {name="Error Message",                   func=read_string,         default=true},
  [57] = {name="Maximum DHCP Message Size",       func=read_2_bytes,        default=false},
  [58] = {name="Renewal Time Value",              func=read_time,           default=false},
  [59] = {name="Rebinding Time Value",            func=read_time,           default=false},
  [60] = {name="Class Identifier",                func=read_string,         default=false},
  [61] = {name="Client Identifier (client)",      func=read_string,         default=false},
  [66] = {name="TFTP Server Name",                func=read_string,         default=false},
  [67] = {name="Bootfile Name",                   func=read_string,         default=false},
  [252]= {name="WPAD",                            func=read_string,         default=false},
}

--- Does the send/receive, doesn't build/parse anything.
local function dhcp_send(socket, host, packet)
  -- Send out the packet
  return socket:sendto(host, { number=67, protocol="udp" }, packet)
end

local function dhcp_receive(socket, transaction_id)

  local status, data = socket:receive()
  if ( not(status) ) then
    socket:close()
    return false, data
  end

  -- This pulls back 4 bytes in the packet that correspond to the transaction id. This should be randomly
  -- generated and different for every instance of a script (to prevent collisions)
  while status and data:sub(5, 8) ~= transaction_id do
    status, data = socket:receive()
  end

  return status, data
end

--- Builds a DHCP packet
--
--@param request_type    The type of request as an integer (use the <code>request_types</code> table at the
--                       top of this file).
--@param ip_address      Your ip address (as a dotted-decimal string). This tells the DHCP server where to
--                       send the response. Setting it to "255.255.255.255" or "0.0.0.0" is generally acceptable (if not,
--                       host.ip_src can work).
--@param mac_address     Your mac address (as a string up to 16 bytes) where the server will send the response. Like
--                       <code>ip_address</code>, setting to the broadcast address (FF:FF:FF:FF:FF:FF) is
--                       common (host.mac_addr_src works).
--@param options         [optional] A table of additional request options where each option is a table containing the
--                       following fields:
--                         * <code>number</code> - The option number
--                         * <code>type</code>   - The option type ("string" or "ip")
--                         * <code>value</code>  - The option value
--@param request_options [optional] The options to request from the server, as an array of integers. For the
--                       acceptable options, see the <code>actions</code> table above or have a look at rfc2132.
--                       Some DHCP servers (such as my Linksys WRT54g) will ignore this list and send whichever
--                       information it wants. Default: all options marked as 'default' in the <code>actions</code>
--                       table above are requested (the typical interesting ones) if no verbosity is given.
--                       If any level of verbosity is on, get all types.
--@param overrides       [optional] A table of overrides. If a field in the table matches a field in the DHCP
--                       packet (see rfc2131 section 2 for a list of possible fields), the value in the table
--                       will be sent instead of the default value.
--@param lease_time      [optional] The lease time used when requestint an IP. Default: 1 second.
--@param transaction_id  The identity of the transaction.
--
--@return status (true or false)
--@return The parsed response, as a table.
function dhcp_build(request_type, ip_address, mac_address, options, request_options, overrides, lease_time, transaction_id)
  local packet = strbuf.new()

  -- Set up the default overrides
  if(overrides == nil) then
    overrides = {}
  end

  if(request_options == nil) then
    -- Request the defaults, or there's no verbosity; otherwise, request everything!
    request_options = strbuf.new()
    for i,v in pairs(actions) do
      if(v.default or nmap.verbosity() > 0) then
        request_options = request_options .. string.char(i)
      end
    end
    request_options = strbuf.dump(request_options)
  end

  -- Header
  packet = packet .. bin.pack(">CCCC", overrides['op'] or 1, overrides['htype'] or 1, overrides['hlen'] or 6, overrides['hops'] or 0)  -- BOOTREQUEST, 10mb ethernet, 6 bytes long, 0 hops
  packet = packet .. ( overrides['xid'] or transaction_id )                                                         -- Transaction ID =
  packet = packet .. bin.pack(">SS", overrides['secs'] or 0, overrides['flags'] or 0x0000)     -- Secs, flags
  packet = packet .. ip_address                                                 -- Client address
  packet = packet .. bin.pack("<I", overrides['yiaddr'] or 0)                                  -- yiaddr
  packet = packet .. bin.pack("<I", overrides['siaddr'] or 0)                                  -- siaddr
  packet = packet .. bin.pack("<I", overrides['giaddr'] or 0)                                  -- giaddr
  packet = packet .. mac_address .. string.rep('\0', 16 - #mac_address)                        -- chaddr (MAC address)
  packet = packet .. (overrides['sname'] or string.rep('\0', 64))                              -- sname
  packet = packet .. (overrides['file'] or string.rep('\0', 128))                              -- file
  packet = packet .. bin.pack(">I", overrides['cookie'] or 0x63825363)                         -- Magic cookie

  -- Options
  packet = packet .. bin.pack(">CCC", 0x35, 1, request_type)                                   -- Request type

  for _, option in ipairs(options or {}) do
    packet = packet .. bin.pack(">C", option.number)
    if ( "string" == option.type ) then
      packet = packet .. bin.pack("p", option.value)
    elseif( "ip" == option.type ) then
      packet = packet .. bin.pack(">CI", 4, option.value)
    end
  end

  packet = packet .. bin.pack(">CCA", 0x37, #request_options, request_options)                 -- Request options
  packet = packet .. bin.pack(">CCI", 0x33, 4, lease_time or 1)                                -- Lease time

  packet = packet .. bin.pack(">C", 0xFF)                                                      -- Termination

  return true, strbuf.dump(packet)
end

---Parse a DHCP packet (either a request or a response) and return the results
-- as a table.
--
-- The table at the top of this function (<code>actions</code>) defines the
-- name of each field, as laid out in rfc2132, and the function that parses it.
--
-- In theory, this should be able to parse any valid DHCP packet.
--
--@param data The DHCP packet data. Any padding at the end of the packet will
--            be ignored (by default, DHCP packets are padded with \x00 bytes).
function dhcp_parse(data, transaction_id)
  local pos = 1
  local result = {}

  -- Receive the first bit and make sure we got the correct operation back
  pos, result['op'], result['htype'], result['hlen'], result['hops'] = bin.unpack(">CCCC", data, pos)
  if(result['op'] ~= 2) then
    return false, string.format("DHCP server returned invalid reply ('op' wasn't BOOTREPLY (it was 0x%02x))", result['op'])
  end

  -- Confirm the transaction id
  pos, result['xid'] = bin.unpack("A4", data, pos)
  if(result['xid'] ~= transaction_id) then
    return false, string.format("DHCP server returned invalid reply (transaction id didn't match (%s != %s))", result['xid'], transaction_id)
  end

  -- Unpack the secs, flags, addresses, sname, and file
  pos, result['secs'], result['flags'] = bin.unpack(">SS", data, pos)
  pos, result['ciaddr'] = bin.unpack(">I", data, pos)
  pos, result['yiaddr'] = bin.unpack(">I", data, pos)
  pos, result['siaddr'] = bin.unpack(">I", data, pos)
  pos, result['giaddr'] = bin.unpack(">I", data, pos)
  pos, result['chaddr'] = bin.unpack("A16", data, pos)
  pos, result['sname']  = bin.unpack("A64", data, pos)
  pos, result['file']   = bin.unpack("A128", data, pos)

  -- Convert the addresses to strings
  result['ciaddr_str'] = ipOps.fromdword(result['ciaddr'])
  result['yiaddr_str'] = ipOps.fromdword(result['yiaddr'])
  result['siaddr_str'] = ipOps.fromdword(result['siaddr'])
  result['giaddr_str'] = ipOps.fromdword(result['giaddr'])

  -- Confirm the cookie
  pos, result['cookie'] = bin.unpack(">I", data, pos)
  if(result['cookie'] ~= 0x63825363) then
    return false, "DHCP server returned invalid reply (the magic cookie was invalid)"
  end

  -- Parse the options
  result['options'] = {}
  while true do
    if #data - pos < 2 then
      stdnse.debug1("Unexpected end of options")
      break
    end

    local option, length
    pos, option, length = bin.unpack(">CC", data, pos)

    -- Check for termination condition
    if(option == 0xFF) then
      break;
    end

    -- Get the action from the array, based on the code
    local action = actions[option]

    -- Verify we got a valid code (if we didn't, we're probably in big trouble)
    local value
    if(action == nil) then
      stdnse.debug1("dhcp-discover: Unknown option: %d", option)
      pos = pos + length
    else
      -- Call the function to parse the option, and insert the result into our results table

      stdnse.debug2("dhcp-discover: Attempting to parse %s", action['name'])
      pos, value = action['func'](data, pos, length)

      if(nmap.verbosity() == 0 and action.default == false) then
        stdnse.debug1("dhcp-discover: Server returned unrequested option (%s => %s)", action['name'], value)

      else
        if(value) then
          table.insert(result['options'], {name=action['name'], value=value})
        else
          stdnse.debug1("dhcp-discover: Couldn't determine value for %s", action['name']);
        end
      end
    end

    -- Handle the 'Option Overload' option specially -- if it's set, it tells us to use the file and/or sname values after we
    -- run out of data.
    if(option == 52) then
      if(value == 1) then
        data = data .. result['file']
      elseif(value == 2) then
        data = data .. result['sname']
      elseif(value == 3) then
        data = data .. result['file'] .. result['sname']
      else
        stdnse.debug1("dhcp-discover: Warning: 'Option Overload' gave an unsupported value: %d", value)
      end
    end
  end

  return true, result
end

---Build and send any kind of DHCP packet, and parse the response. This is the only interface
-- to the DHCP library, and should be the only one necessary.
--
-- All DHCP packet have the same structure, but different fields. It is therefore easy to build
-- any of the possible request types:
-- * DHCPDISCOVER
-- * DHCPOFFER
-- * DHCPREQUEST
-- * DHCPDECLINE
-- * DHCPACK
-- * DHCPNAK
-- * DHCPRELEASE
-- * DHCPINFORM
--
-- Although these will all build a valid packet with any option, and the default options (that can be
-- overridden with the <code>overrides</code> argument) won't necessarily work with every request
-- type. If you're going to build some DHCP code on your own, I recommend reading rfc2131.
--
--@param request_type    The type of request as an integer (use the <code>request_types</code> table at the
--                       top of this file).
--@param ip_address      Your ip address (as a dotted-decimal string). This tells the DHCP server where to
--                       send the response. Setting it to "255.255.255.255" or "0.0.0.0" is generally acceptable (if not,
--                       host.ip_src can work).
--@param mac_address     Your mac address (as a string up to 16 bytes) where the server will send the response. Like
--                       <code>ip_address</code>, setting to the broadcast address (FF:FF:FF:FF:FF:FF) is
--                       common (host.mac_addr_src works).
--@param options         [optional] A table of additional request options where each option is a table containing the
--                       following fields:
--                         * <code>number</code> - The option number
--                         * <code>type</code>   - The option type ("string" or "ip")
--                         * <code>value</code>  - The option value
--@param request_options [optional] The options to request from the server, as an array of integers. For the
--                       acceptable options, see the <code>actions</code> table above or have a look at rfc2132.
--                       Some DHCP servers (such as my Linksys WRT54g) will ignore this list and send whichever
--                       information it wants. Default: all options marked as 'default' in the <code>actions</code>
--                       table above are requested (the typical interesting ones) if no verbosity is given.
--                       If any level of verbosity is on, get all types.
--@param overrides       [optional] A table of overrides. If a field in the table matches a field in the DHCP
--                       packet (see rfc2131 section 2 for a list of possible fields), the value in the table
--                       will be sent instead of the default value.
--@param lease_time      [optional] The lease time used when requestint an IP. Default: 1 second.
--@return status (true or false)
--@return The parsed response, as a table.
function make_request(target, request_type, ip_address, mac_address, options, request_options, overrides, lease_time)
  -- A unique id that identifies this particular session (and lets us filter out what we don't want to see)
  local transaction_id = overrides and overrides['xid'] or bin.pack("<I", math.random(0, 0x7FFFFFFF))

  -- Generate the packet
  local status, packet = dhcp_build(request_type, bin.pack(">I", ipOps.todword(ip_address)), mac_address, options, request_options, overrides, lease_time, transaction_id)
  if(not(status)) then
    stdnse.debug1("dhcp: Couldn't build packet: " .. packet)
    return false, "Couldn't build packet: "  .. packet
  end

  local socket = nmap.new_socket("udp")
  socket:bind(nil, 68)
  socket:set_timeout(5000)

  -- Send the packet and get the response
  local status, response = dhcp_send(socket, target, packet)
  if(not(status)) then
    stdnse.debug1("dhcp: Couldn't send packet: " .. response)
    return false, "Couldn't send packet: "  .. response
  end

  status, response = dhcp_receive(socket, transaction_id)
  socket:close()

  if ( not(status) ) then
    stdnse.debug1("dhcp: Couldn't receive packet: " .. response)
    return false, "Couldn't receive packet: "  .. response
  end

  -- Parse the response
  local status, parsed = dhcp_parse(response, transaction_id)
  if(not(status)) then
    stdnse.debug1("dhcp: Couldn't parse response: " .. parsed)
    return false, "Couldn't parse response: "  .. parsed
  end

  return true, parsed
end


return _ENV;
