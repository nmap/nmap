---
-- Utility functions for manipulating and comparing IP addresses.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local bin = require "bin"
local bit = require "bit"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local type     = type
local ipairs   = ipairs
local tonumber = tonumber
local unittest = require "unittest"


_ENV = stdnse.module("ipOps", stdnse.seeall)

---
-- Checks to see if the supplied IP address is part of a non-routable
-- address space.
--
-- The non-Internet-routable address spaces known to this function are
-- * IPv4 Loopback (RFC3330)
-- * IPv4 Private Use (RFC1918)
-- * IPv4 Link Local (RFC3330)
-- * IPv4 IETF Protocol Assignments (RFC 5736)
-- * IPv4 TEST-NET-1, TEST-NET-2, TEST-NET-3 (RFC 5737)
-- * IPv4 Network Interconnect Device Benchmark Testing (RFC 2544)
-- * IPv4 Reserved for Future Use (RFC 1112, Section 4)
-- * IPv4 Multicast Local Network Control Block (RFC 3171, Section 3)
-- * IPv6 Unspecified and Loopback (RFC3513)
-- * IPv6 Site-Local (RFC3513, deprecated in RFC3879)
-- * IPv6 Unique Local Unicast (RFC4193)
-- * IPv6 Link Local Unicast (RFC4291)
-- @param ip  String representing an IPv4 or IPv6 address.  Shortened notation
-- is permitted.
-- @usage
-- local is_private = ipOps.isPrivate( "192.168.1.1" )
-- @return True or false (or <code>nil</code> in case of an error).
-- @return String error message in case of an error or
--         String non-routable address containing the supplied IP address.
isPrivate = function( ip )
  local err

  ip, err = expand_ip( ip )
  if err then return nil, err end

  if ip:match( ":" ) then

    local is_private
    local ipv6_private = { "::/127", "FC00::/7", "FE80::/10", "FEC0::/10" }

    for _, range in ipairs( ipv6_private ) do
      is_private, err = ip_in_range( ip, range )
      if is_private == true then
        return true, range
      end
      if err then
        return nil, err
      end
    end

  elseif ip:sub(1,3) == '10.' then

    return true, '10/8'

  elseif ip:sub(1,4) == '127.' then

    return true, '127/8'

  elseif ip:sub(1,8) == '169.254.' then

    return true, '169.254/16'

  elseif ip:sub(1,4) == '172.' then

    local p, e = ip_in_range(ip, '172.16/12')
    if p == true then
      return true, '172.16/12'
    else
      return p, e
    end

  elseif ip:sub(1,4) == '192.' then

    if ip:sub(5,8) == '168.' then
      return true, '192.168/16'
    elseif ip:match('^192%.[0][0]?[0]?%.[0][0]?[0]?%.') then
      return true, '192.0.0/24'
    elseif ip:match('^192%.[0][0]?[0]?%.[0]?[0]?2') then
      return true, '192.0.2/24'
    end

  elseif ip:sub(1,4) == '198.' then

    if ip:match('^198%.[0]?18%.') or ip:match('^198%.[0]?19%.') then
      return true, '198.18/15'
    elseif ip:match('^198%.[0]?51%.100%.') then
      return true, '198.51.100/24'
    end

  elseif ip:match('^203%.[0][0]?[0]?%.113%.') then

    return true, '203.0.113/24'

  elseif ip:match('^224%.[0][0]?[0]?%.[0][0]?[0]?%.') then

    return true, '224.0.0/24'

  elseif ip:match('^24[0-9]%.') or ip:match('^25[0-5]%.') then

    return true, '240.0.0/4'

  end

  return false, nil

end



---
-- Converts the supplied IPv4 address into a DWORD value.
--
-- For example, the address a.b.c.d becomes (((a*256+b)*256+c)*256+d).
--
-- Note: IPv6 addresses are not supported. Currently, numbers in NSE are
-- limited to 10^14, and consequently not all IPv6 addresses can be
-- represented. Consider using <code>ip_to_str</code> for IPv6 addresses.
-- @param ip  String representing an IPv4 address.  Shortened notation is
-- permitted.
-- @usage
-- local dword = ipOps.todword( "73.150.2.210" )
-- @return Number corresponding to the supplied IP address (or <code>nil</code>
-- in case of an error).
-- @return String error message in case of an error.
todword = function( ip )

  if type( ip ) ~= "string" or ip:match( ":" ) then
    return nil, "Error in ipOps.todword: Expected IPv4 address."
  end

  local n, ret, err = {}
  n, err = get_parts_as_number( ip )
  if err then return nil, err end

  ret = (((n[1]*256+n[2]))*256+n[3])*256+n[4]

  return ret

end

---
-- Converts the supplied IPv4 address from a DWORD value into a dotted string.
--
-- For example, the address (((a*256+b)*256+c)*256+d) becomes a.b.c.d.
--
--@param ip DWORD representing an IPv4 address.
--@return The string representing the address.
fromdword = function( ip )
  if type( ip ) ~= "number" then
    stdnse.debug1("Error in ipOps.fromdword: Expected 32-bit number.")
    return nil
  end

  local n1 = bit.band(bit.rshift(ip, 0),  0x000000FF)
  local n2 = bit.band(bit.rshift(ip, 8),  0x000000FF)
  local n3 = bit.band(bit.rshift(ip, 16), 0x000000FF)
  local n4 = bit.band(bit.rshift(ip, 24), 0x000000FF)

  return string.format("%d.%d.%d.%d", n1, n2, n3, n4)
end

---
-- Separates the supplied IP address into its constituent parts and
-- returns them as a table of numbers.
--
-- For example, the address 139.104.32.123 becomes { 139, 104, 32, 123 }.
-- @usage
-- local a, b, c, d;
-- local t, err = ipOps.get_parts_as_number( "139.104.32.123" )
-- if t then a, b, c, d = table.unpack( t ) end
-- @param ip  String representing an IPv4 or IPv6 address.  Shortened notation
-- is permitted.
-- @return   Array of numbers for each part of the supplied IP address (or
-- <code>nil</code> in case of an error).
-- @return String error message in case of an error.
get_parts_as_number = function( ip )
  local err

  ip, err = expand_ip( ip )
  if err then return nil, err end

  local pattern, base
  if ip:match( ":" ) then
    pattern = "%x+"
    base = 16
  else
    pattern = "%d+"
    base = 10
  end
  local t = {}
  for part in string.gmatch(ip, pattern) do
    t[#t+1] = tonumber( part, base )
  end

  return t

end



---
-- Compares two IP addresses.
--
-- When comparing addresses from different families,
-- IPv4 addresses will sort before IPv6 addresses.
-- @param left String representing an IPv4 or IPv6 address.  Shortened
--             notation is permitted.
-- @param op A comparison operator which may be one of the following strings:
--           <code>"eq"</code>, <code>"ge"</code>, <code>"le"</code>,
--           <code>"gt"</code> or <code>"lt"</code> (respectively ==, >=, <=,
--           >, <).
-- @param right String representing an IPv4 or IPv6 address.  Shortened
--              notation is permitted.
-- @usage
-- if ipOps.compare_ip( "2001::DEAD:0:0:0", "eq", "2001:0:0:0:DEAD::" ) then
--   ...
-- end
-- @return True or false (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
compare_ip = function( left, op, right )

  if type( left ) ~= "string" or type( right ) ~= "string" then
    return nil, "Error in ipOps.compare_ip: Expected IP address as a string."
  end

  local err ={}
  left, err[#err+1] = ip_to_str( left )
  right, err[#err+1] = ip_to_str( right )
  if #err > 0 then
    return nil, table.concat( err, " " )
  end

  if #left > #right then
    left = bin.pack( "CA", 0x06, left )
    right = bin.pack( "CA", 0x04, right )
  elseif #right > #left then
    right = bin.pack( "CA", 0x06, right )
    left = bin.pack( "CA", 0x04, left )
  end

  if ( op == "eq" ) then
    return ( left == right )
  elseif ( op == "ne" ) then
    return ( left ~= right )
  elseif ( op == "le" ) then
    return ( left <= right )
  elseif ( op == "ge" ) then
    return ( left >= right )
  elseif ( op == "lt" ) then
    return ( left < right )
  elseif ( op == "gt" ) then
    return ( left > right )
  end

  return nil, "Error in ipOps.compare_ip: Invalid Operator."
end



---
-- Checks whether the supplied IP address is within the supplied range of IP
-- addresses.
--
-- The address and the range must both belong to the same address family.
-- @param ip     String representing an IPv4 or IPv6 address.  Shortened
-- notation is permitted.
-- @param range  String representing a range of IPv4 or IPv6 addresses in
-- first-last or CIDR notation (e.g.
-- <code>"192.168.1.1 - 192.168.255.255"</code> or
-- <code>"2001:0A00::/23"</code>).
-- @usage
-- if ipOps.ip_in_range( "192.168.1.1", "192/8" ) then ... end
-- @return True or false (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
ip_in_range = function( ip, range )

  local first, last, err = get_ips_from_range( range )
  if err then return nil, err end
  ip, err = expand_ip( ip )
  if err then return nil, err end
  if ( ip:match( ":" ) and not first:match( ":" ) ) or ( not ip:match( ":" ) and first:match( ":" ) ) then
    return nil, "Error in ipOps.ip_in_range: IP address is of a different address family to Range."
  end

  err = {}
  local ip_ge_first, ip_le_last
  ip_ge_first, err[#err+1] = compare_ip( ip, "ge", first )
  ip_le_last, err[#err+1] = compare_ip( ip, "le", last )
  if #err > 0 then
    return nil, table.concat( err, " " )
  end

  if ip_ge_first and ip_le_last then
    return true
  else
    return false
  end

end



---
-- Expands an IP address supplied in shortened notation.
-- Serves also to check the well-formedness of an IP address.
--
-- Note: IPv4in6 notated addresses will be returned in pure IPv6 notation unless
-- the IPv4 portion is shortened and does not contain a dot, in which case the
-- address will be treated as IPv6.
-- @param ip  String representing an IPv4 or IPv6 address in shortened or full notation.
-- @param family String representing the address family to expand to. Only
-- affects IPv4 addresses when "inet6" is provided, causing the function to
-- return an IPv4-mapped IPv6 address.
-- @usage
-- local ip = ipOps.expand_ip( "2001::" )
-- @return    String representing a fully expanded IPv4 or IPv6 address (or
-- <code>nil</code> in case of an error).
-- @return String error message in case of an error.
expand_ip = function( ip, family )
  local err

  if type( ip ) ~= "string" or ip == "" then
    return nil, "Error in ipOps.expand_ip: Expected IP address as a string."
  end

  local err4 = "Error in ipOps.expand_ip: An address assumed to be IPv4 was malformed."

  if not ip:match( ":" ) then
    -- ipv4: missing octets should be "0" appended
    if ip:match( "[^%.0-9]" ) then
      return nil, err4
    end
    local octets = {}
    for octet in string.gmatch( ip, "%d+" ) do
      if tonumber( octet, 10 ) > 255 then return nil, err4 end
      octets[#octets+1] = octet
    end
    if #octets > 4 then return nil, err4 end
    while #octets < 4 do
      octets[#octets+1] = "0"
    end
    if family == "inet6" then
      return ( table.concat( { 0,0,0,0,0,"ffff",
        stdnse.tohex( 256*octets[1]+octets[2] ),
        stdnse.tohex( 256*octets[3]+octets[4] )
        }, ":" ) )
    else
      return ( table.concat( octets, "." ) )
    end
  end

  if family ~= nil and family ~= "inet6" then
    return nil, "Error in ipOps.expand_ip: Cannot convert IPv6 address to IPv4"
  end

  if ip:match( "[^%.:%x]" ) then
    return nil, ( err4:gsub( "IPv4", "IPv6" ) )
  end

  -- preserve ::
  ip = string.gsub(ip, "::", ":z:")

  -- get a table of each hexadectet
  local hexadectets = {}
  for hdt in string.gmatch( ip, "[%.z%x]+" ) do
    hexadectets[#hexadectets+1] = hdt
  end

  -- deal with IPv4in6 (last hexadectet only)
  local t = {}
  if hexadectets[#hexadectets]:match( "[%.]+" ) then
    hexadectets[#hexadectets], err = expand_ip( hexadectets[#hexadectets] )
    if err then return nil, ( err:gsub( "IPv4", "IPv4in6" ) ) end
    t = stdnse.strsplit( "[%.]+", hexadectets[#hexadectets] )
    for i, v in ipairs( t ) do
      t[i] = tonumber( v, 10 )
    end
    hexadectets[#hexadectets] = stdnse.tohex( 256*t[1]+t[2] )
    hexadectets[#hexadectets+1] = stdnse.tohex( 256*t[3]+t[4] )
  end

  -- deal with :: and check for invalid address
  local z_done = false
  for index, value in ipairs( hexadectets ) do
    if value:match( "[%.]+" ) then
      -- shouldn't have dots at this point
      return nil, ( err4:gsub( "IPv4", "IPv6" ) )
    elseif value == "z" and z_done then
      -- can't have more than one ::
      return nil, ( err4:gsub( "IPv4", "IPv6" ) )
    elseif value == "z" and not z_done then
      z_done = true
      hexadectets[index] = "0"
      local bound = 8 - #hexadectets
      for i = 1, bound, 1 do
        table.insert( hexadectets, index+i, "0" )
      end
    elseif tonumber( value, 16 ) > 65535 then
      -- more than FFFF!
      return nil, ( err4:gsub( "IPv4", "IPv6" ) )
    end
  end

  -- make sure we have exactly 8 hexadectets
  if #hexadectets > 8 then return nil, ( err4:gsub( "IPv4", "IPv6" ) ) end
  while #hexadectets < 8 do
    hexadectets[#hexadectets+1] = "0"
  end

  return ( table.concat( hexadectets, ":" ) )

end



---
-- Returns the first and last IP addresses in the supplied range of addresses.
-- @param range  String representing a range of IPv4 or IPv6 addresses in either
-- CIDR or first-last notation.
-- @usage
-- first, last = ipOps.get_ips_from_range( "192.168.0.0/16" )
-- @return       String representing the first address in the supplied range (or
-- <code>nil</code> in case of an error).
-- @return       String representing the last address in the supplied range (or
-- <code>nil</code> in case of an error).
-- @return       String error message in case of an error.
get_ips_from_range = function( range )

  if type( range ) ~= "string" then
    return nil, nil, "Error in ipOps.get_ips_from_range: Expected a range as a string."
  end

  local first, last, prefix
  if range:match( "/" ) then
    first, prefix = range:match( "([%x%d:%.]+)/(%d+)" )
  elseif range:match( "-" ) then
    first, last = range:match( "([%x%d:%.]+)%s*%-%s*([%x%d:%.]+)" )
  end

  local err = {}
  if first and ( last or prefix ) then
    first, err[#err+1] = expand_ip( first )
  else
    return nil, nil, "Error in ipOps.get_ips_from_range: The range supplied could not be interpreted."
  end
  if last then
    last, err[#err+1] = expand_ip( last )
  elseif first and prefix then
    last, err[#err+1] = get_last_ip( first, prefix )
  end

  if first and last then
    if ( first:match( ":" ) and not last:match( ":" ) ) or ( not first:match( ":" ) and last:match( ":" ) ) then
      return nil, nil, "Error in ipOps.get_ips_from_range: First IP address is of a different address family to last IP address."
    end
    return first, last
  else
    return nil, nil, table.concat( err, " " )
  end

end



---
-- Calculates the last IP address of a range of addresses given an IP address in
-- the range and prefix length for that range.
-- @param ip String representing an IPv4 or IPv6 address.  Shortened notation
--           is permitted.
-- @param prefix Number or a string representing a decimal number corresponding
--               to a prefix length.
-- @usage
-- last = ipOps.get_last_ip( "192.0.0.0", 26 )
-- @return String representing the last IP address of the range denoted by the
--         supplied parameters (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
get_last_ip = function( ip, prefix )

  local first, err = ip_to_bin( ip )
  if err then return nil, err end

  prefix = tonumber( prefix )
  if not prefix or ( prefix < 0 ) or ( prefix > # first  ) then
    return nil, "Error in ipOps.get_last_ip: Invalid prefix length."
  end

  local hostbits = string.sub( first, prefix + 1 )
  hostbits = string.gsub( hostbits, "0", "1" )
  local last = string.sub( first, 1, prefix ) .. hostbits
  last, err = bin_to_ip( last )
  if err then return nil, err end
  return last

end

---
-- Converts an IP address into an opaque string (big-endian)
-- @param ip  String representing an IPv4 or IPv6 address.
-- @param family (optional) Address family to convert to. "ipv6" converts IPv4
-- addresses to IPv4-mapped IPv6.
-- @usage
-- opaque = ipOps.ip_to_str( "192.168.3.4" )
-- @return 4- or 16-byte string representing IP address (or <code>nil</code>
-- in case of an error).
-- @return String error message in case of an error
ip_to_str = function( ip, family )
  local err

  ip, err = expand_ip( ip, family )
  if err then return nil, err end

  local t = {}

  if not ip:match( ":" ) then
    -- ipv4 string
    for octet in string.gmatch( ip, "%d+" ) do
      t[#t+1] = bin.pack( ">C", tonumber(octet) )
    end
  else
    -- ipv6 string
    for hdt in string.gmatch( ip, "%x+" ) do
      t[#t+1] = bin.pack( ">S", tonumber(hdt, 16) )
    end
  end


  return table.concat( t )
end

---
-- Converts an opaque string (big-endian) into an IP address
--
-- @param ip Opaque string representing an IP address. If length 4, then IPv4
--           is assumed. If length 16, then IPv6 is assumed.
-- @return IP address in readable notation (or <code>nil</code> in case of an
--         error)
-- @return String error message in case of an error
str_to_ip = function (ip)
  if #ip == 4 then
    local _, a, b, c, d = bin.unpack("C4", ip)
    return ("%d.%d.%d.%d"):format(a, b, c, d)
  elseif #ip == 16 then
    local _, a, b, c, d, e, f, g, h = bin.unpack(">S8", ip)
    local full = ("%x:%x:%x:%x:%x:%x:%x:%x"):format(a, b, c, d, e, f, g, h)
    full = full:gsub(":[:0]+", "::", 1) -- Collapse the first (should be longest?) series of :0:
    full = full:gsub("^0::", "::", 1) -- handle special case of ::1
    return full
  else
    return nil, "Invalid length"
  end
end

---
-- Converts an IP address into a string representing the address as binary
-- digits.
-- @param ip String representing an IPv4 or IPv6 address.  Shortened notation
--           is permitted.
-- @usage
-- bit_string = ipOps.ip_to_bin( "2001::" )
-- @return String representing the supplied IP address as 32 or 128 binary
--         digits (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
ip_to_bin = function( ip )
  local err

  ip, err = expand_ip( ip )
  if err then return nil, err end

  local t, mask = {}

  if not ip:match( ":" ) then
    -- ipv4 string
    for octet in string.gmatch( ip, "%d+" ) do
      t[#t+1] = stdnse.tohex( tonumber(octet) )
    end
    mask = "00"
  else
    -- ipv6 string
    for hdt in string.gmatch( ip, "%x+" ) do
      t[#t+1] = hdt
    end
    mask = "0000"
  end

  -- padding
  for i, v in ipairs( t ) do
    t[i] = mask:sub( 1, # mask  - # v  ) .. v
  end

  return hex_to_bin( table.concat( t ) )

end



---
-- Converts a string of binary digits into an IP address.
-- @param binstring  String representing an IP address as 32 or 128 binary
-- digits.
-- @usage
-- ip = ipOps.bin_to_ip( "01111111000000000000000000000001" )
-- @return           String representing an IP address (or <code>nil</code> in
-- case of an error).
-- @return           String error message in case of an error.
bin_to_ip = function( binstring )

  if type( binstring ) ~= "string" or binstring:match( "[^01]+" ) then
    return nil, "Error in ipOps.bin_to_ip: Expected string of binary digits."
  end

  local af
  if # binstring  == 32 then
    af = 4
  elseif # binstring  == 128 then
    af = 6
  else
    return nil, "Error in ipOps.bin_to_ip: Expected exactly 32 or 128 binary digits."
  end

  local t = {}
  if af == 6 then
    local pattern = string.rep( "[01]", 16 )
    for chunk in string.gmatch( binstring, pattern ) do
      t[#t+1] = stdnse.tohex( tonumber( chunk, 2 ) )
    end
    return table.concat( t, ":" )
  end

  if af == 4 then
    local pattern = string.rep( "[01]", 8 )
    for chunk in string.gmatch( binstring, pattern ) do
      t[#t+1] = tonumber( chunk, 2 ) .. ""
    end
    return table.concat( t, "." )
  end

end



---
-- Converts a string of hexadecimal digits into the corresponding string of
-- binary digits.
--
-- Each hex digit results in four bits.
-- @param hex  String representing a hexadecimal number.
-- @usage
-- bin_string = ipOps.hex_to_bin( "F00D" )
-- @return     String representing the supplied number in binary digits (or
-- <code>nil</code> in case of an error).
-- @return     String error message in case of an error.
hex_to_bin = function( hex )

  if type( hex ) ~= "string" or hex == "" or hex:match( "[^%x]+" ) then
    return nil, "Error in ipOps.hex_to_bin: Expected string representing a hexadecimal number."
  end

  local d = bin.pack("H", hex)
  local _, b = bin.unpack("B" .. #d, d)
  return b:sub(1, #hex * 4)
end

--Ignore the rest if we are not testing.
if not unittest.testing() then
  return _ENV
end

test_suite = unittest.TestSuite:new()
test_suite:add_test(unittest.is_true(isPrivate("192.168.123.123")), "192.168.123.123 is private")
test_suite:add_test(unittest.is_false(isPrivate("1.1.1.1")), "1.1.1.1 is not private")
test_suite:add_test(unittest.equal(todword("65.66.67.68"),0x41424344), "todword")
test_suite:add_test(unittest.equal(fromdword(0xffffffff),"255.255.255.255"), "fromdword")
test_suite:add_test(unittest.equal(str_to_ip("\x01\x02\x03\x04"),"1.2.3.4"), "str_to_ip (ipv4)")
test_suite:add_test(unittest.equal(str_to_ip("\0\x01\xbe\xef\0\0\0\0\0\0\x02\x03\0\0\0\x01"),"1:beef::203:0:1"), "str_to_ip (ipv6)")
test_suite:add_test(unittest.equal(str_to_ip(("\0"):rep(15) .. "\x01"),"::1"), "str_to_ip (ipv6)")
test_suite:add_test(function()
  local parts, err = get_parts_as_number("8.255.0.1")
  if parts == nil then return false, err end
  if parts[1] == 8 and parts[2] == 255 and parts[3] == 0 and parts[4] == 1 then
    return true
  end
  return false, string.format("Expected {8, 255, 0, 1}, got {%d, %d, %d, %d}", table.unpack(parts))
end, "get_parts_as_number")

do
  local low_ip4 = "192.168.1.10"
  local high_ip4 = "192.168.10.1"
  local low_ip6 = "2001::DEAD:0:0:9"
  local high_ip6 = "2001::DEAF:0:0:9"
  for _, op in ipairs({
    {low_ip4, "eq", low_ip4, unittest.is_true, "IPv4"},
    {low_ip6, "eq", low_ip6, unittest.is_true, "IPv6"},
    {high_ip4, "eq", low_ip4, unittest.is_false, "IPv4"},
    {high_ip6, "eq", low_ip6, unittest.is_false, "IPv6"},
    {low_ip4, "eq", low_ip6, unittest.is_false, "mixed"},
    {low_ip4, "ne", low_ip4, unittest.is_false, "IPv4"},
    {low_ip6, "ne", low_ip6, unittest.is_false, "IPv6"},
    {high_ip4, "ne", low_ip4, unittest.is_true, "IPv4"},
    {high_ip6, "ne", low_ip6, unittest.is_true, "IPv6"},
    {low_ip4, "ne", low_ip6, unittest.is_true, "mixed"},
    {low_ip4, "ge", low_ip4, unittest.is_true, "IPv4, equal"},
    {low_ip6, "ge", low_ip6, unittest.is_true, "IPv6, equal"},
    {high_ip4, "ge", low_ip4, unittest.is_true, "IPv4"},
    {high_ip6, "ge", low_ip6, unittest.is_true, "IPv6"},
    {low_ip4, "ge", high_ip4, unittest.is_false, "IPv4"},
    {low_ip6, "ge", high_ip6, unittest.is_false, "IPv6"},
    {low_ip6, "ge", low_ip4, unittest.is_true, "mixed"},
    {low_ip4, "ge", low_ip6, unittest.is_false, "mixed"},
    {low_ip4, "le", low_ip4, unittest.is_true, "IPv4, equal"},
    {low_ip6, "le", low_ip6, unittest.is_true, "IPv6, equal"},
    {high_ip4, "le", low_ip4, unittest.is_false, "IPv4"},
    {high_ip6, "le", low_ip6, unittest.is_false, "IPv6"},
    {low_ip4, "le", high_ip4, unittest.is_true, "IPv4"},
    {low_ip6, "le", high_ip6, unittest.is_true, "IPv6"},
    {low_ip6, "le", low_ip4, unittest.is_false, "mixed"},
    {low_ip4, "le", low_ip6, unittest.is_true, "mixed"},
    {low_ip4, "gt", low_ip4, unittest.is_false, "IPv4, equal"},
    {low_ip6, "gt", low_ip6, unittest.is_false, "IPv6, equal"},
    {high_ip4, "gt", low_ip4, unittest.is_true, "IPv4"},
    {high_ip6, "gt", low_ip6, unittest.is_true, "IPv6"},
    {low_ip4, "gt", high_ip4, unittest.is_false, "IPv4"},
    {low_ip6, "gt", high_ip6, unittest.is_false, "IPv6"},
    {low_ip6, "gt", low_ip4, unittest.is_true, "mixed"},
    {low_ip4, "gt", low_ip6, unittest.is_false, "mixed"},
    {low_ip4, "lt", low_ip4, unittest.is_false, "IPv4, equal"},
    {low_ip6, "lt", low_ip6, unittest.is_false, "IPv6, equal"},
    {high_ip4, "lt", low_ip4, unittest.is_false, "IPv4"},
    {high_ip6, "lt", low_ip6, unittest.is_false, "IPv6"},
    {low_ip4, "lt", high_ip4, unittest.is_true, "IPv4"},
    {low_ip6, "lt", high_ip6, unittest.is_true, "IPv6"},
    {low_ip6, "lt", low_ip4, unittest.is_false, "mixed"},
    {low_ip4, "lt", low_ip6, unittest.is_true, "mixed"},
    }) do
    test_suite:add_test(op[4](compare_ip(op[1], op[2], op[3])),
      string.format("compare_ip(%s, %s, %s) (%s)", op[1], op[2], op[3], op[5]))
  end
end

do
  for _, op in ipairs({
    {"192.168.13.1", "192/8", unittest.is_true, "IPv4 CIDR"},
    {"193.168.13.1", "192/8", unittest.is_false, "IPv4 CIDR"},
    {"2001:db8::9", "2001:db8/32", unittest.is_true, "IPv6 CIDR"},
    {"2001:db7::9", "2001:db8/32", unittest.is_false, "IPv6 CIDR"},
    {"192.168.13.1", "192.168.10.33-192.168.80.80", unittest.is_true, "IPv4 range"},
    {"193.168.13.1", "192.168.1.1 - 192.168.5.0", unittest.is_false, "IPv4 range"},
    {"2001:db8::9", "2001:db8::1-2001:db8:1::1", unittest.is_true, "IPv6 range"},
    {"2001:db8::9", "2001:db8:10::1-2001:db8:11::1", unittest.is_false, "IPv6 range"},
    {"193.168.1.1", "192.168.1.1 - 2001:db8::1", unittest.is_nil, "mixed"},
    {"2001:db8::1", "192.168.1.1 - 2001:db8::1", unittest.is_nil, "mixed"},
    }) do
    test_suite:add_test(op[3](ip_in_range(op[1], op[2])),
      string.format("ip_in_range(%s, %s) (%s)", op[1], op[2], op[4]))
  end
end

do
  for _, op in ipairs({
    {"192.168", nil, "192.168.0.0", "IPv4 trunc"},
    {"192.0.2.3", nil, "192.0.2.3", "IPv4"},
    {"192.168", "inet6", "0:0:0:0:0:ffff:c0a8:0", "IPv4 trunc to IPv6"},
    {"2001:db8::9", nil, "2001:db8:0:0:0:0:0:9", "IPv6"},
    {"::ffff:192.0.2.128", "inet6", "0:0:0:0:0:ffff:c000:280", "IPv4-mapped to IPv6"},
    -- TODO: Perhaps we should support extracting IPv4 from IPv4-mapped addresses?
    --{"::ffff:192.0.2.128", "inet4", "192.0.2.128", "IPv4-mapped to IPv4"},
    --{"::ffff:c000:0280", "inet4", "192.0.2.128", "IPv4-mapped to IPv4"},
    }) do
    test_suite:add_test(unittest.equal(expand_ip(op[1], op[2]), op[3]),
      string.format("expand_ip(%s, %s) (%s)", op[1], op[2], op[4]))
  end
  test_suite:add_test(unittest.is_nil(expand_ip("2001:db8::1", "ipv4")),
      "IPv6 to IPv4")
end

return _ENV;
