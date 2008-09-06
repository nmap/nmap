id = "AS Numbers"
description = [[
This script performs IP address to Autonomous System Numbers (ASN) lookups.  It
sends DNS TXT queries to a DNS server which in turn queries a third party service
provided by Team Cymru (team-cymru.org) using an in-addr.arpa style zone set-up
especially for use by Nmap.
\n
The respnses to these queries contain both Origin and Peer ASNs and their descriptions,
displayed along with the BG Prefix and Country Code.
\n
The script caches results to reduce the number of queries and should perform a single
query for all scanned targets in a BG Prefix present in Team Cymru's database.
\n\n
Please be aware that any targets for which a query is performed will be revealed
to a Team Cymru.
]]


---
-- @usage
-- nmap <target> --script asn
--
-- @args dns Optional recursive nameserver.  e.g. --script-args dns=192.168.1.1
--
-- @output
-- Host script results:
-- \n|  AS Numbers:
-- \n|  BGP: 64.13.128.0/21 | Country: US
-- \n|    Origin AS: 10565 SVCOLO-AS - Silicon Valley Colocation, Inc.
-- \n|      Peer AS: 3561 6461
-- \n|  BGP: 64.13.128.0/18 | Country: US
-- \n|    Origin AS: 10565 SVCOLO-AS - Silicon Valley Colocation, Inc.
-- \n|_     Peer AS: 174 2914 6461
--


author = "jah, Michael"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}
runlevel = 1



local dns   = require "dns"
local comm  = require "comm"


local mutex = nmap.mutex( id )
if not nmap.registry.asn then
  nmap.registry.asn = {}
  nmap.registry.asn.cache = {}
  nmap.registry.asn.descr = {}
end



---
-- This script will run for any non-private IP address.

hostrule = function( host )
  return not isPrivate( host.ip )
end



---
-- Cached results are checked before sending a query for the target and extracting the
-- relevent information from the response.  Mutual exclusion is used so that results can be
-- cached and so a single thread will be active at any time.
-- @param host  Host Table.
-- @return      Formatted answers or nil on NXDOMAIN/errors.

action = function( host )

  mutex "lock"

  -- check for cached data
  local in_cache, records
  local combined_records = {}

  in_cache, records = check_cache( host.ip )
  records = records or {}

  if not in_cache then

    ---
    -- @class table
    -- @name cymru
    -- Team Cymru zones for rDNS like queries.  The zones are as follows:
    -- \n nmap.asn.cymru.com for IPv4 to Origin AS lookup.
    -- \n peer-nmap.asn.cymru.com for IPv4 to Peer AS lookup.
    -- \n nmap6.asn.cymru.com for IPv6 to Origin AS lookup.
    local cymru = { [4] = { ["Origin"] = ".nmap.asn.cymru.com", ["Peer"] = ".peer-nmap.asn.cymru.com" },
                    [6] = { ["Origin"] = ".nmap6.asn.cymru.com" }
    }
    local zone_repl, IPv = "%.in%-addr%.arpa", 4
    if host.ip:match( ":" ) then
      zone_repl, IPv = "%.ip6%.arpa", 6
    end

    -- name to query for
    local dname = reverse( host.ip )

    -- perform queries for each applicable zone
    for asn_type, zone in pairs( cymru[IPv] ) do
      -- replace arpa with cymru zone
      local temp = dname
      dname = dname:gsub( zone_repl, zone )
      -- send query and recognise and organise fields from response
      local success, retval = result_recog( ip_to_asn( dname ), asn_type, records )
      -- if success then records = retval end
      -- un-replace arpa zone
      dname = temp
    end

    -- combine records into unique BGP
    for _, record in ipairs( records ) do
      if not combined_records[record.cache_bgp] then
        combined_records[record.cache_bgp] = record
      elseif combined_records[record.cache_bgp].asn_type ~= record.asn_type then
        -- origin before peer.
        if record.asn_type == "Origin" then
          combined_records[record.cache_bgp].asn = { unpack( record.asn ), unpack( combined_records[record.cache_bgp].asn ) }
        else
          combined_records[record.cache_bgp].asn = { unpack( combined_records[record.cache_bgp].asn ), unpack( record.asn ) }
        end
      end
    end

    -- cache combined records
    for _, rec in pairs( combined_records ) do
      table.insert( nmap.registry.asn.cache, rec )
    end

  else -- records were in the cache
    combined_records = records
  end

  -- format each combined_record for output
  local output = {}
  for _, rec in pairs( combined_records ) do
    local r = {}
    if rec.bgp then r[#r+1] = rec.bgp end
    if rec.co then r[#r+1] = rec.co end
    output[#output+1] = ( "%s\n  %s" ):format( table.concat( r, " | " ), table.concat( rec.asn, "\n    " ) )
  end

  mutex "done"

  if type( output ) ~= "table" or #output == 0 then return nil end
  -- sort BGP asc.
  table.sort( output, function(a,b) return (get_prefix_length(a) or 0) > (get_prefix_length(b) or 0) end )

  -- return combined and formatted answers
  return (" \n%s"):format( table.concat( output, "\n" ) )

end


---
-- Checks whether the target IP address is within any BGP prefixes for which a query has
-- already been performed and returns any applicable answers.
-- @param ip String representing the target IP address.
-- @return   Boolean True if there are cached answers for the supplied target, otherwise
--           false.
-- @return   Table containing a string for each answer or nil if there are none.

function check_cache( ip )
  local ret = {}
  for _, cache_entry in ipairs( nmap.registry.asn.cache ) do
    if ip_in_range( ip, cache_entry.cache_bgp ) then
      ret[#ret+1] = cache_entry
    end
  end
  if #ret > 0 then return true, ret end
  return false, nil
end


---
-- Extracts fields from the supplied DNS answer sections.
-- @param answers    Table containing string DNS answers.
-- @param asn_type   String denoting whether the query is for Origin or Peer ASN.
-- @param recs       Table of existing recognised answers to which to add (ref to actions() records{}.
-- @return           Boolean true if successful otherwise false.

function result_recog( answers, asn_type, recs )

  if type( answers ) ~= "table" or #answers == 0 then return false end

  for _, answer in ipairs( answers ) do
    local t = {}
    -- break the answer up into fields and strip whitespace
    local fields = { answer:match( ("([^|]*)|" ):rep(3) ) }
    for i, field in ipairs( fields ) do
      fields[i] = field:gsub( "^%s*(.-)%s*$", "%1" )
    end
    -- assign fields with labels to table
    t.cache_bgp = fields[2]
    t.asn_type = asn_type
    t.asn = { asn_type .. " AS: " .. fields[1] }
    t.bgp = "BGP: "     .. fields[2]
    if fields[3] ~= "" then t.co = "Country: " .. fields[3] end
    recs[#recs+1] = t
    -- lookup AS descriptions for Origin AS numbers
    local asn_descr = nmap.registry.asn.descr
    local u = {}
    if asn_type == "Origin" then
      for num in fields[1]:gmatch( "%d+" ) do
        if not asn_descr[num] then
          asn_descr[num] = asn_description( num )
        end
        u[#u+1] = ( "%s AS: %s%s%s" ):format( asn_type, num, ( asn_descr[num] ~= "" and " - " ) or "", asn_descr[num] )
      end
      t.asn = { table.concat(u, "\n  " ) }
    end
  end

  return true

end


---
-- Performs an IP address to ASN lookup.  See http://www.team-cymru.org/Services/ip-to-asn.html#dns
-- @param query String - PTR like DNS query.
-- @return      Table containing string answers or Boolean false.

function ip_to_asn( query )

  if type( query ) ~= "string" or query == "" then
    return nil
  end

  -- dns query options
  local options = {}
  options.dtype = "TXT"
  options.retAll = true
  if type( nmap.registry.args.dns ) == "string" and nmap.registry.args.dns ~= "" then
    options.host = nmap.registry.args.dns
    options.port = 53
  end

  local decoded_response, other_response = dns.query( query, options)

  return decoded_response

end


---
-- Performs an AS Number to AS Description lookup.
-- @param asn String AS Number
-- @return    String Description or ""

function asn_description( asn )

  if type( asn ) ~= "string" or asn == "" then
    return ""
  end

  -- dns query options
  local options = {}
  options.dtype = "TXT"
  if type( nmap.registry.args.dns ) == "string" and nmap.registry.args.dns ~= "" then
    options.host = nmap.registry.args.dns
    options.port = 53
  end

  -- send query
  local query = ( "AS%s.asn.cymru.com" ):format( asn )
  local decoded_response, other_response = dns.query( query, options)
  if type( decoded_response ) ~= "string" then
    return ""
  end

  return decoded_response:match( "|%s*([^|$]+)%s*$" ) or ""

end



-- *** UTILITY FUNCTIONS ***
--     remove when these functions are available in libraries


---
-- Formats IP for reverse lookup.
-- @param ip String IP address.
-- @return   "Domain" style representation of IP as subdomain of in-addr.arpa or ip6.arpa

function reverse(ip)
   ip = expand_ip(ip)
   if type(ip) ~= "string" then return nil end
   local delim = "%."
   local arpa = ".in-addr.arpa"
   if ip:match(":") then
      delim = ":"
      arpa = ".ip6.arpa"
   end
   local ipParts = stdnse.strsplit(delim, ip)
   if #ipParts == 8 then
      -- padding
      local mask = "0000"
      for i, part in ipairs(ipParts) do
          ipParts[i] = mask:sub(1, string.len(mask) - string.len(part)) .. part
      end
      -- 32 parts from 8
      local temp = {}
      for i, hdt in ipairs(ipParts) do
         for part in hdt:gmatch("%x") do
          temp[#temp+1] = part
         end
      end
      ipParts = temp
   end
   local ipReverse = {}
   for i = #ipParts, 1, -1 do
      table.insert(ipReverse, ipParts[i])
   end
   return table.concat(ipReverse, ".") .. arpa
end


---
-- Checks to see if the supplied IP address is part of the following non-internet-routable address spaces:
-- IPv4 Loopback (RFC3330),
-- IPv4 Private Use (RFC1918),
-- IPv4 Link Local (RFC3330),
-- IPv6 Unspecified and Loopback (RFC3513),
-- IPv6 Unique Local Unicast (RFC4193),
-- IPv6 Link Local Unicast (RFC4291)
-- @param ip  String representing an IPv4 or IPv6 address.  Shortened notation is permitted.
-- @usage     local is_private = isPrivate( "192.168.1.1" )
-- @return    Boolean True or False (or nil in case of an error).
-- @return    Nil (or String error message in case of an error).

isPrivate = function( ip )

  ip, err = expand_ip( ip )
  if err then return nil, err end

  local ipv4_private = { "10/8", "127/8", "169.254/16", "172.15/12", "192.168/16" }
  local ipv6_private = { "::/127", "FC00::/7", "FE80::/10" }
  local t, is_private = {}
  if ip:match( ":" ) then
    t = ipv6_private
  else
    t = ipv4_private
  end

  for _, range in ipairs( t ) do
    is_private, err = ip_in_range( ip, range )
    -- return as soon as is_private is true or err
    if is_private then return true end
    if err then return nil, err end
  end
  return false

end


---
-- Checks whether the supplied IP address is within the supplied Range of IP addresses if they belong to the same address family.
-- @param ip     String representing an IPv4 or IPv6 address.  Shortened notation is permitted.
-- @param range  String representing a range of IPv4 or IPv6 addresses in first-last or cidr notation  (e.g. "192.168.1.1 - 192.168.255.255" or "2001:0A00::/23").
-- @usage        if ip_in_range( "192.168.1.1", "192/8" ) then ...
-- @return       Boolean True or False (or nil in case of an error).
-- @return       Nil (or String error message in case of an error).

ip_in_range = function( ip, range )

  local first, last, err = get_ips_from_range( range )
  if err then return nil, err end
  ip, err = expand_ip( ip )
  if err then return nil, err end
  if ( ip:match( ":" ) and not first:match( ":" ) ) or ( not ip:match( ":" ) and first:match( ":" ) ) then
    return nil, "Error in ip_in_range: IP address is of a different address family to Range."
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
-- Note: IPv4in6 notated addresses will be returned in pure IPv6 notation unless the IPv4 portion
-- is shortened and does not contain a dot - in which case the address will be treated as IPv6.
-- @param ip  String representing an IPv4 or IPv6 address in shortened or full notation.
-- @usage     local ip = expand_ip( "2001::" )
-- @return    String representing a fully expanded IPv4 or IPv6 address (or nil in case of an error).
-- @return    Nil (or String error message in case of an error).

expand_ip = function( ip )

  if type( ip ) ~= "string" or ip == "" then
    return nil, "Error in expand_ip: Expected IP address as a string."
  end

  local err4 = "Error in expand_ip: An address assumed to be IPv4 was malformed."

  if not ip:match( ":" ) then
    -- ipv4: missing octets should be "0" appended
    if ip:match( "[^\.0-9]" ) then
      return nil, err4
    end
    local octets = {}
    for octet in string.gfind( ip, "%d+" ) do
      if tonumber( octet, 10 ) > 255 then return nil, err4 end
      octets[#octets+1] = octet
    end
    if #octets > 4 then return nil, err4 end
    while #octets < 4 do
      octets[#octets+1] = "0"
    end
    return ( table.concat( octets, "." ) )
  end

  if ip:match( "[^\.:%x]" ) then
    return nil, ( err4:gsub( "IPv4", "IPv6" ) )
  end

  -- preserve ::
  ip = string.gsub(ip, "::", ":z:")

  -- get a table of each hexadectet
  local hexadectets = {}
  for hdt in string.gfind( ip, "[\.z%x]+" ) do
    hexadectets[#hexadectets+1] = hdt
  end

  -- deal with IPv4in6 (last hexadectet only)
  local t = {}
  if hexadectets[#hexadectets]:match( "[\.]+" ) then
    hexadectets[#hexadectets], err = expand_ip( hexadectets[#hexadectets] )
    if err then return nil, ( err:gsub( "IPv4", "IPv4in6" ) ) end
    t = stdnse.strsplit( "[\.]+", hexadectets[#hexadectets] )
    for i, v in ipairs( t ) do
      t[i] = tonumber( v, 10 )
    end
    hexadectets[#hexadectets] = stdnse.tohex( 256*t[1]+t[2] )
    hexadectets[#hexadectets+1] = stdnse.tohex( 256*t[3]+t[4] )
  end

  -- deal with :: and check for invalid address
  local z_done = false
  for index, value in ipairs( hexadectets ) do
    if value:match( "[\.]+" ) then
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
-- Compares two IP addresses (from the same address family).
-- @param left   String representing an IPv4 or IPv6 address.  Shortened notation is permitted.
-- @param op     A comparison operator which may be one of the following strings: "eq", "ge", "le", "gt" or "lt" (respectively ==, >=, <=, >, <).
-- @param right  String representing an IPv4 or IPv6 address.  Shortened notation is permitted.
-- @usage        if compare_ip( "2001::DEAD:0:0:0", "eq", "2001:0:0:0:DEAD::" ) then ...
-- @return       Boolean True or False (or nil in case of an error).
-- @return       Nil (or String error message in case of an error).

compare_ip = function( left, op, right )

  if type( left ) ~= "string" or type( right ) ~= "string" then
    return nil, "Error in compare_ip: Expected IP address as a string."
  end

  if ( left:match( ":" ) and not right:match( ":" ) ) or ( not left:match( ":" ) and right:match( ":" ) ) then
    return nil, "Error in compare_ip: IP addresses must be from the same address family."
  end

  if op == "lt" or op == "le" then
    left, right = right, left
  elseif op ~= "eq" and op ~= "ge" and op ~= "gt" then
    return nil, "Error in compare_ip: Invalid Operator."
  end

  local err ={}
  left, err[#err+1] = ip_to_bin( left )
  right, err[#err+1] = ip_to_bin( right )
  if #err > 0 then
    return nil, table.concat( err, " " )
  end

  if string.len( left ) ~= string.len( right ) then
      -- shouldn't happen...
      return nil, "Error in compare_ip: Binary IP addresses were of different lengths."
  end

  -- equal?
  if ( op == "eq" or op == "le" or op == "ge" ) and left == right then
    return true
  elseif op == "eq" then
    return false
  end

  -- starting from the leftmost bit, subtract the bit in right from the bit in left
  local compare
  for i = 1, string.len( left ), 1 do
    compare = tonumber( string.sub( left, i, i ) ) - tonumber( string.sub( right, i, i ) )
    if compare == 1 then
      return true
    elseif compare == -1 then
      return false
    end
  end
  return false

end


---
-- Returns the first and last IP addresses in the supplied range of addresses.
-- @param range  String representing a range of IPv4 or IPv6 addresses in either cidr or first-last notation.
-- @usage        first, last = get_ips_from_range( "192.168.0.0/16" )
-- @return       String representing the first address in the supplied range (or nil in case of an error).
-- @return       String representing the last address in the supplied range (or nil in case of an error).
-- @return       Nil (or String error message in case of an error).

get_ips_from_range = function( range )

  if type( range ) ~= "string" then
    return nil, nil, "Error in get_ips_from_range: Expected a range as a string."
  end

  local first, last, prefix
  if range:match( "/" ) then
    first, prefix = range:match( "([%x%d:\.]+)/(%d+)" )
  elseif range:match( "-" ) then
    first, last = range:match( "([%x%d:\.]+)%s*\-%s*([%x%d:\.]+)" )
  end

  local err = {}
  if first and ( last or prefix ) then
    first, err[#err+1] = expand_ip( first )
  else
    return nil, nil, "Error in get_ips_from_range: The range supplied could not be interpreted."
  end
  if last then
    last, err[#err+1] = expand_ip( last )
  elseif first and prefix then
    last, err[#err+1] = get_last_ip( first, prefix )
  end

  if first and last then
    if ( first:match( ":" ) and not last:match( ":" ) ) or ( not first:match( ":" ) and last:match( ":" ) ) then
      return nil, nil, "Error in get_ips_from_range: First IP address is of a different address family to last IP address."
    end
    return first, last
  else
    return nil, nil, table.concat( err, " " )
  end

end


---
-- Calculates the last IP address of a range of addresses given an IP address in the range and prefix length for that range.
-- @param ip      String representing an IPv4 or IPv6 address.  Shortened notation is permitted.
-- @param prefix  Decimal number or a string representing a decimal number corresponding to a Prefix length.
-- @usage         last = get_last_ip( "192.0.0.0", 26 )
-- @return        String representing the last IP address of the range denoted by the supplied parameters (or nil in case of an error).
-- @return        Nil (or String error message in case of an error).

get_last_ip = function( ip, prefix )

  local first, err = ip_to_bin( ip )
  if err then return nil, err end

  prefix = tonumber( prefix )
  if not prefix or ( prefix < 0 ) or ( prefix > string.len( first ) ) then
    return nil, "Error in get_last_ip: Invalid prefix length."
  end

  local hostbits = string.sub( first, prefix + 1 )
  hostbits = string.gsub( hostbits, "0", "1" )
  local last = string.sub( first, 1, prefix ) .. hostbits
  last, err = bin_to_ip( last )
  if err then return nil, err end
  return last

end


---
-- Converts an IP address into a string representing the address as binary digits.
-- @param ip  String representing an IPv4 or IPv6 address.  Shortened notation is permitted.
-- @usage     bit_string = ip_to_bin( "2001::" )
-- @return    String representing the supplied IP address as 32 or 128 binary digits (or nil in case of an error).
-- @return    Nil (or String error message in case of an error).

ip_to_bin = function( ip )

  ip, err = expand_ip( ip )
  if err then return nil, err end

  local t, mask = {}

  if not ip:match( ":" ) then
    -- ipv4 string
    for octet in string.gfind( ip, "%d+" ) do
      t[#t+1] = stdnse.tohex( octet )
    end
    mask = "00"
  else
    -- ipv6 string
    for hdt in string.gfind( ip, "%x+" ) do
      t[#t+1] = hdt
    end
    mask = "0000"
  end

  -- padding
  for i, v in ipairs( t ) do
    t[i] = mask:sub( 1, string.len( mask ) - string.len( v ) ) .. v
  end

  return hex_to_bin( table.concat( t ) )

end


---
-- Converts a string representing binary digits into an IP address.
-- @param binstring  String representing an IP address as 32 or 128 binary digits.
-- @usage            ip = bin_to_ip( "01111111000000000000000000000001" )
-- @return           String representing an IP address (or nil in case of an error).
-- @return           Nil (or String error message in case of an error).

bin_to_ip = function( binstring )

  if type( binstring ) ~= "string" or binstring:match( "[^01]+" ) then
    return nil, "Error in bin_to_ip: Expected string of binary digits."
  end

  if string.len( binstring ) == 32 then
    af = 4
  elseif string.len( binstring ) == 128 then
    af = 6
  else
    return nil, "Error in bin_to_ip: Expected exactly 32 or 128 binary digits."
  end

  t = {}
  if af == 6 then
    local pattern = string.rep( "[01]", 16 )
    for chunk in string.gfind( binstring, pattern ) do
      t[#t+1] = stdnse.tohex( tonumber( chunk, 2 ) )
    end
    return table.concat( t, ":" )
  end

  if af == 4 then
    local pattern = string.rep( "[01]", 8 )
    for chunk in string.gfind( binstring, pattern ) do
      t[#t+1] = tonumber( chunk, 2 ) .. ""
    end
    return table.concat( t, "." )
  end

end


---
-- Converts a string representing a hexadecimal number into a string representing that number as binary digits.
-- Each hex digit results in four bits - this function is really just a wrapper around stdnse.tobinary().
-- @param hex  String representing a hexadecimal number.
-- @usage      bin_string = hex_to_bin( "F00D" )
-- @return     String representing the supplied number in binary digits (or nil in case of an error).
-- @return     Nil (or String error message in case of an error).

hex_to_bin = function( hex )

  if type( hex ) ~= "string" or hex == "" or hex:match( "[^%x]+" ) then
    return nil, "Error in hex_to_bin: Expected string representing a hexadecimal number."
  end

  local t, mask, binchar = {}, "0000"
  for hexchar in string.gfind( hex, "%x" ) do
      binchar = stdnse.tobinary( tonumber( hexchar, 16 ) )
      t[#t+1] = mask:sub( 1, string.len( mask ) - string.len( binchar ) ) .. binchar
  end
  return table.concat( t )

end


---
-- Calculates the prefix length for the given IP address range.
-- @param range  String representing an IP address range
-- @return       Number - prefix length of the range

function get_prefix_length( range )

  if type( range ) ~= "string" or range == "" then return nil end

  local first, last, err = get_ips_from_range( range )
  if err then return nil end

  first = ip_to_bin( first ):reverse()
  last = ip_to_bin( last ):reverse()

  local hostbits = 0
  for pos = 1, string.len( first ), 1 do

    if first:sub( pos, pos ) == "0" and last:sub( pos, pos ) == "1" then
      hostbits = hostbits + 1
    else
      break
    end

  end

  return ( string.len( first ) - hostbits )

end
