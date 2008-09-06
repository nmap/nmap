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
local ipOps = require "ipOps"


local mutex = nmap.mutex( id )
if not nmap.registry.asn then
  nmap.registry.asn = {}
  nmap.registry.asn.cache = {}
  nmap.registry.asn.descr = {}
end



---
-- This script will run for any non-private IP address.

hostrule = function( host )
  return not ipOps.isPrivate( host.ip )
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
    if ipOps.ip_in_range( ip, cache_entry.cache_bgp ) then
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
   ip = ipOps.expand_ip(ip)
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
-- Calculates the prefix length for the given IP address range.
-- @param range  String representing an IP address range
-- @return       Number - prefix length of the range

function get_prefix_length( range )

  if type( range ) ~= "string" or range == "" then return nil end

  local first, last, err = ipOps.get_ips_from_range( range )
  if err then return nil end

  first = ipOps.ip_to_bin( first ):reverse()
  last = ipOps.ip_to_bin( last ):reverse()

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
