local dns = require "dns"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Maps IP addresses to autonomous system (AS) numbers.

The script works by sending DNS TXT queries to a DNS server which in
turn queries a third-party service provided by Team Cymru
(https://www.team-cymru.org/Services/ip-to-asn.html) using an in-addr.arpa
style zone set up especially for
use by Nmap. The responses to these queries contain both Origin and Peer
ASNs and their descriptions, displayed along with the BGP Prefix and
Country Code. The script caches results to reduce the number of queries
and should perform a single query for all scanned targets in a BGP
Prefix present in Team Cymru's database.

Be aware that any targets against which this script is run will be sent
to and potentially recorded by one or more DNS servers and Team Cymru.
In addition your IP address will be sent along with the ASN to a DNS
server (your default DNS server, or whichever one you specified with the
<code>dns</code> script argument).
]]

---
-- @usage
-- nmap --script asn-query [--script-args dns=<DNS server>] <target>
-- @args dns The address of a recursive nameserver to use (optional).
-- @output
-- Host script results:
-- |  asn-query:
-- |  BGP: 64.13.128.0/21 | Country: US
-- |    Origin AS: 10565 SVCOLO-AS - Silicon Valley Colocation, Inc.
-- |      Peer AS: 3561 6461
-- |  BGP: 64.13.128.0/18 | Country: US
-- |    Origin AS: 10565 SVCOLO-AS - Silicon Valley Colocation, Inc.
-- |_     Peer AS: 174 2914 6461

author = {"jah", "Michael Pattrick"}
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "external", "safe"}




local mutex = nmap.mutex( "ASN" )
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
-- relevant information from the response.  Mutual exclusion is used so that results can be
-- cached and so a single thread will be active at any time.
-- @param host  Host table.
-- @return      Formatted answers or <code>nil</code> on errors.

action = function( host )

  mutex "lock"

  local output, records, combined_records = {}, {}, {}

  -- check for cached data
  local in_cache, cache_data = check_cache( host.ip )

  if in_cache and type( cache_data ) == "table" then
    combined_records = cache_data
  elseif in_cache and type( cache_data ) == "string" and cache_data ~= "Unknown Error" then
    output = cache_data
  end

  if not in_cache then

    local dname = dns.reverse( host.ip )
    local zone_repl, IPv = "%.in%-addr%.arpa", 4
    if host.ip:match( ":" ) then
      zone_repl, IPv = "%.ip6%.arpa", 6
    end

    ---
    -- Team Cymru zones for rDNS-like queries.  The zones are as follows:
    -- * nmap.asn.cymru.com for IPv4 to Origin AS lookup.
    -- * peer-nmap.asn.cymru.com for IPv4 to Peer AS lookup.
    -- * nmap6.asn.cymru.com for IPv6 to Origin AS lookup.
    -- @class table
    -- @name cymru
    local cymru = { [4] = { ".nmap.asn.cymru.com", ".peer-nmap.asn.cymru.com" },
                    [6] = { ".nmap6.asn.cymru.com" }
    }

    -- perform queries for each applicable zone
    for _, zone in ipairs( cymru[IPv] ) do

      local asn_type = ( zone:match( "peer" ) and "Peer" ) or "Origin"
      -- replace arpa with cymru zone
      local temp = dname
      dname = dname:gsub( zone_repl, zone )

      -- send query
      local success, response = ip_to_asn( dname )
      if not success then
        records = {}
        output = ( type( response ) == "string" and response ) or output
        break
      end

      -- recognize and organise fields from response
      local success = result_recog( response, asn_type, records, host.ip )

      -- un-replace arpa zone
      dname = temp

    end

    -- combine records into unique BGP, cache and format for output
    combined_records = process_answers( records, output, host.ip )

  end -- if not in_cache


  mutex "done"

  return nice_output( output, combined_records )

end -- action



---
-- Checks whether the target IP address is within any BGP prefixes for which a query has
-- already been performed and returns a pointer to the HOST SCRIPT RESULT displaying the applicable answers.
-- @param ip String representing the target IP address.
-- @return   Boolean true if there are cached answers for the supplied target, otherwise
--           false.
-- @return   Table containing a string for each answer or <code>nil</code> if there are none.

function check_cache( ip )
  local ret = {}

  -- collect any applicable answers
  for _, cache_entry in ipairs( nmap.registry.asn.cache ) do
    if ipOps.ip_in_range( ip, cache_entry.cache_bgp ) then
      ret[#ret+1] = cache_entry
    end
  end
  if #ret < 1 then return false, nil end

  -- /0 signals that we want to kill this thread (all threads in fact)
  if #ret == 1 and type( ret[1].cache_bgp ) == "string" and ret[1].cache_bgp:match( "/0" ) then return true, nil end

  -- should return pointer unless there are more than one unique pointer
  local dirty, last_ip = false
  for _, entry in ipairs( ret ) do
    if last_ip and last_ip ~= entry.pointer then
      dirty = true; break
    end
    last_ip = entry.pointer
  end
  if not dirty then
    return true, ( "See the result for %s" ):format( last_ip )
  else
    return true, ret
  end

  return false, nil
end


---
-- Performs an IP address to ASN lookup.  See http://www.team-cymru.org/Services/ip-to-asn.html#dns.
-- @param query String - PTR-like DNS query.
-- @return      Boolean true for a successful DNS query resulting in an answer, otherwise false.
-- @return      Table of answers or a string error message.

function ip_to_asn( query )

  if type( query ) ~= "string" or query == "" then
    return false, nil
  end

  -- error codes from dns.lua that we want to display.
  local err_code = {}
  err_code[3] = "No Such Name"

  -- dns query options
  local options = {}
  options.dtype = "TXT"
  options.retAll = true
  options.sendCount = 1
  if type( nmap.registry.args.dns ) == "string" and nmap.registry.args.dns ~= "" then
    options.host = nmap.registry.args.dns
    options.port = 53
  end

  -- send the query
  local status, decoded_response = dns.query( query, options)

  if not status then
    stdnse.debug1("Error from dns.query(): %s", decoded_response )
  end

  return status, decoded_response

end


---
-- Extracts fields from the supplied DNS answer sections and generates a records entry for each.
-- @param answers    Table containing string DNS answers.
-- @param asn_type   String denoting whether the query is for Origin or Peer ASN.
-- @param recs       Table of existing recognized answers to which to add (refer to the <code>records</code> table inside <code>action</code>.
-- @return           Boolean true if successful otherwise false.

function result_recog( answers, asn_type, recs, discoverer_ip )

  if type( answers ) ~= "table" or #answers == 0 then return false end

  for _, answer in ipairs( answers ) do
    local t = {}
    t.pointer = discoverer_ip

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
-- Performs an AS Number to AS Description lookup.
-- @param asn String AS number.
-- @return    String description or <code>""</code>.

function asn_description( asn )

  if type( asn ) ~= "string" or asn == "" then
    return ""
  end

  -- dns query options
  local options = {}
  options.dtype = "TXT"
  options.sendCount = 1
  if type( nmap.registry.args.dns ) == "string" and nmap.registry.args.dns ~= "" then
    options.host = nmap.registry.args.dns
    options.port = 53
  end

  -- send query
  local query = ( "AS%s.asn.cymru.com" ):format( asn )
  local status, decoded_response = dns.query( query, options )
  if not status then
    return ""
  end

  return decoded_response:match( "|%s*([^|$]+)%s*$" ) or ""

end


---
-- Processes records which are recognized DNS answers by combining them into unique BGPs before caching
-- them in the registry and returning <code>combined_records</code>.  If there aren't any records (No Such Name message
-- or DNS failure) we signal this fact to other threads by using the cache and return with an empty table.
-- @param records  Table of recognized answers (may be empty).
-- @param output   String non-answer message or an empty table.
-- @param ip       String <code>host.ip</code>.
-- @return         Table containing combined records for the target (or an empty table).

function process_answers( records, output, ip )

  local combined_records = {}

  -- if records empty and no error message (output) then assume catastrophic dns failure and have all threads fail without trying.
  if #records == 0 and type( output ) ~= "string" then
    nmap.registry.asn.cache = { {["cache_bgp"] = "0/0"}, {["cache_bgp"] = "::/0"} }
    return {}
  end

  if #records == 0 and type( output ) == "string" then
    table.insert( nmap.registry.asn.cache, { ["pointer"] = ip, ["cache_bgp"] = get_assignment( ip, ( ip:match(":") and 48 ) or 29 ) } )
    return {}
  end


  if type( records ) ~= "table" or #records == 0 then
    return {}
  end

  -- combine fields for unique BGP
  for _, record in ipairs( records ) do
    if not combined_records[record.cache_bgp] then
      combined_records[record.cache_bgp] = record
    elseif combined_records[record.cache_bgp].asn_type ~= record.asn_type then
      -- origin before peer.
      if record.asn_type == "Origin" then
        combined_records[record.cache_bgp].asn = { table.unpack( record.asn ), table.unpack( combined_records[record.cache_bgp].asn ) }
      else
        combined_records[record.cache_bgp].asn = { table.unpack( combined_records[record.cache_bgp].asn ), table.unpack( record.asn ) }
      end
    end
  end

  -- cache combined records
  for _, rec in pairs( combined_records ) do
    table.insert( nmap.registry.asn.cache, rec )
  end

  return combined_records

end


---
-- Calculates the prefix length for the given IP address range.
-- @param range  String representing an IP address range.
-- @return       Number - prefix length of the range.

function get_prefix_length( range )

  if type( range ) ~= "string" or range == "" then return nil end

  local first, last, err = ipOps.get_ips_from_range( range )
  if err then return nil end

  first = ipOps.ip_to_bin( first ):reverse()
  last = ipOps.ip_to_bin( last ):reverse()

  local hostbits = 0
  for pos = 1, # first , 1 do

    if first:sub( pos, pos ) == "0" and last:sub( pos, pos ) == "1" then
      hostbits = hostbits + 1
    else
      break
    end

  end

  return ( # first  - hostbits )

end

---
-- Given an IP address and a prefix length, returns a string representing a
-- valid IP address assignment (size is not checked) which contains the
-- supplied IP address.  For example, with
-- <code>ip</code> = <code>"192.168.1.187"</code> and
-- <code>prefix</code> = <code>24</code> the return value will be
-- <code>"192.168.1.1-192.168.1.255"</code>
-- @param ip      String representing an IP address.
-- @param prefix  String or number representing a prefix length.  Should be of the same address family as <code>ip</code>.
-- @return        String representing a range of addresses from the first to the last hosts (or <code>nil</code> in case of an error).
-- @return        <code>nil</code> or error message in case of an error.

function get_assignment( ip, prefix )

  local some_ip, err = ipOps.ip_to_bin( ip )
  if err then return nil, err end

  prefix = tonumber( prefix )
  if not prefix or ( prefix < 0 ) or ( prefix > # some_ip  ) then
    return nil, "Error in get_assignment: Invalid prefix length."
  end

  local hostbits = string.sub( some_ip, prefix + 1 )
  hostbits = string.gsub( hostbits, "1", "0" )
  local first = string.sub( some_ip, 1, prefix ) .. hostbits
  local last
  err = {}
  first, err[#err+1] = ipOps.bin_to_ip( first )
  last, err[#err+1] = ipOps.get_last_ip( ip, prefix )
  if #err > 0 then return nil, table.concat( err, " " ) end

  return first .. "-" .. last

end


---
-- Decides what to output based on the content of the supplied parameters and formats it for return by <code>action</code>.
-- @param output            String non-answer message to be returned as is or an empty table.
-- @param combined_records  Table containing combined records.
-- @return                  Formatted nice output string.

function nice_output( output, combined_records )

  -- return a string message
  if type( output ) == "string" and output ~= "" then
    return output
  end

  -- return nothing (dns failure)
  if type( output ) ~= "table" then return nil end

  -- format each combined_record for output
  for _, rec in pairs( combined_records ) do
    local r = {}
    if rec.bgp then r[#r+1] = rec.bgp end
    if rec.co then r[#r+1] = rec.co end
    if rec.asn then output[#output+1] = ( "%s\n  %s" ):format( table.concat( r, " | " ), table.concat( rec.asn, "\n    " ) ) end
  end

  -- return nothing
  if #output == 0 then return nil end

  -- sort BGP asc. and combine BGP when ASN info is duplicated
  local first, second
  table.sort( output, function(a,b) return (get_prefix_length(a) or 0) > (get_prefix_length(b) or 0) end )
  for i=1,#output,1 do
    for j=1,#output,1 do
      -- does everything after the first pipe match for i ~= j?
      if i ~= j and output[i]:match( "[^|]+|([^$]+$)" ) == output[j]:match( "[^|]+|([^$]+$)" ) then
        first = output[i]:match( "([%x%d:%.]+/%d+)%s|" ) -- the lastmost BGP before the pipe in i.
        second = output[j]:match( "([%x%d:%.]+/%d+)" ) -- first BGP in j
        -- add in the new BGP from j and delete j
        if first and second then
          output[i] = output[i]:gsub( first, ("%s and %s"):format( first, second ) )
          output[j] = ""
        end
      end
    end
  end

  -- return combined and formatted answers
  return "\n" .. table.concat( output, "\n" )

end
