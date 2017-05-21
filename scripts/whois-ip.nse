local http = require "http"
local io = require "io"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Queries the WHOIS services of Regional Internet Registries (RIR) and attempts to retrieve information about the IP Address
Assignment which contains the Target IP Address.

The fields displayed contain information about the assignment and the organisation responsible for managing the address
space. When output verbosity is requested on the Nmap command line (<code>-v</code>) extra information about the assignment will
be displayed.

To determine which of the RIRs to query for a given Target IP Address this script utilises Assignments Data hosted by IANA.
The data is cached locally and then parsed for use as a lookup table.  The locally cached files are refreshed periodically
to help ensure the data is current.  If, for any reason, these files are not available to the script then a default sequence
of Whois services are queried in turn until: the desired record is found; or a referral to another (defined) Whois service is
found; or until the sequence is exhausted without finding either a referral or the desired record.

The script will recognize a referral to another Whois service if that service is defined in the script and will continue by
sending a query to the referred service.  A record is assumed to be the desired one if it does not contain a referral.

To reduce the number unnecessary queries sent to Whois services a record cache is employed and the entries in the cache can be
applied to any targets within the range of addresses represented in the record.

In certain circumstances, the ability to cache responses prevents the discovery of other, smaller IP address assignments
applicable to the target because a cached response is accepted in preference to sending a Whois query.  When it is important
to ensure that the most accurate information about the IP address assignment is retrieved the script argument <code>whodb</code>
should be used with a value of <code>"nocache"</code> (see script arguments).  This reduces the range of addresses that may use a
cached record to a size that helps ensure that smaller assignments will be discovered.  This option should be used with caution
due to the potential to send large numbers of whois queries and possibly be banned from using the services.

In using this script your IP address will be sent to iana.org. Additionally
your address and the address of the target of the scan will be sent to one of
the RIRs.
]]

---
-- @args whodb Takes any of the following values, which may be combined:
-- * <code>whodb=nofile</code> Prevent the use of IANA assignments data and instead query the default services.
-- * <code>whodb=nofollow</code> Ignore referrals and instead display the first record obtained.
-- * <code>whodb=nocache</code> Prevent the acceptance of records in the cache when they apply to large ranges of addresses.
-- * <code>whodb=[service-ids]</code> Redefine the default services to query.  Implies <code>nofile</code>.
-- @usage
-- # Basic usage:
-- nmap target --script whois-ip
--
-- # To prevent the use of IANA assignments data supply the nofile value
-- # to the whodb argument:
-- nmap target --script whois-ip --script-args whodb=nofile
-- nmap target --script whois-ip --script-args whois.whodb=nofile
--
-- # Supplying a sequence of whois services will also prevent the use of
-- # IANA assignments data and override the default sequence:
-- nmap target --script whois-ip --script-args whodb=arin+ripe+afrinic
-- nmap target --script whois-ip --script-args whois.whodb=apnic*lacnic
-- # The order in which the services are supplied is the order in which
-- # they will be queried. (N.B. commas or semi-colons should not be
-- # used to delimit argument values.)
--
-- # To return the first record obtained even if it contains a referral
-- # to another service, supply the nofollow value to whodb:
-- nmap target --script whois-ip --script-args whodb=nofollow
-- nmap target --script whois-ip --script-args whois.whodb=nofollow+ripe
-- # Note that only one service (the first one supplied) will be used in
-- # conjunction with nofollow.
--
-- # To ensure discovery of smaller assignments even if larger ones
-- # exist in the cache, supply the nocache value to whodb:
-- nmap target --script whois-ip --script-args whodb=nocache
-- nmap target --script whois-ip --script-args whois.whodb=nocache
-- @output
-- Host script results:
-- |  whois-ip: Record found at whois.arin.net
-- |  netrange: 64.13.134.0 - 64.13.134.63
-- |  netname: NET-64-13-143-0-26
-- |  orgname: Titan Networks
-- |  orgid: INSEC
-- |_ country: US stateprov: CA

author = "jah"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "external", "safe"}




-------------------------------------------------------------------------------------------------------------------------
--
--
--
--
-- This script will run only if the target IP address has been determined to be routable on the Internet.

hostrule = function( host )

  local is_private, err = ipOps.isPrivate( host.ip )
  if is_private == nil then
    stdnse.debug1("Error in Hostrule: %s.", err)
    return false
  end

  return not is_private

end



-------------------------------------------------------------------------------------------------------------------------
--
--
--
--
-- Queries WHOIS services until an applicable record is found or the list of services to query
-- is exhausted and finishes by displaying elements of an applicable record.

action = function( host )

  if not nmap.registry.whois then
    ---
    -- Data and flags shared between threads.
    -- @name whois
    -- @class table
    --@field whoisdb_default_order          The default number and order of whois services to query.
    --@field using_local_assignments_file   The boolean values of the two keys ipv4 and ipv6 determine whether or not to use the data from an IANA
    --                                      hosted assignments file for that address family.
    --@field local_assignments_file_expiry  A period, between 0 and 7 days, during which cached assignments data may be used without being refreshed.
    --@field init_done                      Set when <code>script_init</code> has been called and prevents it being called again.
    --@field mutex                          A table of mutex functions, one for each service defined herein.  Allows a thread exclusive access to a
    --                                      service, preventing concurrent connections to it.
    --@field nofollow                       A flag that prevents referrals to other whois records and allows the first record retrieved to be
    --                                      returned instead.  Set to true when whodb=nofollow
    --@field using_cache                    A flag which modifies the size of ranges in a cache entry.  Set to false when whodb=nocache
    --@field cache                          Storage for cached redirects, records and other data for output.
    nmap.registry.whois = {}
    nmap.registry.whois.whoisdb_default_order = {"arin","ripe","apnic"}
    nmap.registry.whois.using_cache = true
    nmap.registry.whois.using_local_assignments_file = {}
    nmap.registry.whois.using_local_assignments_file.ipv4 = true
    nmap.registry.whois.using_local_assignments_file.ipv6 = true
    nmap.registry.whois.local_assignments_file_expiry = "16h"
    nmap.registry.whois.nofollow = false
    nmap.registry.whois.cache = {}

  end

  -- script initialisation - threads must wait until this has been completed before continuing
  local mutex = nmap.mutex( "whois" )
  mutex "lock"
  if not nmap.registry.whois.init_done then
    script_init()
  end
  mutex "done"

  ---
  -- Holds field data captured from the responses of each service queried and includes additional information about the final desired record.
  --
  -- The table, indexed by whois service id, holds a table of fields captured from each queried service.  Once it has been determined that a record
  -- represents the final record we wish to output, the existing values are destroyed and replaced with the one required record.  This is done purely
  -- to make it easier to reference the data of a desired record.  Other values in the table are as follows.
  -- @name data
  -- @class table
  --@field data.iana        is set after the table is initialised and is the number of times a response encountered represents "The Whole Address Space".
  --                  If the value reaches 2 it is assumed that a valid record is held at ARIN.
  --@field data.id          is set in <code>analyse_response</code> after final record and is the service name at which a valid record has been found.  Used in
  --                  <code>format_data_for_output</code>.
  --@field data.mirror      is set in <code>analyse_response</code> after final record and is the service name from which a mirrored record has been found.  Used in
  --                  <code>format_data_for_output</code>.
  --@field data.comparison  is set in <code>analyse_response</code> after final record and is a string concatenated from fields extracted from a record and which
  --                  serves as a fingerprint for a record, used in <code>get_cache_key</code>, to compare two records for equality.
  local data = {}
  data.iana = 0

  ---
  -- Used in the main loop to manage mutexes, the structure of tracking is as follows.
  -- @name tracking
  -- @class table
  --@field this_db    The service for which a thread will wait for exclusive access before sending a query to it.
  --@field next_db    The next service to query.  Allows a thread to continue in the main "while do" loop.
  --@field last_db    The value of this_db after sending a query, used when exclusive access to a service is no longer required.
  --@field completed  An array of services previously queried.
  local tracking = {}
  tracking.completed = {}
  local addr_family = #host.bin_ip == 4 and "ipv4" or "ipv6"

  tracking = get_next_action( tracking, host.ip, addr_family )

  -- main loop
  while tracking.next_db do

    local status, retval
    tracking.this_db, tracking.next_db = tracking.next_db, nil

    nmap.registry.whois.mutex[tracking.this_db] "lock"

    status, retval = pcall( get_next_action, tracking, host.ip, addr_family )
    if not status then
      stdnse.debug1("pcall caught an exception in get_next_action: %s.", retval)
    else tracking = retval end

    if tracking.this_db then
      -- do query
      local response = do_query( tracking.this_db, host.ip )
      tracking.completed[#tracking.completed+1] = tracking.this_db

      -- analyse data
      status, retval = pcall( analyse_response, tracking, host.ip, response, data )
      if not status then
        stdnse.debug1("pcall caught an exception in analyse_response: %s.", retval)
      else data = retval end

      -- get next action
      status, retval = pcall( get_next_action, tracking, host.ip, addr_family )
      if not status then
        stdnse.debug1("pcall caught an exception in get_next_action: %s.", retval)
        if not tracking.last_db then tracking.last_db, tracking.this_db = tracking.this_db or tracking.next_db, nil end
      else tracking = retval end
    end

    nmap.registry.whois.mutex[tracking.last_db] "done"
    tracking.last_db = nil

  end


  return output( host.ip, tracking.completed )

end -- action




----------------------------------------------------------------------------------------------------------------------------
--
--
--
--
-- Determines whether or not to query a whois service and which one to query.  Checks the cache first - where there may be a redirect or a
-- cached record.  If not, it trys to get a service from the assignments files if this was not previously attempted.  Finally, if a service has
-- not yet been obtained the first unqueried service from whoisdb_default_order is used.  The tracking table is manipulated such that a thread
-- knows its next move in the main loop.
-- @param tracking  The Tracking table.
-- @param ip        String representing the Target's IP address.
-- @param addr_fam  String representing the Target's IP address family.
-- @return          The supplied and possibly modified tracking table.
-- @see             tracking, check_response_cache, get_db_from_assignments

function get_next_action( tracking, ip, addr_fam )

  if type( ip ) ~= "string" or ip == "" or type( tracking ) ~= "table" or type( tracking.completed ) ~= "table" then return nil end

  --next_db should always be nil when calling this
  if tracking.next_db then return tracking end


  -- check for cached redirects and records
  local in_cache
  in_cache, tracking.next_db = check_response_cache( ip )

  if in_cache and not tracking.next_db then

    -- found cached data - quit
    tracking.this_db, tracking.last_db = nil, tracking.this_db
    return tracking

  elseif in_cache and tracking.next_db then

    -- found cached redirect
    if tracking.next_db ~= tracking.this_db then

      -- skip query to this_db and set last_db so we can unlock mutex
      tracking.this_db, tracking.last_db = nil, tracking.this_db

    else

      -- we were already about to query this_db
      tracking.next_db = nil

    end

    -- kill redirect if the user specified "nofollow"
    if nmap.registry.whois.nofollow then tracking.next_db = nil end

    return tracking

  elseif not in_cache and tracking.this_db and table.concat( tracking.completed, " " ):match( tracking.this_db ) then

    -- we've already queried this_db so lets skip it and try whoisdb_default_order
    tracking.last_db, tracking.this_db = tracking.this_db, nil

  end


  -- try to find a service to query in the assignments files, if allowed
  if nmap.registry.whois.using_local_assignments_file[addr_fam] and not tracking.this_db and not tracking.last_db then

    tracking.next_db = get_db_from_assignments( ip )
    if tracking.next_db and not table.concat( tracking.completed, " " ):match( tracking.next_db ) then
      -- we got one we haven't queried - we probably haven't queried any yet.
      return tracking
    end

  end


  -- get the next untried service from whoisdb_default_order
  if not tracking.this_db and nmap.registry.whois.whoisdb_default_order then

    for i, db in ipairs( nmap.registry.whois.whoisdb_default_order ) do
      if not table.concat( tracking.completed, " " ):match( db ) then
        tracking.next_db = db
        break
      end
    end

  end

  return tracking

end



---
-- Checks the registry for cached redirects and results applicable to the supplied Target's IP address.
-- @param ip  String representing the Target's IP address.
-- @return    Boolean True if the supplied IP address is within a range of addresses for which there is a cache entry and a redirect or a
--            record is present; otherwise false.
-- @return    ID of a service defined in whoisdb if a redirect is present; otherwise nil.
-- @see       get_cache_key

function check_response_cache( ip )

  if not next( nmap.registry.whois.cache ) then return false, nil end
  if type( ip ) ~= "string" or ip == "" then return false, nil end

  local ip_key = get_cache_key( ip )
  if not ip_key then return false, nil end

  local cache_data = nmap.registry.whois.cache[ip_key]

  if cache_data.redirect then
    -- redirect found in cache
    return true, cache_data.redirect
  elseif cache_data.data then
    -- record found in cache
    return true, nil
  else
    stdnse.debug1("Error in check_response_cache: Empty Cache Entry was found.")
  end

  return false, nil

end



---
-- Determines which entry in the cache is applicable to the Target and returns the key for that entry.
-- @param ip  String representing the Target's IP address.
-- @return    String key (IP address) of the cache entry applicable to the Target.

function get_cache_key( ip )

  -- if this ip cached an entry, then we'll use it except when it represents a found record and we're not using_cache
  if nmap.registry.whois.cache[ip] and ( nmap.registry.whois.using_cache or nmap.registry.whois.cache[ip].redirect ) then
    return ip
  end

  -- When not using_cache, we compare our record to any others in the cache to avoid printing out the same record repeatedly.
  local self_compare
  if nmap.registry.whois.cache[ip] and nmap.registry.whois.cache[ip].data then
    -- we should have a string which we can use to compare with other records
    self_compare = nmap.registry.whois.cache[ip].data.comparison
  end

  local cache_entries = {}
  for ip_key, cache_data in pairs( nmap.registry.whois.cache ) do

    if type( ip_key ) == "string" and ip_key ~= "" and type( cache_data ) == "table" then

      -- compare and return original pointer
      if self_compare and ip ~= ip_key and not cache_data.pointer and self_compare == cache_data.data.comparison then
        nmap.registry.whois.cache[ip].pointer = ip_key
        return ip_key
      end

      -- check if ip is in a cached range and add the entry to cache_entries if it is
      local in_range, err = ipOps.ip_in_range( ip, cache_data.range )
      if in_range then
        local t = {}
        t.key = ip_key
        t.range = cache_data.range
        t.pointer = cache_data.pointer
        cache_entries[#cache_entries+1] = t
      end

    end

  end

  if #cache_entries == 0 then
    -- no applicable cache entries
    return nil
  elseif #cache_entries == 1 then
    -- just one applicable entry
    return cache_entries[1].pointer or cache_entries[1].key
  end

  -- more than one entry need sorting into ascending order
  table.sort( cache_entries, smallest_range )

  -- we'll choose the smallest range
  return cache_entries[1].key

end



---
-- Calculates the prefix length for the given assignment.
-- @param range  String representing an IP address assignment
-- @return       Number - prefix length of the assignment

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




---
-- Performs a lookup against assignments data to determine which service to query for the supplied Target.
-- @param ip  String representing the Target's IP address.
-- @return    String id of the whois service to query, or nil.

function get_db_from_assignments( ip )

  if type( ip ) ~= "string" or ip == "" then return nil end

  local af
  if ip:match( ":" ) then
    af = "ipv6"
  else
    af = "ipv4"
  end

  if not nmap.registry.whois.local_assignments_data or not nmap.registry.whois.local_assignments_data[af] then
    stdnse.debug1("Error in get_db_from_assignments: Missing assignments data in registry.")
    return nil
  end

  if next( nmap.registry.whois.local_assignments_data[af] ) then
    for _, assignment in ipairs( nmap.registry.whois.local_assignments_data[af] ) do
      if ipOps.ip_in_range( ip, assignment.range.first .. "-" .. assignment.range.last ) then
        return assignment.service
      end
    end
  end

  return nil

end



---
-- Connects to a whois service (usually TCP port 43) and sends an IP address query, returning any response.
-- @param db  String id of a service defined in whoisdb.
-- @param ip  String representing the Target's IP address.
-- @return    String response to query or nil.

function do_query(db, ip)

  if type( db ) ~= "string" or not nmap.registry.whois.whoisdb[db] then
    stdnse.debug1("Error in do_query: %s is not a defined Whois service.", db)
    return nil
  end

  local service = nmap.registry.whois.whoisdb[db]

  if type( service.hostname ) ~= "string" or service.hostname == "" then
    stdnse.debug1("Error in do_query: Invalid hostname for %s.", db)
    return nil
  end

  local query_data = ""
  if type( service.preflag ) == "string" and service.preflag ~= "" then
    query_data = service.preflag .. " "
  end
  query_data = query_data .. ip
  if type( service.postflag ) == "string" and service.postflag ~= "" then
    query_data = query_data .. service.postflag
  end
  query_data = query_data .. "\n"

  local socket = nmap.new_socket()
  local catch = function()
    stdnse.debug1("Connection to %s failed or was aborted! No Output for this Target.", db)
    nmap.registry.whois.mutex[db] "done"
    socket:close()
  end

  local result, status, line = {}
  local try = nmap.new_try( catch )

  socket:set_timeout( 10000 )
  try( socket:connect( service.hostname, 43 ) )
  try( socket:send( query_data ) )

  while true do
    local status, lines = socket:receive_lines(1)
    if not status then
      break
    else
      result[#result+1] = lines
    end
  end

  socket:close()

  stdnse.debug3("Ended Query at %s.", db)

  if #result == 0 then
    return nil
  end

  return table.concat( result )

end



---
-- Extracts fields (if present) from the information returned in response to our query and determines whether it represents a referral to a
-- record hosted elsewhere.  The referral is cached in the registry to allow threads for targets in the same assignment to avoid performing
-- their queries to this service.  If it is not a referral, we assume it is the desired record and the extracted fields are cached in the
-- registry ready for output.
-- @param tracking  Tracking table.
-- @param ip        String representing a Target's IP address.
-- @param response  String obtained from a service in response to our query.
-- @param data      Table of fields captured from previously queried services, indexed by service name.
-- @return          The data table passed as a parameter which may have been added to or may contain only the fields extracted from the desired
--                  record (in which case it will no longer be indexed by service name).
-- @see             extract_objects_from_response, redirection_rules, constrain_response, add_to_cache

function analyse_response( tracking, ip, response, data )

  if type( response ) ~= "string" or response == "" then return data end

  local meta, mirrored_db
  local last_db, this_db, next_db = tracking.last_db, (tracking.this_db or tracking.last_db), tracking.next_db
  data[this_db] = {}

  -- check for foreign resource
  for _, db in pairs( nmap.registry.whois.whoisdb ) do
    if type( db ) == "table" and type( db.id ) == "string" and db.id ~= "iana" and db.id ~= this_db and type( db.hostname ) == "string" then
      local pattern = db.id:upper() .. ".*%s*resource:%s*" .. db.hostname
      if response:match( pattern ) then
        mirrored_db = db.id
        meta = db
        meta.redirects = nil
        break
      end
    end
  end

  meta = meta or nmap.registry.whois.whoisdb[this_db]

  -- do we recognize objects in the response?.
  local have_objects
  if type( meta ) == "table" and type( meta.fieldreq ) == "table" and type( meta.fieldreq.ob_exist ) == "string" then
    have_objects = response:match( meta.fieldreq.ob_exist )
  else
    stdnse.debug2("Could not check for objects, problem with meta data.")
    have_objects = false
  end

  -- if we do not recognize objects check for an known error/non-object message
  if not have_objects then
    stdnse.debug4("%s has not responded with the expected objects.", this_db)
    local tmp, msg
    -- may have found our record saying something similar to "No Record Found"
    for _, pattern in ipairs( nmap.registry.whois.m_none ) do
      local pattern_l = pattern:gsub( "$addr", ip:lower() )
      local pattern_u = pattern:gsub( "$addr", ip:upper() )
      msg = response:match( pattern_l ) or response:match( pattern_u )
      if msg then
        stdnse.debug4("%s responded with a message which is assumed to be authoritative (but may not be).", this_db)
        break
      end
    end
    -- may have an error
    if not msg then
      for _, pattern in ipairs( nmap.registry.whois.m_err ) do
        msg = response:match( pattern )
        if msg then
          stdnse.debug4("%s responded with an ERROR message.", this_db)
          break
        end
      end
    end
    -- if we've recognized a non-object message,
    if msg then
      add_to_cache( ip, nil, nil, "Message from " .. nmap.registry.whois.whoisdb[this_db].hostname .. "\n" .. msg )
      return data
    end
  end

  -- the query response may not contain the set of objects we were expecting and we do not recognize the response message.
  -- it may contain a record mirrored (or found by recursion) from a different service
  if not have_objects then
    local foreign_obj
    for setname, set in pairs( nmap.registry.whois.fields_meta ) do
      if set ~= nmap.registry.whois.whoisdb[this_db].fieldreq and response:match(set.ob_exist) then
        foreign_obj = setname
        stdnse.debug4("%s seems to have responded using the set of objects named: %s.", this_db, foreign_obj)
        break
      end
    end
    if foreign_obj and foreign_obj == "rpsl" then
      mirrored_db = nmap.registry.whois.whoisdb.ripe.id
      meta = nmap.registry.whois.whoisdb.ripe
      meta.redirects = nil
      have_objects = true
      stdnse.debug4("%s will use the display properties of ripe.", this_db)
    elseif foreign_obj then
      -- find a display to match the objects.
      for some_db, db_props in pairs( nmap.registry.whois.whoisdb ) do
        if db_props.fieldreq and nmap.registry.whois.fields_meta[foreign_obj] and db_props.fieldreq == nmap.registry.whois.fields_meta[foreign_obj] then
          mirrored_db = nmap.registry.whois.whoisdb[some_db].id
          meta = nmap.registry.whois.whoisdb[some_db]
          meta.redirects = nil
          have_objects = true
          stdnse.debug4("%s will use the display properties of %s.", this_db, some_db)
          break
        end
      end
    end -- if foreign_obj
  end

  -- extract fields from the entire response for record/redirect discovery
  if have_objects then
    stdnse.debug4("Parsing Query response from %s.", this_db)
    data[this_db] = extract_objects_from_response( response, this_db, meta )
  end

  local response_chunk, found, nextdb

  -- do record/redirect discovery, cache found redirect
  if not nmap.registry.whois.nofollow and have_objects and meta.redirects then
    stdnse.debug4("Testing response for redirection.")
    found, nextdb, data.iana = redirection_rules( this_db, data, meta )
  end

  -- get most specific assignment and handle arin's organisation-focused record layout and then
  -- modify the data table depending on whether we're redirecting or quitting
  if have_objects then

    stdnse.debug5("Extracting Fields from response.")

    -- optionally constrain response to a more focused area
    -- discarding previous extraction
    if meta.smallnet_rule then
      local offset, ptr, strbgn, strend
      response_chunk, offset = constrain_response( response, this_db, ip, meta )
      if offset > 0 then
        data[this_db] = extract_objects_from_response( response_chunk, this_db, meta )
      end
      if offset > 1 and meta.unordered then
        -- fetch an object immediately in front of inetnum
        stdnse.debug5("%s Searching for an object group immediately before this range.", this_db)
        -- split objects from the record, up to offset.  Last object should be the one we want.
        local obj_sel = stdnse.strsplit( "\r?\n\r?\n", response:sub( 1, offset ) )
        response_chunk = "\n" .. obj_sel[#obj_sel] .. "\n"
        -- check if any of the objects we like match this single object in response chunk
        for ob, t in pairs( meta.fieldreq ) do
          if ob ~= "ob_exist" and type( t.ob_start ) == "string" and response_chunk:match( t.ob_start ) then
            data[this_db][ob] = extract_objects_from_response( response_chunk, this_db, meta, ob )
          end
        end

      end -- if offset
    end -- if meta.smallnet_rule

    -- collect, from each extracted object, the tables of field values and positions and concatenate these
    -- to provide the ability to easily compare two results
    local coll, comp = {}, ""
    for ob, t in pairs( data[this_db] ) do
      for i, comp_string in pairs( t.for_compare ) do
        coll[#coll+1] = { i, comp_string }
      end
      -- kill these now they're collected
      data[this_db][ob].for_compare = nil
    end
    -- sort them by position in the record, ascending
    table.sort( coll, function(a,b) return a[1]<b[1] end )
    -- concatenate them to create a long string we can compare.  Assign to .comparison after the debug bit following...
    for i, v in ipairs( coll ) do
      comp = comp .. v[2]
    end

    -- DEBUG
    stdnse.debug5("%s Fields captured :", this_db)
    for ob, t in pairs( data[this_db] ) do
      for fieldname, fieldvalue in pairs( t ) do
        stdnse.debug5("%s %s.%s %s.", this_db, ob, fieldname, fieldvalue)
      end
    end

    -- add comparison string to extracted data
    data[this_db].comparison = comp

    -- add mirrored_db to extracted data
    data[this_db].mirror = mirrored_db

  end -- have objects

  -- If we are accepting a record, only cache the data for that record
  if (have_objects and not nextdb) or nmap.registry.whois.nofollow then
    -- no redirect - accept as result and clear any previous data
    data = data[this_db]
    data.id = this_db
  elseif nextdb and table.concat( tracking.completed, " " ):match( nextdb ) then
    -- redirected to a previously queried service - accept as result
    data = data[nextdb]
    data.id = nextdb
    nextdb = nil
  elseif have_objects and ( data.iana > 1 ) and not table.concat( tracking.completed, " " ):match( nmap.registry.whois.whoisdb.arin.id ) then
    -- two redirects to IANA - query ARIN next (which we should probably have done already!)
    nextdb = nmap.registry.whois.whoisdb.arin.id
  elseif have_objects and ( data.iana > 1 ) and table.concat( tracking.completed, " " ):match( nmap.registry.whois.whoisdb.arin.id ) then
    -- two redirects to IANA - accept result from ARIN
    data = data[nmap.registry.whois.whoisdb.arin.id]
    data.id = nmap.registry.whois.whoisdb.arin.id
    nextdb = nil
  elseif not have_objects then
    data = data[this_db]
    data.id = this_db
  end

  -- cache our analysis
  local range

  if have_objects then

    if data[this_db] and data[this_db].ob_netnum then
      range = data[this_db].ob_netnum[meta.reg]
    elseif data.ob_netnum and data.mirror then
      range = data.ob_netnum[nmap.registry.whois.whoisdb[data.mirror].reg]
    elseif data.ob_netnum then
      range = data.ob_netnum[nmap.registry.whois.whoisdb[data.id].reg]
    end

    -- if nocache then enforce a smallest allowed prefix length
    -- (these values should match those in add_to_cache)
    if not nmap.registry.whois.using_cache and not nextdb then
      local smallest_allowed_prefix = 29
      if range:match( ":" ) then
        smallest_allowed_prefix = 48
      end
      local range_prefix = get_prefix_length( range )
      if type( range_prefix ) ~= "number" or range_prefix < smallest_allowed_prefix then
        range = nil
      end
    end

    -- prevent caching (0/0 or /8) or (::/0 or /23) or
    range = not_short_prefix( ip, range, nextdb )

  end

  add_to_cache( ip, range, nextdb, data )

  return data

end



---
-- Extracts Whois record objects (or a single object) and accompanying fields from the supplied (possibly partial) response to a whois query.
-- If a fifth parameter specific_object is not supplied, all objects defined in fields_meta will be captured if they are present in the response.
-- @param response_string  String obtained from a service in response to our query.
-- @param db               String id of the whois service queried.
-- @param meta             Table, nmap.registry.whois.whoisdb[db] where db is either the service queried or a mirrored service.
-- @param specific_object  Optional string index of a single object defined in fields_meta (e.g. "inetnum").
-- @return                 Table indexed by object name containing the fields captured for each object found.

function extract_objects_from_response( response_string, db, meta, specific_object )

  local objects_to_extract = {}
  local extracted_objects = {}

  if type( response_string ) ~= "string" or response_string == "" then return {} end
  if type( meta ) ~= "table" or type( meta.fieldreq ) ~= "table" then return {} end

  -- we either receive a table for one object or for all objects
  if type( specific_object ) == "string" and meta.fieldreq[specific_object] then
    objects_to_extract[specific_object] = meta.fieldreq[specific_object]
    stdnse.debug5("Extracting a single object: %s.", specific_object)
  else
    stdnse.debug5("Extracting all objects.")
    objects_to_extract = meta.fieldreq
  end

  for object_name, object in pairs( objects_to_extract ) do
    if object_name and object_name ~= "ob_exist" then
      stdnse.debug5("Seeking object group: %s.", object_name)
      extracted_objects[object_name] = {}
      extracted_objects[object_name].for_compare = {} -- this will allow us to compare two tables
      -- get a substr of response_string that corresponds to a single object
      local ob_start, j = response_string:find( object.ob_start )
      local i, ob_end = response_string:find( object.ob_end, j )
      -- if we could not find the end, make the end EOF
      ob_end = ob_end or -1
      if ob_start and ob_end then
        stdnse.debug5("Capturing: %s with indices %s and %s.", object_name, ob_start, ob_end)
        local obj_string = response_string:sub( ob_start, ob_end )
        for fieldname, pattern in pairs( object ) do
          if fieldname ~= "ob_start" and fieldname ~= "ob_end" then
            local data_pos, data_string = obj_string:find( pattern ), trim( obj_string:match( pattern ) )
            if data_string then
              extracted_objects[object_name][fieldname] = data_string
              extracted_objects[object_name].for_compare[data_pos+ob_start] = data_string
            end
          end
        end
      end -- if ob_start and ob_end

    end -- if object_name
  end -- for object_name

  if specific_object then extracted_objects = extracted_objects[specific_object] end -- returning one object

  return extracted_objects

end -- function



---
-- Checks for referrals in fields extracted from the whois query response.
-- @param db    String id of the whois service queried.
-- @param data  Table, indexed by whois service id, of extracted fields.
-- @param meta  Table, nmap.registry.whois.whoisdb[db] where db is either the service queried or a mirrored service.
-- @return      Boolean "found". True if a referral is not found (i.e. No Referral means the desired record has been "found"), otherwise False.
-- @return      String "redirect". Service id to which we are referred, or nil.
-- @return      Number "iana_count". This is the total number of referral to IANA for this Target (for all queries) and is stored in data.iana.
-- @see         redirection_validation

function redirection_rules( db, data, meta )

  if type( db ) ~= "string" or db == "" or type( data ) ~= "table" or not next( data ) then
    return false, nil, nil
  end

  local found = false
  local redirect = nil
  local iana_count
  if type( data.iana ) == "number" then
    iana_count = data.iana
  else
    iana_count = 0
  end

  if not meta or not meta.redirects then
    return found, redirect, iana_count
  end

  ---
  -- Decides the value of a redirect and whether it should be followed.  Referrals to IANA, found in whois records that represent the
  -- "Whole Address Space",  are acted upon by redirecting to ARIN or accepting the record from ARIN if it was previously queried.  This
  -- function also catches (ignores) referrals to the referring service - which happens as a side-effect of the method of redirection detection.
  -- The return values of this function will be returned by its parent function.
  -- @param directed_to    String id of a whois service.
  -- @param directed_from  String id of a whois service.
  -- @param icnt           Number of total redirects to IANA.
  -- @return               Boolean "found". True if a redirect is not found or ignored, otherwise False.
  -- @return               String "redirect". Service id to which we are redirected, or nil.
  -- @return               Number "iana_count" which is incremented here if applicable.

  local redirection_validation = function( directed_to, directed_from, icnt )

    local iana = nmap.registry.whois.whoisdb.iana.id
    local arin = nmap.registry.whois.whoisdb.arin.id

    -- arin record points to iana so we won't follow and we assume we have our record
    if directed_to == iana and directed_from == arin then
      stdnse.debug4("%s Accept arin record (matched IANA).", directed_from)
      return true, nil, ( icnt+1 )
    end

    -- non-arin record points to iana so we query arin next
    if directed_to == iana then
      stdnse.debug4("Redirecting to arin (matched IANA).")
      return false, arin, ( icnt+1 )
    end

    -- a redirect, but not to iana or to self, so we follow it.
    if directed_to ~= nmap.registry.whois.whoisdb[directed_from].id then
      stdnse.debug4("%s redirects us to %s.", directed_from, directed_to)
      return false, directed_to, icnt
    end

    -- redirect to self
    return true, nil, icnt

  end --redirection_validation

  -- iterate over each table of redirect info for a specific field
  for _, redirect_elems in ipairs( meta.redirects ) do

    local obj, fld, pattern = table.unpack( redirect_elems )   -- three redirect elements
    -- if a field has been captured for the given redirect info
    if data[db][obj] and data[db][obj][fld] then

      stdnse.debug5("Seek redirect in object: %s.%s for %s.", obj, fld, pattern)
      -- iterate over nmap.registry.whois.whoisdb to find pattern (from each service) in the designated field
      for member, mem_properties in pairs( nmap.registry.whois.whoisdb ) do

        -- if pattern if found in the field, we have a redirect to member
        if type( mem_properties[pattern] ) == "string" and string.lower( data[db][obj][fld] ):match( mem_properties[pattern] ) then

          stdnse.debug5("Matched %s in %s.%s.", pattern, obj, fld)
          return redirection_validation( nmap.registry.whois.whoisdb[member].id, db, iana_count )

        elseif type( mem_properties[pattern] ) == "table" then

          -- pattern is an array of patterns
          for _, pattn in ipairs( mem_properties[pattern] ) do
            if type( pattn ) == "string" and string.lower( data[db][obj][fld] ):match( pattn ) then
              stdnse.debug5("Matched %s in %s.%s.", pattern, obj, fld)
              return redirection_validation( nmap.registry.whois.whoisdb[member].id, db, iana_count )
            end
          end

        end

      end -- for mem, mem_properties

    end

  end -- for _,v in ipairs

  -- if redirects have not been found then assume that the record has been found.
  found = true
  return found, redirect, iana_count

end



---
-- Attempts to reduce the query response to a subset containing the most specific assignment information.
-- It does this by collecting inetnum objects (and their positions in the response) and choosing the smallest assignment represented by them.
-- A subset beginning with the most specific inetnum object and ending before any further inetnum objects is returned along with the position
-- of the subset within the entire response.
-- @param response  String obtained from a whois service in response to our query.
-- @param db        String id of the service from which the response was obtained.
-- @param ip        String representing the Target's IP address.
-- @param meta      Table, nmap.registry.whois.whoisdb[db] where db is either the service queried or a mirrored service.
-- @return          String containing the most specific part of the response (or the entire response if only one inetnum object is present).
-- @return          Number position of the start of the most specific part of the response.
-- @see             smallest_range

function constrain_response( response, db, ip, meta )
  local strbgn = 1
  local strend = 1
  local ptr = 1
  local mptr = {}
  local bound = nil

  -- collect all inetnums objects (and their position) into a table
  while strbgn and meta.fieldreq do
    strbgn, strend = response:find( meta.fieldreq.ob_exist, strend )
    if strbgn then
      local pair = {}
      pair.pointer = strbgn
      pair.range = trim( response:match( meta.smallnet_rule, strbgn ) )
      mptr[#mptr+1] = pair
    end
  end

  if # mptr > 1 then
    -- find the closest one to host.ip and constrain the response to it
    stdnse.debug5("%s Focusing on the smallest of %s address ranges.", db, #mptr)
    -- sort the table mptr into nets ascending
    table.sort( mptr, smallest_range )
    -- select the first net that includes host.ip
    local str_net
    local index
    for i, pointer_to_inetnum in ipairs( mptr ) do
      if ipOps.ip_in_range( ip, pointer_to_inetnum.range ) then
        str_net = pointer_to_inetnum.range
        ptr = pointer_to_inetnum.pointer
        index = i
        break
      end
    end

    if mptr[index+1] and ( mptr[index+1].pointer > mptr[index].pointer ) then
      bound = mptr[index+1].pointer
    end
    stdnse.debug5("%s Smallest range containing target IP addr. is %s.", db, trim( str_net ))
    -- isolate inetnum and associated objects
    if bound then
      stdnse.debug5("%s smallest range is offset from %s to %s.", db, ptr, bound)
      -- get from pointer to bound
      return response:sub(ptr,bound), ptr
    else
      stdnse.debug5("%s smallest range is offset from %s to %s.", db, ptr, "the end")
      -- or get the whole thing from the pointer onwards
      return response:sub(ptr), ptr
    end
  end -- if # mptr

  return response, 0

end -- function



---
-- This function prevents the caching of large ranges in certain circumstances which would adversely affect lookups against the cache.
-- Specifically we don't allow a cache entry including either a referral or a found record with a range equal to 0/0 or ::/0.
-- Instead we cache an /8 or, in the case of IPv6, /23 - These are large, but safer ranges.
-- Additionally, we don't allow a cache entry for a found record with ranges larger than IPv4 /8 and IPv6 /23.
-- Instead we cache an /24 or, in the case of IPv6, /96 - These are small ranges and are a fair trade-off between accuracy and repeated queries.
-- @param ip     String representing the Target's IP address.
-- @param range  String representing a range of IP addresses.
-- @usage        range = not_short_prefix( ip, range )
-- @return       String range - either the supplied, or a modified one (or nil in case of an error).
-- @see          get_assignment

function not_short_prefix( ip, range, redirect )

  if type( range ) ~= "string" or range == "" then return nil end

  local err, zero_first, zero_last, fake_prefix, short_prefix, safe_prefix, first, last = {}
  if range:match( ":" ) then
    short_prefix = 23
    safe_prefix = 96
    zero_first, zero_last, err[#err+1] = ipOps.get_ips_from_range( "::/0" )
  else
    short_prefix = 8
    safe_prefix = 24
    zero_first, zero_last, err[#err+1] = ipOps.get_ips_from_range( "0/0" )
  end

  first, last, err[#err+1] = ipOps.get_ips_from_range( range )

  if #err > 0 then
    stdnse.debug1("Error in not_short_prefix: s%.", table.concat( err, " " ))
    return nil
  end

  if ipOps.compare_ip( first, "eq", zero_first ) and ipOps.compare_ip( last, "eq", zero_last ) then
    return ( get_assignment ( ip, short_prefix ) )
  elseif not redirect and ( get_prefix_length( range ) <= short_prefix ) then
    return ( get_assignment ( ip, safe_prefix ) )
  end

  return range

end



---
-- Caches discovered records and referrals in the registry.
-- The cache is indexed by the Target IP addresses sent as Whois query terms.
-- A lookup against the cache is performed by testing the cached IP address range, hence a range must always be present in each cache entry.
-- Where a range is not passed as a parameter, a small assignment containing the Target's IP address is instead cached.
-- Either a referral or output data should also be present in the cache - so one or the other should always be passed as a parameter.
-- @param ip         String representing the Target's IP address.
-- @param range      String representing the most specific assignment found in a whois record.  May be nil.
-- @param redirect   String id of a referred service defined in whoisdb.
-- @param data       Table or String of extracted data.
-- @see              get_assignment

function add_to_cache( ip, range, redirect, data )

  if type( ip ) ~= "string" or ip == "" then return end

  local af, longest_prefix
  if ip:match( ":" ) then
    af = "ipv6"
    longest_prefix = 48 -- increased from 32 (20080902).
  else
    af = "ipv4"
    longest_prefix = 29 -- 8 hosts
  end

  -- we need to cache some range so we'll cache the small assignment that includes ip.
  if type( range ) ~= "string" or type( get_prefix_length( range ) ) ~= "number" then
    range = get_assignment( ip, longest_prefix )
    stdnse.debug5("Caching an assumed Range: %s", range)
  end

  nmap.registry.whois.cache[ip] = {} -- destroy any previous cache entry for this target.
  nmap.registry.whois.cache[ip].data = data
  nmap.registry.whois.cache[ip].range = range
  nmap.registry.whois.cache[ip].redirect = redirect

end



---
-- When passed to <code>table.sort</code>, will sort a table of tables containing IP address ranges in ascending order of size.
-- Identical ranges will be sorted in descending order of their position within a record if it is present.
-- @param range_1  Table: {range = String, pointer = Number}
--                 where range is an IP address range and pointer is the position of that range in a record.
-- @param range_2  Same as range_1.
-- @return         Boolean True if the positions of range_1 and range_2 in the table being sorted are correct, otherwise false.

function smallest_range( range_1, range_2 )

  local sorted = true  -- return value (defaulting true to avoid a loop)
  local r1_first, r1_last = ipOps.get_ips_from_range( range_1.range )
  local r2_first, r2_last = ipOps.get_ips_from_range( range_2.range )

  if  range_1.pointer
  and ipOps.compare_ip( r1_first, "eq", r2_first )
  and ipOps.compare_ip( r1_last, "eq", r2_last )
  and range_1.pointer < range_2.pointer then
    sorted = false
  end

  if ipOps.compare_ip( r1_first, "le", r2_first ) and ipOps.compare_ip( r1_last, "ge", r2_last ) then sorted = false end

  return sorted

end



---
-- Given an IP address and a prefix length, returns a string representing a valid IP address assignment (size is not checked) which contains
-- the supplied IP address.  For example, with ip = 192.168.1.187 and prefix = 24 the return value will be 192.168.1.1-192.168.1.255
-- @param ip      String representing an IP address.
-- @param prefix  String or number representing a prefix length.  Should be of the same address family as ip.
-- @return        String representing a range of addresses from the first to the last hosts (or nil in case of an error).
-- @return        Nil or error message in case of an error.

function get_assignment( ip, prefix )

  local some_ip, err = ipOps.ip_to_bin( ip )
  if err then return nil, err end

  prefix = tonumber( prefix )
  if not prefix or ( prefix < 0 ) or ( prefix > string.len( some_ip ) ) then
    return nil, "Error in get_assignment: Invalid prefix length."
  end

  local hostbits = string.sub( some_ip, prefix + 1 )
  hostbits = string.gsub( hostbits, "1", "0" )
  local first = string.sub( some_ip, 1, prefix ) .. hostbits
  err = {}
  first, err[#err+1] = ipOps.bin_to_ip( first )
  local last
  last, err[#err+1] = ipOps.get_last_ip( ip, prefix )
  if #err > 0 then return nil, table.concat( err, " " ) end

  return first .. "-" .. last

end



---
-- Controls what to output at the end of the script execution.  Attempts to get data from the registry.  If the data is a string it is output as
-- it is.  If the data is a table then <code>format_data_for_output</code> is called.  If there is no cached data, nothing will be output.
-- @param ip                String representing the Target's IP address.
-- @param services_queried  Table of strings. Each is the id of a whois service queried for the Target (tracking.completed).
-- @return                  String - Host Script Results.
-- @see                     get_output_from_cache, format_data_for_output

function output( ip, services_queried )

  local data = get_output_from_cache( ip )

  if type( data ) == "string" then
    return data
  elseif type( data ) == "table" then
    return format_data_for_output( data )
  end

  if type( services_queried ) ~= "table" then
    stdnse.debug1("Error in output(): No data found.")
    return nil
  elseif #services_queried == 0 then
    stdnse.debug1("Error in output(): No data found, no queries were completed.")
    return nil
  elseif #services_queried > 0 then
    stdnse.debug1("Error in output(): No data found - could not understand query responses.")
    return nil
  end

  return nil -- just to be safe

end



---
-- Retrieves data applicable to the Target from the registry.  Cached data is only returned if the Target IP matches a key in the cache.
-- If the Target IP is in a range for which there exists cached data then a pointer string is instead returned.
-- @param ip  String representing the Target's IP address.
-- @return    Table or string or nil.
-- @see       get_cache_key

function get_output_from_cache( ip )

  local ip_key = get_cache_key( ip )
  if not ip_key then
    stdnse.debug1("Error in get_output_from_cache().")
    return nil
  end

  local cache_data = nmap.registry.whois.cache[ip_key]

  if ip == ip_key then
    return cache_data.data
  else
    return "See the result for " .. ip_key .. "."
  end

end



---
-- Uses the output_short or output_long tables to format the supplied table of data for output as a string.
-- @param data  Table of captured fields grouped into whois record objects from a single record.
--              data.id is a string id of the service from which the record was retrieved and data.mirror is a string id of a mirrored service.
-- @return      String, ready for output (i.e. to be returned by action() ).

function format_data_for_output( data )
  -- DISPLAY THE FOUND RECORD
  -- ipairs over the table that dictates the order in which fields
  -- should be output

  local output, display_owner, display_rules = {}
  if data.mirror then
    display_owner = nmap.registry.whois.whoisdb[data.mirror]
  else
    display_owner = nmap.registry.whois.whoisdb[data.id]
  end

  if nmap.verbosity() > 0 then
    display_rules = display_owner.output_long or display_owner.output_short
  else
    display_rules = display_owner.output_short or display_owner.output_long
  end
  if not display_rules then return "Could not format results for display." end

  output[#output+1] = "Record found at "
  output[#output+1] = nmap.registry.whois.whoisdb[data.id].hostname

  for _, objects in ipairs( display_rules ) do

    local object_name, fields
    if type( objects[1] ) == "string" and objects[1] ~= "" and data[objects[1]] then
      object_name = objects[1]
    end
    if object_name and type( objects[2] ) == "table" and #objects[2] > 0 then
      fields = objects[2]
    end

    if fields then
      for _, field_name in ipairs( fields ) do
        if type( field_name ) == "string" and data[object_name][field_name] then

          output[#output+1] = "\n"
          output[#output+1] = field_name
          output[#output+1] = ": "
          output[#output+1] = data[object_name][field_name]

        elseif type( field_name ) == "table" then

          local first_in_line = true

          for _, field_name_sameline in ipairs( field_name ) do
            if type( field_name_sameline ) == "string" and data[object_name][field_name_sameline] then
              if first_in_line then
                first_in_line = false
                output[#output+1] = "\n"
              else
                output[#output+1] = " " -- the space between items on a line
              end
              output[#output+1] = field_name_sameline
              output[#output+1] = ": "
              output[#output+1] = data[object_name][field_name_sameline]

            end
          end

        end
      end
    end

  end

  if #output < 3 then
     output[#output+1] = ", but its content was not understood."
  end

  return ( table.concat( output ):gsub( "[%s\n]\n", "\n" ) )

end



---
-- Trims space characters from either end of a string and converts an empty string to nil.
-- @param to_trim  String to be trimmed.
-- @return         String, trimmed.  If the string is empty before or after trimming (or if the parameter was not a string) then returns nil.

function trim( to_trim )

  if type( to_trim ) ~= "string" or to_trim == "" then return nil end
  local trimmed = ( string.gsub( to_trim, "^%s*(.-)%s*$", "%1" ) )
  if trimmed == "" then trimmed = nil end
  return trimmed

end



---
-- Called once per script invocation, the purpose of this function is to populate the registry with variables and data for use by all threads.
-- @see  get_args, get_local_assignments_data

function script_init()

  ---
  -- fields_meta is a table of patterns and captures and defines from which fields of a whois record to extract data.
  -- The fields are grouped into sets of RPSL-like objects with a key (e.g. rpsl, arin) which identifies the set.
  --
  -- ob_exist:   A pattern that is used to determine whether a record contains a set of objects.
  --             It does not have to be unique to the set of objects.  It does not require captures.
  -- ob_netnum:  A RPSL-like object containing fields describing the Address Assignment.  This object is mandatory for this script.
  -- Other optional objects include: ob_org (organisation), ob_role (role), ob_persn (person) and ob_cust (customer).
  --
  -- Each object table must contain the following:
  -- ob_start:  Pattern for the first field in the object and which marks the start of the object.  Does not require captures.
  -- ob_end:    Pattern for the last field in the object and which marks the end of the object.  Usually ends with "\r?\n\r?\n".
  --            Does not require captures.
  --
  -- The remaining key-value pairs for each object should conform to the following:
  -- key:    is a short name for the field in a whois record and which will be displayed in the scripts output to identify the field.
  -- value:  is a pattern for the field and contains a capture for the data required to be captured.

  nmap.registry.whois.fields_meta = {
    rpsl = {
      ob_exist =  "\r?\n?%s*[Ii]net6?num:%s*.-\r?\n",
      ob_netnum = {
        ob_start = "\r?\n?%s*[Ii]net6?num:%s*.-\r?\n",
        ob_end = "\r?\n%s*[Ss]ource:%s*.-\r?\n\r?\n",
        inetnum = "\r?\n%s*[Ii]net6?num:%s*(.-)\r?\n",
        netname = "\r?\n%s*[Nn]et[-]-[Nn]ame:%s*(.-)\r?\n",
        nettype = "\r?\n%s*[Nn]et[-]-[Tt]ype:%s*(.-)\r?\n",
        descr = "[Dd]escr:[^\r?\n][%s]*(.-)\r?\n",
        country = "\r?\n%s*[Cc]ountry:%s*(.-)\r?\n",
        status = "\r?\n%s*[Ss]tatus:%s*(.-)\r?\n",
        source = "\r?\n%s*[Ss]ource:%s*(.-)\r?\n"
      },
      ob_org = {
        ob_start = "\r?\n%s*[Oo]rgani[sz]ation:%s*.-\r?\n",
        ob_end = "\r?\n%s*[Ss]ource:%s*.-\r?\n\r?\n",
        organisation = "\r?\n%s*[Oo]rgani[sz]ation:%s*(.-)\r?\n",
        orgname = "\r?\n%s*[Oo]rg[-]-[Nn]ame:%s*(.-)\r?\n",
        descr = "[Dd]escr:[^\r?\n][%s]*(.-)\r?\n",
        email = "\r?\n%s*[Ee][-]-[Mm]ail:%s*(.-)\r?\n"
      },
      ob_role = {
        ob_start = "\r?\n%s*[Rr]ole:%s*.-\r?\n",
        ob_end = "\r?\n%s*[Ss]ource:%s*.-\r?\n\r?\n",
        role = "\r?\n%s*[Rr]ole:%s*(.-)\r?\n",
        email = "\r?\n%s*[Ee][-]-[Mm]ail:%s*(.-)\r?\n"
      },
      ob_persn = {
        ob_start = "\r?\n%s*[Pp]erson:%s*.-\r?\n",
        ob_end = "\r?\n%s*[Ss]ource:%s*.-\r?\n\r?\n",
        person = "\r?\n%s*[Pp]erson:%s*(.-)\r?\n",
        email = "\r?\n%s*[Ee][-]-[Mm]ail:%s*(.-)\r?\n"
      }
    },
    arin = {
      ob_exist =  "\r?\n%s*[Nn]et[-]-[Rr]ange:.-\r?\n",
      ob_netnum = {
        ob_start = "\r?\n%s*[Nn]et[-]-[Rr]ange:.-\r?\n",
        ob_end = "\r?\n\r?\n",
        netrange = "\r?\n%s*[Nn]et[-]-[Rr]ange:(.-)\r?\n",
        netname = "\r?\n%s*[Nn]et[-]-[Nn]ame:(.-)\r?\n",
        nettype = "\r?\n%s*[Nn]et[-]-[Tt]ype:(.-)\r?\n"
      },
      ob_org = {
        ob_start = "\r?\n%s*[Oo]rg[-]-[Nn]ame:.-\r?\n",
        ob_end = "\r?\n\r?\n",
        orgname = "\r?\n%s*[Oo]rg[-]-[Nn]ame:(.-)\r?\n",
        orgid = "\r?\n%s*[Oo]rg[-]-[Ii][Dd]:(.-)\r?\n",
        stateprov = "\r?\n%s*[Ss]tate[-]-[Pp]rov:(.-)\r?\n",
        country = "\r?\n%s*[Cc]ountry:(.-)\r?\n"
      },
      ob_cust = {
        ob_start = "\r?\n%s*[Cc]ust[-]-[Nn]ame:.-\r?\n",
        ob_end = "\r?\n\r?\n",
        custname =  "\r?\n%s*[Cc]ust[-]-[Nn]ame:(.-)\r?\n",
        stateprov = "\r?\n%s*[Ss]tate[-]-[Pp]rov:(.-)\r?\n",
        country = "\r?\n%s*[Cc]ountry:(.-)\r?\n"
      },
      ob_persn = {
        ob_start = "\r?\n%s*[Oo]rg[-]-[Tt]ech[-]-[Nn]ame:.-\r?\n",
        ob_end = "\r?\n\r?\n",
        orgtechname = "\r?\n%s*[Oo]rg[-]-[Tt]ech[-]-[Nn]ame:(.-)\r?\n",
        orgtechemail = "\r?\n%s*[Oo]rg[-]-[Tt]ech[-]-[Ee][-]-[Mm]ail:(.-)\r?\n"
      }
    },
    lacnic = {
      ob_exist =  "\r?\n%s*[Ii]net6?num:%s*.-\r?\n",
      ob_netnum = {
        ob_start = "\r?\n%s*[Ii]net6?num:%s*.-\r?\n",
        ob_end = "\r?\n\r?\n",
        inetnum = "\r?\n%s*[Ii]net6?num:%s*(.-)\r?\n",
        owner = "\r?\n%s*[Oo]wner:%s*(.-)\r?\n",
        ownerid = "\r?\n%s*[Oo]wner[-]-[Ii][Dd]:%s*(.-)\r?\n",
        responsible = "\r?\n%s*[Rr]esponsible:%s*(.-)\r?\n",
        country = "\r?\n%s*[Cc]ountry:%s*(.-)\r?\n",
        source = "\r?\n%s*[Ss]ource:%s*(.-)\r?\n"},
        ob_persn = {ob_start = "\r?\n%s*[Pp]erson:%s*.-\r?\n",
        ob_end = "\r?\n\r?\n",
        person = "\r?\n%s*[Pp]erson:%s*(.-)\r?\n",
        email = "\r?\n%s*[Ee][-]-[Mm]ail:%s*(.-)\r?\n"
      }
    },
    jpnic = {
      ob_exist =  "\r?\n%s*[Nn]etwork%s-[Ii]nformation:%s*.-\r?\n",
      ob_netnum = {
        ob_start = "[[Nn]etwork%s*[Nn]umber]%s*.-\r?\n",
        ob_end = "\r?\n\r?\n",
        inetnum = "[[Nn]etwork%s*[Nn]umber]%s*(.-)\r?\n",
        netname = "[[Nn]etwork%s*[Nn]ame]%s*(.-)\r?\n",
        orgname = "[[Oo]rganization]%s*(.-)\r?\n"
      }
    }
  }

  ---
  -- whoisdb defines the whois services this script is able to query and the script output produced for them.
  -- Each entry is a key-value pair where the key is a short name for the service and value is a table of definitions for that service.
  -- Note that there is defined here an entry for IANA which does not have a whois service.  The entry is defined to allow us to redirect to ARIN when
  -- IANA is referred to in a record.
  --
  -- Each service defined should contain the following:
  --
  -- id:             String. Matches the key for the service and is a short name for the service.
  -- hostname:       String. Hostname of the service.
  -- preflag:        String. Prepended to the target IP address sent in the whois query.
  -- postflag:       String. Appended to the target IP address sent in the whois query.
  -- longname:       Table of strings. Each is a lowercase official (or semi-official) name of the service.
  -- fieldreq:       Linked table entry.  The key identifying a table of a set of objects defined in fields_meta.
  --                 In its records each whois service displays a particular set of objects as defined here.
  -- smallnet_rule:  Linked table entry. The key of a pattern for the field defined in fields_meta which captures the Assignment Range.  This is an
  --                 optional entry and is used to extract the smallest (i.e. Most Specific) range from a record when more than one range is detailed.
  -- redirects:      Table of tables, containing strings.  Used to determine whether a record is referring to a different whois service by
  --                 searching for service specific information in certain fields of the record.
  --                 Each entry is a table thus: { "search_object", "search_field", "pattern" }
  --                 search_object: is the key name for a record object defined in fields_meta, in which to search.
  --                 search_field:  is the key name for a field of the object, the data of which to search.
  --                 pattern:       is typically the id or longname key names.
  --                 In the example: {"ob_org", "orgname", "longname"}, we cycle through each service defined in whoisdb and look for its longname in
  --                 the ob_org.orgname of the current record.
  -- output_short:   Table for each object to be displayed when Nmap verbosity is zero.  The first element of each table is the object name and the
  --                 second element is a table of fields to display.  The elements of the second may be field names, which are each output to a new
  --                 line, or tables containing field names which are output to the same line.
  -- output_long:    Table for each object to be displayed when Nmap verbosity is one or above.  The structure is the same as output_short.
  -- reg:            String name for the field in ob_netnum which captures the Assignment Range (e.g. "netrange", "inetnum"), the data of which is
  --                 cached in the registry.
  -- unordered:      Boolean.  Optional. True if the records from the service display an object other than ob_netnum as the first in the record (such
  --                 as at ARIN).  This flag is used to decide whether we should extract an object immediately before the relevant ob_netnum object
  --                 from a record.

  nmap.registry.whois.whoisdb = {
    arin = {
      id = "arin",
      hostname = "whois.arin.net", preflag = "n +", postflag = "",
      longname = {"american registry for internet numbers"},
      fieldreq = nmap.registry.whois.fields_meta.arin,
      smallnet_rule = nmap.registry.whois.fields_meta.arin.ob_netnum.netrange,
      redirects = {
        {"ob_org", "orgname", "longname"},
        {"ob_org", "orgname", "id"},
        {"ob_org", "orgid", "id"} },
      output_short = {
        {"ob_netnum", {"netrange", "netname"}},
        {"ob_org", {"orgname", "orgid", {"country", "stateprov"}}}  },
      output_long = {
        {"ob_netnum", {"netrange", "netname"}},
        {"ob_org", {"orgname", "orgid", {"country", "stateprov"}}},
        {"ob_cust", {"custname", {"country", "stateprov"}}},
        {"ob_persn", {"orgtechname", "orgtechemail"}} },
      reg = "netrange",
      unordered = true
    },
    ripe = {
      id = "ripe",
      hostname = "whois.ripe.net", preflag = "-B", postflag = "",
      longname = {"ripe network coordination centre"},
      fieldreq = nmap.registry.whois.fields_meta.rpsl,
      smallnet_rule = nmap.registry.whois.fields_meta.rpsl.ob_netnum.inetnum,
      redirects = {
        {"ob_role", "role", "longname"},
        {"ob_org", "orgname", "id"},
        {"ob_org", "orgname", "longname"} },
      output_short = {
        {"ob_netnum", {"inetnum", "netname", "descr", "country"}},
        {"ob_org", {"orgname", "organisation", "descr", "email"}} },
      output_long = {
        {"ob_netnum", {"inetnum", "netname", "descr", "country"}},
        {"ob_org", {"orgname", "organisation", "descr", "email"}},
        {"ob_role", {"role", "email"}},
        {"ob_persn", {"person", "email"}} },
      reg = "inetnum"
    },
    apnic = {
      id = "apnic",
      hostname = "whois.apnic.net", preflag = "", postflag = "",
      longname = {"asia pacific network information centre"},
      fieldreq = nmap.registry.whois.fields_meta.rpsl,
      smallnet_rule = nmap.registry.whois.fields_meta.rpsl.ob_netnum.inetnum,
      redirects = {
        {"ob_netnum", "netname", "id"},
        {"ob_org", "orgname", "longname"},
        {"ob_role", "role", "longname"},
        {"ob_netnum", "source", "id"} },
      output_short = {
        {"ob_netnum", {"inetnum", "netname", "descr", "country"}},
        {"ob_org", {"orgname", "organisation", "descr", "email"}} },
      output_long = {
        {"ob_netnum", {"inetnum", "netname", "descr", "country"}},
        {"ob_org", {"orgname", "organisation", "descr", "email"}},
        {"ob_role", {"role", "email"}},
        {"ob_persn", {"person", "email"}} },
      reg = "inetnum"
    },
    lacnic = {
      id = "lacnic",
      hostname = "whois.lacnic.net", preflag = "", postflag = "",
      longname =
      {"latin american and caribbean ip address regional registry"},
      fieldreq = nmap.registry.whois.fields_meta.lacnic,
      smallnet_rule = nmap.registry.whois.fields_meta.lacnic.ob_netnum.inetnum,
      redirects = {
        {"ob_netnum", "ownerid", "id"},
        {"ob_netnum", "source", "id"} },
      output_short = {
        {"ob_netnum",
        {"inetnum", "owner", "ownerid", "responsible", "country"}}  },
      output_long = {
        {"ob_netnum",
        {"inetnum", "owner", "ownerid", "responsible", "country"}},
        {"ob_persn", {"person", "email"}} },
      reg = "inetnum"
    },
    afrinic = {
      id = "afrinic",
      hostname = "whois.afrinic.net", preflag = "-c", postflag = "",
      longname = {
        "african internet numbers registry",
        "african network information center"
      },
      fieldreq = nmap.registry.whois.fields_meta.rpsl,
      smallnet_rule = nmap.registry.whois.fields_meta.rpsl.ob_netnum.inetnum,
      redirects = {
        {"ob_org", "orgname", "longname"} },
      output_short = {
        {"ob_netnum", {"inetnum", "netname", "descr", "country"}},
        {"ob_org", {"orgname", "organisation", "descr", "email"}} },
      output_long = {
        {"ob_netnum", {"inetnum", "netname", "descr", "country"}},
        {"ob_org", {"orgname", "organisation", "descr", "email"}},
        {"ob_role", {"role", "email"}},
        {"ob_persn", {"person", "email"}} },
      reg = "inetnum"
    },--[[
    jpnic = {
      id = "jpnic",
      hostname = "whois.nic.ad.jp", preflag = "", postflag = "/e",
      longname = {"japan network information center"},
      fieldreq = nmap.registry.whois.fields_meta.jpnic,
      output_short = {
        {"ob_netnum", {"inetnum", "netname", "orgname"}}  },
      reg = "inetnum" },--]]
    iana = {  -- not actually a db but required here
      id = "iana", longname = {"internet assigned numbers authority"}
    }
  }

  nmap.registry.whois.m_none = {
    "\n%s*([Nn]o match found for[%s+]*$addr)",
    "\n%s*([Uu]nallocated resource:%s*$addr)",
    "\n%s*([Rr]eserved:%s*$addr)",
    "\n[^\n]*([Nn]ot%s[Aa]ssigned[^\n]*$addr)",
    "\n%s*(No match!!)%s*\n",
    "(Invalid IP or CIDR block:%s*$addr)",
    "\n%s*%%%s*(Unallocated and unassigned in LACNIC block:%s*$addr)",
  }
  nmap.registry.whois.m_err = {
    "\n%s*([Aa]n [Ee]rror [Oo]ccured)%s*\n",
    "\n[^\n]*([Ee][Rr][Rr][Oo][Rr][^\n]*)\n"
  }

  nmap.registry.whois.remote_assignments_files = {}
  nmap.registry.whois.remote_assignments_files.ipv4 = {
    {
      remote_resource = "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.txt",
      local_resource = "ipv4-address-space",
      match_assignment = "^%s*([%.%d]+/%d+)",
      match_service = "whois%.(%w+)%.net"
    }
  }
  nmap.registry.whois.remote_assignments_files.ipv6 = {
    --[[{
    remote_resource = "http://www.iana.org/assignments/ipv6-address-space/ipv6-address-space.txt",
    local_resource = "ipv6-address-space",
    match_assignment = "^([:%x]+/%d+)",
    match_service = "^[:%x]+/%d+%s*(%w+)"
    },--]]
    {
      remote_resource = "https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.txt",
      local_resource = "ipv6-unicast-address-assignments",
      match_assignment = "^%s*([:%x]+/%d+)",
      match_service = "whois%.(%w+)%.net"
    }
  }

  local err

  -- get and validate any --script-args
  get_args()

  -- mutex for each service
  nmap.registry.whois.mutex = {}
  for id, v in pairs( nmap.registry.whois.whoisdb ) do
    if id ~= "iana" then
      nmap.registry.whois.mutex[id] = nmap.mutex(nmap.registry.whois.whoisdb[id])
    end
  end

  -- get IANA assignments lists
  if nmap.registry.whois.using_local_assignments_file.ipv4
  or nmap.registry.whois.using_local_assignments_file.ipv6 then
    nmap.registry.whois.local_assignments_data = get_local_assignments_data()
    for _, af in ipairs({"ipv4", "ipv6"}) do
      if not nmap.registry.whois.local_assignments_data[af] then
        nmap.registry.whois.using_local_assignments_file[af] = false
        stdnse.debug1("Cannot use local assignments file for address family %s.", af)
      end
    end
  end

  nmap.registry.whois.init_done = true

end



---
-- Parses the command line arguments passed to the script with --script-args.
-- Sets flags in the registry which threads read to determine certain behaviours.
-- Permitted args are 'nofile' - Prevents use of a list of assignments to determine which service to query,
-- 'nofollow' - Prevents following redirects found in records,
-- 'arin', 'ripe', 'apnic', etc. - Service id's, as defined in the whoisdb table in the registry (see script_init).

function get_args()

  if not nmap.registry.args then return end

  local args = stdnse.get_script_args('whois.whodb')

  if type( args ) ~= "string" or ( args == "" ) then return end

  local t = {}
  -- match words in args which may be whois dbs or other arguments
  for db in string.gmatch( args, "%w+" ) do
    if not nmap.registry.whois.whoisdb[db] then
      if ( db == "nofollow" ) then
        nmap.registry.whois.nofollow = true
      elseif ( db == "nocache" ) then
        nmap.registry.whois.using_cache = false
      elseif ( db == "nofile" ) then
        nmap.registry.whois.using_local_assignments_file.ipv4 = false
        nmap.registry.whois.using_local_assignments_file.ipv6 = false
      end
    elseif not ( string.match( table.concat( t, " " ), db ) ) then
      -- we have a unique valid whois db
      t[#t+1] = db
    end
  end

  if ( #t > 0 ) then
    -- "nofile" is implied by supplying custom whoisdb_default_order
    nmap.registry.whois.using_local_assignments_file.ipv4 = false
    nmap.registry.whois.using_local_assignments_file.ipv6 = false
    stdnse.debug3("Not using local assignments data because custom whoisdb_default_order was supplied.")
  end

  if ( #t > 1 ) and nmap.registry.whois.nofollow then
    -- using nofollow, we do not follow redirects and can only accept what we find as a record therefore we only accept the first db supplied
    t = {t[1]}
    stdnse.debug1("Too many args supplied with 'nofollow', only using %s.", t[1])
  end

  if ( #t > 0 ) then
    nmap.registry.whois.whoisdb_default_order = t
    stdnse.debug2("whoisdb_default_order: %s.", table.concat( t, " " ))
  end

end



---
-- Makes IANA hosted assignments data available for lookups against that data.  In more detail it:
-- Caches a local copy of remote assignments data if copies do not currently exist or are out-of-date.
-- Checks whether the cached copies require updating and performs update as required.
-- Parses the cached copies and populates a table of lookup data which is returned to the caller.
-- Sets a flag in the registry to prevent use of the lookup data in the event of an error.
-- @return  Table of lookup data (or nil in case of an error).
-- @return  Nil or error message in case of an error.

function get_local_assignments_data()

  if not next( nmap.registry.whois.remote_assignments_files ) then
    stdnse.debug1("Error in get_local_assignments_data: Remote resources not defined in remote_assignments_files registry key")
    return nil
  end

  -- get the directory path where cached files will be stored.
  local fetchfile = "nmap-services"
  local directory_path, err = get_parentpath( fetchfile )
  if err then
    stdnse.debug1("Nmap.fetchfile() failed to get a path to %s: %s.", fetchfile, err)
    return nil
  end

  local ret = {}

  -- cache or update and parse each remote file for each address family
  for address_family, t in pairs( nmap.registry.whois.remote_assignments_files ) do
    for i, assignment_data_spec in ipairs( t ) do

      local update_required, modified_date, entity_tag

      -- do we have a cached file and does it need updating?
      local file = directory_path .. assignment_data_spec.local_resource
      local exists, readable, writable = file_stat(file)
      if not exists and (readable and writable) then
        update_required = true
      elseif exists and readable then
        update_required, modified_date, entity_tag = requires_updating( file )
        if update_required and not writable then
          update_required = false
          readable = false
        end
      end

      local file_content

      -- read an existing and up-to-date file into file_content.
      if readable and not update_required then
        stdnse.debug2("%s was cached less than %s ago. Reading...", file, nmap.registry.whois.local_assignments_file_expiry)
        file_content = read_from_file( file )
      end

      -- cache or update and then read into file_content
      local http_response, write_success
      if update_required then
        http_response = ( conditional_download( assignment_data_spec.remote_resource, modified_date, entity_tag ) )
        if not http_response or type( http_response.status ) ~= "number" then
          stdnse.debug1("Failed whilst requesting %s.", assignment_data_spec.remote_resource)
        elseif http_response.status == 200 then
          -- prepend our file header
          stdnse.debug2("Retrieved %s.", assignment_data_spec.remote_resource)
          file_content = stdnse.strsplit( "\r?\n", http_response.body )
          table.insert( file_content, 1, "** Do Not Alter This Line or The Following Line **" )
          local hline = {}
          hline[#hline+1] = "<" .. os.time() .. ">"
          hline[#hline+1] = "<" .. http_response.header["last-modified"] .. ">"
          if http_response.header.etag then
            hline[#hline+1] = "<" .. http_response.header.etag .. ">"
          end
          table.insert( file_content, 2, table.concat( hline ) )
          write_success, err = write_to_file( file, file_content )
          if err then
            stdnse.debug1("Error writing %s to %s: %s.", assignment_data_spec.remote_resource, file, err)
          end
        elseif http_response.status == 304 then
          -- update our file header with a new timestamp
          stdnse.debug1("%s is up-to-date.", file)
          file_content = read_from_file( file )
          file_content[2] = file_content[2]:gsub("^<[-+]?%d+>(.*)$", "<" .. os.time() .. ">%1")
          write_success, err = write_to_file( file, file_content )
          if err then
            stdnse.debug1("Error writing to %s: %s.", file, err)
          end
        else
          stdnse.debug1("HTTP %s whilst requesting %s.", http_response.status, assignment_data_spec.remote_resource)
        end
      end


      if file_content then
        -- Create a table for this address family (if there isn't one already).
        if not ret[address_family] then ret[address_family] = {} end
        -- Parse data and add to the table for this address family.
        local t
        t, err = parse_assignments( assignment_data_spec, file_content )
        if #t == 0 or err then
          -- good header, but bad file?  Kill the file!
          write_to_file( file, "" )
          stdnse.debug1("Problem with the data in %s.", file)
        else
          for i, v in pairs( t ) do
            ret[address_family][#ret[address_family]+1] = v
          end
        end
      end

    end -- file
  end -- af

  -- If we decide to use more than one assignments file for ipv6 we may need to sort the resultant parsed list so that sub-assignments appear
  -- before their parent.  This is expensive, but it's worth doing to ensure the lookup process returns the correct service.
  -- table.sort( ret.ipv6, sort_assignments )

  -- final check for an empty table which we'll convert to nil
  for af, t in pairs( ret ) do
    if #t == 0 then
      ret[af] = nil
    end
  end

  return ret

end



---
-- Uses <code>nmap.fetchfile</code> to get the path of the parent directory of the supplied Nmap datafile SCRIPT_NAME.
-- @param fname  String - Filename of an Nmap datafile.
-- @return       String - The filepath of the directory containing the supplied SCRIPT_NAME including the trailing slash (or nil in case of an error).
-- @return       Nil or error message in case of an error.

function get_parentpath( fname )

  if type( fname ) ~= "string" or fname == "" then
    return nil, "Error in get_parentpath: Expected fname as a string."
  end

  local path = nmap.fetchfile( fname )
  if not path then
    return nil, "Error in get_parentpath: Call to fetchfile() failed."
  end

  path = path:sub( 1, path:len() - fname:len() )
  return path

end



--;
-- Tests a file path to determine whether it exists, can be read from and can be written to.
-- An attempt is made to create the file if it does not exist and no attempt is made to remove
-- it if creation succeeded.
-- @param path Path to a file.
-- @return     Boolean True if exists, False if not (at time of calling), nil if determination failed.
-- @return     Boolean True if readable, False if not, nil if determination failed.
-- @return     Boolean True if writable, False if not, nil if determination failed.
function file_stat( path )

  local exists, readable, writable

  local f, err = io.open(path, 'r')
  if f then
    f.close()
    exists = true
    readable = true
    f, err = io.open(path, 'a')
    if f then
      f.close()
      writable = true
    elseif err:match('Permission denied') then
      writable = false
    end
  elseif err:match('No such file or directory') then
    exists = false
    f, err = io.open(path, 'w')
    if f then
      f.close()
      writable = true
      f, err = io.open(path, 'r')
      if f then
        f.close()
        readable = true
      elseif err:match('Permission denied') then
        readable = false
      end
    elseif err:match('Permission denied') then
      writable = false
    end
  elseif err:match('Permission denied') then
    exists = true -- probably
    readable = false
  end

  return exists, readable, writable

end



---
-- Checks whether a cached file requires updating via HTTP.
-- The cached file should contain the following string on the second line: "<timestamp><Last-Modified-Date><Entity-Tag>".
-- where timestamp is number of seconds since epoch at the time the file was last cached and
-- Last-Modified-Date is an HTTP compliant date sting returned by an HTTP server at the time the file was last cached and
-- Entity-Tag is an HTTP Etag returned by an HTTP server at the time the file was last cached.
-- @param file  Filepath of the cached file.
-- @return      Boolean False if file does not require updating, true otherwise.
-- @return      nil or a valid modified-date (string).
-- @return      nil or a valid entity_tag (string).
-- @see         file_is_expired

function requires_updating( file )

  local last_cached, mod, etag, has_expired

  local f, err, _ = io.open( file, "r" )
  if not f then return true, nil end

  local _ = f:read()
  local stamp = f:read()
  f:close()
  if not stamp then return true, nil end

  last_cached, mod, etag = stamp:match( "^<([^>]*)><([^>]*)><?([^>]*)>?$" )
  if (etag == "") then etag = nil end
  if not ( last_cached or mod or etag ) then return true, nil end
  if not (
    mod:match( "%a%a%a,%s%d%d%s%a%a%a%s%d%d%d%d%s%d%d:%d%d:%d%d%s%u%u%u" )
  or
    mod:match( "%a*day,%d%d-%a%a%a-%d%d%s%d%d:%d%d:%d%d%s%u%u%u" )
  or
    mod:match( "%a%a%a%s%a%a%a%s%d?%d%s%d%d:%d%d:%d%d%s%d%d%d%d" )
  ) then
    mod = nil
  end
  if not etag and not mod then
    return true, nil
  end

  -- Check whether the file was cached within local_assignments_file_expiry (registry value)
  has_expired = file_is_expired( last_cached )

  return has_expired, mod, etag

end



---
-- Reads a file, line by line, into a table.
-- @param file  String representing a filepath.
-- @return      Table (array-style) of lines read from the file (or nil in case of an error).
-- @return      Nil or error message in case of an error.

function read_from_file( file )

  if type( file ) ~= "string" or file == "" then
    return nil, "Error in read_from_file: Expected file as a string."
  end

  local f, err, _ = io.open( file, "r" )
  if not f then
    stdnse.debug1("Error opening %s for reading: %s", file, err)
    return nil, err
  end

  local line, ret = nil, {}
  while true do
    line = f:read()
    if not line then break end
    ret[#ret+1] = line
  end

  f:close()

  return ret

end



---
-- Performs either an HTTP Conditional GET request if mod_date or e_tag is passed, or a plain GET request otherwise.
-- Will follow a single redirect for the remote resource.
-- @param url       String representing the full URL of the remote resource.
-- @param mod_date  String representing an HTTP date.
-- @param e_tag     String representing an HTTP entity tag.
-- @return          Table as per <code>http.request</code> or <code>nil</code> in case of a non-HTTP error.
-- @return          Nil or error message in case of an error.
-- @see             http.request

function conditional_download( url, mod_date, e_tag )

  if type( url ) ~= "string" or url == "" then
    return nil, "Error in conditional_download: Expected url as a string."
  end

  -- mod_date and e_tag allowed to be nil or a non-empty string
  if mod_date and ( type( mod_date ) ~= "string" or mod_date == "" ) then
    return nil, "Error in conditional_download: Expected mod_date as nil or as a non-empty string."
  end
  if e_tag and ( type( e_tag ) ~= "string" or e_tag == "" ) then
    return nil, "Error in conditional_download: Expected e_tag as nil or as a non-empty string."
  end

  -- use e_tag in preference to mod_date
  local request_options = {}
  request_options.header = {}
  if e_tag then
    request_options.header["If-None-Match"] = e_tag
  elseif mod_date then
    request_options.header["If-Modified-Since"] = mod_date
  end
  if not next( request_options.header ) then request_options = nil end

  local request_response = http.get_url( url, request_options )

  -- follow one redirection
  if  request_response.status ~= 304
  and ( tostring( request_response.status ):match( "30%d" )
  and type( request_response.header.location ) == "string"
  and request_response.header.location ~= "" ) then
    stdnse.debug2("HTTP Status:%d New Location: %s.", request_response.status, request_response.header.location)
    request_response = http.get_url( request_response.header.location, request_options )
  end

  return request_response

end



---
-- Writes the supplied content to file.
-- @param file     String representing a filepath (if it exists it will be overwritten).
-- @param content  String or table of data to write to file.  Empty string or table is permitted.
--                 A table will be written to file with each element of the table on a new line.
-- @return         Boolean True on success or nil in case of an error.
-- @return         Nil or error message in case of an error.

function write_to_file( file, content )

  if type( file ) ~= "string" or file == "" then
    return nil, "Error in write_to_file: Expected file as a string."
  end
  if type( content ) ~= "string" and type( content ) ~= "table" then
    return nil, "Error in write_to_file: Expected content as a table or string."
  end

  local f, err, _ = io.open( file, "w" )
  if not f then
    stdnse.debug1("Error opening %s for writing: %s.", file, err)
    return nil, err
  end

  if ( type( content ) == "table" ) then
    content = table.concat( content, "\n" ) or ""
  end
  f:write( content )

  f:close()

  return true

end



---
-- Converts raw data from an assignments file into a form optimised for lookups against that data.
-- @param address_family_spec  Table (assoc. array) containing patterns for extracting data.
-- @param table_of_lines       Table containing a line of data per table element.
-- @return                     Table - each element of the form { range = { first = data, last = data }, service = data } (or nil in case of an error).
-- @return                     Nil or error message in case of an error.

function parse_assignments( address_family_spec, table_of_lines )

  if #table_of_lines < 1 then
    return nil, "Error in parse_assignments: Expected table_of_lines as a non-empty table."
  end

  local mnetwork = address_family_spec.match_assignment
  local mservice = address_family_spec.match_service

  local ret, net, svc = {}

  for i, line in ipairs( table_of_lines ) do

    net = line:match( mnetwork )
    if net then
      svc = line:match( mservice )
      if svc then svc = string.lower( svc ) end
      if not svc or ( svc == "iana" ) then
        svc = "arin"
      elseif not nmap.registry.whois.whoisdb[svc] then
        svc = "arin"
      end
      -- optimise the data
      local first_ip, last_ip, err = ipOps.get_ips_from_range( net )
      if not err then
        local t = { first = first_ip, last = last_ip }
        ret[#ret+1] = { range = t, service = svc }
      end
    end

  end

  return ret

end



---
-- Checks the age of the supplied timestamp and compares it to the value of local_assignments_file_expiry.
-- @param time_string  String representing a timestamp (seconds since epoch).
-- @return             Boolean True if the period elapsed since the timestamp is longer than the value of local_assignments_file_expiry
--                     also returns true if the parameter is not of the expected type, otherwise returns false.
-- @see                sane_expiry_period

function file_is_expired( time_string )

  if type( time_string ) ~= "string" or time_string == "" then return true end
  local allowed_age = nmap.registry.whois.local_assignments_file_expiry
  if allowed_age == "" then return true end

  local cached_time = tonumber(time_string)
  if not cached_time then return true end

  local now_time = os.time()
  if now_time < cached_time then return true end
  if now_time > ( cached_time + sane_expiry_period( allowed_age ) ) then return true end

  return false

end



---
-- Checks that the supplied string represents a period of time between 0 and 7 days.
-- @param period  String representing a period.
-- @return        Number representing the supplied period or a failsafe period in whole seconds.
-- @see           get_period

function sane_expiry_period( period )

  local sane_default_expiry = 57600 -- 16h
  local max_expiry = 604800 -- 7d

  period = get_period( period )
  if not period or ( period == "" ) then return sane_default_expiry end

  if period < max_expiry then return period end
  return max_expiry

end



---
-- Converts a string representing a period of time made up of a quantity and a unit such as "24h"
-- into whole seconds.
-- @param period  String combining a quantity and a unit of time.
--                Acceptable units are days (D or d), hours (H or h), minutes (M or m) and seconds (S or s).
--                If a unit is not supplied or not one of the above acceptable units, it is assumed to be seconds.
--                Negative or fractional periods are permitted.
-- @return        Number representing the supplied period in whole seconds (or nil in case of an error).

function get_period( period )

  if type( period ) ~= string or ( period == "" ) then return nil end
  local quant, unit = period:match( "(-?+?%d*%.?%d*)([SsMmHhDd]?)" )
  if not ( tonumber( quant ) ) then return nil end

  if ( string.lower( unit ) == "m" ) then
    unit = 60
  elseif ( string.lower( unit ) == "h" ) then
    unit = 3600
  elseif ( string.lower( unit ) == "d" ) then
    unit = 86400
  else
    -- seconds and catch all
    unit = 1
  end

  return ( math.modf( quant * unit ) )

end



--
-- Passed to <code>table.sort</code>, will sort a table of IP assignments such that sub-assignments appear before their parent.
-- This function is not in use at the moment (see get_local_assignments_data) and will not appear in nse documentation.
-- @param first   Table { range = { first = IP_addr, last = IP_addr } }
-- @param second  Table { range = { first = IP_addr, last = IP_addr } }
-- @return        Boolean True if the tables are already in the correct order, otherwise false.

function sort_assignments( first, second )

  local f_lo, f_hi = first.range.first, first.range.last
  local s_lo, s_hi = second.range.first, second.range.last

  if ipOps.compare_ip( f_lo, "gt", s_lo ) then return false end
  if ipOps.compare_ip( f_lo, "le", s_lo ) and ipOps.compare_ip( f_hi, "ge", s_hi ) then
    return false
  end

  return true

end
