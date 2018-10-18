--- Library for supporting DNS Service Discovery
--
-- The library supports
-- * Unicast and Multicast requests
-- * Decoding responses
-- * Running requests in parallel using Lua coroutines
--
-- The library contains the following classes
-- * <code>Comm</code>
-- ** A class with static functions that handle communication using the dns library
-- * <code>Helper</code>
-- ** The helper class wraps the <code>Comm</code> class using functions with a more descriptive name.
-- ** The purpose of this class is to give developers easy access to some of the common DNS-SD tasks.
-- * <code>Util</code>
-- ** The <code>Util</code> class contains a number of static functions mainly used to convert data.
--
-- The following code snippet queries all mDNS resolvers on the network for a
-- full list of their supported services and returns the formatted output:
-- <code>
--   local helper = dnssd.Helper:new( )
--   helper:setMulticast(true)
--   return stdnse.format_output(helper:queryServices())
-- </code>
--
-- This next snippet queries a specific host for the same information:
-- <code>
--   local helper = dnssd.Helper:new( host, port )
--   return stdnse.format_output(helper:queryServices())
-- </code>
--
-- In order to query for a specific service a string or table with service
-- names can be passed to the <code>Helper.queryServices</code> method.
--
-- @args dnssd.services string or table containing services to query
--
-- @author Patrik Karlsson <patrik@cqure.net>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
--

local coroutine = require "coroutine"
local dns = require "dns"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"
local target = require "target"
_ENV = stdnse.module("dnssd", stdnse.seeall)

Util = {

  --- Compare function used for sorting IP-addresses
  --
  -- @param a table containing first item
  -- @param b table containing second item
  -- @return true if a is less than b
  ipCompare = function(a, b)
    return ipOps.compare_ip(a, "lt", b)
  end,

  --- Function used to compare discovered DNS services so they can be sorted
  --
  -- @param a table containing first item
  -- @param b table containing second item
  -- @return true if the port of a is less than the port of b
  serviceCompare = function(a, b)
    -- if no port is found use 999999 for comparing, this way all services
    -- without ports and device information gets printed at the end
    local port_a = a.name:match("^(%d+)") or 999999
    local port_b = b.name:match("^(%d+)") or 999999

    if ( tonumber(port_a) < tonumber(port_b) ) then
      return true
    end
    return false
  end,

  --- Creates a service host table
  --
  -- ['_ftp._tcp.local'] = {10.10.10.10,20.20.20.20}
  -- ['_http._tcp.local'] = {30.30.30.30,40.40.40.40}
  --
  -- @param response containing multiple responses from <code>dns.query</code>
  -- @return services table containing the service name as a key and all host addresses as value
  createSvcHostTbl = function( response )
    local services = {}
    -- Create unique table of services
    for _, r in ipairs( response ) do
      -- do we really have multiple responses?
      if ( not(r.output) ) then return end
      for _, svc in ipairs(r.output ) do
        services[svc] = services[svc] or {}
        table.insert(services[svc], r.peer)
      end
    end

    return services
  end,

  --- Creates a unique list of services
  --
  -- @param response containing a single or multiple responses from
  --        <code>dns.query</code>
  -- @return array of strings containing service names
  getUniqueServices = function( response )
    local services = {}

    for _, r in ipairs(response) do
      if ( r.output ) then
        for _, svc in ipairs(r.output) do services[svc] = true end
      else
        services[r] = true
      end
    end

    return services
  end,

  --- Returns the amount of currently active threads
  --
  -- @param threads table containing the list of threads
  -- @return count number containing the number of non-dead threads
  threadCount = function( threads )
    local count = 0

    for thread in pairs(threads) do
      if ( coroutine.status(thread) == "dead" ) then
        threads[thread] = nil
      else
        count = count + 1
      end
    end
    return count
  end

}

Comm = {

  --- Gets a record from both the Answer and Additional section
  --
  -- @param dtype DNS resource record type.
  -- @param response Decoded DNS response.
  -- @param retAll If true, return all entries, not just the first.
  -- @return True if one or more answers of the required type were found - otherwise false.
  -- @return Answer according to the answer fetcher for <code>dtype</code> or an Error message.
  getRecordType = function( dtype, response, retAll )

    local result = {}
    local status1, answers = dns.findNiceAnswer( dtype, response, retAll )

    if status1 then
      if retAll then
        for _, v in ipairs(answers) do
          table.insert(result, string.format("%s", v) )
        end
      else
        return true, answers
      end
    end

    local status2, answers = dns.findNiceAdditional( dtype, response, retAll )

    if status2 then
      if retAll then
        for _, v in ipairs(answers) do
          table.insert(result, v)
        end
      else
        return true, answers
      end
    end

    if not status1 and not status2 then
      return false, answers
    end

    return true, result

  end,

  --- Send a query for a particular service and store the response in a table
  --
  -- @param host string containing the ip to connect to
  -- @param port number containing the port to connect to
  -- @param svc the service record to retrieve
  -- @param multiple true if responses from multiple hosts are expected
  -- @param svcresponse table to which results are stored
  queryService = function( host, port, svc, multiple, svcresponse )
    local condvar = nmap.condvar(svcresponse)
    local status, response = dns.query( svc, { port = port, host = host, dtype="PTR", retPkt=true, retAll=true, multiple=multiple, sendCount=1, timeout=2000} )
    if not status then
      stdnse.debug1("Failed to query service: %s; Error: %s", svc, response)
      return
    end
    svcresponse[svc] = svcresponse[svc] or {}
    if ( multiple ) then
      for _, r in ipairs(response) do
        table.insert( svcresponse[svc], r )
      end
    else
      svcresponse[svc] = response
    end
    condvar("broadcast")
  end,

  --- Decodes a record received from the <code>queryService</code> function
  --
  -- @param response as returned by <code>queryService</code>
  -- @param result table into which the decoded output should be stored
  decodeRecords = function( response, result )
    local service, deviceinfo = {}, {}
    local txt = {}
    local ipv6, srv, address, port, proto

    local record = ( #response.questions > 0 and response.questions[1].dname ) and response.questions[1].dname or ""

    local status, ip = Comm.getRecordType( dns.types.A, response, false )
    if status then address = ip end

    status, ipv6 = Comm.getRecordType( dns.types.AAAA, response, false )
    if status then
      address = address or ""
      address = address .. " " .. ipv6
    end

    status, txt = Comm.getRecordType( dns.types.TXT, response, true )
    if status then
      for _, v in ipairs(txt) do
        if v:len() > 0 then
          table.insert(service, v)
        end
      end
    end

    status, srv = Comm.getRecordType( dns.types.SRV, response, false )
    if status then
      local srvparams = stringaux.strsplit( ":", srv )

      if #srvparams > 3 then
        port = srvparams[3]
      end
    end

    if address then
      table.insert( service, ("Address=%s"):format( address ) )
    end

    if record == "_device-info._tcp.local" then
      service.name = "Device Information"
      deviceinfo = service
      table.insert(result, deviceinfo)
    else
      local serviceparams = stringaux.strsplit("[.]", record)

      if #serviceparams > 2 then
        local servicename = serviceparams[1]:sub(2)
        local proto = serviceparams[2]:sub(2)

        if port == nil or proto == nil or servicename == nil then
          service.name = record
        else
          service.name = string.format( "%s/%s %s", port, proto, servicename)
        end
      end
      table.insert( result, service )
    end
  end,

  --- Query the mDNS resolvers for a list of their services
  --
  -- @param host table as received by the action function
  -- @param port number specifying the port to connect to
  -- @param multiple receive multiple responses (multicast)
  -- @return True if a dns response was received and contained an answer of
  --         the requested type, or the decoded dns response was requested
  --         (retPkt) and is being returned - or False otherwise.
  -- @return String answer of the requested type, Table of answers or a
  --         String error message of one of the following:
  --         "No Such Name", "No Servers", "No Answers",
  --         "Unable to handle response"
  queryAllServices = function( host, port, multiple )
    local sendCount, timeout = 1, 2000
    if ( multiple ) then
      sendCount, timeout = 2, 5000
    end
    return dns.query( "_services._dns-sd._udp.local", { port = port, host = ( host.ip or host ), dtype="PTR", retAll=true, multiple=multiple, sendCount=sendCount, timeout=timeout } )
  end,

}

Helper = {

  --- Creates a new helper instance
  --
  -- @param host string containing the host name or ip
  -- @param port number containing the port to connect to
  -- @return o a new instance of Helper
  new = function( self, host, port )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.mcast = false
    return o
  end,


  --- Instructs the helper to use unconnected sockets supporting multicast
  --
  -- @param mcast boolean true if multicast is to be used, false otherwise
  setMulticast = function( self, mcast )
    assert( type(mcast)=="boolean", "mcast has to be either true or false")
    self.mcast = mcast
  end,

  --- Performs a DNS-SD query against a host
  --
  -- @param host table as received by the action function
  -- @param port number specifying the port to connect to
  -- @param service string or table with the service(s) to query eg.
  --         _ssh._tcp.local, _afpovertcp._tcp.local
  --        if nil defaults to _services._dns-sd._udp.local (all)
  -- @param mcast boolean true if a multicast query is to be done
  -- @return status true on success, false on failure
  -- @return response table suitable for <code>stdnse.format_output</code>
  queryServices = function( self, service )
    local result = {}
    local status, response
    local mcast = self.mcast
    local port = self.port or 5353
    local family = nmap.address_family()
    local host = mcast and (family=="inet6" and "ff02::fb" or "224.0.0.251") or self.host
    local service = service or stdnse.get_script_args('dnssd.services')

    if ( not(service) ) then
      status, response = Comm.queryAllServices( host, port, mcast )
      if ( not(status) ) then return status, response end
    else
      if ( 'string' == type(service) ) then
        response = { service }
      elseif ( 'table' == type(service) ) then
        response = service
      end
    end

    response = Util.getUniqueServices(response)

    local svcresponse = {}
    local condvar = nmap.condvar( svcresponse )
    local threads = {}

    for svc in pairs(response) do
      local co = stdnse.new_thread( Comm.queryService, (host.ip or host), port, svc, mcast, svcresponse )
      threads[co] = true
    end

    -- Wait for all threads to finish running
    while Util.threadCount(threads)>0 do condvar("wait") end

    local ipsvctbl = {}
    if ( mcast ) then
      -- Process all records that were returned
      for svcname, response in pairs(svcresponse) do
        for _, r in ipairs( response ) do
          ipsvctbl[r.peer] = ipsvctbl[r.peer] or {}
          Comm.decodeRecords( r.output, ipsvctbl[r.peer] )
        end
      end
    else
      -- Process all records that were returned
      for svcname, response in pairs(svcresponse) do
        Comm.decodeRecords( response, result )
      end
    end

    if ( mcast ) then
      -- Restructure and build our output table
      for ip, svctbl in pairs( ipsvctbl ) do
        table.sort(svctbl, Util.serviceCompare)
        svctbl.name = ip
        if target.ALLOW_NEW_TARGETS then target.add(ip) end
        table.insert( result, svctbl )
      end
      table.sort( result, Util.ipCompare )
    else
      -- sort the tables per port
      table.sort( result, Util.serviceCompare )
    end
    return true, result
  end,

}

return _ENV;
