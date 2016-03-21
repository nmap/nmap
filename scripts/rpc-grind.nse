local stdnse = require "stdnse"
local nmap = require "nmap"
local rpc = require "rpc"
local bin = require "bin"
local math = require "math"
local io = require "io"
local coroutine = require "coroutine"
local table = require "table"

description = [[
Fingerprints the target RPC port to extract the target service, RPC number and version.

The script works by sending RPC Null call requests with a random high version
unsupported number to the target service with iterated over RPC program numbers
from the nmap-rpc file and check for replies from the target port.
A reply with a RPC accept state 2 (Remote can't support version) means that we
the request sent the matching program number, and we proceed to extract the
supported versions. A reply with an accept state RPC accept state 1 (remote
hasn't exported program) means that we have sent the incorrect program number.
Any other accept state is an incorrect behaviour.
]]

---
-- @args rpc-grind.threads Number of grinding threads. Defaults to <code>4</code>
--
-- @usage
-- nmap -sV <target>
-- nmap --script rpc-grind <target>
-- nmap --script rpc-grind --script-args 'rpc-grind.threads=8' -p <targetport>
-- <target>
--
--@output
--PORT      STATE SERVICE VERSION
--53344/udp open  walld   1 (RPC #100008)
--


author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"version"}

-- Depend on rpcinfo so we don't grind something that's already known.
dependencies = {"rpcinfo"}

portrule = function(host, port)
  -- Do not run for excluded ports
  if (nmap.port_is_excluded(port.number, port.protocol)) then
    return false
  end
  if port.service ~= nil and port.version.service_dtype ~= "table" and port.service ~= 'rpcbind' then
    -- Exclude services that have already been detected as something
    -- different than rpcbind.
    return false
  end
  return nmap.version_intensity() >= 7
end

--- Function that determines if the target port of host uses RPC protocol.
--@param host Host table as commonly used in Nmap.
--@param port Port table as commonly used in Nmap.
--@return status boolean True if target port uses RPC protocol, false else.
local isRPC = function(host, port)
  -- If rpcbind is already set up by -sV
  -- which does practically the same check as in the "else" part.
  -- The nmap-services-probe entry "rpcbind" is not correctly true, and should
  -- be changed to something like "sunrpc"
  if port.service == 'rpcbind' then
    return true
  else
    -- this check is important if we didn't run the scan with -sV.
    -- If we run the scan with -sV, this check shouldn't return true as it is pretty much similar
    -- to the "rpcbind" service probe in nmap-service-probes.
    local rpcConn, status, err, data, rxid, msgtype, _

    -- Create new socket
    -- rpcbind is not really important, we could have used another protocol from rpc.lua
    -- such as nfs or mountd. Same thing for version 2.
    rpcConn = rpc.Comm:new("rpcbind", 2)
    status, err = rpcConn:Connect(host, port)
    if not status then
      stdnse.debug1("%s", err)
      return
    end

    -- Send packet
    local xid = math.random(1234567890)
    data = rpcConn:EncodePacket(xid)
    status, err = rpcConn:SendPacket(data)
    if not status then
      stdnse.debug1("SendPacket(): %s", err)
      return
    end

    -- And check response
    status, data = rpcConn:ReceivePacket()
    if not status then
      stdnse.debug1("isRPC didn't receive response.")
      return
    else
      -- If we got response, set port to open
      nmap.set_port_state(host, port, "open")

      _, rxid = bin.unpack(">I", data, 1)
      _, msgtype = bin.unpack(">I", data, 5)
      -- If response XID does match request XID
      -- and message type equals 1 (REPLY) then
      -- it is a RPC port.
      if rxid == xid and msgtype == 1 then
        return true
      end
    end
  end
  stdnse.debug1("RPC checking function response data is not RPC.")
end

-- Function that iterates over the nmap-rpc file and
-- returns program name and number pairs.
-- @return name Name of the RPC service.
-- @return number RPC number of the matching service name.
local rpcIterator = function()
  -- Check if nmap-rpc file is present.
  local path = nmap.fetchfile("nmap-rpc")
  if not path then
    stdnse.debug1("Could not find nmap-rpc file.")
    return false
  end

  -- And is readable
  local nmaprpc, _, _ = io.open( path, "r" )
  if not nmaprpc then
    stdnse.debug1("Could not open nmap-rpc for reading.")
    return false
  end

  return function()
    while true do
      local line = nmaprpc:read()
      if not line then
        break
      end
      -- Now, we parse lines for meaningful ones
      local name, number = line:match("^%s*([^%s#]+)%s+(%d+)")
      -- And return program name and number
      if name and number then
        return name, tonumber(number)
      end
    end
  end
end

--- Function that sends RPC null commands with a random version number and
-- iterated over program numbers and checks the response for a sign that the
-- sent program number is the matching one for the target service.
-- @param host Host table as commonly used in Nmap.
-- @param port Port table as commonly used in Nmap.
-- @param iterator Iterator function that returns program name and number pairs.
-- @param result table to put result into.
local rpcGrinder = function(host, port, iterator, result)
  local condvar = nmap.condvar(result)
  local rpcConn, version, xid, status, response, packet, err, data, _

  xid = math.random(123456789)
  -- We use a random, most likely unsupported version so that
  -- we also trigger min and max version disclosure for the target service.
  version = math.random(12345, 123456789)
  rpcConn = rpc.Comm:new("rpcbind", version)
  rpcConn:SetCheckProgVer(false)
  status, err = rpcConn:Connect(host, port)

  if not status then
    stdnse.debug1("Connect(): %s", err)
    condvar "signal";
    return
  end
  for program, number in iterator do
    -- No need to continue further if we found the matching service.
    if #result > 0 then
      break
    end

    xid = xid + 1 -- XiD increased by 1 each time (from old RPC grind) <= Any important reason for that?
    rpcConn:SetProgID(number)
    packet = rpcConn:EncodePacket(xid)
    status, err = rpcConn:SendPacket(packet)
    if not status then
      stdnse.debug1("SendPacket(): %s", err)
      condvar "signal";
      return
    end

    status, data = rpcConn:ReceivePacket()
    if not status then
      stdnse.debug1("ReceivePacket(): %s", data)
      condvar "signal";
      return
    end

    _,response = rpcConn:DecodeHeader(data, 1)
    if type(response) == 'table' then
      if xid ~= response.xid then
        -- Shouldn't happen.
        stdnse.debug1("XID mismatch.")
      end
      -- Look at accept state
      -- Not supported version means that we used the right program number
      if response.accept_state == rpc.Portmap.AcceptState.PROG_MISMATCH then
        result.program = program
        result.number = number
        _, result.highver = bin.unpack(">I", data, #data - 3)
        _, result.lowver = bin.unpack(">I", data, #data - 7)
        table.insert(result, true) -- To make #result > 1

        -- Otherwise, an Accept state other than Program unavailable is not normal behaviour.
      elseif response.accept_state ~= rpc.Portmap.AcceptState.PROG_UNAVAIL then
        stdnse.debug1("returned %s accept state for %s program number.", response.accept_state, number)
      end
    end
  end
  condvar "signal";
  return result
end

action = function(host, port)
  local result, lthreads = {}, {}

  if not isRPC(host, port) then
    stdnse.debug1("Target port %s is not a RPC port.", port.number)
    return
  end
  local threads = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".threads")) or 4

  local iterator = rpcIterator()
  if not iterator then
    return
  end
  -- And now, exec our grinder
  for i = 1,threads do
    local co = stdnse.new_thread(rpcGrinder, host, port, iterator, result)
    lthreads[co] = true
  end

  local condvar = nmap.condvar(result)
  repeat
    for thread in pairs(lthreads) do
      if coroutine.status(thread) == "dead" then
        lthreads[thread] = nil
      end
    end
    if ( next(lthreads) ) then
      condvar "wait";
    end
  until next(lthreads) == nil;

  -- Check the result and set the port version.
  if #result > 0 then
    port.version.name = result.program
    port.version.extrainfo = "RPC #" .. result.number
    if result.highver ~= result.lowver then
      port.version.version = ("%s-%s"):format(result.lowver, result.highver)
    else
      port.version.version = result.highver
    end
    nmap.set_port_version(host, port, "hardmatched")
  else
    stdnse.debug1("Couldn't determine the target RPC service. Running a service not in nmap-rpc ?")
  end
  return nil
end
