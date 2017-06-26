local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description = [[
Retrieves version and database information from a SAP Max DB database.
]]

---
-- @usage
-- nmap -p 7210 --script maxdb-info <ip>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 7210/tcp open  maxdb   syn-ack
-- | maxdb-info:
-- |   Version: 7.8.02
-- |   Build: DBMServer 7.8.02   Build 021-121-242-175
-- |   OS: UNIX
-- |   Instroot: /opt/sdb/MaxDB
-- |   Sysname: Linux 3.0.0-12-generic #20-Ubuntu SMP Fri Oct 7 14:56:25 UTC 2011
-- |   Databases
-- |     instance  path            version    kernel  state
-- |     MAXDB     /opt/sdb/MaxDB  7.8.02.21  fast    running
-- |     MAXDB     /opt/sdb/MaxDB  7.8.02.21  quick   offline
-- |     MAXDB     /opt/sdb/MaxDB  7.8.02.21  slow    offline
-- |_    MAXDB     /opt/sdb/MaxDB  7.8.02.21  test    offline
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "default", "version", "safe" }


portrule = shortport.version_port_or_service(7210, "maxdb", "tcp")

-- Sends and receive a MaxDB packet
-- @param socket already connected to the server
-- @param packet string containing the data to send
-- @return status true on success, false on failure
-- @return data string containing the raw response from the server
local function exchPacket(socket, packet)
  local status, err = socket:send(packet)
  if ( not(status) ) then
    stdnse.debug2("Failed to send packet to server")
    return false, "Failed to send packet to server"
  end

  local data
  status, data= socket:receive()
  if ( not(status) ) then
    stdnse.debug2("Failed to read packet from server")
    return false, "Failed to read packet from server"
  end
  local pos, len = bin.unpack("<S", data)

  -- make sure we've got it all
  if ( len ~= #data ) then
    local tmp
    status, tmp = socket:receive_bytes(len - #data)
    if ( not(status) ) then
      stdnse.debug2("Failed to read packet from server")
      return false, "Failed to read packet from server"
    end
    data = data .. tmp
  end
  return true, data
end

-- Sends and receives a MaxDB command and does some very basic checks of the
-- response.
-- @param socket already connected to the server
-- @param packet string containing the data to send
-- @return status true on success, false on failure
-- @return data string containing the raw response from the server
local function exchCommand(socket, packet)
  local status, data = exchPacket(socket, packet)
  if( status ) then
    if ( #data < 26 ) then
      return false, "Response to short"
    end
    if ( "OK" ~= data:sub(25, 26) ) then
      return false, "Incorrect response from server (no OK found)"
    end
  end
  return status, data
end

-- Parses and decodes the raw version response from the server
-- @param data string containing the raw response
-- @return version_info table containing a number of dynamic fields based on
--         the response from the server. The fields typically include:
--         <code>VERSION</code>, <code>BUILD</code>, <code>OS</code>,
--         <code>INSTROOT</code>,<code>LOGON</code>, <code>CODE</code>,
--         <code>SWAP</code>, <code>UNICODE</code>, <code>INSTANCE</code>,
--         <code>SYSNAME</code>, <code>MASKING</code>,
--         <code>REPLYTREATMENT</code> and <code>SDBDBM_IPCLOCATION</code>
local function parseVersion(data)
  local version_info = {}
  if ( #data > 27 ) then
    for _, line in ipairs(stdnse.strsplit("\n", data:sub(28))) do
      local key, val = line:match("^(%S+)%s-=%s(.*)%s*$")
      if ( key ) then  version_info[key] = val end
    end
  end
  return version_info
end

-- Parses and decodes the raw database response from the server
-- @param data string containing the raw response
-- @return result string containing a table of database instance information
local function parseDatabases(data)
  local result = tab.new(5)
  tab.addrow(result, "instance", "path", "version", "kernel", "state")
  for _, line in ipairs(stdnse.strsplit("\n", data:sub(28))) do
    local cols = {}
    cols.instance, cols.path, cols.ver, cols.kernel,
      cols.state = line:match("^(.-)%s*\t(.-)%s*\t(.-)%s*\t(.-)%s-\t(.-)%s-$")
    if ( cols.instance ) then
      tab.addrow(result, cols.instance, cols.path, cols.ver, cols.kernel, cols.state)
    end
  end
  return tab.dump(result)
end

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  -- this could really be more elegant, but it has to do for now
  local handshake   = "5a000000035b000001000000ffffffff000004005a000000000242000409000000400000d03f00000040000070000000000500000004000000020000000300000749343231360004501c2a035201037201097064626d73727600"
  local dbm_version = "28000000033f000001000000ac130000000004002800000064626d5f76657273696f6e2020202020"
  local db_enum     = "20000000033f000001000000ac130000000004002000000064625f656e756d20"

  local socket = nmap.new_socket()
  socket:set_timeout(10000)
  local status, err = socket:connect(host, port)
  local data

  status, data = exchPacket(socket, stdnse.fromhex( handshake))
  if ( not(status) ) then
    return fail("Failed to perform handshake with MaxDB server")
  end

  status, data = exchPacket(socket, stdnse.fromhex( dbm_version))
  if ( not(status) ) then
    return fail("Failed to request version information from server")
  end

  local version_info = parseVersion(data)
  if ( not(version_info) ) then
    return fail("Failed to parse version information from server")
  end

  local result, filter = {}, {"Version", "Build", "OS", "Instroot", "Sysname"}
  for _, f in ipairs(filter) do
    table.insert(result, ("%s: %s"):format(f, version_info[f:upper()]))
  end

  status, data = exchCommand(socket, stdnse.fromhex( db_enum))
  socket:close()
  if ( not(status) ) then
    return fail("Failed to request version information from server")
  end
  local dbs = parseDatabases(data)
  table.insert(result, { name = "Databases", dbs } )

  -- set the version information
  port.version.name = "maxdb"
  port.version.product = "SAP MaxDB"
  port.version.version = version_info.VERSION
  port.version.ostype = version_info.SYSNAME
  nmap.set_port_version(host, port)

  return stdnse.format_output(true, result)
end
