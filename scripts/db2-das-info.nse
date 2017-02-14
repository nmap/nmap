local bin = require "bin"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Connects to the IBM DB2 Administration Server (DAS) on TCP or UDP port 523 and
exports the server profile.  No authentication is required for this request.

The script will also set the port product and version if a version scan is
requested.
]]

-- rev 1.1 (2010-01-28)

---
-- @output
-- PORT    STATE SERVICE VERSION
-- 523/tcp open  ibm-db2 IBM DB2 Database Server 9.07.0
-- | db2-das-info: DB2 Administration Server Settings
-- | ;DB2 Server Database Access Profile
-- | ;Use BINARY file transfer
-- | ;Comment lines start with a ";"
-- | ;Other lines must be one of the following two types:
-- | ;Type A: [section_name]
-- | ;Type B: keyword=value
-- |
-- | [File_Description]
-- | Application=DB2/LINUX 9.7.0
-- | Platform=18
-- | File_Content=DB2 Server Definitions
-- | File_Type=CommonServer
-- | File_Format_Version=1.0
-- | DB2System=MYBIGDATABASESERVER
-- | ServerType=DB2LINUX
-- |
-- | [adminst>dasusr1]
-- | NodeType=1
-- | DB2Comm=TCPIP
-- | Authentication=SERVER
-- | HostName=MYBIGDATABASESERVER
-- | PortNumber=523
-- | IpAddress=127.0.1.1
-- |
-- | [inst>db2inst1]
-- | NodeType=1
-- | DB2Comm=TCPIP
-- | Authentication=SERVER
-- | HostName=MYBIGDATABASESERVER
-- | ServiceName=db2c_db2inst1
-- | PortNumber=50000
-- | IpAddress=127.0.1.1
-- | QuietMode=No
-- | TMDatabase=1ST_CONN
-- |
-- | [db>db2inst1:TOOLSDB]
-- | DBAlias=TOOLSDB
-- | DBName=TOOLSDB
-- | Drive=/home/db2inst1
-- | Dir_entry_type=INDIRECT
-- |_Authentication=NOTSPEC

author = {"Patrik Karlsson", "Tom Sellers"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "version"}


--- Research Notes:
--
-- Little documentation on the protocol used to communicate with the IBM DB2 Admin Server
-- service exists.  The packets and methods here were developed based on data captured
-- in the wild.  Interviews with knowledgeable individuals indicates that the following
-- information can be used to recreate the traffic.
--
-- Requirements:
--   IBM DB2 Administrative Server (DAS) version >= 7.x instance, typically on port 523 tcp or udp
--   IBM DB2 Control Center (Java application, workings on Linux, Windows, etc)
--
-- Steps to reproduce:
--   Ensure network connectivity from test host to DB2 DAS instance on 523
--   In the Control Center, right click on All Systems and click Add
--   Enter the DB2 server IP or hostname in the System Name field and click OK
--   Start packet capture
--   Under All Systems right click on your DB2 server, choose export profile, enter file location, click OK
--   Stop packet capture
--
--   Details on how to reproduce these steps with the CLI are welcome.

portrule = shortport.version_port_or_service({523}, nil,
                                            {"tcp","udp"},
                                            {"open", "open|filtered"})

--- Extracts the server profile from an already parsed db2 packet
--
-- This function assumes that the data contains the server profile and does
-- no attempts to verify whether it does or not. The response from the function
-- is simply a substring starting at offset 37.
--
-- @param data string containing the "info" section as parsed by parse_db2_packet
-- @return string containing the complete server profile
function extract_server_profile(data)

  local server_profile_offset = 37

  if server_profile_offset > data:len() then
    return
  end

  return data:sub(server_profile_offset)

end

--- Does *very* basic parsing of a DB2 packet
--
-- Due to the limited documentation of the protocol this function is guesswork
-- The section called info is essentially the data part of the db2das data response
-- The length of this section is found at offset 158 in the db2das.data section
--
--
-- @param packet table as returned from read_db2_packet
-- @return table with parsed data
function parse_db2_packet(packet)

  local info_length_offset = 158
  local info_offset = 160
  local version_offset = 97
  local response = {}

  if packet.header.data_len < info_length_offset then
    stdnse.debug1("packet too short to be DB2 response...")
    return
  end

  local _, len = bin.unpack(">S", packet.data:sub(info_length_offset, info_length_offset + 1))
  _, response.version = bin.unpack("z", packet.data:sub(version_offset) )
  response.info_length = len - 4
  response.info = packet.data:sub(info_offset, info_offset + response.info_length - (info_offset-info_length_offset))

  if(nmap.debugging() > 3)  then
    stdnse.debug1("version: %s", response.version)
    stdnse.debug1("info_length: %d", response.info_length)
    stdnse.debug1("response.info:len(): %d", response.info:len())
  end

  return response

end

--- Reads a DB2 packet from the socket
--
-- Due to the limited documentation of the protocol this function is guesswork
-- The first 41 bytes of the db2das response are considered to be the header
-- The bytes following the header are considered to be the data
--
-- Offset 38 of the header contains an integer with the length of the data section
-- The length of the data section can unfortunately be of either endianness
-- There's
--
-- @param socket connected to the server
-- @return table with header and data
function read_db2_packet(socket)

  local packet = {}
  local header_len = 41
  local total_len = 0
  local buf

  local DATA_LENGTH_OFFSET = 38
  local ENDIANESS_OFFSET = 23

  local catch = function()
    stdnse.debug1("ERROR communicating with DB2 server")
    socket:close()
  end

  local try = nmap.new_try(catch)
  packet.header = {}

  buf = try( socket:receive_bytes(header_len) )

  packet.header.raw = buf:sub(1, header_len)

  if packet.header.raw:sub(1, 10) == "\x00\x00\x00\x00\x44\x42\x32\x44\x41\x53" then

    stdnse.debug1("Got DB2DAS packet")

    local _, endian = bin.unpack( "A2", packet.header.raw, ENDIANESS_OFFSET )

    if endian == "9z" then
      _, packet.header.data_len = bin.unpack("<I", packet.header.raw, DATA_LENGTH_OFFSET )
    else
      _, packet.header.data_len = bin.unpack(">I", packet.header.raw, DATA_LENGTH_OFFSET )
    end

    total_len = header_len + packet.header.data_len

    if(nmap.debugging() > 3) then
      stdnse.debug1("data_len: %d", packet.header.data_len)
      stdnse.debug1("buf_len: %d", buf:len())
      stdnse.debug1("total_len: %d", total_len)
    end

    -- do we have all data as specified by data_len?
    while total_len > buf:len() do
      -- if not read additional bytes
      if(nmap.debugging() > 3)  then
        stdnse.debug1("Reading %d additional bytes", total_len - buf:len())
      end
      local tmp = try( socket:receive_bytes( total_len - buf:len() ) )
      if(nmap.debugging() > 3)  then
        stdnse.debug1("Read %d bytes", tmp:len())
      end
      buf = buf .. tmp
    end

    packet.data = buf:sub(header_len + 1)

  else
    stdnse.debug1("Unknown packet, aborting ...")
    return
  end

  return packet

end

--- Sends a db2 packet table over the wire
--
-- @param socket already connected to the server
-- @param packet table as returned from <code>create_das_packet</code>
--
function send_db2_packet( socket, packet )

  local catch = function()
    stdnse.debug1("ERROR communicating with DB2 server")
    socket:close()
  end

  local try = nmap.new_try(catch)

  local buf = packet.header.raw .. packet.data

  try( socket:send(buf) )

end

--- Creates a db2 packet table using the magic byte and data
--
-- The function returns a db2 packet table:
-- packet.header - contains header specific values
-- packet.header.raw - contains the complete un-parsed header (string)
-- packet.header.data_len - contains the length of the data block
-- packet.data - contains the complete un-parsed data block (string)
--
-- @param magic byte containing a value of unknown function (could be type)
-- @param data string containing the db2 packet data
-- @return table as described above
--
function create_das_packet( magic, data )

  local packet = {}
  local data_len = data:len()

  packet.header = {}

  packet.header.raw = "\x00\x00\x00\x00\x44\x42\x32\x44\x41\x53\x20\x20\x20\x20\x20\x20"
  .. "\x01\x04\x00\x00\x00\x10\x39\x7a\x00\x05\x00\x00\x00\x00\x00\x00"
  .. "\x00\x00\x00\x00"
  .. bin.pack("C", magic)
  .. bin.pack("<S", data_len)
  .. "\x00\x00"

  packet.header.data_len = data_len
  packet.data = data

  return packet
end

action = function(host, port)


  -- create the socket used for our connection
  local socket = nmap.new_socket()

  -- set a reasonable timeout value
  socket:set_timeout(10000)

  -- do some exception handling / cleanup
  local catch = function()
    stdnse.debug1("ERROR communicating with " .. host.ip .. " on port " .. port.number)
    socket:close()
  end

  local try = nmap.new_try(catch)


  try(socket:connect(host, port))

  local query

  -- ************************************************************************************
  -- Transaction block 1
  -- ************************************************************************************
  local data = "\x00\x00\x00\x0d\x00\x00\x00\x0c\x00\x00\x00\x4a\x00"

  --try(socket:send(query))
  local db2packet = create_das_packet(0x02, data)

  send_db2_packet( socket, db2packet )
  read_db2_packet( socket )

  -- ************************************************************************************
  -- Transaction block 2
  -- ************************************************************************************
  data = "\x00\x00\x00\x2c\x00\x00\x00"
  .. "\x0c\x00\x00\x00\x08\x59\xe7\x1f\x4b\x79\xf0\x90\x72\x85\xe0\x8f"
  .. "\x3e\x38\x45\x38\xe3\xe5\x12\xc4\x3b\xe9\x7d\xe2\xf5\xf0\x78\xcc"
  .. "\x81\x6f\x87\x5f\x91"

  db2packet = create_das_packet(0x05, data)

  send_db2_packet( socket, db2packet )
  read_db2_packet( socket )

  -- ************************************************************************************
  -- Transaction block 3
  -- ************************************************************************************
  data = "\x00\x00\x00\x0d\x00\x00\x00\x0c\x00\x00\x00\x4a\x01\x00\x00\x00"
  .. "\x10\x00\x00\x00\x0c\x00\x00\x00\x4c\xff\xff\xff\xff\x00\x00\x00"
  .. "\x20\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x04\xb8\x64\x62\x32"
  .. "\x64\x61\x73\x4b\x6e\x6f\x77\x6e\x44\x73\x63\x76\x00\x00\x00\x00"
  .. "\x20\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x04\xb8\x64\x62\x32"
  .. "\x4b\x6e\x6f\x77\x6e\x44\x73\x63\x76\x53\x72\x76\x00"

  db2packet = create_das_packet(0x0a, data)
  send_db2_packet( socket, db2packet )
  read_db2_packet( socket )

  -- ************************************************************************************
  -- Transaction block 4
  -- ************************************************************************************
  data = "\x00\x00\x00\x0d\x00\x00\x00\x0c\x00\x00\x00\x4a\x01\x00\x00\x00"
  .. "\x20\x00\x00\x00\x0c\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x03"
  .. "\x48\x00\x00\x00\x00\x4a\xfb\x42\x90\x00\x00\x24\x93\x00\x00\x00"
  .. "\x10\x00\x00\x00\x0c\x00\x00\x00\x4c\xff\xff\xff\xff\x00\x00\x00"
  .. "\x10\x00\x00\x00\x0c\x00\x00\x00\x4c\xff\xff\xff\xff\x00\x00\x00"
  .. "\x20\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x04\xb8\x64\x62\x32"
  .. "\x4b\x6e\x6f\x77\x6e\x44\x73\x63\x76\x53\x72\x76\x00\x00\x00\x00"
  .. "\x20\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x04\xb8\x64\x62\x32"
  .. "\x64\x61\x73\x4b\x6e\x6f\x77\x6e\x44\x73\x63\x76\x00\x00\x00\x00"
  .. "\x0c\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00"
  .. "\x0c\x00\x00\x00\x4c\xff\xff\xff\xff\x00\x00\x00\x10\x00\x00\x00"
  .. "\x0c\x00\x00\x00\x4c\xff\xff\xff\xff\x00\x00\x00\x11\x00\x00\x00"
  .. "\x0c\x00\x00\x00\x04\x00\x00\x04\xb8\x00"

  db2packet = create_das_packet(0x06, data)
  send_db2_packet( socket, db2packet )

  data =  "\x00\x00\x00\x20\x00\x00\x00\x0c\x00\x00\x00\x04\x00"
  .. "\x00\x04\xb8\x64\x62\x32\x64\x61\x73\x4b\x6e\x6f\x77\x6e\x44\x73"
  .. "\x63\x76\x00\x00\x00\x00\x20\x00\x00\x00\x0c\x00\x00\x00\x04\x00"
  .. "\x00\x04\xb8\x64\x62\x32\x4b\x6e\x6f\x77\x6e\x44\x73\x63\x76\x53"
  .. "\x72\x76\x00\x00\x00\x00\x10\x00\x00\x00\x0c\x00\x00\x00\x4c\x00"
  .. "\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x0c\x00\x00\x00\x4c\x00"
  .. "\x00\x00\x01\x00\x00\x00\x10\x00\x00\x00\x0c\x00\x00\x00\x4c\x00"
  .. "\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x0c\x00\x00\x00\x08\x00"
  .. "\x00\x00\x10\x00\x00\x00\x0c\x00\x00\x00\x4c\x00\x00\x00\x01\x00"
  .. "\x00\x00\x18\x00\x00\x00\x0c\x00\x00\x00\x08\x00\x00\x00\x0c\x00"
  .. "\x00\x00\x0c\x00\x00\x00\x18"

  db2packet = create_das_packet(0x06, data)
  send_db2_packet( socket, db2packet )

  local packet = read_db2_packet( socket )
  local db2response = parse_db2_packet(packet)

  socket:close()

  -- The next block of code is essentially the version extraction code from db2-info.nse
  local server_version
  if string.sub(db2response.version,1,3) == "SQL" then
    local major_version = string.sub(db2response.version,4,5)

    -- strip the leading 0 from the major version, for consistency with
    -- nmap-service-probes results
    if string.sub(major_version,1,1) == "0" then
      major_version = string.sub(major_version,2)
    end
    local minor_version = string.sub(db2response.version,6,7)
    local hotfix = string.sub(db2response.version,8)
    server_version = major_version .. "." .. minor_version .. "." .. hotfix
  end

  -- Try to determine which of the two values (probe version vs script) has more
  -- precision.  A couple DB2 versions send DB2 UDB 7.1 vs SQL090204 (9.02.04)
  local _
  local current_count = 0
  if port.version.version ~= nil then
    _, current_count = string.gsub(port.version.version, "%.", ".")
  end

  local new_count = 0
  if server_version ~= nil then
    _, new_count = string.gsub(server_version, "%.", ".")
  end

  if current_count < new_count then
    port.version.version = server_version
  end

  local result = false

  local db2profile = extract_server_profile( db2response.info )

  if (db2profile ~= nil ) then
    result = "DB2 Administration Server Settings\r\n"
    .. extract_server_profile( db2response.info )

    -- Set port information
    port.version.name = "ibm-db2"
    port.version.product = "IBM DB2 Database Server"
    port.version.name_confidence = 10
    nmap.set_port_version(host, port)
    nmap.set_port_state(host, port, "open")
  end

  return result

end
