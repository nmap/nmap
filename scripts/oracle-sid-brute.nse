local bin = require "bin"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Guesses Oracle instance/SID names against the TNS-listener.

If the <code>oraclesids</code> script argument is not used to specify an
alternate file, the default <code>oracle-sids</code> file will be used.
License to use the <code>oracle-sids</code> file was granted by its
author, Alexander Kornbrust (http://seclists.org/nmap-dev/2009/q4/645).
]]

---
-- @args oraclesids A file containing SIDs to try.
--
-- @usage
-- nmap --script=oracle-sid-brute --script-args=oraclesids=/path/to/sidfile -p 1521-1560 <host>
-- nmap --script=oracle-sid-brute -p 1521-1560 <host>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 1521/tcp open  oracle  syn-ack
-- | oracle-sid-brute:
-- |   orcl
-- |   prod
-- |_  devel

-- Version 0.3

-- Created 12/10/2009 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 12/11/2009 - v0.2 - Added tns_type, split packet creation to header & data
-- Revised 12/14/2009 - v0.3 - Fixed ugly file_exist kludge

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


portrule = shortport.port_or_service(1521, 'oracle-tns')

-- A table containing the different TNS types ... not complete :)
local tns_type = {CONNECT=1, REFUSE=4, REDIRECT=5, RESEND=11}

--- Creates a TNS header
-- A lot of values are still hardcoded ...
--
-- @param packetType string containing the type of TNS packet
-- @param packetLength number defining the length of the DATA segment of the packet
--
-- @return string with the raw TNS header
--
local function create_tns_header(packetType, packetLength)

  local request = bin.pack( ">SSCCS",
    packetLength + 34, -- Packet Length
    0, -- Packet Checksum
    tns_type[packetType], -- Packet Type
    0, -- Reserved Byte
    0 -- Header Checksum
    )

  return request

end

--- Creates a TNS connect packet
--
-- @param host_ip string containing the IP of the remote host
-- @param port_no number containing the remote port of the Oracle instance
-- @param sid string containing the SID against which to attempt to connect
--
-- @return string containing the raw TNS packet
--
local function create_connect_packet( host_ip, port_no, sid )

  local connect_data = string.format(
    "(DESCRIPTION=(CONNECT_DATA=(SID=%s)(CID=(PROGRAM=)(HOST=__jdbc__)(USER=)))\z
    (ADDRESS=(PROTOCOL=tcp)(HOST=%s)(PORT=%d)))", sid, host_ip, port_no)

  local data = bin.pack(">SSSSSSSSSSICCA",
    308, -- Version
    300, -- Version (Compatibility)
    0, -- Service Options
    2048, -- Session Data Unit Size
    32767, -- Maximum Transmission Data Unit Size
    20376, -- NT Protocol Characteristics
    0, -- Line Turnaround Value
    1, -- Value of 1 in Hardware
    connect_data:len(), -- Length of connect data
    34, -- Offset to connect data
    0, -- Maximum Receivable Connect Data
    1, -- Connect Flags 0
    1, -- Connect Flags 1
    connect_data
    )


  local header = create_tns_header("CONNECT", connect_data:len() )

  return header .. data

end

--- Process a TNS response and extracts Length, Checksum and Type
--
-- @param packet string as a raw TNS response
-- @return table with Length, Checksum and Type set
--
local function process_tns_packet( packet )

  local tnspacket = {}

  -- just pull out the bare minimum to be able to match
  local _
  _, tnspacket.Length, tnspacket.Checksum, tnspacket.Type = bin.unpack(">SSC", packet)

  return tnspacket

end

action = function(host, port)

  local found_sids = {}
  local socket = nmap.new_socket()
  local catch = function() socket:close() end
  local try = nmap.new_try(catch)
  local request, response, tns_packet
  local sidfile

  socket:set_timeout(5000)

  -- open the sid file specified by the user or fallback to the default oracle-sids file
  local sidfilename = nmap.registry.args.oraclesids or nmap.fetchfile("nselib/data/oracle-sids")

  sidfile = io.open(sidfilename)

  if not sidfile then
    return
  end

  -- read sids line-by-line from the sidfile
  for sid in sidfile:lines() do

    -- check for comments
    if not sid:match("#!comment:") then

      try(socket:connect(host, port))
      request = create_connect_packet( host.ip, port.number, sid )
      try(socket:send(request))
      response = try(socket:receive_bytes(1))
      tns_packet = process_tns_packet(response)

      -- If we get anything other than REFUSE consider it as a valid SID
      if tns_packet.Type ~= tns_type.REFUSE then
        table.insert(found_sids, sid)
      end

      try(socket:close())

    end

  end

  sidfile:close()

  return stdnse.format_output(true, found_sids)

end
