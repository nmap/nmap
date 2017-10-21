local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local snmp = require "snmp"
local stdnse = require "stdnse"
local table = require "table"
local tftp = require "tftp"

description = [[
Attempts to downloads Cisco router IOS configuration files using SNMP RW (v1) and display or save them.
]]

---
-- @usage
-- nmap -sU -p 161 --script snmp-ios-config --script-args creds.snmp=:<community> <target>
--
-- @output
-- | snmp-ios-config:
-- | !
-- | version 12.3
-- | service timestamps debug datetime msec
-- | service timestamps log datetime msec
-- | no service password-encryption
-- | !
-- | hostname Router
-- | !
-- | boot-start-marker
-- | boot-end-marker
-- <snip>
--
-- @args snmp-ios-config.tftproot If set, specifies to what directory the downloaded config should be saved

--
-- Version 0.2
-- Created 01/03/2011 - v0.1 - created by Vikas Singhal
-- Revised 02/22/2011 - v0.2 - cleaned up and added support for built-in tftp, Patrik Karlsson <patrik@cqure.net>

author = {"Vikas Singhal", "Patrik Karlsson"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive"}

dependencies = {"snmp-brute"}


portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})

local function fail (err) return stdnse.format_output(false, err) end
---
-- Sends SNMP packets to host and reads responses
action = function(host, port)

  local tftproot = stdnse.get_script_args("snmp-ios-config.tftproot")

  if ( tftproot and not( tftproot:match("[\\/]+$") ) ) then
    return fail("tftproot needs to end with slash")
  end

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  local status, tftpserver, _, _, _ = snmpHelper.socket:get_info()
  if( not(status) ) then
    return fail("Failed to determine local ip")
  end

  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.2.9999 (ConfigCopyProtocol is set to TFTP [1] )

  local request = snmpHelper:set({reqiId=28428},".1.3.6.1.4.1.9.9.96.1.1.1.1.2.9999",1)

  -- Fail silently if the first request doesn't get a proper response
  if ( not(request) ) then return  end

  -- since we got something back, the port is definitely open
  nmap.set_port_state(host, port, "open")

  -------------------------------------------------
  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.3 (SourceFileType is set to running-config [4] )

  request = snmpHelper:set({reqId=28428}, ".1.3.6.1.4.1.9.9.96.1.1.1.1.3.9999",4)

  -------------------------------------------------
  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.4 (DestinationFileType is set to networkfile [1] )

  request = snmpHelper:set({reqId=28428}, ".1.3.6.1.4.1.9.9.96.1.1.1.1.4.9999",1)

  -------------------------------------------------
  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.15 (ServerAddress is set to the IP address of the TFTP server )

  local tbl = {}
  tbl._snmp = '40'
  for octet in tftpserver:gmatch("%d+") do
    table.insert(tbl, octet)
  end

  request = snmpHelper:set({reqId=28428}, nil, { { snmp.str2oid(".1.3.6.1.4.1.9.9.96.1.1.1.1.5.9999"), tbl } } )
  -- request = sendrequest(".1.3.6.1.4.1.9.9.96.1.1.1.1.5.9999",tftpserver)


  -------------------------------------------------
  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.15 (ServerAddressType is set 1 for ipv4 )
  -- more options - 1:ipv4, 2:ipv6, 3:ipv4z, 4:ipv6z, 16:dns

  request = snmpHelper:set({reqId=28428}, ".1.3.6.1.4.1.9.9.96.1.1.1.1.15.9999",1)

  -------------------------------------------------
  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.16 (ServerAddress is set to the IP address of the TFTP server )

  request = snmpHelper:set({reqId=28428}, ".1.3.6.1.4.1.9.9.96.1.1.1.1.16.9999",tftpserver)

  -------------------------------------------------
  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.6 (CopyFilename is set to IP-config)

  request = snmpHelper:set({reqId=28428}, ".1.3.6.1.4.1.9.9.96.1.1.1.1.6.9999",host.ip .. "-config")

  -------------------------------------------------
  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.14 (Start copying by setting CopyStatus to active [1])
  -- more options: 1:active, 2:notInService, 3:notReady, 4:createAndGo, 5:createAndWait, 6:destroy

  request = snmpHelper:set({reqId=28428}, ".1.3.6.1.4.1.9.9.96.1.1.1.1.14.9999",1)

  -- wait for sometime and print the status of filetransfer
  tftp.start()
  local status, infile = tftp.waitFile(host.ip .. "-config", 10)

  -- build a SNMP v1 packet
  -- get value: .1.3.6.1.4.1.9.9.96.1.1.1.1.10 (Check the status of filetransfer) 1:waiting, 2:running, 3:successful, 4:failed

  local response
  status, response = snmpHelper:get({reqId=28428}, ".1.3.6.1.4.1.9.9.96.1.1.1.1.10.9999")

  if (not status) or (response == "TIMEOUT") then
    return fail("Failed to receive cisco configuration file")
  end

  local result = response and response[1] and response[1][1]
  if not result then
    return
  end

  if result == 3 then
    result = ( infile and infile:getContent() )

    if ( tftproot ) then
      local fname = tftproot .. stdnse.filename_escape(host.ip .. "-config")
      local file, err = io.open(fname, "w")
      if ( file ) then
        file:write(result)
        file:close()
      else
        return fail(file)
      end
      result = ("\n  Configuration saved to (%s)"):format(fname)
    end
  else
    result = "Not successful! error code: " .. result .. " (1:waiting, 2:running, 3:successful, 4:failed)"
  end

  -------------------------------------------------
  -- build a SNMP v1 packet
  -- set value: .1.3.6.1.4.1.9.9.96.1.1.1.1.14 (Destroy settings by setting CopyStatus to destroy [6])

  request = snmpHelper:set({reqId=28428}, ".1.3.6.1.4.1.9.9.96.1.1.1.1.14.9999",6)


  return result
end

