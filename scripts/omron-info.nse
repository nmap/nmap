local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
This NSE script is used to send a FINS packet to a remote device. The script
will send a Controller Data Read Command and once a response is received, it
validates that it was a proper response to the command that was sent, and then
will parse out the data.
]]
---
-- @usage
-- nmap --script omron-info -sU -p 9600 <host>
--
-- @output
-- 9600/tcp open  OMRON FINS
-- | omron-info:
-- |   Controller Model: CJ2M-CPU32          02.01
-- |   Controller Version: 02.01
-- |   For System Use:
-- |   Program Area Size: 20
-- |   IOM size: 23
-- |   No. DM Words: 32768
-- |   Timer/Counter: 8
-- |   Expansion DM Size: 1
-- |   No. of steps/transitions: 0
-- |   Kind of Memory Card: 0
-- |_  Memory Card Size: 0

-- @xmloutput
-- <elem key="Controller Model">CS1G_CPU44H         03.00</elem>
-- <elem key="Controller Version">03.00</elem>
-- <elem key="For System Use"></elem>
-- <elem key="Program Area Size">20</elem>
-- <elem key="IOM size">23</elem>
-- <elem key="No. DM Words">32768</elem>
-- <elem key="Timer/Counter">8</elem>
-- <elem key="Expansion DM Size">1</elem>
-- <elem key="No. of steps/transitions">0</elem>
-- <elem key="Kind of Memory Card">0</elem>
-- <elem key="Memory Card Size">0</elem>


author = "Stephen Hilt (Digital Bond)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

--
-- Function to define the portrule as per nmap standards
--
--
portrule = shortport.version_port_or_service(9600, "fins", {"tcp", "udp"})

---
--  Function to set the nmap output for the host, if a valid OMRON FINS packet
--  is received then the output will show that the port is open instead of
--  <code>open|filtered</code>
--
-- @param host Host that was passed in via nmap
-- @param port port that FINS is running on (Default UDP/9600)
function set_nmap(host, port)

  --set port Open
  port.state = "open"
  -- set version name to OMRON FINS
  port.version.name = "fins"
  nmap.set_port_version(host, port)
  nmap.set_port_state(host, port, "open")

end

local memcard = {
  [0] = "No Memory Card",
  [1] = "SPRAM",
  [2] = "EPROM",
  [3] = "EEPROM"
}

function memory_card(value)
  local mem_card = memcard[value] or "Unknown Memory Card Type"
  return mem_card
end
---
--  send_udp is a function that is used to run send the appropriate traffic to
--  the omron devices via UDP
--
-- @param socket Socket that is passed in from Action
function send_udp(socket)
  local controller_data_read = stdnse.fromhex( "800002000000006300ef050100")
  -- send Request Information Packet
  socket:send(controller_data_read)
  local rcvstatus, response = socket:receive()
  return response
end
---
--  send_tcp is a function that is used to run send the appropriate traffic to
--  the omron devices via TCP
--
-- @param socket Socket that is passed in from Action
function send_tcp(socket)
  -- this is the request address command
  local req_addr = stdnse.fromhex( "46494e530000000c000000000000000000000000")
  -- TCP requires a network address that is revived from the first request,
  -- The read controller data these two strings will be joined with the address
  local controller_data_read = stdnse.fromhex("46494e5300000015000000020000000080000200")
  local controller_data_read2 = stdnse.fromhex("000000ef050501")

  -- send Request Information Packet
  socket:send(req_addr)
  local rcvstatus, response = socket:receive()
  local header = string.byte(response, 1)
  if(header == 0x46) then
    local address = string.byte(response, 24)
    local controller_data = ("%s%c%s%c"):format(controller_data_read, address, controller_data_read2, 0x00)
    -- send the read controller data request
    socket:send(controller_data)
    local rcvstatus, response = socket:receive()
    return response
  end
  return "ERROR"
end

---
--  Action Function that is used to run the NSE. This function will send the initial query to the
--  host and port that were passed in via nmap. The initial response is parsed to determine if host
--  is a FINS supported device.
--
-- @param host Host that was scanned via nmap
-- @param port port that was scanned via nmap
action = function(host,port)

  -- create table for output
  local output = stdnse.output_table()
  -- create new socket
  local socket = nmap.new_socket()
  local catch = function()
    socket:close()
  end
  -- create new try
  local try = nmap.new_try(catch)
  -- connect to port on host
  try(socket:connect(host, port))
  -- init response var
  local response = ""
  -- set offset to 0, this will mean its UDP
  local offset = 0
  -- check to see if the protocol is TCP, if it is set offset to 16
  -- and perform the tcp_send function
  if (port.protocol == "tcp")then
    offset = 16
    response = send_tcp(socket)
    -- else its udp and call the send_udp function
  else
    response = send_udp(socket)
  end
  -- unpack the first byte for checking that it was a valid response
  local header = string.unpack("B", response, 1)
  if(header == 0xc0 or header == 0xc1 or header == 0x46) then
    set_nmap(host, port)
    local response_code = string.unpack("<I2", response, 13 + offset)
    -- test for a few of the error codes I saw when testing the script
    if(response_code == 2081) then
      output["Response Code"] = "Data cannot be changed (0x2108)"
    elseif(response_code == 290) then
      output["Response Code"] = "The mode is wrong (executing) (0x2201)"
      -- if a successful response code then
    elseif(response_code == 0) then
      -- parse information from response
      output["Response Code"] = "Normal completion (0x0000)"
      output["Controller Model"] = string.unpack("z", response,15 + offset)
      output["Controller Version"] = string.unpack("z", response, 35 + offset)
      output["For System Use"] = string.unpack("z", response, 55 + offset)
      local pos
      output["Program Area Size"], pos = string.unpack(">I2", response, 95 + offset)
      output["IOM size"], pos = string.unpack("B", response, pos)
      output["No. DM Words"], pos = string.unpack(">I2", response, pos)
      output["Timer/Counter"], pos = string.unpack("B", response, pos)
      output["Expansion DM Size"], pos = string.unpack("B", response, pos)
      output["No. of steps/transitions"], pos = string.unpack(">I2", response, pos)
      local mem_card_type
      mem_card_type, pos = string.unpack("B", response, pos)
      output["Kind of Memory Card"] = memory_card(mem_card_type)
      output["Memory Card Size"], pos = string.unpack(">I2", response, pos)

    else
      output["Response Code"] = "Unknown Response Code"
    end
    socket:close()
    return output

  else
    socket:close()
    return nil
  end

end
