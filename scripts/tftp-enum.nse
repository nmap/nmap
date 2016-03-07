local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local coroutine = require "coroutine"
local io = require "io"

description = [[
Enumerates TFTP (trivial file transfer protocol) filenames by testing
for a list of common ones.

TFTP doesn't provide directory listings. This script tries to retrieve
filenames from a list. The list is composed of static names from the
file <code>tftplist.txt</code>, plus configuration filenames for Cisco
devices that change based on the target address, of the form
<code>A.B.C.X-confg</code> for an IP address A.B.C.D and for X in 0 to
255.

Use the <code>tftp-enum.filelist</code> script argument to search for
other static filenames.

This script is a reimplementation of tftptheft from
http://code.google.com/p/tftptheft/.
]]

---
-- @usage nmap -sU -p 69 --script tftp-enum.nse --script-args="tftp-enum.filelist=customlist.txt" <host>
--
-- @args filelist - file name with list of filenames to enumerate at tftp server
--
-- @output
-- PORT   STATE SERVICE REASON
-- 69/udp open  tftp    script-set
-- | tftp-enum:
-- |_  bootrom.ld

author = "Alexander Rudakov"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "intrusive" }


local REQUEST_ERROR = -1
local FILE_FOUND = 1
local FILE_NOT_FOUND = 2

portrule = shortport.portnumber(69, "udp")


local create_tftp_file_request = function(filename)
  return "\0\x01" .. filename .. "\0octet\0"
end

local check_file_present = function(host, port, filename)
  stdnse.debug1("checking file %s", filename)

  local file_request = create_tftp_file_request(filename)


  local socket = nmap.new_socket("udp")
  socket:connect(host, port, "udp")
  local status, lhost, lport, rhost, rport = socket:get_info()

  if (not (status)) then
    stdnse.debug1("error %s", lhost)
    socket:close()
    return REQUEST_ERROR
  end

  stdnse.debug1("local port = %d", lport)

  socket:send(file_request)
  socket:close()

  local bindOK, error = socket:bind(nil, lport)


  stdnse.debug1("starting listener")

  if (not (bindOK)) then
    stdnse.debug1("Error in bind %s", error)
    socket:close()
    return REQUEST_ERROR
  end

  socket:set_timeout(1000)
  local recvOK, data = socket:receive()

  if (not (recvOK)) then
    stdnse.debug1("Error in receive %s", data)
    socket:close()
    return REQUEST_ERROR
  end

  if (data:byte(1) == 0x00 and data:byte(2) == 0x03) then
    socket:close()
    return FILE_FOUND
  elseif (data:byte(1) == 0x00 and data:byte(2) == 0x05) then
    socket:close()
    return FILE_NOT_FOUND
  else
    socket:close()
    return REQUEST_ERROR
  end

  return FILE_NOT_FOUND
end

local check_open_tftp = function(host, port)
  local random_name = stdnse.generate_random_string(8, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
  local ret_value = check_file_present(host, port, random_name)
  if (ret_value == FILE_FOUND or ret_value == FILE_NOT_FOUND) then
    return true
  else
    return false
  end
end

local filename_iterator = function(host)
  return coroutine.wrap(function ()

    local filename = stdnse.get_script_args('tftp-enum.filelist')
    filename = filename or "nselib/data/tftplist.txt"

    for line in io.lines(filename) do
      if line:match('{[Mm][Aa][Cc]}') then
        if not host.mac_addr then
          goto next_filename
        end
        line = line:gsub('{MAC}', string.upper(stdnse.tohex(host.mac_addr)))
        line = line:gsub('{mac}', stdnse.tohex(host.mac_addr))
      end
      coroutine.yield(line)
      ::next_filename::
    end

    local octets = stdnse.strsplit("%.", host.ip)

    for i = 0, 255 do
      local address_confg = octets[1] .. "." .. octets[2] .. "." .. octets[3] .. "." .. i .. "-confg"
      coroutine.yield(address_confg) 
    end
  end)
end

action = function(host, port)
  if (not (check_open_tftp(host, port))) then
    stdnse.debug1("tftp seems not active")
    return
  end

  stdnse.debug1("tftp detected")

  port.service = "tftp"
  nmap.set_port_state(host, port, "open")

  local results = {}

  for filename in filename_iterator(host) do
    local retries = 3
    repeat
      local request_status = check_file_present(host, port, filename)
      if (request_status == FILE_FOUND) then
        table.insert(results, filename)
        break
      end
      retries = retries - 1
    until retries == 0
  end

  return stdnse.format_output(true, results)
end
